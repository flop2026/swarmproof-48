#!/usr/bin/env node

import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { lstat, mkdir, open, readFile, rename, rm, writeFile } from "node:fs/promises";
import {
  assessCheckpointChain,
  assessCheckpointInputs,
  checkpointAgeSeconds,
  createCheckpointEnvelope,
} from "../lib/checkpoint.mjs";
import { didFromPrivateKey, signUtf8 } from "../lib/crypto.mjs";
import { verifyEnvelope } from "../lib/protocol.mjs";

const ORIGIN = "https://technocore.chat";
const PROJECT_ROOT = fileURLToPath(new URL("..", import.meta.url));
const DEFAULT_STATE_FILE = join(homedir(), ".local", "state", "technocore-chat", "swarmproof-48-checkpoint.json");
const DEFAULT_LOCK_FILE = join(homedir(), ".local", "state", "technocore-chat", "swarmproof-48-checkpoint.lock");
const HASH_RE = /^[0-9a-f]{64}$/;
let releaseCheckpointLock = null;

function parseArguments(arguments_) {
  const allowed = new Set(["--dry-run"]);
  for (const argument of arguments_) {
    if (!allowed.has(argument)) throw new Error(`Unknown argument: ${argument}`);
  }
  return { dryRun: arguments_.includes("--dry-run") };
}

async function readJson(path) {
  return JSON.parse(await readFile(path, "utf8"));
}

async function readState(path) {
  try {
    const state = await readJson(path);
    if (state.schema !== "swarmproof-checkpoint-local-state-v1") {
      throw new Error("Unsupported local checkpoint state.");
    }
    return state;
  } catch (error) {
    if (error.code === "ENOENT") return null;
    throw error;
  }
}

async function writeState(path, state) {
  await mkdir(dirname(path), { recursive: true, mode: 0o700 });
  const temporary = `${path}.tmp-${process.pid}`;
  await writeFile(temporary, `${JSON.stringify(state, null, 2)}\n`, {
    encoding: "utf8",
    mode: 0o600,
  });
  await rename(temporary, path);
}

async function acquireCheckpointLock(path) {
  const directory = dirname(path);
  if (directory === "/") throw new Error("Checkpoint lock path is unsafe.");
  await mkdir(directory, { recursive: true, mode: 0o700 });
  const metadata = await lstat(directory);
  if (!metadata.isDirectory() || metadata.isSymbolicLink()) {
    throw new Error("Checkpoint lock directory must be a regular directory.");
  }
  const handle = await open(path, "wx", 0o600).catch(error => {
    if (error.code === "EEXIST") throw new Error("Another checkpoint process may be active; refusing to post.");
    throw error;
  });
  await handle.writeFile(`${process.pid}\n`, "utf8");
  return async () => {
    await handle.close();
    await rm(path, { force: true });
  };
}

function output(value) {
  process.stdout.write(`${JSON.stringify(value)}\n`);
}

const sleep = milliseconds => new Promise(resolve => setTimeout(resolve, milliseconds));

async function fetchWithRetry(label, factory) {
  let lastError;
  for (let attempt = 1; attempt <= 4; attempt += 1) {
    try {
      const response = await factory();
      if (response.ok) return response;
      const body = (await response.text()).slice(0, 500);
      lastError = new Error(`${label}: HTTP ${response.status}: ${body}`);
      if (response.status !== 429 && response.status < 500) {
        lastError.nonRetryable = true;
        throw lastError;
      }
      const retryAfter = Number(response.headers.get("retry-after"));
      await sleep(Number.isFinite(retryAfter) ? retryAfter * 1000 : attempt * 1500);
    } catch (error) {
      lastError = error;
      if (error.nonRetryable) throw error;
      if (attempt === 4) break;
      await sleep(attempt * 1500);
    }
  }
  throw lastError;
}

async function boundedText(response, limit, label) {
  const declared = Number(response.headers.get("content-length"));
  if (Number.isFinite(declared) && declared > limit) throw new Error(`${label} response is oversized.`);
  const body = await response.text();
  if (Buffer.byteLength(body, "utf8") > limit) throw new Error(`${label} response is oversized.`);
  return body;
}

function ownerDidFromBody(body) {
  const dids = body
    .split("\n")
    .map(line => line.trim())
    .filter(line => /^did:key:z6Mk[1-9A-HJ-NP-Za-km-z]+$/.test(line));
  if (dids.length !== 1) throw new Error("Owned-room record is missing or ambiguous.");
  return dids[0];
}

function checkpointsFromRoom(data, config) {
  if (!data || !Array.isArray(data.messages)) throw new Error("Official-room response is invalid.");
  const checkpoints = [];
  const seenEventIds = new Set();
  for (const message of data.messages) {
    if (message.from !== config.coordinator_did || typeof message.text !== "string") continue;
    try {
      const verified = verifyEnvelope(message.text, {
        allowedRepositories: new Set([config.repository]),
        allowedTasks: new Set(["event-start", "daily-checkpoint"]),
        coordinatorDid: config.coordinator_did,
      });
      if (
        verified.payload.type !== "CHECKPOINT"
        || verified.payload.did !== config.coordinator_did
        || String(message.nonce ?? "") !== verified.payload.nonce
        || seenEventIds.has(verified.event_id)
      ) continue;
      seenEventIds.add(verified.event_id);
      checkpoints.push({
        event_id: verified.event_id,
        report_sha256: verified.payload.content_sha256,
        nonce: verified.payload.nonce,
        posted_at: verified.payload.claimed_at,
        task_id: verified.payload.task_id,
        parent_event_ids: verified.payload.parent_event_ids,
      });
    } catch {
      // The owned room is still treated as untrusted input. Ignore malformed envelopes.
    }
  }
  return checkpoints.sort((left, right) => {
    const leftNonce = BigInt(left.nonce);
    const rightNonce = BigInt(right.nonce);
    return leftNonce < rightNonce ? -1 : leftNonce > rightNonce ? 1 : 0;
  });
}

async function securePrivateKey(path) {
  if (!path) throw new Error("SWARMPROOF_KEY_FILE is required when a checkpoint is eligible.");
  const metadata = await lstat(path);
  if (!metadata.isFile() || metadata.isSymbolicLink()) throw new Error("Private key must be a regular file.");
  if ((metadata.mode & 0o077) !== 0) throw new Error("Private key permissions must deny group and other access.");
  if (metadata.size <= 0 || metadata.size > 16_384) throw new Error("Private key size is invalid.");
  return readFile(path, "utf8");
}

function nextNonce(now, state, checkpoints) {
  const candidates = [BigInt(now.getTime())];
  if (/^[0-9]{1,19}$/.test(state?.nonce ?? "")) candidates.push(BigInt(state.nonce) + 1n);
  for (const checkpoint of checkpoints) {
    if (/^[0-9]{1,19}$/.test(checkpoint.nonce ?? "")) candidates.push(BigInt(checkpoint.nonce) + 1n);
  }
  const nonce = String(candidates.reduce((largest, candidate) => candidate > largest ? candidate : largest));
  if (!/^[0-9]{1,19}$/.test(nonce)) throw new Error("Could not derive a safe nonce.");
  return nonce;
}

async function observeCheckpoint(config, eventId) {
  for (let attempt = 1; attempt <= 4; attempt += 1) {
    const response = await fetchWithRetry("checkpoint read-back", () => fetch(
      `${ORIGIN}/r/${encodeURIComponent(config.official_room)}?format=json&limit=200&n=${Date.now()}-${attempt}`,
      { signal: AbortSignal.timeout(20_000) },
    ));
    const body = await boundedText(response, 2_000_000, "Checkpoint read-back");
    let data;
    try {
      data = JSON.parse(body);
    } catch {
      throw new Error("Checkpoint read-back response is not valid JSON.");
    }
    const observed = checkpointsFromRoom(data, config).find(checkpoint => checkpoint.event_id === eventId);
    if (observed) return observed;
    if (attempt < 4) await sleep(attempt * 500);
  }
  return null;
}

async function main() {
  const { dryRun } = parseArguments(process.argv.slice(2));
  const paths = {
    config: process.env.SWARMPROOF_CONFIG_FILE ?? join(PROJECT_ROOT, "config", "event.json"),
    report: process.env.SWARMPROOF_REPORT_FILE ?? join(PROJECT_ROOT, "public", "data", "report.json"),
    status: process.env.SWARMPROOF_STATUS_FILE ?? join(PROJECT_ROOT, "public", "data", "status.json"),
    state: process.env.SWARMPROOF_CHECKPOINT_STATE_FILE ?? DEFAULT_STATE_FILE,
  };
  const [config, report, status] = await Promise.all([
    readJson(paths.config),
    readJson(paths.report),
    readJson(paths.status),
  ]);
  const now = new Date();
  const maxAgeSeconds = process.env.SWARMPROOF_CHECKPOINT_MAX_AGE_SECONDS === undefined
    ? null
    : Number(process.env.SWARMPROOF_CHECKPOINT_MAX_AGE_SECONDS);
  const assessment = assessCheckpointInputs({ config, report, status, now, maxAgeSeconds });
  if (!assessment.eligible) {
    output({ action: "skip", reason: assessment.reason, dry_run: dryRun });
    return;
  }
  if (!dryRun) {
    releaseCheckpointLock = await acquireCheckpointLock(
      process.env.SWARMPROOF_CHECKPOINT_LOCK_FILE ?? DEFAULT_LOCK_FILE,
    );
  }

  const state = await readState(paths.state);
  if (state && (state.room !== config.official_room || state.did !== config.coordinator_did)) {
    throw new Error("Local checkpoint state belongs to a different room or DID.");
  }
  const minimumIntervalSeconds = Number(process.env.SWARMPROOF_CHECKPOINT_MIN_INTERVAL_SECONDS ?? 72_000);
  if (!Number.isFinite(minimumIntervalSeconds) || minimumIntervalSeconds < 0) {
    throw new Error("Checkpoint minimum interval is invalid.");
  }
  let secondsSincePrevious = Number.POSITIVE_INFINITY;
  if (state?.posted_at) {
    const previous = Date.parse(state.posted_at);
    if (!Number.isFinite(previous)) throw new Error("Local checkpoint time is invalid.");
    if (previous > now.getTime() + 300_000) throw new Error("Local checkpoint time is in the future.");
    secondsSincePrevious = (now.getTime() - previous) / 1000;
    if (secondsSincePrevious < minimumIntervalSeconds) {
      output({ action: "skip", reason: "minimum_interval", dry_run: dryRun });
      return;
    }
  }
  const maximumSilenceSeconds = Number(process.env.SWARMPROOF_CHECKPOINT_MAX_SILENCE_SECONDS ?? 82_800);
  if (!Number.isFinite(maximumSilenceSeconds) || maximumSilenceSeconds < minimumIntervalSeconds) {
    throw new Error("Checkpoint maximum silence is invalid.");
  }
  if (
    state?.meaningful_sha256 === assessment.meaningful_sha256
    && secondsSincePrevious < maximumSilenceSeconds
  ) {
    output({ action: "skip", reason: "no_meaningful_change", dry_run: dryRun });
    return;
  }

  const [ownerResponse, roomResponse] = await Promise.all([
    fetchWithRetry("owned-room lookup", () => fetch(
      `${ORIGIN}/kv/room-owners/${encodeURIComponent(config.official_room)}`,
      { signal: AbortSignal.timeout(20_000) },
    )),
    fetchWithRetry("official-room read", () => fetch(
      `${ORIGIN}/r/${encodeURIComponent(config.official_room)}?format=json&limit=200`,
      { signal: AbortSignal.timeout(20_000) },
    )),
  ]);
  const [ownerBody, roomBody] = await Promise.all([
    boundedText(ownerResponse, 16_384, "Owned-room lookup"),
    boundedText(roomResponse, 2_000_000, "Official-room read"),
  ]);
  if (ownerDidFromBody(ownerBody) !== config.coordinator_did) {
    throw new Error("Coordinator DID does not own the configured official room.");
  }

  let roomData;
  try {
    roomData = JSON.parse(roomBody);
  } catch {
    throw new Error("Official-room response is not valid JSON.");
  }
  const checkpoints = checkpointsFromRoom(roomData, config);
  const chain = assessCheckpointChain(checkpoints);
  if (!chain.eligible) {
    output({ action: "skip", reason: chain.reason, dry_run: dryRun });
    return;
  }
  const duplicate = checkpoints.find(checkpoint => checkpoint.report_sha256 === assessment.report_sha256);
  if (duplicate) {
    if (!dryRun) {
      await writeState(paths.state, {
        schema: "swarmproof-checkpoint-local-state-v1",
        room: config.official_room,
        did: config.coordinator_did,
        report_sha256: assessment.report_sha256,
        meaningful_sha256: assessment.meaningful_sha256,
        event_id: duplicate.event_id,
        nonce: duplicate.nonce,
        posted_at: duplicate.posted_at,
      });
    }
    output({ action: "skip", reason: "already_in_room", dry_run: dryRun, event_id: duplicate.event_id });
    return;
  }

  const latestRemote = checkpoints.at(-1);
  if (checkpointAgeSeconds(latestRemote, now) < minimumIntervalSeconds) {
    output({ action: "skip", reason: "minimum_interval", dry_run: dryRun });
    return;
  }

  const privateKeyPem = await securePrivateKey(process.env.SWARMPROOF_KEY_FILE);
  const signingDid = didFromPrivateKey(privateKeyPem);
  if (signingDid !== config.coordinator_did) throw new Error("Private key does not match the coordinator DID.");

  if (state?.event_id && !checkpoints.some(checkpoint => checkpoint.event_id === state.event_id)) {
    throw new Error("Local checkpoint state is not present in the verified remote chain tail.");
  }
  const parentEventId = latestRemote.event_id;
  if (parentEventId !== null && !HASH_RE.test(parentEventId)) {
    throw new Error("Previous checkpoint event ID is invalid.");
  }
  const nonce = nextNonce(now, state, checkpoints);
  const claimedAt = now.toISOString();
  const created = createCheckpointEnvelope({
    config,
    reportSha256: assessment.report_sha256,
    privateKeyPem,
    nonce,
    claimedAt,
    parentEventId,
  });

  if (dryRun) {
    output({
      action: "would_post",
      dry_run: true,
      room: config.official_room,
      event_id: created.event_id,
      report_sha256: assessment.report_sha256,
      meaningful_sha256: assessment.meaningful_sha256,
      parent_event_id: parentEventId,
    });
    return;
  }

  const [ownerRecheckResponse, roomRecheckResponse] = await Promise.all([
    fetchWithRetry("owned-room pre-write recheck", () => fetch(
      `${ORIGIN}/kv/room-owners/${encodeURIComponent(config.official_room)}`,
      { signal: AbortSignal.timeout(20_000) },
    )),
    fetchWithRetry("official-room pre-write recheck", () => fetch(
      `${ORIGIN}/r/${encodeURIComponent(config.official_room)}?format=json&limit=200&n=${Date.now()}`,
      { signal: AbortSignal.timeout(20_000) },
    )),
  ]);
  const [ownerRecheckBody, roomRecheckBody] = await Promise.all([
    boundedText(ownerRecheckResponse, 16_384, "Owned-room pre-write recheck"),
    boundedText(roomRecheckResponse, 2_000_000, "Official-room pre-write recheck"),
  ]);
  if (ownerDidFromBody(ownerRecheckBody) !== config.coordinator_did) {
    throw new Error("Official-room owner changed before checkpoint write.");
  }
  let roomRecheckData;
  try {
    roomRecheckData = JSON.parse(roomRecheckBody);
  } catch {
    throw new Error("Official-room pre-write response is not valid JSON.");
  }
  const rechecked = checkpointsFromRoom(roomRecheckData, config);
  assessCheckpointChain(rechecked);
  const recheckedDuplicate = rechecked.find(checkpoint => checkpoint.report_sha256 === assessment.report_sha256);
  if (recheckedDuplicate) {
    await writeState(paths.state, {
      schema: "swarmproof-checkpoint-local-state-v1",
      room: config.official_room,
      did: config.coordinator_did,
      report_sha256: assessment.report_sha256,
      meaningful_sha256: assessment.meaningful_sha256,
      event_id: recheckedDuplicate.event_id,
      nonce: recheckedDuplicate.nonce,
      posted_at: recheckedDuplicate.posted_at,
    });
    output({ action: "skip", reason: "already_in_room", dry_run: false, event_id: recheckedDuplicate.event_id });
    return;
  }
  if (rechecked.at(-1)?.event_id !== parentEventId) {
    throw new Error("Remote checkpoint chain advanced before write; rerun from the new tail.");
  }

  const signature = signUtf8(privateKeyPem, `${config.official_room}|${nonce}|${created.envelope}`).toString("base64url");
  let postError = null;
  try {
    await fetchWithRetry("signed checkpoint", () => fetch(`${ORIGIN}/r/${encodeURIComponent(config.official_room)}?format=json`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        did: signingDid,
        sig: signature,
        nonce,
        text: created.envelope,
      }),
      signal: AbortSignal.timeout(20_000),
    }));
  } catch (error) {
    postError = error;
  }
  const observed = await observeCheckpoint(config, created.event_id);
  if (!observed) {
    if (postError) throw new Error("Checkpoint write outcome is unknown and read-back did not observe the event.");
    throw new Error("Checkpoint POST returned but read-back did not observe the event.");
  }

  await writeState(paths.state, {
    schema: "swarmproof-checkpoint-local-state-v1",
    room: config.official_room,
    did: config.coordinator_did,
    report_sha256: assessment.report_sha256,
    meaningful_sha256: assessment.meaningful_sha256,
    event_id: created.event_id,
    nonce,
    posted_at: observed.posted_at,
  });
  output({
    action: "posted",
    dry_run: false,
    room: config.official_room,
    event_id: created.event_id,
    report_sha256: assessment.report_sha256,
  });
}

main().catch(error => {
  console.error(`checkpoint failed: ${error.message}`);
  process.exitCode = 1;
}).finally(async () => {
  if (releaseCheckpointLock) {
    try {
      await releaseCheckpointLock();
    } catch (error) {
      console.error(`checkpoint lock cleanup failed: ${error.message}`);
      process.exitCode = 1;
    }
  }
});
