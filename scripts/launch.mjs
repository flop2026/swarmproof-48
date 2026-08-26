#!/usr/bin/env node

import { execFile } from "node:child_process";
import { lstat, mkdir, open, readFile, rename, rm, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { canonicalize } from "../lib/canonical.mjs";
import { replayTrustedCheck } from "../lib/artifact.mjs";
import { didFromPrivateKey, sha256Hex, signUtf8 } from "../lib/crypto.mjs";
import {
  LAUNCH_ARTIFACTS,
  LAUNCH_TASK_IDS,
  assessLaunchInputs,
  assessPostStartResultCommit,
  createLaunchCheckpoint,
  createLaunchResultEvents,
  createLaunchTaskEvents,
  coordinatorPreStartConflicts,
  indexExpectedTaskEvents,
  publicLaunchSummary,
  selectRecoverableBaseline,
  verifyLaunchEvents,
} from "../lib/launch.mjs";
import { EXPERIMENT, verifyEnvelope } from "../lib/protocol.mjs";

const executeFile = promisify(execFile);
const PROJECT_ROOT = fileURLToPath(new URL("..", import.meta.url));
const TECHNCORE_ORIGIN = "https://technocore.chat";
const DEFAULT_LOCK_FILE = join(homedir(), ".local", "state", "technocore-chat", "swarmproof-48-launch.lock");
const DEFAULT_STATE_FILE = join(homedir(), ".local", "state", "technocore-chat", "swarmproof-48-launch-state.json");
const HASH_RE = /^[0-9a-f]{64}$/;
const COMMIT_RE = /^[0-9a-f]{40}$/;
const NONCE_RE = /^[0-9]{1,19}$/;
const BUILD_ROOM_RE = /^[a-z0-9][a-z0-9_-]{0,47}$/;

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function parseArguments(arguments_) {
  let stage = "checkpoint";
  let post = false;
  let confirmation = null;
  const seen = new Set();
  for (const argument of arguments_) {
    if (argument === "--post") {
      assert(!seen.has("post"), "--post was provided more than once.");
      seen.add("post");
      post = true;
    } else if (argument === "--dry-run") {
      assert(!seen.has("dry-run"), "--dry-run was provided more than once.");
      seen.add("dry-run");
    } else if (argument.startsWith("--stage=")) {
      assert(!seen.has("stage"), "--stage was provided more than once.");
      seen.add("stage");
      stage = argument.slice("--stage=".length);
    } else if (argument.startsWith("--confirm=")) {
      assert(!seen.has("confirm"), "--confirm was provided more than once.");
      seen.add("confirm");
      confirmation = argument.slice("--confirm=".length);
    } else {
      throw new Error(`Unknown argument: ${argument}`);
    }
  }
  assert(["tasks", "results", "checkpoint"].includes(stage), "--stage must be tasks, results, or checkpoint.");
  assert(!(post && seen.has("dry-run")), "--post and --dry-run cannot be combined.");
  if (post) assert(confirmation === EXPERIMENT, `Posting requires --confirm=${EXPERIMENT}.`);
  else assert(confirmation === null, "--confirm is only accepted with --post.");
  return { stage, post };
}

function output(value) {
  process.stdout.write(`${JSON.stringify(value)}\n`);
}

async function readJson(path) {
  return JSON.parse(await readFile(path, "utf8"));
}

async function readEventArchive(path, report) {
  const content = await readFile(path, "utf8");
  assert(Buffer.byteLength(content, "utf8") <= 8 * 1024 * 1024, "Event archive is oversized.");
  assert(
    sha256Hex(content) === report.snapshot_manifest?.events_archive_sha256,
    "Event archive does not match the public snapshot manifest.",
  );
  const lines = content.split("\n").filter(Boolean);
  assert(lines.length <= 1024, "Event archive exceeds its record bound.");
  const records = lines.map((line, index) => {
    try {
      return JSON.parse(line);
    } catch {
      throw new Error(`Event archive line ${index + 1} is not valid JSON.`);
    }
  });
  return { content, records };
}

async function readLaunchState(path) {
  let metadata;
  try {
    metadata = await lstat(path);
  } catch (error) {
    if (error.code === "ENOENT") return null;
    throw error;
  }
  assert(metadata.isFile() && !metadata.isSymbolicLink(), "Launch state must be a regular file.");
  assert(metadata.size > 0 && metadata.size <= 131_072, "Launch state size is invalid.");
  const state = await readJson(path);
  assert(state?.schema === "swarmproof-launch-local-state-v1", "Unsupported launch state schema.");
  assert(state.experiment === EXPERIMENT, "Launch state experiment is invalid.");
  assert(/^did:key:z6Mk[1-9A-HJ-NP-Za-km-z]+$/.test(state.did ?? ""), "Launch state DID is invalid.");
  assert(/^d-[a-z0-9][a-z0-9_-]{0,45}$/.test(state.official_room ?? ""), "Launch state room is invalid.");
  assert(/^[A-Za-z0-9_.-]{1,39}\/[A-Za-z0-9_.-]{1,100}$/.test(state.repository ?? ""), "Launch state repository is invalid.");
  assert(COMMIT_RE.test(state.baseline_commit ?? ""), "Launch state baseline commit is invalid.");
  assert(COMMIT_RE.test(state.baseline_evidence_commit ?? ""), "Launch state baseline evidence commit is invalid.");
  assert(HASH_RE.test(state.baseline_report_sha256 ?? ""), "Launch state baseline report hash is invalid.");
  assert(HASH_RE.test(state.start_checkpoint_event_id ?? ""), "Launch state checkpoint event ID is invalid.");
  assert(typeof state.started_at === "string" && new Date(state.started_at).toISOString() === state.started_at, "Launch state start time is invalid.");
  for (const field of ["task_events", "result_events"]) {
    const records = state[field];
    assert(records && typeof records === "object" && !Array.isArray(records), `Launch state ${field} is invalid.`);
    assert(Object.keys(records).length <= LAUNCH_TASK_IDS.length, `Launch state ${field} is oversized.`);
    for (const [taskId, record] of Object.entries(records)) {
      assert(LAUNCH_TASK_IDS.includes(taskId), `Launch state ${field} has an invalid task ID.`);
      assert(
        record && typeof record === "object" && !Array.isArray(record)
          && Object.keys(record).length === 3
          && typeof record.envelope === "string" && record.envelope.length <= 4096
          && HASH_RE.test(record.event_id ?? "")
          && ["pending", "observed"].includes(record.status),
        `Launch state ${field} record is invalid for ${taskId}.`,
      );
    }
  }
  return state;
}

async function writeLaunchState(path, state) {
  const directory = dirname(path);
  await mkdir(directory, { recursive: true, mode: 0o700 });
  const metadata = await lstat(directory);
  assert(metadata.isDirectory() && !metadata.isSymbolicLink(), "Launch state directory must be a regular directory.");
  const temporary = `${path}.tmp-${process.pid}`;
  await writeFile(temporary, `${JSON.stringify(state, null, 2)}\n`, { encoding: "utf8", mode: 0o600 });
  await rename(temporary, path);
}

async function git(arguments_, options = {}) {
  const { stdout } = await executeFile("git", arguments_, {
    cwd: PROJECT_ROOT,
    encoding: options.encoding ?? "utf8",
    timeout: options.timeout ?? 20_000,
    maxBuffer: options.maxBuffer ?? 5 * 1024 * 1024,
  });
  return stdout;
}

async function localRepositoryState() {
  const [commitRaw, branchRaw, status] = await Promise.all([
    git(["rev-parse", "HEAD"]),
    git(["branch", "--show-current"]),
    git(["status", "--porcelain=v1", "--untracked-files=all"]),
  ]);
  const commit = commitRaw.trim();
  assert(COMMIT_RE.test(commit), "Local HEAD is not a full lowercase commit SHA.");
  assert(branchRaw.trim() === "main", "Launch requires the local main branch.");
  assert(status.length === 0, "Launch requires a completely clean worktree.");
  return commit;
}

function securePublicUrl(value) {
  assert(typeof value === "string" && value.length > 0, "SWARMPROOF_PUBLIC_URL is required.");
  const url = new URL(value);
  assert(url.protocol === "https:", "Public URL must use HTTPS.");
  assert(url.username === "" && url.password === "", "Public URL must not contain credentials.");
  assert(url.search === "" && url.hash === "", "Public URL must not contain a query or fragment.");
  assert(url.hostname !== "localhost" && url.hostname !== "127.0.0.1" && url.hostname !== "::1", "Public URL must not be local.");
  url.pathname = `${url.pathname.replace(/\/+$/u, "")}/`;
  return url;
}

async function boundedBody(response, limit, label) {
  const declared = Number(response.headers.get("content-length"));
  if (Number.isFinite(declared) && declared > limit) throw new Error(`${label} response is oversized.`);
  const bytes = Buffer.from(await response.arrayBuffer());
  assert(bytes.byteLength <= limit, `${label} response is oversized.`);
  return bytes;
}

async function fetchBounded(url, { label, limit = 2_000_000, json = false } = {}) {
  const response = await fetch(url, {
    headers: { accept: json ? "application/json" : "*/*", "user-agent": "swarmproof-48-launch/1" },
    redirect: "follow",
    signal: AbortSignal.timeout(20_000),
  });
  assert(response.ok, `${label}: HTTP ${response.status}.`);
  const body = await boundedBody(response, limit, label);
  if (!json) return { body, response };
  try {
    return { body: JSON.parse(body.toString("utf8")), response };
  } catch {
    throw new Error(`${label} response is not valid JSON.`);
  }
}

function samePublicOrigin(response, expected, label) {
  const final = new URL(response.url);
  assert(final.origin === expected.origin, `${label} redirected to another origin.`);
}

async function verifyPublicDeployment(publicUrl, localReport, localStatus, localEventsContent) {
  const reportUrl = new URL("data/report.json", publicUrl);
  const statusUrl = new URL("data/status.json", publicUrl);
  const eventsUrl = new URL("data/events.jsonl", publicUrl);
  const [home, reportResult, statusResult, eventsResult] = await Promise.all([
    fetchBounded(publicUrl, { label: "Public site", limit: 1_000_000 }),
    fetchBounded(reportUrl, { label: "Public report", json: true }),
    fetchBounded(statusUrl, { label: "Public status", json: true }),
    fetchBounded(eventsUrl, { label: "Public event archive", limit: 8 * 1024 * 1024 }),
  ]);
  samePublicOrigin(home.response, publicUrl, "Public site");
  samePublicOrigin(reportResult.response, publicUrl, "Public report");
  samePublicOrigin(statusResult.response, publicUrl, "Public status");
  samePublicOrigin(eventsResult.response, publicUrl, "Public event archive");
  assert(home.body.toString("utf8").includes("SwarmProof 48"), "Public site does not identify SwarmProof 48.");
  assert(
    sha256Hex(canonicalize(reportResult.body)) === sha256Hex(canonicalize(localReport)),
    "Public report does not match the launch report.",
  );
  assert(
    sha256Hex(canonicalize(statusResult.body)) === sha256Hex(canonicalize(localStatus)),
    "Public status does not match the launch status.",
  );
  assert(eventsResult.body.equals(Buffer.from(localEventsContent, "utf8")), "Public event archive does not match the launch archive.");
}

function githubPath(repository, commit, path) {
  return `https://raw.githubusercontent.com/${repository.split("/").map(encodeURIComponent).join("/")}/${commit}/${path.split("/").map(encodeURIComponent).join("/")}`;
}

async function artifactHashesAtCommit(config, commit) {
  const hashes = {};
  for (const taskId of LAUNCH_TASK_IDS) {
    const path = LAUNCH_ARTIFACTS[taskId];
    const localBytes = await git(["show", `${commit}:${path}`], { encoding: "buffer" });
    const localHash = sha256Hex(localBytes);
    const { body: remoteBytes } = await fetchBounded(githubPath(config.repository, commit, path), {
      label: `Published artifact ${taskId}`,
      limit: 5 * 1024 * 1024,
    });
    assert(sha256Hex(remoteBytes) === localHash, `Published artifact differs from local commit for ${taskId}.`);
    hashes[taskId] = localHash;
  }
  return hashes;
}

async function verifyPublishedCommit(config, commit) {
  const repositoryPath = config.repository.split("/").map(encodeURIComponent).join("/");
  const { body } = await fetchBounded(`https://api.github.com/repos/${repositoryPath}/commits/${commit}`, {
    label: "Published source commit",
    json: true,
    limit: 2_000_000,
  });
  assert(body?.sha === commit, "GitHub did not return the exact launch commit.");
}

function ownerDidFromBody(body) {
  const dids = body
    .toString("utf8")
    .split("\n")
    .map(line => line.trim())
    .filter(line => /^did:key:z6Mk[1-9A-HJ-NP-Za-km-z]+$/.test(line));
  assert(dids.length === 1, "Owned-room record is missing or ambiguous.");
  return dids[0];
}

async function verifyOfficialRoomOwner(config) {
  const { body } = await fetchBounded(
    `${TECHNCORE_ORIGIN}/kv/room-owners/${encodeURIComponent(config.official_room)}`,
    { label: "Official-room ownership", limit: 16_384 },
  );
  assert(ownerDidFromBody(body) === config.coordinator_did, "Coordinator DID does not own the official room.");
}

async function readRoom(room, label) {
  assert(BUILD_ROOM_RE.test(room), `${label} name is invalid.`);
  const cacheBust = Date.now();
  const { body } = await fetchBounded(
    `${TECHNCORE_ORIGIN}/r/${encodeURIComponent(room)}?format=json&limit=200&n=${cacheBust}`,
    { label, json: true, limit: 2_000_000 },
  );
  assert(body && Array.isArray(body.messages), `${label} response is invalid.`);
  assert(body.messages.length <= 200, `${label} response exceeds the requested bound.`);
  return body;
}

function protocolOptions(config, manifest) {
  return {
    allowedRepositories: new Set([config.repository]),
    allowedTasks: new Set(manifest.tasks.map(task => task.id)),
    coordinatorDid: config.coordinator_did,
  };
}

function strictRoomEvents(roomData, config, manifest) {
  const events = [];
  const options = protocolOptions(config, manifest);
  for (const message of roomData.messages) {
    if (typeof message?.text !== "string") continue;
    try {
      const event = verifyEnvelope(message.text, options);
      events.push({
        ...event,
        transport_from: typeof message.from === "string" ? message.from : null,
        transport_nonce: NONCE_RE.test(String(message.nonce ?? "")) ? String(message.nonce) : null,
        transport_ts: typeof message.ts === "string" ? message.ts : null,
      });
    } catch {
      // Rooms are untrusted input. Only strict, project-bound SP1 events are retained here.
    }
  }
  return events;
}

function verifiedRoomEvents(roomData, config, manifest) {
  return strictRoomEvents(roomData, config, manifest).filter(event => (
    event.payload.did === config.coordinator_did
      && event.transport_from === config.coordinator_did
      && event.transport_nonce === event.payload.nonce
  ));
}

function verifiedArchiveEvents(records, config, manifest) {
  const events = [];
  const options = protocolOptions(config, manifest);
  for (const record of records) {
    if (typeof record?.envelope !== "string") continue;
    try {
      const event = verifyEnvelope(record.envelope, options);
      if (event.payload.did === config.coordinator_did) events.push(event);
    } catch {
      // The public archive is bounded but still treated as untrusted until SP1 verification.
    }
  }
  return events;
}

function verifiedStateEvents(state, config, manifest) {
  if (!state) return [];
  const options = protocolOptions(config, manifest);
  const events = [];
  for (const [field, expectedType] of [["task_events", "TASK"], ["result_events", "RESULT"]]) {
    for (const [taskId, record] of Object.entries(state[field])) {
      const event = verifyEnvelope(record.envelope, options);
      assert(event.event_id === record.event_id, `Launch state ${expectedType} event ID is invalid for ${taskId}.`);
      assert(event.payload.type === expectedType && event.payload.task_id === taskId, `Launch state ${expectedType} binding is invalid for ${taskId}.`);
      assert(event.payload.did === config.coordinator_did, `Launch state ${expectedType} signer is invalid for ${taskId}.`);
      events.push({ ...event, local_status: record.status });
    }
  }
  return events;
}

function mergeVerifiedEvents(...sources) {
  const merged = new Map();
  for (const events of sources) {
    for (const event of events) {
      const previous = merged.get(event.event_id);
      if (!previous || (previous.local_status === "pending" && event.local_status !== "pending")) {
        merged.set(event.event_id, event);
      }
    }
  }
  return [...merged.values()];
}

function reconcileLaunchState(state, externalEvents, config, manifest) {
  if (!state) return { state: null, stateEvents: [] };
  const reconciled = structuredClone(state);
  const externalIds = new Set(externalEvents.map(event => event.event_id));
  for (const field of ["task_events", "result_events"]) {
    for (const record of Object.values(reconciled[field])) {
      if (record.status === "pending") {
        assert(externalIds.has(record.event_id), "A pending launch write cannot be confirmed from the room tail or public archive.");
        record.status = "observed";
      }
    }
  }
  return { state: reconciled, stateEvents: verifiedStateEvents(reconciled, config, manifest) };
}

function hydrateLaunchState(state, taskEvents, resultEvents) {
  if (!state) return null;
  const hydrated = structuredClone(state);
  for (const [taskId, event] of Object.entries(taskEvents)) {
    hydrated.task_events[taskId] = { envelope: event.envelope, event_id: event.event_id, status: "observed" };
  }
  for (const [taskId, event] of Object.entries(resultEvents)) {
    hydrated.result_events[taskId] = { envelope: event.envelope, event_id: event.event_id, status: "observed" };
  }
  return hydrated;
}

function maximumRoomNonce(roomData, did) {
  let maximum = 0n;
  for (const message of roomData.messages) {
    const nonce = String(message?.nonce ?? "");
    if (message?.from === did && NONCE_RE.test(nonce)) {
      const candidate = BigInt(nonce);
      if (candidate > maximum) maximum = candidate;
    }
  }
  return maximum;
}

function firstNonce(roomData, did, count, now = new Date()) {
  const maximum = maximumRoomNonce(roomData, did);
  const milliseconds = BigInt(now.getTime());
  const first = maximum >= milliseconds ? maximum + 1n : milliseconds;
  assert(NONCE_RE.test(String(first + BigInt(count) - 1n)), "No safe nonce range remains in this room.");
  return String(first);
}

function resultMatches(event, { config, taskId, artifactHash, taskEventId }) {
  const artifact = event.payload.artifact;
  return event.payload.type === "RESULT"
    && event.payload.task_id === taskId
    && event.payload.parent_event_ids.length === 1
    && event.payload.parent_event_ids[0] === taskEventId
    && event.payload.content_sha256 === artifactHash
    && artifact?.repository === config.repository
    && COMMIT_RE.test(artifact.commit ?? "")
    && artifact.path === LAUNCH_ARTIFACTS[taskId]
    && artifact.sha256 === artifactHash;
}

async function verifyResolvedResultHistory(results, launchState, currentCommit, config) {
  for (const [taskId, event] of Object.entries(results)) {
    const resultCommit = event.payload.artifact.commit;
    assert(resultCommit !== launchState.baseline_commit, `Baseline artifact cannot satisfy RESULT ${taskId}.`);
    assert(
      Date.parse(event.payload.claimed_at) > Date.parse(launchState.started_at),
      `RESULT ${taskId} was claimed before the observed start checkpoint.`,
    );
    try {
      await git(["merge-base", "--is-ancestor", launchState.baseline_commit, resultCommit]);
      await git(["merge-base", "--is-ancestor", resultCommit, currentCommit]);
    } catch {
      throw new Error(`RESULT ${taskId} commit is outside the post-start source lineage.`);
    }
    const commitTimeRaw = await git(["show", "-s", "--format=%cI", resultCommit]);
    const commitTime = new Date(commitTimeRaw.trim());
    assert(
      !Number.isNaN(commitTime.getTime()) && commitTime.getTime() > Date.parse(launchState.started_at),
      `RESULT ${taskId} commit predates the observed start checkpoint.`,
    );
    const { body } = await fetchBounded(githubPath(config.repository, resultCommit, event.payload.artifact.path), {
      label: `Existing RESULT artifact ${taskId}`,
      limit: 5 * 1024 * 1024,
    });
    assert(sha256Hex(body) === event.payload.artifact.sha256, `Existing RESULT artifact hash failed for ${taskId}.`);
  }
}

function resolveResultEvents(events, inputs, taskIds = LAUNCH_TASK_IDS) {
  const resolved = {};
  for (const taskId of taskIds) {
    const candidates = events.filter(event => event.payload.type === "RESULT" && event.payload.task_id === taskId);
    const matching = candidates.filter(event => resultMatches(event, {
      ...inputs,
      taskId,
      artifactHash: inputs.artifactHashes[taskId],
      taskEventId: inputs.taskEvents[taskId].event_id,
    }));
    assert(candidates.length === matching.length, `Build room contains a divergent coordinator RESULT for ${taskId}.`);
    assert(matching.length <= 1, `Build room contains duplicate coordinator RESULT events for ${taskId}.`);
    if (matching[0]) resolved[taskId] = matching[0];
  }
  return resolved;
}

function assertAllResolved(events, type) {
  for (const taskId of LAUNCH_TASK_IDS) assert(events[taskId], `${type} stage is incomplete for ${taskId}.`);
}

function validateStateBinding(state, config) {
  assert(state, "A verified start checkpoint state is required before this stage.");
  assert(state.did === config.coordinator_did, "Launch state belongs to a different DID.");
  assert(state.official_room === config.official_room, "Launch state belongs to a different official room.");
  assert(state.repository === config.repository, "Launch state belongs to a different repository.");
}

async function verifyBaselineBinding(state, currentConfig) {
  const [reportText, statusText, baselineConfigText] = await Promise.all([
    git(["show", `${state.baseline_evidence_commit}:public/data/report.json`]),
    git(["show", `${state.baseline_evidence_commit}:public/data/status.json`]),
    git(["show", `${state.baseline_commit}:config/event.json`]),
  ]);
  let report;
  let status;
  let baselineConfig;
  try {
    report = JSON.parse(reportText);
    status = JSON.parse(statusText);
    baselineConfig = JSON.parse(baselineConfigText);
  } catch {
    throw new Error("Baseline commit does not contain valid public evidence JSON.");
  }
  assert(sha256Hex(canonicalize(report)) === state.baseline_report_sha256, "Baseline commit does not match the start checkpoint report hash.");
  assert(report.snapshot_manifest?.source_commit === state.baseline_commit, "Baseline report is not bound to the baseline source commit.");
  assert(status.source_commit === state.baseline_commit, "Baseline status is not bound to the baseline source commit.");
  assert(status.report_sha256 === state.baseline_report_sha256, "Baseline status does not bind the checkpoint report hash.");
  assert(report.event_state === "active" && status.state === "active", "Baseline public evidence was not active.");
  assert(baselineConfig.state === "active", "Baseline config was not active.");
  for (const key of ["coordinator_did", "repository", "build_room", "official_room", "starts_at", "ends_at"]) {
    assert(baselineConfig[key] === currentConfig[key], `Current config changed the baseline ${key}.`);
  }
  assert(canonicalize(baselineConfig.sample) === canonicalize(currentConfig.sample), "Current config changed the baseline sample policy.");
  assert(["active", "complete"].includes(currentConfig.state), "Current config state is outside the maintained lifecycle.");
  try {
    await git(["merge-base", "--is-ancestor", state.baseline_commit, state.baseline_evidence_commit]);
  } catch {
    throw new Error("Baseline source commit is not an ancestor of its evidence commit.");
  }
}

function resolveStartCheckpoint(officialEvents, state) {
  const starts = officialEvents.filter(event => (
    event.payload.type === "CHECKPOINT"
      && event.payload.task_id === "event-start"
      && event.payload.parent_event_ids.length === 0
  ));
  assert(starts.length <= 1, "Official room contains duplicate event-start CHECKPOINT events.");
  const start = starts[0] ?? null;
  if (state) {
    assert(start?.event_id === state.start_checkpoint_event_id, "Stored start checkpoint is not present in the official room tail.");
    assert(start.payload.content_sha256 === state.baseline_report_sha256, "Stored start checkpoint report binding is invalid.");
    return start;
  }
  return start;
}

function launchStateDocument({ config, sourceCommit, evidenceCommit, reportSha256, start }) {
  return {
    schema: "swarmproof-launch-local-state-v1",
    experiment: EXPERIMENT,
    did: config.coordinator_did,
    official_room: config.official_room,
    repository: config.repository,
    baseline_commit: sourceCommit,
    baseline_evidence_commit: evidenceCommit,
    baseline_report_sha256: reportSha256,
    start_checkpoint_event_id: start.event_id,
    started_at: normalizeObservedTime(start.transport_ts),
    task_events: {},
    result_events: {},
  };
}

async function recoverLaunchState(config, start) {
  const rawCandidates = await git([
    "rev-list",
    "--max-count=512",
    "HEAD",
    "--",
    "public/data/report.json",
    "public/data/status.json",
    "config/event.json",
  ]);
  const candidates = [];
  for (const evidenceCommit of rawCandidates.split("\n").filter(value => COMMIT_RE.test(value))) {
    try {
      const [reportText, statusText, configText] = await Promise.all([
        git(["show", `${evidenceCommit}:public/data/report.json`]),
        git(["show", `${evidenceCommit}:public/data/status.json`]),
        git(["show", `${evidenceCommit}:config/event.json`]),
      ]);
      const report = JSON.parse(reportText);
      const status = JSON.parse(statusText);
      const historicalConfig = JSON.parse(configText);
      candidates.push({ evidence_commit: evidenceCommit, report, status, config: historicalConfig });
    } catch {
      // A history entry without the complete launch evidence set cannot be the baseline.
    }
  }
  const match = selectRecoverableBaseline({ startEvent: start, candidates, config });
  try {
    await git(["merge-base", "--is-ancestor", match.source_commit, match.evidence_commit]);
  } catch {
    throw new Error("Recovered baseline source is not an ancestor of its evidence commit.");
  }
  const recovered = launchStateDocument({
    config,
    sourceCommit: match.source_commit,
    evidenceCommit: match.evidence_commit,
    reportSha256: match.report_sha256,
    start,
  });
  await verifyBaselineBinding(recovered, config);
  return recovered;
}

async function securePrivateKey(path) {
  assert(typeof path === "string" && path.length > 0, "SWARMPROOF_KEY_FILE is required after all public gates pass.");
  const metadata = await lstat(path);
  assert(metadata.isFile() && !metadata.isSymbolicLink(), "Private key must be a regular file.");
  assert((metadata.mode & 0o077) === 0, "Private key permissions must deny group and other access.");
  assert(metadata.size > 0 && metadata.size <= 16_384, "Private key size is invalid.");
  return readFile(path, "utf8");
}

async function acquireLaunchLock(path) {
  const directory = dirname(path);
  assert(directory !== "/", "Launch lock path is unsafe.");
  await mkdir(directory, { recursive: true, mode: 0o700 });
  const metadata = await lstat(directory);
  assert(metadata.isDirectory() && !metadata.isSymbolicLink(), "Launch lock directory must be a regular directory.");
  const handle = await open(path, "wx", 0o600).catch(error => {
    if (error.code === "EEXIST") throw new Error("Another launch process may be active; refusing to post.");
    throw error;
  });
  await handle.writeFile(`${process.pid}\n`, "utf8");
  return async () => {
    await handle.close();
    await rm(path, { force: true });
  };
}

const sleep = milliseconds => new Promise(resolve => setTimeout(resolve, milliseconds));

async function messageObserved(room, config, manifest, eventId) {
  for (let attempt = 1; attempt <= 4; attempt += 1) {
    const data = await readRoom(room, "Post-write room verification");
    const observed = verifiedRoomEvents(data, config, manifest).find(event => event.event_id === eventId);
    if (observed) return observed;
    if (attempt < 4) await sleep(attempt * 500);
  }
  return null;
}

async function postSignedEvent({ room, created, privateKeyPem, config, manifest }) {
  const nonce = created.payload.nonce;
  const signature = signUtf8(privateKeyPem, `${room}|${nonce}|${created.envelope}`).toString("base64url");
  let response;
  let requestError = null;
  try {
    response = await fetch(`${TECHNCORE_ORIGIN}/r/${encodeURIComponent(room)}?format=json`, {
      method: "POST",
      headers: { "content-type": "application/json", "user-agent": "swarmproof-48-launch/1" },
      body: JSON.stringify({
        did: config.coordinator_did,
        sig: signature,
        nonce,
        text: created.envelope,
      }),
      signal: AbortSignal.timeout(20_000),
    });
  } catch (error) {
    requestError = error;
  }

  const observed = await messageObserved(room, config, manifest, created.event_id);
  if (observed) return observed;
  if (requestError) throw new Error("Signed write outcome is unknown and the event was not observed; rerun after checking the room.");
  const body = (await boundedBody(response, 4096, "Signed write")).toString("utf8");
  throw new Error(`Signed write was not observed (HTTP ${response.status}, response SHA-256 ${sha256Hex(body)}).`);
}

async function postStartEvidence(config, launchState, commit, currentHashes) {
  validateStateBinding(launchState, config);
  await verifyBaselineBinding(launchState, config);
  try {
    await git(["merge-base", "--is-ancestor", launchState.baseline_commit, commit]);
  } catch {
    throw new Error("Result commit does not descend from the recorded baseline commit.");
  }
  await verifyPublishedCommit(config, launchState.baseline_commit);
  const baselineHashes = await artifactHashesAtCommit(config, launchState.baseline_commit);
  const mappedPaths = LAUNCH_TASK_IDS.map(taskId => LAUNCH_ARTIFACTS[taskId]);
  const [changedRaw, commitTimeRaw] = await Promise.all([
    git(["diff", "--name-only", launchState.baseline_commit, commit, "--", ...mappedPaths]),
    git(["show", "-s", "--format=%cI", commit]),
  ]);
  const parsedCommitTime = new Date(commitTimeRaw.trim());
  assert(!Number.isNaN(parsedCommitTime.getTime()), "Result commit time is invalid.");
  const taskIds = assessPostStartResultCommit({
    baselineCommit: launchState.baseline_commit,
    commit,
    startsAt: config.starts_at,
    checkpointObservedAt: launchState.started_at,
    commitTime: parsedCommitTime.toISOString(),
    changedPaths: changedRaw.split("\n").filter(Boolean),
    baselineHashes,
    currentHashes,
  });
  return { baselineHashes, taskIds };
}

async function verifyTaskBaselineUnchanged(config, manifest, launchState, commit, currentHashes) {
  validateStateBinding(launchState, config);
  await verifyBaselineBinding(launchState, config);
  try {
    await git(["merge-base", "--is-ancestor", launchState.baseline_commit, commit]);
  } catch {
    throw new Error("TASK commit does not descend from the recorded baseline commit.");
  }
  const baselineManifest = JSON.parse(await git(["show", `${launchState.baseline_commit}:config/tasks.json`]));
  assert(canonicalize(baselineManifest) === canonicalize(manifest), "TASK manifest changed after the start checkpoint.");
  const baselineHashes = await artifactHashesAtCommit(config, launchState.baseline_commit);
  for (const taskId of LAUNCH_TASK_IDS) {
    assert(baselineHashes[taskId] === currentHashes[taskId], `Prebuilt artifact ${taskId} changed before TASK publication.`);
  }
}

async function preflight({ stage }) {
  const paths = {
    config: join(PROJECT_ROOT, "config", "event.json"),
    manifest: join(PROJECT_ROOT, "config", "tasks.json"),
    report: join(PROJECT_ROOT, "public", "data", "report.json"),
    status: join(PROJECT_ROOT, "public", "data", "status.json"),
    events: join(PROJECT_ROOT, "public", "data", "events.jsonl"),
    state: process.env.SWARMPROOF_LAUNCH_STATE_FILE ?? DEFAULT_STATE_FILE,
  };
  const [config, manifest, report, status, publicationCommit, storedLaunchState] = await Promise.all([
    readJson(paths.config),
    readJson(paths.manifest),
    readJson(paths.report),
    readJson(paths.status),
    localRepositoryState(),
    readLaunchState(paths.state),
  ]);
  assert(BUILD_ROOM_RE.test(config.build_room ?? "") && !config.build_room.startsWith("d-"), "Build room must be a valid open room.");
  if (storedLaunchState) validateStateBinding(storedLaunchState, config);
  const commit = status.source_commit;
  assert(COMMIT_RE.test(commit ?? ""), "Public status source commit is invalid.");
  try {
    await git(["merge-base", "--is-ancestor", commit, publicationCommit]);
  } catch {
    throw new Error("Public source commit is not an ancestor of the local publication commit.");
  }
  const publicUrl = securePublicUrl(process.env.SWARMPROOF_PUBLIC_URL);
  const maxAgeSeconds = process.env.SWARMPROOF_LAUNCH_MAX_AGE_SECONDS === undefined
    ? null
    : Number(process.env.SWARMPROOF_LAUNCH_MAX_AGE_SECONDS);
  assessLaunchInputs({ config, manifest, report, status, sourceCommit: commit, publicationCommit, maxAgeSeconds });
  const eventArchive = await readEventArchive(paths.events, report);

  const replay = await replayTrustedCheck(commit, ["node", "--test"], {
    repositoryRoot: PROJECT_ROOT,
    trustedRef: "HEAD",
  });
  assert(replay.status === "pass", "Exact launch commit failed the trusted replay check.");

  await Promise.all([
    verifyPublicDeployment(publicUrl, report, status, eventArchive.content),
    verifyPublishedCommit(config, commit),
    verifyPublishedCommit(config, publicationCommit),
    verifyOfficialRoomOwner(config),
  ]);
  const artifactHashes = await artifactHashesAtCommit(config, commit);
  const [buildRoomData, officialRoomData] = await Promise.all([
    readRoom(config.build_room, "Build room"),
    readRoom(config.official_room, "Official room"),
  ]);
  const allBuildEvents = strictRoomEvents(buildRoomData, config, manifest);
  const buildEvents = verifiedRoomEvents(buildRoomData, config, manifest);
  const archiveEvents = verifiedArchiveEvents(eventArchive.records, config, manifest);
  const externalEvents = mergeVerifiedEvents(buildEvents, archiveEvents);
  const officialEvents = verifiedRoomEvents(officialRoomData, config, manifest);
  const startCheckpoint = resolveStartCheckpoint(officialEvents, storedLaunchState);
  let launchState = storedLaunchState;
  if (startCheckpoint && !launchState) launchState = await recoverLaunchState(config, startCheckpoint);
  if (launchState) await verifyBaselineBinding(launchState, config);
  const reconciled = reconcileLaunchState(launchState, externalEvents, config, manifest);
  launchState = reconciled.state;
  const durableEvents = mergeVerifiedEvents(externalEvents, reconciled.stateEvents);
  const taskEvents = indexExpectedTaskEvents(durableEvents, manifest);
  let resultEvents = {};
  let resultTaskIds = [];

  if (stage === "checkpoint") {
    if (!startCheckpoint) {
      assert(storedLaunchState === null, "Launch state exists without a start checkpoint.");
      assert(
        coordinatorPreStartConflicts(mergeVerifiedEvents(allBuildEvents, archiveEvents), config.coordinator_did).length === 0,
        "event-start CHECKPOINT must precede every coordinator project event in the build room.",
      );
    }
  } else {
    validateStateBinding(launchState, config);
    assert(startCheckpoint, "Verified event-start CHECKPOINT must precede this stage.");
    if (stage === "tasks") {
      await verifyTaskBaselineUnchanged(config, manifest, launchState, commit, artifactHashes);
    } else {
      assertAllResolved(taskEvents, "TASK");
      const evidence = await postStartEvidence(config, launchState, commit, artifactHashes);
      resultTaskIds = evidence.taskIds;
      resultEvents = resolveResultEvents(durableEvents, {
        config,
        commit,
        artifactHashes,
        taskEvents,
      }, resultTaskIds);
      await verifyResolvedResultHistory(resultEvents, launchState, commit, config);
    }
  }
  launchState = hydrateLaunchState(launchState, taskEvents, resultEvents);
  return {
    stage,
    paths,
    config,
    manifest,
    report,
    status,
    commit,
    publicationCommit,
    launchState,
    storedLaunchState,
    publicUrl,
    eventArchive,
    artifactHashes,
    buildRoomData,
    officialRoomData,
    allBuildEvents,
    buildEvents,
    archiveEvents,
    durableEvents,
    officialEvents,
    startCheckpoint,
    taskEvents,
    resultEvents,
    resultTaskIds,
  };
}

async function recheck(preflightState) {
  const [config, manifest, report, status, publicationCommit, storedLaunchState, eventArchiveContent] = await Promise.all([
    readJson(preflightState.paths.config),
    readJson(preflightState.paths.manifest),
    readJson(preflightState.paths.report),
    readJson(preflightState.paths.status),
    localRepositoryState(),
    readLaunchState(preflightState.paths.state),
    readFile(preflightState.paths.events, "utf8"),
  ]);
  assert(canonicalize(config) === canonicalize(preflightState.config), "Config changed after launch preflight.");
  assert(canonicalize(manifest) === canonicalize(preflightState.manifest), "Task manifest changed after launch preflight.");
  assert(canonicalize(report) === canonicalize(preflightState.report), "Report changed after launch preflight.");
  assert(canonicalize(status) === canonicalize(preflightState.status), "Status changed after launch preflight.");
  assert(eventArchiveContent === preflightState.eventArchive.content, "Event archive changed after launch preflight.");
  assert(canonicalize(storedLaunchState) === canonicalize(preflightState.storedLaunchState), "Launch state changed after launch preflight.");
  assert(publicationCommit === preflightState.publicationCommit, "HEAD changed after launch preflight.");
  assert(status.source_commit === preflightState.commit, "Source commit changed after launch preflight.");
  assessLaunchInputs({
    config,
    manifest,
    report,
    status,
    sourceCommit: preflightState.commit,
    publicationCommit,
  });
  await Promise.all([
    verifyPublicDeployment(preflightState.publicUrl, report, status, eventArchiveContent),
    verifyOfficialRoomOwner(config),
  ]);
  const [buildRoomData, officialRoomData] = await Promise.all([
    readRoom(config.build_room, "Build-room launch recheck"),
    readRoom(config.official_room, "Official-room launch recheck"),
  ]);
  const officialEvents = verifiedRoomEvents(officialRoomData, config, manifest);
  if (preflightState.stage === "checkpoint" && !preflightState.startCheckpoint) {
    assert(
      coordinatorPreStartConflicts(mergeVerifiedEvents(
        strictRoomEvents(buildRoomData, config, manifest),
        preflightState.archiveEvents,
      ), config.coordinator_did).length === 0,
      "A coordinator project event appeared before event-start CHECKPOINT.",
    );
    assert(resolveStartCheckpoint(officialEvents, null) === null, "A concurrent event-start CHECKPOINT appeared.");
  } else {
    assert(resolveStartCheckpoint(officialEvents, preflightState.launchState), "Start checkpoint disappeared during launch.");
  }
}

function selectTaskStage(preflightState, privateKeyPem, now) {
  const existing = preflightState.taskEvents;
  const created = createLaunchTaskEvents({
    config: preflightState.config,
    manifest: preflightState.manifest,
    privateKeyPem,
    claimedAt: now.toISOString(),
    firstNonce: firstNonce(preflightState.buildRoomData, preflightState.config.coordinator_did, LAUNCH_TASK_IDS.length, now),
  });
  verifyLaunchEvents(created, {
    config: preflightState.config,
    manifest: preflightState.manifest,
    expectedType: "TASK",
  });
  return {
    created: created.filter(event => !existing[event.payload.task_id]),
    skipped: Object.values(existing),
    room: preflightState.config.build_room,
  };
}

function selectResultStage(preflightState, privateKeyPem, now) {
  const taskEventIds = Object.fromEntries(Object.entries(preflightState.taskEvents).map(([id, event]) => [id, event.event_id]));
  const created = createLaunchResultEvents({
    config: preflightState.config,
    manifest: preflightState.manifest,
    privateKeyPem,
    commit: preflightState.commit,
    artifactHashes: preflightState.artifactHashes,
    taskEventIds,
    taskIds: preflightState.resultTaskIds,
    claimedAt: now.toISOString(),
    firstNonce: firstNonce(preflightState.buildRoomData, preflightState.config.coordinator_did, preflightState.resultTaskIds.length, now),
  });
  verifyLaunchEvents(created, {
    config: preflightState.config,
    manifest: preflightState.manifest,
    expectedType: "RESULT",
  });
  return {
    created: created.filter(event => !preflightState.resultEvents[event.payload.task_id]),
    skipped: Object.values(preflightState.resultEvents),
    room: preflightState.config.build_room,
  };
}

function selectCheckpointStage(preflightState, privateKeyPem, now) {
  if (preflightState.startCheckpoint) {
    return { created: [], skipped: [preflightState.startCheckpoint], room: preflightState.config.official_room };
  }
  const created = createLaunchCheckpoint({
    config: preflightState.config,
    reportSha256: preflightState.status.report_sha256,
    privateKeyPem,
    nonce: firstNonce(preflightState.officialRoomData, preflightState.config.coordinator_did, 1, now),
    claimedAt: now.toISOString(),
  });
  const verified = verifyEnvelope(created.envelope, protocolOptions(preflightState.config, preflightState.manifest));
  assert(verified.payload.type === "CHECKPOINT" && verified.payload.task_id === "event-start", "Start checkpoint verification failed.");
  return { created: [created], skipped: [], room: preflightState.config.official_room };
}

function normalizeObservedTime(value) {
  const parsed = new Date(value);
  assert(!Number.isNaN(parsed.getTime()), "Server did not return a valid start-checkpoint timestamp.");
  return parsed.toISOString();
}

async function main() {
  const arguments_ = parseArguments(process.argv.slice(2));
  let releaseLock = null;
  try {
    if (arguments_.post) {
      releaseLock = await acquireLaunchLock(process.env.SWARMPROOF_LAUNCH_LOCK_FILE ?? DEFAULT_LOCK_FILE);
    }
    const state = await preflight(arguments_);
    const privateKeyPem = await securePrivateKey(process.env.SWARMPROOF_KEY_FILE);
    assert(didFromPrivateKey(privateKeyPem) === state.config.coordinator_did, "Private key does not match the coordinator DID.");
    const now = new Date();
    const selection = arguments_.stage === "tasks"
      ? selectTaskStage(state, privateKeyPem, now)
      : arguments_.stage === "results"
        ? selectResultStage(state, privateKeyPem, now)
        : selectCheckpointStage(state, privateKeyPem, now);

    const summary = publicLaunchSummary({
      stage: arguments_.stage,
      events: selection.created,
      skipped: selection.skipped,
    });
    const baseline = arguments_.stage === "checkpoint" ? {
      classification: "prebuilt-seed-excluded-from-result-evidence",
      commit: state.launchState?.baseline_commit ?? state.commit,
      evidence_commit: state.launchState?.baseline_evidence_commit ?? state.publicationCommit,
      report_sha256: state.launchState?.baseline_report_sha256 ?? state.status.report_sha256,
    } : undefined;
    if (!arguments_.post) {
      output({ action: "would_post", dry_run: true, room: selection.room, ...summary, ...(baseline ? { baseline } : {}) });
      return;
    }

    await recheck(state);
    let workingLaunchState = state.launchState ? structuredClone(state.launchState) : null;
    if (workingLaunchState) await writeLaunchState(state.paths.state, workingLaunchState);
    const observed = [];
    for (const created of selection.created) {
      const field = arguments_.stage === "tasks"
        ? "task_events"
        : arguments_.stage === "results"
          ? "result_events"
          : null;
      if (field) {
        assert(workingLaunchState, "Launch state is required before a build-room write.");
        workingLaunchState[field][created.payload.task_id] = {
          envelope: created.envelope,
          event_id: created.event_id,
          status: "pending",
        };
        await writeLaunchState(state.paths.state, workingLaunchState);
      }
      const observedEvent = await postSignedEvent({
        room: selection.room,
        created,
        privateKeyPem,
        config: state.config,
        manifest: state.manifest,
      });
      observed.push(observedEvent);
      if (field) {
        workingLaunchState[field][created.payload.task_id].status = "observed";
        await writeLaunchState(state.paths.state, workingLaunchState);
      }
    }
    if (arguments_.stage === "checkpoint") {
      const start = observed[0] ?? state.startCheckpoint;
      assert(start, "Start checkpoint was not observed.");
      workingLaunchState = state.launchState ?? launchStateDocument({
        config: state.config,
        sourceCommit: state.commit,
        evidenceCommit: state.publicationCommit,
        reportSha256: state.status.report_sha256,
        start,
      });
      await writeLaunchState(state.paths.state, workingLaunchState);
    }
    output({
      action: selection.created.length === 0 ? "already_complete" : "posted",
      dry_run: false,
      room: selection.room,
      ...summary,
      ...(baseline ? { baseline } : {}),
    });
  } finally {
    if (releaseLock) await releaseLock();
  }
}

main().catch(error => {
  console.error(`launch failed: ${error.message}`);
  process.exit(1);
});
