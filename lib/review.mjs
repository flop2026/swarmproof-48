import { execFile } from "node:child_process";
import { constants as fsConstants } from "node:fs";
import { mkdir, open, rm } from "node:fs/promises";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { promisify } from "node:util";
import { auditEvents } from "./audit.mjs";
import { canonicalize } from "./canonical.mjs";
import { didFromPrivateKey, sha256Hex, signUtf8 } from "./crypto.mjs";
import { launchTaskContentSha, validateLaunchManifest } from "./launch.mjs";
import {
  EXPERIMENT,
  createEnvelope,
  createPayloadScaffold,
  verifyEnvelope,
} from "./protocol.mjs";
import { analyzeEventSemantics } from "./semantics.mjs";

const executeFile = promisify(execFile);

export const REVIEW_PUBLIC_ORIGIN = "https://swarmproof-48-e463.pages.dev";
export const REVIEW_TECHNOCORE_ORIGIN = "https://technocore.chat";
export const REVIEW_REPOSITORY = "flop2026/swarmproof-48";
export const REVIEW_BUILD_ROOM = "swarmproof-48-e463";
export const DEFAULT_REVIEW_LOCK_FILE = join(
  homedir(),
  ".local",
  "state",
  "technocore-chat",
  "swarmproof-48-review.lock",
);

const HASH_RE = /^[0-9a-f]{64}$/u;
const COMMIT_RE = /^[0-9a-f]{40}$/u;
const NONCE_RE = /^[0-9]{1,19}$/u;
const DID_RE = /^did:key:z6Mk[1-9A-HJ-NP-Za-km-z]+$/u;
const ROOM_RE = /^[a-z0-9][a-z0-9_-]{0,47}$/u;
const EVENT_RECORD_KEYS = new Set(["envelope", "observed_at", "source_ts", "source_room", "source_seq"]);
const REPORT_KEYS = new Set([
  "schema", "source_event_count", "unattributable_observation_count", "source_digest", "signing_keys",
  "evidence", "review_evidence", "events", "rejected", "semantically_ignored", "limitations",
  "audit_core_sha256", "generated_at", "event_state", "unsigned_proposals_observed", "build_room",
  "artifact_verification", "archive_policy", "snapshot_manifest", "snapshot_manifest_sha256",
  "network_sample",
]);
const STATUS_KEYS = new Set([
  "schema", "state", "generated_at", "starts_at", "ends_at", "report_sha256", "audit_core_sha256",
  "snapshot_manifest_sha256", "source_commit", "signing_keys", "reproducible_artifacts",
  "cross_key_reviews", "accepted_results", "stale_after_seconds",
]);
const MANIFEST_KEYS = new Set([
  "schema", "generated_at", "source_commit", "audit_core_sha256", "network_sample_sha256",
  "events_archive_sha256", "proposals_archive_sha256",
]);
const AUDIT_CORE_KEYS = [
  "schema", "source_event_count", "unattributable_observation_count", "source_digest", "signing_keys",
  "evidence", "review_evidence", "events", "rejected", "semantically_ignored", "limitations",
];
const PUBLIC_LIMITS = Object.freeze({
  report: 16 * 1024 * 1024,
  status: 256 * 1024,
  events: 16 * 1024 * 1024,
  room: 2 * 1024 * 1024,
});
const MAX_EVENT_RECORDS = 1024;
const MAX_ROOM_MESSAGES = 200;
const MAX_CLOCK_SKEW_MS = 5 * 60 * 1000;

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function assertExactKeys(value, expected, label) {
  assert(value && typeof value === "object" && !Array.isArray(value), `${label} must be an object.`);
  const keys = Object.keys(value);
  assert(keys.length === expected.size, `${label} has an invalid field set.`);
  for (const key of keys) assert(expected.has(key), `${label} contains an unknown field: ${key}`);
  for (const key of expected) assert(Object.hasOwn(value, key), `${label} is missing field: ${key}`);
}

function canonicalTime(value, label) {
  assert(typeof value === "string", `${label} must be canonical UTC.`);
  const milliseconds = Date.parse(value);
  assert(
    Number.isFinite(milliseconds) && new Date(milliseconds).toISOString() === value,
    `${label} must be canonical UTC.`,
  );
  return milliseconds;
}

function parseJson(text, label) {
  try {
    return JSON.parse(text);
  } catch {
    throw new Error(`${label} is not valid JSON.`);
  }
}

function protocolOptions(config, manifest) {
  return {
    allowedRepositories: new Set([config.repository]),
    allowedTasks: new Set(manifest.tasks.map(task => task.id)),
    coordinatorDid: config.coordinator_did,
  };
}

function validateProjectContext(config, manifest) {
  assert(config?.schema === "swarmproof-event-config-v1", "Project config schema is unsupported.");
  assert(config.repository === REVIEW_REPOSITORY, "Project repository does not match SwarmProof 48.");
  assert(config.build_room === REVIEW_BUILD_ROOM, "Project build room does not match SwarmProof 48.");
  assert(config.state === "active", "Reviews may only be prepared while the event is active.");
  assert(DID_RE.test(config.coordinator_did ?? ""), "Project coordinator DID is invalid.");
  assert(ROOM_RE.test(config.build_room ?? ""), "Project build room is invalid.");
  const startsAt = canonicalTime(config.starts_at, "Project starts_at");
  const endsAt = canonicalTime(config.ends_at, "Project ends_at");
  assert(endsAt - startsAt === 48 * 60 * 60 * 1000, "Project event window must be exactly 48 hours.");
  validateLaunchManifest(manifest);
  return { startsAt, endsAt };
}

function validatePublicMetadata(config, report, status, now) {
  assertExactKeys(report, REPORT_KEYS, "Public report");
  assertExactKeys(status, STATUS_KEYS, "Public status");
  assertExactKeys(report.snapshot_manifest, MANIFEST_KEYS, "Public snapshot manifest");
  assert(report.schema === "swarmproof-report-v1", "Public report schema is unsupported.");
  assert(status.schema === "swarmproof-status-v1", "Public status schema is unsupported.");
  assert(report.snapshot_manifest.schema === "swarmproof-snapshot-manifest-v1", "Public snapshot manifest schema is unsupported.");
  assert(report.event_state === "active" && status.state === "active", "Public event state is not active.");
  assert(report.event_state === config.state, "Public report state does not match project config.");
  assert(status.state === config.state, "Public status state does not match project config.");
  assert(status.starts_at === config.starts_at && status.ends_at === config.ends_at, "Public event window does not match project config.");
  assert(report.build_room?.room === config.build_room, "Public report build room does not match project config.");
  assert(report.build_room.collection_error === null, "Public build-room collection failed.");
  assert(report.build_room.continuity_complete === true, "Public build-room history is not contiguous.");

  const generatedAt = canonicalTime(report.generated_at, "Public report generated_at");
  assert(status.generated_at === report.generated_at, "Public report and status timestamps differ.");
  assert(report.snapshot_manifest.generated_at === report.generated_at, "Public snapshot timestamp differs from report.");
  const nowMs = new Date(now).getTime();
  assert(Number.isFinite(nowMs), "Review time is invalid.");
  assert(generatedAt <= nowMs + MAX_CLOCK_SKEW_MS, "Public snapshot is too far in the future.");
  assert(Number.isSafeInteger(status.stale_after_seconds) && status.stale_after_seconds > 0, "Public stale policy is invalid.");
  assert(nowMs - generatedAt <= status.stale_after_seconds * 1000, "Public snapshot is stale.");
  assert(nowMs >= Date.parse(config.starts_at) && nowMs <= Date.parse(config.ends_at), "Review time is outside the event window.");

  const reportSha256 = sha256Hex(canonicalize(report));
  assert(status.report_sha256 === reportSha256, "Public report SHA-256 does not match status.");
  const manifestSha256 = sha256Hex(canonicalize(report.snapshot_manifest));
  assert(report.snapshot_manifest_sha256 === manifestSha256, "Public snapshot manifest hash does not match report.");
  assert(status.snapshot_manifest_sha256 === manifestSha256, "Public snapshot manifest hash does not match status.");
  assert(report.audit_core_sha256 === status.audit_core_sha256, "Public audit-core hashes differ.");
  assert(report.snapshot_manifest.audit_core_sha256 === report.audit_core_sha256, "Snapshot audit-core hash differs from report.");
  assert(COMMIT_RE.test(status.source_commit ?? ""), "Public source commit is invalid.");
  assert(report.snapshot_manifest.source_commit === status.source_commit, "Public source commits differ.");
  return { reportSha256, manifestSha256, sourceCommit: status.source_commit };
}

function parseEventArchive(content, config, manifest) {
  assert(Buffer.byteLength(content, "utf8") <= PUBLIC_LIMITS.events, "Public event archive is oversized.");
  const lines = content.split("\n").filter(line => line.length > 0);
  assert(lines.length <= MAX_EVENT_RECORDS, "Public event archive exceeds its record bound.");
  const records = lines.map((line, index) => parseJson(line, `Public event archive line ${index + 1}`));
  const options = protocolOptions(config, manifest);
  const eventIds = new Set();
  const sourceSequences = new Set();
  const verified = [];
  records.forEach((record, index) => {
    const label = `Public event archive record ${index + 1}`;
    assertExactKeys(record, EVENT_RECORD_KEYS, label);
    assert(record.source_room === config.build_room, `${label} came from the wrong build room.`);
    canonicalTime(record.observed_at, `${label}.observed_at`);
    if (record.source_ts !== null) canonicalTime(record.source_ts, `${label}.source_ts`);
    assert(record.source_seq === null || (Number.isSafeInteger(record.source_seq) && record.source_seq >= 1), `${label}.source_seq is invalid.`);
    if (record.source_seq !== null) {
      assert(!sourceSequences.has(record.source_seq), `${label}.source_seq duplicates another record.`);
      sourceSequences.add(record.source_seq);
    }
    const event = verifyEnvelope(record.envelope, options);
    assert(!eventIds.has(event.event_id), `${label} duplicates another event.`);
    eventIds.add(event.event_id);
    verified.push({ ...event, ...record });
  });
  return { records, verified };
}

function compareAuditCore(report, records, config, manifest) {
  assert(Number.isSafeInteger(report.unattributable_observation_count) && report.unattributable_observation_count >= 0, "Public unattributable count is invalid.");
  assert(Array.isArray(report.events), "Public report events are invalid.");
  const artifactChecks = Object.fromEntries(report.events
    .filter(event => event?.type === "RESULT" && HASH_RE.test(event.event_id ?? ""))
    .map(event => [event.event_id, event.artifact_check]));
  const audited = auditEvents(records, {
    allowedRepositories: [config.repository],
    allowedTasks: new Set(manifest.tasks.map(task => task.id)),
    coordinatorDid: config.coordinator_did,
    startsAt: config.starts_at,
    endsAt: config.ends_at,
    artifactChecks,
    additionalObserved: report.unattributable_observation_count,
  });
  const publicCore = Object.fromEntries(AUDIT_CORE_KEYS.map(key => [
    key,
    key === "limitations" ? report.limitations.slice(0, audited.report.limitations.length) : report[key],
  ]));
  assert(canonicalize(publicCore) === canonicalize(audited.report), "Public audit core does not replay from the event archive.");
  assert(report.audit_core_sha256 === audited.report_sha256, "Public audit-core SHA-256 does not replay.");
  return audited;
}

function bindTarget({ targetEventId, decision, report, records, verified, config, manifest }) {
  assert(HASH_RE.test(targetEventId ?? ""), "Target RESULT event ID must be a lowercase SHA-256.");
  const normalized = normalizeReviewDecision(decision);
  const graph = analyzeEventSemantics(records, {
    allowedRepositories: [config.repository],
    allowedTasks: new Set(manifest.tasks.map(task => task.id)),
    coordinatorDid: config.coordinator_did,
    startsAt: config.starts_at,
    endsAt: config.ends_at,
  });
  const targets = verified.filter(event => event.event_id === targetEventId);
  assert(targets.length === 1, "Target RESULT is missing or ambiguous in the public event archive.");
  const target = targets[0];
  assert(target.payload.type === "RESULT", "Target event is not a RESULT.");
  assert(graph.validResultIds.has(targetEventId), "Target RESULT lacks valid project TASK ancestry.");
  assert(target.source_ts !== null && Number.isSafeInteger(target.source_seq), "Target RESULT lacks authoritative transport ordering.");
  const taskEventId = graph.resultTaskRoot.get(targetEventId);
  assert(HASH_RE.test(taskEventId ?? ""), "Target RESULT has no fixed TASK root.");
  const task = graph.eventById.get(taskEventId);
  assert(task?.payload.type === "TASK", "Target RESULT TASK root is invalid.");
  assert(task.payload.task_id === target.payload.task_id, "Target RESULT task binding is inconsistent.");
  assert(task.payload.did === config.coordinator_did, "Target RESULT TASK root lacks coordinator authority.");
  assert(task.source_ts !== null && Number.isSafeInteger(task.source_seq), "Target TASK root lacks authoritative transport ordering.");
  const taskManifestEntry = manifest.tasks.find(entry => entry.id === target.payload.task_id);
  assert(taskManifestEntry, "Target RESULT task is absent from the project task manifest.");
  assert(
    task.payload.content_sha256 === launchTaskContentSha(taskManifestEntry),
    "Target TASK root does not bind the checked-in task manifest entry.",
  );

  const summaries = report.events.filter(event => event?.event_id === targetEventId);
  assert(summaries.length === 1, "Target RESULT is missing or ambiguous in the public report.");
  const summary = summaries[0];
  for (const [key, value] of Object.entries({
    type: target.payload.type,
    task_id: target.payload.task_id,
    did: target.payload.did,
    claimed_at: target.payload.claimed_at,
    source_ts: target.source_ts,
    content_sha256: target.payload.content_sha256,
  })) assert(summary[key] === value, `Target RESULT ${key} differs between report and archive.`);
  assert(canonicalize(summary.parent_event_ids) === canonicalize(target.payload.parent_event_ids), "Target RESULT parents differ between report and archive.");
  assert(canonicalize(summary.artifact) === canonicalize(target.payload.artifact), "Target RESULT artifact differs between report and archive.");
  assert(!report.semantically_ignored.some(entry => entry?.event_id === targetEventId), "Target RESULT is semantically ignored by the public report.");
  if (normalized.protocolVerdict === "PASS") {
    assert(summary.artifact_check?.status === "pass", "PASS requires a reproducible target with a passing public artifact check.");
    assert(["REPRODUCIBLE", "CROSS-KEY-REVIEWED", "ACCEPTED"].includes(summary.evidence_level), "PASS requires a reproducible target.");
  }
  return {
    decision: normalized.decision,
    protocolVerdict: normalized.protocolVerdict,
    target,
    task,
    taskManifestEntry,
  };
}

export function normalizeReviewDecision(value) {
  assert(typeof value === "string", "Review verdict must be PASS or FAIL.");
  const decision = value.toUpperCase();
  assert(decision === "PASS" || decision === "FAIL", "Review verdict must be PASS or FAIL.");
  return { decision, protocolVerdict: decision === "PASS" ? "PASS" : "REJECT" };
}

export function validateAndBindPublicReview({
  config,
  manifest,
  report,
  status,
  eventsContent,
  targetEventId,
  decision,
  now = new Date(),
}) {
  validateProjectContext(config, manifest);
  const publicMetadata = validatePublicMetadata(config, report, status, now);
  assert(
    sha256Hex(eventsContent) === report.snapshot_manifest.events_archive_sha256,
    "Public event archive SHA-256 does not match the snapshot manifest.",
  );
  const archive = parseEventArchive(eventsContent, config, manifest);
  assert(report.source_event_count === archive.records.length, "Public report event count does not match the archive.");
  compareAuditCore(report, archive.records, config, manifest);
  const binding = bindTarget({
    targetEventId,
    decision,
    report,
    records: archive.records,
    verified: archive.verified,
    config,
    manifest,
  });
  return {
    ...binding,
    config,
    manifest,
    report,
    status,
    records: archive.records,
    verified: archive.verified,
    ...publicMetadata,
  };
}

async function boundedResponseText(response, maximumBytes, label) {
  const declared = Number(response.headers.get("content-length"));
  if (Number.isFinite(declared)) assert(declared <= maximumBytes, `${label} is oversized.`);
  if (!response.body) return "";
  const chunks = [];
  let total = 0;
  for await (const chunk of response.body) {
    total += chunk.byteLength;
    assert(total <= maximumBytes, `${label} is oversized.`);
    chunks.push(Buffer.from(chunk));
  }
  return Buffer.concat(chunks).toString("utf8");
}

async function fetchExactText(url, { fetchImpl, maximumBytes, label, method = "GET", body, headers = {} }) {
  let response;
  try {
    response = await fetchImpl(url, {
      method,
      headers,
      ...(body === undefined ? {} : { body }),
      redirect: "error",
      signal: AbortSignal.timeout(20_000),
    });
  } catch (error) {
    throw new Error(`${label} request failed: ${error.message}`);
  }
  const text = await boundedResponseText(response, maximumBytes, label);
  return { response, text };
}

export async function fetchPublicReviewDocuments({
  fetchImpl = fetch,
  publicOrigin = REVIEW_PUBLIC_ORIGIN,
  cacheBust = Date.now(),
} = {}) {
  const origin = new URL(publicOrigin);
  assert(origin.protocol === "https:" && origin.pathname === "/" && !origin.username && !origin.password && !origin.search && !origin.hash, "Public origin is invalid.");
  const fetchDocument = async (path, label, maximumBytes) => {
    const url = new URL(path, origin);
    url.searchParams.set("n", String(cacheBust));
    const { response, text } = await fetchExactText(url, {
      fetchImpl,
      maximumBytes,
      label,
      headers: { accept: path.endsWith(".jsonl") ? "application/x-ndjson" : "application/json", "cache-control": "no-cache" },
    });
    assert(response.ok, `${label} returned HTTP ${response.status}.`);
    assert(response.url === "" || new URL(response.url).origin === origin.origin, `${label} escaped the public origin.`);
    return text;
  };
  const [reportText, statusText, eventsContent] = await Promise.all([
    fetchDocument("/data/report.json", "Public report", PUBLIC_LIMITS.report),
    fetchDocument("/data/status.json", "Public status", PUBLIC_LIMITS.status),
    fetchDocument("/data/events.jsonl", "Public event archive", PUBLIC_LIMITS.events),
  ]);
  return {
    report: parseJson(reportText, "Public report"),
    status: parseJson(statusText, "Public status"),
    eventsContent,
    reportText,
    statusText,
  };
}

export async function readSecureReviewKey(path) {
  assert(typeof path === "string" && path.length > 0, "A local private-key path is required.");
  let handle;
  try {
    handle = await open(path, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
  } catch (error) {
    throw new Error(`Private key could not be opened safely: ${error.message}`);
  }
  try {
    const metadata = await handle.stat();
    assert(metadata.isFile(), "Private key must be a regular file.");
    assert((metadata.mode & 0o077) === 0, "Private key permissions must deny group and other access.");
    assert(metadata.size > 0 && metadata.size <= 16_384, "Private key size is invalid.");
    return await handle.readFile("utf8");
  } finally {
    await handle.close();
  }
}

export async function assertReviewSourceCommitTrusted(sourceCommit, repositoryRoot) {
  assert(COMMIT_RE.test(sourceCommit ?? ""), "Public source commit is invalid.");
  try {
    await executeFile("git", ["merge-base", "--is-ancestor", sourceCommit, "HEAD"], {
      cwd: repositoryRoot,
      encoding: "utf8",
      timeout: 10_000,
      env: { PATH: process.env.PATH },
    });
  } catch {
    throw new Error("Public source commit is not on the trusted HEAD history.");
  }
}

async function gitOutput(arguments_, repositoryRoot, maximumBytes = 1024 * 1024) {
  return (await executeFile("git", arguments_, {
    cwd: repositoryRoot,
    encoding: "utf8",
    timeout: 20_000,
    maxBuffer: maximumBytes,
    env: { PATH: process.env.PATH },
  })).stdout;
}

export async function assertReviewSnapshotTrusted({
  reportText,
  statusText,
  eventsContent,
  sourceCommit,
  repositoryRoot,
}) {
  assert(typeof reportText === "string" && typeof statusText === "string" && typeof eventsContent === "string", "Public snapshot bytes are missing.");
  const history = (await gitOutput([
    "log",
    "-n",
    "512",
    "--format=%H",
    "HEAD",
    "--",
    "public/data/report.json",
    "public/data/status.json",
    "public/data/events.jsonl",
  ], repositoryRoot)).split("\n").filter(COMMIT_RE.test.bind(COMMIT_RE));
  assert(history.length > 0, "Trusted HEAD contains no public snapshot history.");
  let evidenceCommit = null;
  for (const commit of history) {
    const candidateStatus = await gitOutput(["show", `${commit}:public/data/status.json`], repositoryRoot, PUBLIC_LIMITS.status + 1024)
      .catch(() => null);
    if (candidateStatus !== statusText) continue;
    const [candidateReport, candidateEvents] = await Promise.all([
      gitOutput(["show", `${commit}:public/data/report.json`], repositoryRoot, PUBLIC_LIMITS.report + 1024).catch(() => null),
      gitOutput(["show", `${commit}:public/data/events.jsonl`], repositoryRoot, PUBLIC_LIMITS.events + 1024).catch(() => null),
    ]);
    if (candidateReport === reportText && candidateEvents === eventsContent) {
      evidenceCommit = commit;
      break;
    }
  }
  assert(evidenceCommit, "Public snapshot bytes do not exist together on trusted HEAD history; update the clone and retry.");
  try {
    await Promise.all([
      gitOutput(["merge-base", "--is-ancestor", sourceCommit, evidenceCommit], repositoryRoot),
      gitOutput(["merge-base", "--is-ancestor", evidenceCommit, "HEAD"], repositoryRoot),
    ]);
  } catch {
    throw new Error("Public snapshot lineage is not on trusted HEAD history.");
  }
  return evidenceCommit;
}

function validateRoomData(data, room) {
  assert(data && typeof data === "object" && !Array.isArray(data), "Build-room response is invalid.");
  assert(data.room === room, "Build-room response names the wrong room.");
  assert(Array.isArray(data.messages) && data.messages.length <= MAX_ROOM_MESSAGES, "Build-room response exceeds its message bound.");
  assert(Number.isSafeInteger(data.count) && data.count === data.messages.length, "Build-room response count is invalid.");
  assert(Number.isSafeInteger(data.last_seq) && data.last_seq >= 0, "Build-room last sequence is invalid.");
  if (data.messages.length === 0) {
    assert(data.first_seq === null && data.last_seq === 0, "Empty build-room sequence metadata is invalid.");
  } else {
    assert(Number.isSafeInteger(data.first_seq) && data.first_seq >= 1, "Build-room first sequence is invalid.");
    assert(data.last_seq === data.first_seq + data.messages.length - 1, "Build-room sequence range is invalid.");
    data.messages.forEach((message, index) => {
      assert(message && typeof message === "object" && !Array.isArray(message), "Build-room message is invalid.");
      assert(message.seq === data.first_seq + index, "Build-room message sequence is not contiguous.");
    });
  }
  return data;
}

export async function fetchReviewRoom({
  room = REVIEW_BUILD_ROOM,
  fetchImpl = fetch,
  technocoreOrigin = REVIEW_TECHNOCORE_ORIGIN,
  cacheBust = Date.now(),
} = {}) {
  assert(room === REVIEW_BUILD_ROOM, "Review posting is restricted to the SwarmProof 48 build room.");
  const origin = new URL(technocoreOrigin);
  assert(origin.protocol === "https:" && origin.pathname === "/" && !origin.username && !origin.password && !origin.search && !origin.hash, "Technocore origin is invalid.");
  const url = new URL(`/r/${encodeURIComponent(room)}`, origin);
  url.searchParams.set("format", "json");
  url.searchParams.set("limit", String(MAX_ROOM_MESSAGES));
  url.searchParams.set("n", String(cacheBust));
  const { response, text } = await fetchExactText(url, {
    fetchImpl,
    maximumBytes: PUBLIC_LIMITS.room,
    label: "Build-room read",
    headers: { accept: "application/json", "cache-control": "no-cache" },
  });
  assert(response.ok, `Build-room read returned HTTP ${response.status}.`);
  assert(response.url === "" || new URL(response.url).origin === origin.origin, "Build-room read escaped Technocore.");
  return validateRoomData(parseJson(text, "Build-room response"), room);
}

function strictLiveReviewEvents(roomData, context) {
  const options = protocolOptions(context.config, context.manifest);
  const events = [];
  for (const message of roomData.messages) {
    if (typeof message?.text !== "string" || Buffer.byteLength(message.text, "utf8") > 4096) continue;
    try {
      const event = verifyEnvelope(message.text, options);
      const transportNonce = String(message.nonce ?? "");
      if (
        message.from === event.payload.did
        && NONCE_RE.test(transportNonce)
        && transportNonce === event.payload.nonce
      ) events.push(event);
    } catch {
      // Arbitrary room messages are untrusted data. Only strict project events survive.
    }
  }
  return events;
}

function maximumSafeRoomNonce(roomData, did) {
  let maximum = 0n;
  for (const message of roomData.messages) {
    const nonce = String(message?.nonce ?? "");
    if (message?.from === did && NONCE_RE.test(nonce)) {
      const candidate = BigInt(nonce);
      assert(candidate <= BigInt(Number.MAX_SAFE_INTEGER), "Reviewer nonce exceeds the safe transport range.");
      if (candidate > maximum) maximum = candidate;
    }
  }
  return maximum;
}

function nextReviewNonce(roomData, did, now) {
  const nowMs = BigInt(new Date(now).getTime());
  assert(nowMs >= 0n, "Review time is invalid.");
  const maximum = maximumSafeRoomNonce(roomData, did);
  const nonce = maximum >= nowMs ? maximum + 1n : nowMs;
  assert(nonce <= BigInt(Number.MAX_SAFE_INTEGER) && NONCE_RE.test(String(nonce)), "No safe review nonce remains.");
  return String(nonce);
}

function existingReview(context, roomData, reviewerDid) {
  return [...context.verified, ...strictLiveReviewEvents(roomData, context)].find(event => (
    event.payload.type === "REVIEW"
    && event.payload.did === reviewerDid
    && event.payload.review.target_event_id === context.target.event_id
    && event.payload.review.verdict === context.protocolVerdict
  )) ?? null;
}

export function prepareSignedReview({ context, roomData, privateKeyPem, now = new Date() }) {
  const reviewerDid = didFromPrivateKey(privateKeyPem);
  assert(reviewerDid !== context.target.payload.did, "A review must use a DID different from the RESULT author.");
  const duplicate = existingReview(context, roomData, reviewerDid);
  if (duplicate) return { duplicate, reviewerDid, created: null };
  const claimedAt = new Date(now).toISOString();
  const claimedMs = canonicalTime(claimedAt, "Review claimed_at");
  assert(claimedMs >= Date.parse(context.config.starts_at) && claimedMs <= Date.parse(context.config.ends_at), "Review time is outside the event window.");
  assert(claimedMs >= Date.parse(context.target.payload.claimed_at), "Review cannot predate its target RESULT.");
  const nonce = nextReviewNonce(roomData, reviewerDid, now);
  const scaffold = createPayloadScaffold({
    type: "REVIEW",
    task_id: context.target.payload.task_id,
    claimed_at: claimedAt,
    nonce,
    parent_event_ids: [context.target.event_id],
    content_sha256: context.target.payload.content_sha256,
    review: {
      target_event_id: context.target.event_id,
      verdict: context.protocolVerdict,
    },
  }, protocolOptions(context.config, context.manifest));
  const created = createEnvelope(scaffold, privateKeyPem, protocolOptions(context.config, context.manifest));
  const verified = verifyEnvelope(created.envelope, protocolOptions(context.config, context.manifest));
  assert(verified.event_id === created.event_id, "Prepared REVIEW failed event-ID verification.");
  assert(verified.payload.parent_event_ids[0] === context.target.event_id, "Prepared REVIEW lost its target binding.");
  assert(verified.payload.task_id === context.target.payload.task_id, "Prepared REVIEW lost its task binding.");
  assert(verified.payload.content_sha256 === context.target.payload.content_sha256, "Prepared REVIEW lost its content binding.");
  return { duplicate: null, reviewerDid, created };
}

export function publicReviewSummary({ context, prepared, action, dryRun }) {
  const event = prepared.created ?? prepared.duplicate;
  return {
    schema: "swarmproof-review-helper-v1",
    action,
    dry_run: dryRun,
    room: context.config.build_room,
    reviewer_did: prepared.reviewerDid,
    decision: context.decision,
    signed_verdict: context.protocolVerdict,
    event_id: event.event_id,
    target: {
      event_id: context.target.event_id,
      author_did: context.target.payload.did,
      task_id: context.target.payload.task_id,
      task_event_id: context.task.event_id,
      parent_event_id: context.target.payload.parent_event_ids[0],
      content_sha256: context.target.payload.content_sha256,
      artifact: context.target.payload.artifact,
      acceptance: context.taskManifestEntry.acceptance,
    },
    public_snapshot: {
      report_sha256: context.reportSha256,
      source_commit: context.sourceCommit,
      evidence_commit: context.evidenceCommit,
      generated_at: context.report.generated_at,
    },
  };
}

const sleep = milliseconds => new Promise(resolve => setTimeout(resolve, milliseconds));

async function observeReview({ context, eventId, fetchImpl, technocoreOrigin }) {
  for (let attempt = 1; attempt <= 4; attempt += 1) {
    const roomData = await fetchReviewRoom({
      room: context.config.build_room,
      fetchImpl,
      technocoreOrigin,
      cacheBust: `${Date.now()}-${attempt}`,
    });
    const observed = strictLiveReviewEvents(roomData, context).find(event => event.event_id === eventId);
    if (observed) return observed;
    if (attempt < 4) await sleep(attempt * 500);
  }
  return null;
}

export async function postSignedReview({
  context,
  prepared,
  privateKeyPem,
  fetchImpl = fetch,
  technocoreOrigin = REVIEW_TECHNOCORE_ORIGIN,
}) {
  assert(prepared.created, "There is no new REVIEW to post.");
  const origin = new URL(technocoreOrigin);
  assert(origin.protocol === "https:" && origin.pathname === "/" && !origin.username && !origin.password && !origin.search && !origin.hash, "Technocore origin is invalid.");
  const created = prepared.created;
  const nonce = created.payload.nonce;
  const transportSignature = signUtf8(
    privateKeyPem,
    `${context.config.build_room}|${nonce}|${created.envelope}`,
  ).toString("base64url");
  const url = new URL(`/r/${encodeURIComponent(context.config.build_room)}`, origin);
  url.searchParams.set("format", "json");
  let response;
  let responseText = "";
  let requestError = null;
  try {
    const result = await fetchExactText(url, {
      fetchImpl,
      maximumBytes: 4096,
      label: "Signed REVIEW write",
      method: "POST",
      headers: { "content-type": "application/json", accept: "application/json" },
      body: JSON.stringify({
        did: prepared.reviewerDid,
        sig: transportSignature,
        nonce,
        text: created.envelope,
      }),
    });
    response = result.response;
    responseText = result.text;
  } catch (error) {
    requestError = error;
  }
  const observed = await observeReview({
    context,
    eventId: created.event_id,
    fetchImpl,
    technocoreOrigin,
  });
  if (observed) return observed;
  if (requestError) throw new Error("Signed REVIEW outcome is unknown and read-back did not observe it.");
  throw new Error(`Signed REVIEW was not observed (HTTP ${response.status}, response SHA-256 ${sha256Hex(responseText)}).`);
}

export async function acquireReviewLock(path = DEFAULT_REVIEW_LOCK_FILE) {
  assert(typeof path === "string" && path.length > 0, "Review lock path is invalid.");
  const directory = dirname(path);
  assert(directory !== "/", "Review lock path is unsafe.");
  await mkdir(directory, { recursive: true, mode: 0o700 });
  const directoryHandle = await open(directory, fsConstants.O_RDONLY | fsConstants.O_DIRECTORY | fsConstants.O_NOFOLLOW);
  try {
    const metadata = await directoryHandle.stat();
    assert(metadata.isDirectory(), "Review lock directory is invalid.");
  } finally {
    await directoryHandle.close();
  }
  const handle = await open(path, "wx", 0o600).catch(error => {
    if (error.code === "EEXIST") throw new Error("Another review post may be active; refusing to post.");
    throw error;
  });
  await handle.writeFile(`${process.pid}\n`, "utf8");
  return async () => {
    await handle.close();
    await rm(path, { force: true });
  };
}

export function stableTargetBinding(context) {
  return sha256Hex(canonicalize({
    experiment: EXPERIMENT,
    room: context.config.build_room,
    target_event_id: context.target.event_id,
    target_author_did: context.target.payload.did,
    task_id: context.target.payload.task_id,
    task_event_id: context.task.event_id,
    target_parent_event_id: context.target.payload.parent_event_ids[0],
    content_sha256: context.target.payload.content_sha256,
    artifact: context.target.payload.artifact,
    decision: context.decision,
    protocol_verdict: context.protocolVerdict,
  }));
}
