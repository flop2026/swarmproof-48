import { canonicalize } from "./canonical.mjs";
import { assessCheckpointInputs, createCheckpointEnvelope } from "./checkpoint.mjs";
import { didFromPrivateKey, sha256Hex } from "./crypto.mjs";
import { createEnvelope, verifyEnvelope } from "./protocol.mjs";

const HASH_RE = /^[0-9a-f]{64}$/;
const COMMIT_RE = /^[0-9a-f]{40}$/;
const NONCE_RE = /^[0-9]{1,19}$/;

export const LAUNCH_ARTIFACTS = Object.freeze({
  protocol: "lib/protocol.mjs",
  collector: "lib/collector.mjs",
  verifier: "lib/artifact.mjs",
  "audit-engine": "lib/audit.mjs",
  observatory: "src/App.tsx",
  "adversarial-fixtures": "test/sp1-gold-vectors.test.mjs",
  replay: "bin/swarmproof.mjs",
  methodology: "public/data/methodology.json",
});

export const LAUNCH_TASK_IDS = Object.freeze(Object.keys(LAUNCH_ARTIFACTS));

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function assertExactKeys(value, required, optional, label) {
  assert(value && typeof value === "object" && !Array.isArray(value), `${label} must be an object.`);
  const allowed = new Set([...required, ...optional]);
  for (const key of Object.keys(value)) assert(allowed.has(key), `${label} contains unknown field: ${key}`);
  for (const key of required) assert(Object.hasOwn(value, key), `${label} is missing ${key}.`);
}

function canonicalTime(value, label) {
  assert(typeof value === "string" && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value), `${label} is not canonical UTC.`);
  const parsed = new Date(value);
  assert(!Number.isNaN(parsed.getTime()) && parsed.toISOString() === value, `${label} is invalid.`);
  return parsed;
}

function nonceSequence(start, count) {
  assert(NONCE_RE.test(start ?? ""), "Launch nonce is invalid.");
  const first = BigInt(start);
  const values = [];
  for (let offset = 0n; offset < BigInt(count); offset += 1n) {
    const value = String(first + offset);
    assert(NONCE_RE.test(value), "Launch nonce exceeded the protocol range.");
    values.push(value);
  }
  return values;
}

export function validateLaunchManifest(manifest) {
  assertExactKeys(manifest, ["schema", "tasks", "trusted_checks"], [], "task manifest");
  assert(manifest.schema === "swarmproof-task-manifest-v1", "Unsupported task manifest schema.");
  assert(Array.isArray(manifest.tasks), "Task manifest tasks must be an array.");
  assert(Array.isArray(manifest.trusted_checks), "Task manifest trusted checks must be an array.");

  const tasks = new Map();
  for (const task of manifest.tasks) {
    assertExactKeys(task, ["id", "title", "acceptance"], ["replay_check"], `task ${task?.id ?? "<unknown>"}`);
    assert(typeof task.id === "string" && /^[a-z0-9][a-z0-9_-]{0,63}$/.test(task.id), "Task manifest contains an invalid ID.");
    assert(!tasks.has(task.id), `Task manifest contains duplicate ID: ${task.id}`);
    assert(typeof task.title === "string" && task.title.length >= 1 && task.title.length <= 160, `Task ${task.id} title is invalid.`);
    assert(Array.isArray(task.acceptance) && task.acceptance.length >= 1 && task.acceptance.length <= 16, `Task ${task.id} acceptance list is invalid.`);
    for (const item of task.acceptance) {
      assert(typeof item === "string" && item.length >= 1 && item.length <= 240, `Task ${task.id} acceptance item is invalid.`);
    }
    if (LAUNCH_TASK_IDS.includes(task.id)) {
      assert(
        Array.isArray(task.replay_check)
          && task.replay_check.length === 2
          && task.replay_check[0] === "node"
          && task.replay_check[1] === "--test",
        `Task ${task.id} must use the fixed replay check.`,
      );
    }
    tasks.set(task.id, task);
  }

  const expected = new Set([...LAUNCH_TASK_IDS, "event-start", "daily-checkpoint"]);
  assert(tasks.size === expected.size, "Task manifest must contain exactly the launch and checkpoint tasks.");
  for (const id of expected) assert(tasks.has(id), `Task manifest is missing ${id}.`);
  return tasks;
}

export function launchTaskContentSha(task) {
  return sha256Hex(canonicalize(task));
}

export function indexExpectedTaskEvents(events, manifest) {
  assert(Array.isArray(events), "Launch event sources are invalid.");
  const tasks = validateLaunchManifest(manifest);
  const resolved = {};
  for (const taskId of LAUNCH_TASK_IDS) {
    const candidates = events.filter(event => event?.payload?.type === "TASK" && event.payload.task_id === taskId);
    const expectedHash = launchTaskContentSha(tasks.get(taskId));
    const matching = candidates.filter(event => event.payload.content_sha256 === expectedHash);
    assert(candidates.length === matching.length, `Launch sources contain a divergent coordinator TASK for ${taskId}.`);
    const unique = new Map(matching.map(event => [event.event_id, event]));
    assert(unique.size <= 1, `Launch sources contain duplicate coordinator TASK events for ${taskId}.`);
    if (unique.size === 1) resolved[taskId] = [...unique.values()][0];
  }
  return resolved;
}

function historicalResultMatches(event, { config, taskId, taskEventId, baselineHash }) {
  const payload = event?.payload;
  const artifact = payload?.artifact;
  return payload?.type === "RESULT"
    && payload.task_id === taskId
    && payload.did === config.coordinator_did
    && payload.parent_event_ids?.length === 1
    && payload.parent_event_ids[0] === taskEventId
    && HASH_RE.test(payload.content_sha256 ?? "")
    && artifact?.repository === config.repository
    && COMMIT_RE.test(artifact.commit ?? "")
    && artifact.path === LAUNCH_ARTIFACTS[taskId]
    && HASH_RE.test(artifact.sha256 ?? "")
    && payload.content_sha256 === artifact.sha256
    && HASH_RE.test(baselineHash ?? "")
    && artifact.sha256 !== baselineHash;
}

export function resolveLaunchResultWork({ events, config, taskEvents, eligibleTaskIds, baselineHashes }) {
  assert(Array.isArray(events), "Launch result sources are invalid.");
  assert(config && typeof config === "object" && !Array.isArray(config), "Launch result config is invalid.");
  assert(taskEvents && typeof taskEvents === "object" && !Array.isArray(taskEvents), "Launch TASK bindings are invalid.");
  assert(baselineHashes && typeof baselineHashes === "object" && !Array.isArray(baselineHashes), "Launch baseline hashes are invalid.");
  assert(Array.isArray(eligibleTaskIds), "Eligible RESULT task list is invalid.");
  assert(new Set(eligibleTaskIds).size === eligibleTaskIds.length, "Eligible RESULT task list contains duplicates.");
  for (const taskId of eligibleTaskIds) {
    assert(LAUNCH_TASK_IDS.includes(taskId), `Eligible RESULT task is invalid: ${taskId}`);
  }

  const existing = {};
  for (const taskId of LAUNCH_TASK_IDS) {
    const taskEventId = taskEvents[taskId]?.event_id;
    assert(HASH_RE.test(taskEventId ?? ""), `TASK event ID is missing for ${taskId}.`);
    const baselineHash = baselineHashes[taskId];
    assert(HASH_RE.test(baselineHash ?? ""), `Baseline artifact hash is missing for ${taskId}.`);
    const candidates = events.filter(event => event?.payload?.type === "RESULT" && event.payload.task_id === taskId);
    const matching = candidates.filter(event => historicalResultMatches(event, {
      config,
      taskId,
      taskEventId,
      baselineHash,
    }));
    assert(candidates.length === matching.length, `Build room contains a divergent coordinator RESULT for ${taskId}.`);
    assert(matching.length <= 1, `Build room contains duplicate coordinator RESULT events for ${taskId}.`);
    if (matching[0]) existing[taskId] = matching[0];
  }

  return {
    existing,
    pendingTaskIds: eligibleTaskIds.filter(taskId => !existing[taskId]),
  };
}

export function assessLaunchInputs({
  config,
  manifest,
  report,
  status,
  commit,
  sourceCommit = commit,
  publicationCommit = null,
  now = new Date(),
  maxAgeSeconds = null,
}) {
  const tasks = validateLaunchManifest(manifest);
  assert(config?.state === "active", "Launch writes require config.state=active.");
  const checkpoint = assessCheckpointInputs({ config, report, status, now, maxAgeSeconds });
  assert(checkpoint.eligible, `Launch checkpoint gate is closed: ${checkpoint.reason}.`);
  assert(COMMIT_RE.test(sourceCommit ?? ""), "Launch requires a full lowercase source commit.");
  if (publicationCommit !== null) assert(COMMIT_RE.test(publicationCommit), "Launch publication commit is invalid.");
  assert(status.source_commit === sourceCommit, "Public status source commit does not match the requested source commit.");
  assert(report.snapshot_manifest?.source_commit === sourceCommit, "Public report source commit does not match the requested source commit.");
  return {
    checkpoint,
    tasks,
    task_ids: [...LAUNCH_TASK_IDS],
  };
}

function protocolOptions(config, manifest) {
  return {
    allowedRepositories: new Set([config.repository]),
    allowedTasks: new Set(manifest.tasks.map(task => task.id)),
    coordinatorDid: config.coordinator_did,
  };
}

export function createLaunchTaskEvents({
  config,
  manifest,
  privateKeyPem,
  claimedAt,
  firstNonce,
}) {
  const tasks = validateLaunchManifest(manifest);
  canonicalTime(claimedAt, "Launch task time");
  assert(didFromPrivateKey(privateKeyPem) === config.coordinator_did, "Private key does not match the coordinator DID.");
  const nonces = nonceSequence(firstNonce, LAUNCH_TASK_IDS.length);
  const options = protocolOptions(config, manifest);
  return LAUNCH_TASK_IDS.map((taskId, index) => {
    const task = tasks.get(taskId);
    return createEnvelope({
      schema: "swarmproof-event-v1",
      type: "TASK",
      task_id: taskId,
      did: config.coordinator_did,
      claimed_at: claimedAt,
      nonce: nonces[index],
      parent_event_ids: [],
      content_sha256: launchTaskContentSha(task),
    }, privateKeyPem, options);
  });
}

export function createLaunchResultEvents({
  config,
  manifest,
  privateKeyPem,
  commit,
  artifactHashes,
  taskEventIds,
  taskIds,
  claimedAt,
  firstNonce,
}) {
  validateLaunchManifest(manifest);
  canonicalTime(claimedAt, "Launch result time");
  assert(COMMIT_RE.test(commit ?? ""), "Result commit must be a full lowercase SHA.");
  assert(didFromPrivateKey(privateKeyPem) === config.coordinator_did, "Private key does not match the coordinator DID.");
  assert(Array.isArray(taskIds) && taskIds.length >= 1 && taskIds.length <= LAUNCH_TASK_IDS.length, "Post-start RESULT task list is invalid.");
  assert(new Set(taskIds).size === taskIds.length, "Post-start RESULT task list contains duplicates.");
  for (const taskId of taskIds) assert(LAUNCH_TASK_IDS.includes(taskId), `Post-start RESULT task is invalid: ${taskId}`);
  const nonces = nonceSequence(firstNonce, taskIds.length);
  const options = protocolOptions(config, manifest);

  return taskIds.map((taskId, index) => {
    const path = LAUNCH_ARTIFACTS[taskId];
    const hash = artifactHashes?.[taskId];
    const parent = taskEventIds?.[taskId];
    assert(HASH_RE.test(hash ?? ""), `Artifact hash is missing for ${taskId}.`);
    assert(HASH_RE.test(parent ?? ""), `TASK event ID is missing for ${taskId}.`);
    return createEnvelope({
      schema: "swarmproof-event-v1",
      type: "RESULT",
      task_id: taskId,
      did: config.coordinator_did,
      claimed_at: claimedAt,
      nonce: nonces[index],
      parent_event_ids: [parent],
      content_sha256: hash,
      artifact: {
        repository: config.repository,
        commit,
        path,
        sha256: hash,
      },
    }, privateKeyPem, options);
  });
}

export function createLaunchCheckpoint({
  config,
  reportSha256,
  privateKeyPem,
  nonce,
  claimedAt,
}) {
  return createCheckpointEnvelope({
    config,
    reportSha256,
    privateKeyPem,
    nonce,
    claimedAt,
    parentEventId: null,
  });
}

export function verifyLaunchEvents(events, { config, manifest, expectedType }) {
  assert(Array.isArray(events), `Expected an array of ${expectedType} events.`);
  if (expectedType === "TASK") assert(events.length === LAUNCH_TASK_IDS.length, `Expected ${LAUNCH_TASK_IDS.length} TASK events.`);
  else assert(events.length >= 1 && events.length <= LAUNCH_TASK_IDS.length, `Expected 1-${LAUNCH_TASK_IDS.length} ${expectedType} events.`);
  const options = protocolOptions(config, manifest);
  const verified = events.map(event => verifyEnvelope(event.envelope ?? event, options));
  const taskIds = new Set();
  for (const event of verified) {
    assert(event.payload.type === expectedType, `Launch event is not ${expectedType}.`);
    assert(event.payload.did === config.coordinator_did, "Launch event is not signed by the coordinator DID.");
    assert(LAUNCH_TASK_IDS.includes(event.payload.task_id), "Launch event has an unexpected task ID.");
    assert(!taskIds.has(event.payload.task_id), `Launch event duplicates ${event.payload.task_id}.`);
    taskIds.add(event.payload.task_id);
  }
  return verified;
}

export function assessPostStartResultCommit({
  baselineCommit,
  commit,
  startsAt,
  checkpointObservedAt,
  commitTime,
  changedPaths,
  baselineHashes,
  currentHashes,
}) {
  assert(COMMIT_RE.test(baselineCommit ?? ""), "Baseline commit is invalid.");
  assert(COMMIT_RE.test(commit ?? ""), "Result commit is invalid.");
  assert(commit !== baselineCommit, "Prebuilt baseline commit cannot be claimed as a RESULT.");
  const start = canonicalTime(startsAt, "Event start time").getTime();
  const observed = canonicalTime(checkpointObservedAt, "Start checkpoint observation time").getTime();
  const committed = canonicalTime(commitTime, "Result commit time").getTime();
  assert(observed >= start - 300_000, "Start checkpoint observation predates the event window.");
  assert(committed > start && committed > observed, "RESULT commit must be created after the observed start checkpoint.");
  assert(Array.isArray(changedPaths), "Changed path list is invalid.");
  const changed = new Set(changedPaths);
  const taskIds = [];
  for (const taskId of LAUNCH_TASK_IDS) {
    const path = LAUNCH_ARTIFACTS[taskId];
    if (!changed.has(path)) continue;
    assert(HASH_RE.test(baselineHashes?.[taskId] ?? ""), `Baseline artifact hash is missing for ${taskId}.`);
    assert(HASH_RE.test(currentHashes?.[taskId] ?? ""), `Current artifact hash is missing for ${taskId}.`);
    assert(baselineHashes[taskId] !== currentHashes[taskId], `Artifact ${taskId} did not materially change after the baseline.`);
    taskIds.push(taskId);
  }
  assert(taskIds.length > 0, "No mapped artifact has a post-start material change.");
  return taskIds;
}

export function coordinatorPreStartConflicts(events, coordinatorDid) {
  assert(Array.isArray(events), "Pre-start event list is invalid.");
  return events.filter(event => event?.payload?.did === coordinatorDid);
}

export function selectRecoverableBaseline({ startEvent, candidates, config }) {
  assert(HASH_RE.test(startEvent?.event_id ?? ""), "Start checkpoint event ID is invalid.");
  assert(startEvent.payload?.type === "CHECKPOINT" && startEvent.payload.task_id === "event-start", "Start event is not event-start CHECKPOINT.");
  assert(startEvent.payload.parent_event_ids?.length === 0, "Start checkpoint must not have a parent.");
  assert(HASH_RE.test(startEvent.payload.content_sha256 ?? ""), "Start checkpoint report hash is invalid.");
  assert(Array.isArray(candidates), "Baseline recovery candidates are invalid.");
  const matches = [];
  for (const candidate of candidates) {
    const { evidence_commit: evidenceCommit, report, status, config: historicalConfig } = candidate ?? {};
    if (
      !COMMIT_RE.test(evidenceCommit ?? "")
      || !report
      || !status
      || !historicalConfig
      || sha256Hex(canonicalize(report)) !== startEvent.payload.content_sha256
      || status.report_sha256 !== startEvent.payload.content_sha256
      || !COMMIT_RE.test(status.source_commit ?? "")
      || report.snapshot_manifest?.source_commit !== status.source_commit
      || report.event_state !== "active"
      || status.state !== "active"
      || historicalConfig.coordinator_did !== config.coordinator_did
      || historicalConfig.official_room !== config.official_room
      || historicalConfig.repository !== config.repository
    ) continue;
    matches.push({
      source_commit: status.source_commit,
      evidence_commit: evidenceCommit,
      report_sha256: startEvent.payload.content_sha256,
    });
  }
  assert(matches.length === 1, matches.length === 0
    ? "Could not recover the immutable baseline for the observed start checkpoint."
    : "Start checkpoint report hash maps to multiple baseline commits.");
  return matches[0];
}

export function publicLaunchSummary({ stage, events, skipped = [] }) {
  assert(["tasks", "results", "checkpoint"].includes(stage), "Launch stage is invalid.");
  assert(Array.isArray(events) && Array.isArray(skipped), "Launch summary inputs are invalid.");
  return {
    stage,
    event_count: events.length,
    event_ids: events.map(event => event.event_id),
    skipped_event_ids: skipped.map(event => event.event_id),
  };
}
