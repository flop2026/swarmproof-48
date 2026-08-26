import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { generateKeyPairSync } from "node:crypto";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { promisify } from "node:util";
import { canonicalize } from "../lib/canonical.mjs";
import { didFromPrivateKey, sha256Hex } from "../lib/crypto.mjs";
import {
  LAUNCH_ARTIFACTS,
  LAUNCH_TASK_IDS,
  assessLaunchInputs,
  assessPostStartResultCommit,
  coordinatorPreStartConflicts,
  createLaunchCheckpoint,
  createLaunchResultEvents,
  createLaunchTaskEvents,
  indexExpectedTaskEvents,
  publicLaunchSummary,
  selectRecoverableBaseline,
  validateLaunchManifest,
  verifyLaunchEvents,
} from "../lib/launch.mjs";
import { verifyEnvelope } from "../lib/protocol.mjs";

const COMMIT = "c".repeat(40);
const REPOSITORY = "flop2026/swarmproof-48";
const NOW = new Date("2026-08-26T12:00:00.000Z");
const executeFile = promisify(execFile);

function privatePem() {
  const { privateKey } = generateKeyPairSync("ed25519");
  return privateKey.export({ format: "pem", type: "pkcs8" });
}

function fixture(key = privatePem()) {
  const coordinatorDid = didFromPrivateKey(key);
  const manifest = {
    schema: "swarmproof-task-manifest-v1",
    tasks: [
      ...LAUNCH_TASK_IDS.map(id => ({
        id,
        title: `Task ${id}`,
        acceptance: ["deterministic acceptance"],
        replay_check: ["node", "--test"],
      })),
      { id: "event-start", title: "Start", acceptance: ["active"] },
      { id: "daily-checkpoint", title: "Daily", acceptance: ["bounded"] },
    ],
    trusted_checks: [["node", "--test"]],
  };
  const config = {
    state: "active",
    starts_at: "2026-08-26T00:00:00.000Z",
    ends_at: "2026-08-28T00:00:00.000Z",
    coordinator_did: coordinatorDid,
    official_room: "d-swarmproof-48-e463",
    build_room: "swarmproof-48-e463",
    repository: REPOSITORY,
    sample: { rooms: 200, messages_per_room: 200, network_snapshot_hours: 6 },
  };
  const report = {
    schema: "swarmproof-report-v1",
    source_event_count: 16,
    source_digest: "a".repeat(64),
    signing_keys: 1,
    evidence: { observed: 16, attributable: 16, reproducible: 8, cross_key_reviewed: 0, accepted: 0 },
    events: [],
    rejected: [],
    generated_at: "2026-08-26T11:30:00.000Z",
    event_state: "active",
    unsigned_proposals_observed: 0,
    build_room: { messages_observed_in_tail: 16, collection_error: null },
    network_sample: {
      schema: "swarmproof-network-sample-v1",
      generated_at: "2026-08-26T11:29:00.000Z",
      selection: {
        rooms_requested: 200,
        rooms_returned: 200,
        messages_per_room_requested: 200,
        rooms_failed: 0,
      },
      aggregate: { messages: 5000 },
      failures: [],
    },
    snapshot_manifest: { source_commit: COMMIT },
  };
  const status = {
    schema: "swarmproof-status-v1",
    state: "active",
    generated_at: report.generated_at,
    starts_at: config.starts_at,
    ends_at: config.ends_at,
    report_sha256: sha256Hex(canonicalize(report)),
    source_commit: COMMIT,
    signing_keys: 1,
    reproducible_artifacts: 8,
    cross_key_reviews: 0,
    accepted_results: 0,
    stale_after_seconds: 2700,
  };
  return { key, config, manifest, report, status };
}

test("launch manifest is exactly the eight public tasks plus two checkpoint tasks", async () => {
  const manifest = JSON.parse(await readFile(new URL("../config/tasks.json", import.meta.url), "utf8"));
  const tasks = validateLaunchManifest(manifest);
  assert.deepEqual([...LAUNCH_TASK_IDS], [
    "protocol",
    "collector",
    "verifier",
    "audit-engine",
    "observatory",
    "adversarial-fixtures",
    "replay",
    "methodology",
  ]);
  assert.equal(tasks.size, 10);
  assert.deepEqual(Object.keys(LAUNCH_ARTIFACTS), [...LAUNCH_TASK_IDS]);
});

test("launcher rejects an unconfirmed write before any preflight or network action", async () => {
  await assert.rejects(
    executeFile(process.execPath, [new URL("../scripts/launch.mjs", import.meta.url).pathname, "--post"], {
      timeout: 5000,
      env: { PATH: process.env.PATH },
    }),
    error => /Posting requires --confirm=swarmproof-48-e463/u.test(error.stderr),
  );
});

test("launcher preflight and recheck both bind the same public event archive", async () => {
  const source = await readFile(new URL("../scripts/launch.mjs", import.meta.url), "utf8");
  const preflight = source.slice(source.indexOf("async function preflight"), source.indexOf("async function recheck"));
  const recheck = source.slice(source.indexOf("async function recheck"), source.indexOf("function selectTaskStage"));
  assert.match(preflight, /const eventArchive = await readEventArchive\(paths\.events, report\)/u);
  assert.doesNotMatch(preflight, /storedLaunchState, eventArchiveContent/u);
  assert.match(recheck, /storedLaunchState, eventArchiveContent\] = await Promise\.all/u);
  assert.match(recheck, /eventArchiveContent === preflightState\.eventArchive\.content/u);
});

test("signed launch writes use only the protocol-required content type", async () => {
  const source = await readFile(new URL("../scripts/launch.mjs", import.meta.url), "utf8");
  const signedWrite = source.slice(source.indexOf("async function postSignedEvent"), source.indexOf("async function postStartEvidence"));
  assert.match(signedWrite, /headers: \{ "content-type": "application\/json" \}/u);
  assert.doesNotMatch(signedWrite, /user-agent/u);
});

test("creates and re-verifies eight coordinator TASK events without parents", () => {
  const input = fixture();
  const created = createLaunchTaskEvents({
    config: input.config,
    manifest: input.manifest,
    privateKeyPem: input.key,
    claimedAt: NOW.toISOString(),
    firstNonce: "1000",
  });
  const verified = verifyLaunchEvents(created, {
    config: input.config,
    manifest: input.manifest,
    expectedType: "TASK",
  });
  assert.equal(verified.length, 8);
  assert.equal(new Set(verified.map(event => event.payload.task_id)).size, 8);
  assert.ok(verified.every(event => event.payload.parent_event_ids.length === 0));
  assert.deepEqual(verified.map(event => event.payload.nonce), ["1000", "1001", "1002", "1003", "1004", "1005", "1006", "1007"]);
});

test("durable verified archive TASKs remain usable after the room tail evicts them", () => {
  const input = fixture();
  const created = createLaunchTaskEvents({
    config: input.config,
    manifest: input.manifest,
    privateKeyPem: input.key,
    claimedAt: NOW.toISOString(),
    firstNonce: "1500",
  });
  const archiveEvents = verifyLaunchEvents(created, {
    config: input.config,
    manifest: input.manifest,
    expectedType: "TASK",
  });
  const roomTail = [];
  const indexed = indexExpectedTaskEvents([...roomTail, ...archiveEvents], input.manifest);
  assert.equal(Object.keys(indexed).length, 8);
  assert.deepEqual(
    Object.values(indexed).map(event => event.event_id).sort(),
    created.map(event => event.event_id).sort(),
  );
});

test("RESULT events bind each exact artifact and its corresponding TASK parent", () => {
  const input = fixture();
  const tasks = createLaunchTaskEvents({
    config: input.config,
    manifest: input.manifest,
    privateKeyPem: input.key,
    claimedAt: NOW.toISOString(),
    firstNonce: "2000",
  });
  const taskEventIds = Object.fromEntries(tasks.map(event => [event.payload.task_id, event.event_id]));
  const artifactHashes = Object.fromEntries(LAUNCH_TASK_IDS.map((id, index) => [id, String(index + 1).repeat(64)]));
  const results = createLaunchResultEvents({
    config: input.config,
    manifest: input.manifest,
    privateKeyPem: input.key,
    commit: COMMIT,
    artifactHashes,
    taskEventIds,
    taskIds: [...LAUNCH_TASK_IDS],
    claimedAt: NOW.toISOString(),
    firstNonce: "3000",
  });
  const verified = verifyLaunchEvents(results, {
    config: input.config,
    manifest: input.manifest,
    expectedType: "RESULT",
  });
  for (const event of verified) {
    const taskId = event.payload.task_id;
    assert.deepEqual(event.payload.parent_event_ids, [taskEventIds[taskId]]);
    assert.equal(event.payload.content_sha256, artifactHashes[taskId]);
    assert.deepEqual(event.payload.artifact, {
      repository: REPOSITORY,
      commit: COMMIT,
      path: LAUNCH_ARTIFACTS[taskId],
      sha256: artifactHashes[taskId],
    });
  }
});

test("RESULT generation fails closed on a missing TASK binding or artifact hash", () => {
  const input = fixture();
  const hashes = Object.fromEntries(LAUNCH_TASK_IDS.map(id => [id, "a".repeat(64)]));
  const parents = Object.fromEntries(LAUNCH_TASK_IDS.map(id => [id, "b".repeat(64)]));
  delete parents.collector;
  assert.throws(() => createLaunchResultEvents({
    config: input.config,
    manifest: input.manifest,
    privateKeyPem: input.key,
    commit: COMMIT,
    artifactHashes: hashes,
    taskEventIds: parents,
    taskIds: [...LAUNCH_TASK_IDS],
    claimedAt: NOW.toISOString(),
    firstNonce: "4000",
  }), /TASK event ID is missing for collector/u);
});

test("prebuilt baseline is ineligible and only materially changed post-start artifacts become RESULTs", () => {
  assert.throws(() => assessPostStartResultCommit({
    baselineCommit: COMMIT,
    commit: COMMIT,
    startsAt: "2026-08-26T12:00:00.000Z",
    checkpointObservedAt: "2026-08-26T12:00:01.000Z",
    commitTime: "2026-08-26T12:05:00.000Z",
    changedPaths: [LAUNCH_ARTIFACTS.protocol],
    baselineHashes: { protocol: "a".repeat(64) },
    currentHashes: { protocol: "b".repeat(64) },
  }), /Prebuilt baseline commit cannot be claimed as a RESULT/u);

  const nextCommit = "d".repeat(40);
  const baselineHashes = Object.fromEntries(LAUNCH_TASK_IDS.map(id => [id, "a".repeat(64)]));
  const currentHashes = { ...baselineHashes, protocol: "b".repeat(64) };
  assert.deepEqual(assessPostStartResultCommit({
    baselineCommit: COMMIT,
    commit: nextCommit,
    startsAt: "2026-08-26T12:00:00.000Z",
    checkpointObservedAt: "2026-08-26T12:00:01.000Z",
    commitTime: "2026-08-26T12:05:00.000Z",
    changedPaths: [LAUNCH_ARTIFACTS.protocol, "README.md"],
    baselineHashes,
    currentHashes,
  }), ["protocol"]);

  assert.throws(() => assessPostStartResultCommit({
    baselineCommit: COMMIT,
    commit: nextCommit,
    startsAt: "2026-08-26T12:00:00.000Z",
    checkpointObservedAt: "2026-08-26T12:00:01.000Z",
    commitTime: "2026-08-26T11:59:59.000Z",
    changedPaths: [LAUNCH_ARTIFACTS.protocol],
    baselineHashes,
    currentHashes,
  }), /after the observed start checkpoint/u);
});

test("a third-party pre-start event cannot block launch, while a coordinator event does", () => {
  const coordinatorDid = fixture().config.coordinator_did;
  const participant = { payload: { did: "did:key:z6MkParticipant" } };
  const coordinator = { payload: { did: coordinatorDid } };
  assert.deepEqual(coordinatorPreStartConflicts([participant], coordinatorDid), []);
  assert.deepEqual(coordinatorPreStartConflicts([participant, coordinator], coordinatorDid), [coordinator]);
});

test("recovers an exact immutable baseline after start-post success but local-state loss", () => {
  const input = fixture();
  const report = structuredClone(input.report);
  report.snapshot_manifest.source_commit = COMMIT;
  const reportSha256 = sha256Hex(canonicalize(report));
  const status = {
    ...input.status,
    source_commit: COMMIT,
    report_sha256: reportSha256,
  };
  const evidenceCommit = "d".repeat(40);
  const startEvent = {
    event_id: "e".repeat(64),
    payload: {
      type: "CHECKPOINT",
      task_id: "event-start",
      parent_event_ids: [],
      content_sha256: reportSha256,
    },
  };
  const recovered = selectRecoverableBaseline({
    startEvent,
    candidates: [{
      evidence_commit: evidenceCommit,
      report,
      status,
      config: input.config,
    }],
    config: input.config,
  });
  assert.deepEqual(recovered, {
    source_commit: COMMIT,
    evidence_commit: evidenceCommit,
    report_sha256: reportSha256,
  });

  assert.throws(() => selectRecoverableBaseline({
    startEvent,
    candidates: [
      { evidence_commit: evidenceCommit, report, status, config: input.config },
      { evidence_commit: "f".repeat(40), report, status, config: input.config },
    ],
    config: input.config,
  }), /multiple baseline commits/u);
});

test("launch input gate requires active, fresh, commit-bound public evidence", () => {
  const input = fixture();
  const assessed = assessLaunchInputs({
    config: input.config,
    manifest: input.manifest,
    report: input.report,
    status: input.status,
    commit: COMMIT,
    now: NOW,
  });
  assert.equal(assessed.checkpoint.eligible, true);

  input.config.state = "preparation";
  assert.throws(() => assessLaunchInputs({
    config: input.config,
    manifest: input.manifest,
    report: input.report,
    status: input.status,
    commit: COMMIT,
    now: NOW,
  }), /config\.state=active/u);
});

test("start checkpoint is coordinator-signed and launch summary omits envelopes", () => {
  const input = fixture();
  const checkpoint = createLaunchCheckpoint({
    config: input.config,
    reportSha256: input.status.report_sha256,
    privateKeyPem: input.key,
    nonce: "5000",
    claimedAt: NOW.toISOString(),
  });
  const verified = verifyEnvelope(checkpoint.envelope, {
    allowedRepositories: new Set([REPOSITORY]),
    allowedTasks: new Set(input.manifest.tasks.map(task => task.id)),
    coordinatorDid: input.config.coordinator_did,
  });
  assert.equal(verified.payload.type, "CHECKPOINT");
  assert.equal(verified.payload.task_id, "event-start");
  assert.equal(verified.payload.content_sha256, input.status.report_sha256);

  const summary = publicLaunchSummary({ stage: "checkpoint", events: [checkpoint], skipped: [] });
  const serialized = JSON.stringify(summary);
  assert.deepEqual(Object.keys(summary), ["stage", "event_count", "event_ids", "skipped_event_ids"]);
  assert.equal(serialized.includes(checkpoint.envelope), false);
  assert.equal(serialized.includes("signature"), false);
  assert.equal(serialized.includes("PRIVATE KEY"), false);
});
