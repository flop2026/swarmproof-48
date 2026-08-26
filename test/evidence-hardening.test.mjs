import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import test from "node:test";
import { mergeProtocolRecords } from "../lib/archive.mjs";
import { auditEvents } from "../lib/audit.mjs";
import { didFromPrivateKey, sha256Hex } from "../lib/crypto.mjs";
import { selectArtifactCandidates } from "../lib/evidence.mjs";
import { createEnvelope } from "../lib/protocol.mjs";

const REPOSITORY = "flop2026/swarmproof-48";
const COMMIT = "c".repeat(40);
const ROOM = "swarmproof-48-e463";
const START = "2026-08-26T00:00:00.000Z";
const END = "2026-08-28T00:00:00.000Z";

function privatePem() {
  const { privateKey } = generateKeyPairSync("ed25519");
  return privateKey.export({ format: "pem", type: "pkcs8" });
}

function payload(type, taskId, claimedAt, nonce, overrides = {}) {
  return {
    schema: "swarmproof-event-v1",
    type,
    task_id: taskId,
    claimed_at: claimedAt,
    nonce: String(nonce),
    parent_event_ids: [],
    content_sha256: sha256Hex(`${type}:${taskId}:${nonce}`),
    ...overrides,
  };
}

function resultPayload(taskId, claimedAt, nonce, parentId, hash, path = `results/${nonce}.json`) {
  return payload("RESULT", taskId, claimedAt, nonce, {
    parent_event_ids: parentId ? [parentId] : [],
    content_sha256: hash,
    artifact: { repository: REPOSITORY, commit: COMMIT, path, sha256: hash },
  });
}

function record(event, seq, sourceTs = "2026-08-26T00:30:00.000Z", observedAt = "2026-08-26T00:31:00.000Z") {
  return {
    envelope: event.envelope,
    observed_at: observedAt,
    source_ts: sourceTs,
    source_room: ROOM,
    source_seq: seq,
  };
}

function protocolOptions(coordinatorDid) {
  return {
    allowedRepositories: new Set([REPOSITORY]),
    coordinatorDid,
  };
}

test("nonce and cross-task copies of one artifact tuple cannot inflate reproducibility or artifact slots", () => {
  const coordinatorKey = privatePem();
  const authorKey = privatePem();
  const coordinatorDid = didFromPrivateKey(coordinatorKey);
  const task = createEnvelope(payload("TASK", "collector", "2026-08-26T00:00:00.000Z", 1), coordinatorKey, { coordinatorDid });
  const otherTask = createEnvelope(payload("TASK", "protocol", "2026-08-26T00:00:00.000Z", 4), coordinatorKey, { coordinatorDid });
  const hash = "a".repeat(64);
  const first = createEnvelope(resultPayload("collector", "2026-08-26T00:10:00.000Z", 2, task.event_id, hash, "results/shared.json"), authorKey);
  const duplicate = createEnvelope(resultPayload("collector", "2026-08-26T00:11:00.000Z", 3, task.event_id, hash, "results/shared.json"), authorKey);
  const crossTaskDuplicate = createEnvelope(resultPayload("protocol", "2026-08-26T00:12:00.000Z", 5, otherTask.event_id, hash, "results/shared.json"), authorKey);
  const records = [record(task, 1), record(otherTask, 2), record(first, 3), record(duplicate, 4), record(crossTaskDuplicate, 5)];

  const selection = selectArtifactCandidates(records, {
    protocolOptions: protocolOptions(coordinatorDid),
    startsAt: START,
    endsAt: END,
    maximumArtifacts: 64,
  });
  assert.equal(selection.eligible.length, 3);
  assert.equal(selection.unique.length, 1);
  assert.equal(selection.duplicates.length, 2);
  assert.equal(selection.selected.length, 1);
  assert.equal(selection.duplicates[0].representative.event_id, first.event_id);

  // Even a caller-supplied forged "pass" for both IDs cannot make both reproducible.
  const audited = auditEvents(records, {
    allowedRepositories: [REPOSITORY],
    coordinatorDid,
    startsAt: START,
    endsAt: END,
    artifactChecks: {
      [first.event_id]: { status: "pass" },
      [duplicate.event_id]: { status: "pass" },
      [crossTaskDuplicate.event_id]: { status: "pass" },
    },
  });
  assert.equal(audited.report.evidence.reproducible, 1);
  assert.equal(
    audited.report.events.find(event => event.event_id === duplicate.event_id).evidence_level,
    "ATTRIBUTABLE",
  );
  assert.equal(
    audited.report.events.find(event => event.event_id === crossTaskDuplicate.event_id).evidence_level,
    "ATTRIBUTABLE",
  );
  assert.ok(audited.report.semantically_ignored.some(entry => (
    entry.event_id === duplicate.event_id && entry.reason === "duplicate-result-artifact"
  )));
});

test("RESULT content digest must bind the exact artifact digest", () => {
  const key = privatePem();
  assert.throws(() => createEnvelope(payload("RESULT", "collector", "2026-08-26T00:10:00.000Z", 6, {
    parent_event_ids: ["1".repeat(64)],
    content_sha256: "2".repeat(64),
    artifact: {
      repository: REPOSITORY,
      commit: COMMIT,
      path: "results/mismatch.json",
      sha256: "3".repeat(64),
    },
  }), key), /content_sha256 must match artifact\.sha256/u);
});

test("RESULT and REVIEW evidence requires a matching, ordered coordinator TASK ancestry", () => {
  const coordinatorKey = privatePem();
  const authorKey = privatePem();
  const otherKey = privatePem();
  const coordinatorDid = didFromPrivateKey(coordinatorKey);
  const task = createEnvelope(payload("TASK", "protocol", "2026-08-26T00:00:00.000Z", 10), coordinatorKey, { coordinatorDid });
  const claim = createEnvelope(payload("CLAIM", "protocol", "2026-08-26T00:05:00.000Z", 11, {
    parent_event_ids: [task.event_id],
  }), authorKey);
  const hash = "b".repeat(64);
  const resultViaClaim = createEnvelope(resultPayload("protocol", "2026-08-26T00:10:00.000Z", 12, claim.event_id, hash), authorKey);
  const emptyParent = createEnvelope(resultPayload("protocol", "2026-08-26T00:10:00.000Z", 13, null, "d".repeat(64)), authorKey);
  const stolenClaim = createEnvelope(resultPayload("protocol", "2026-08-26T00:10:00.000Z", 14, claim.event_id, "e".repeat(64)), otherKey);
  const review = createEnvelope(payload("REVIEW", "protocol", "2026-08-26T00:20:00.000Z", 15, {
    parent_event_ids: [resultViaClaim.event_id],
    content_sha256: hash,
    review: { target_event_id: resultViaClaim.event_id, verdict: "PASS" },
  }), otherKey);
  const records = [
    record(task, 1),
    record(claim, 2),
    record(resultViaClaim, 3),
    record(emptyParent, 4),
    record(stolenClaim, 5),
    record(review, 6),
  ];
  const audited = auditEvents(records, {
    allowedRepositories: [REPOSITORY],
    coordinatorDid,
    startsAt: START,
    endsAt: END,
    artifactChecks: {
      [resultViaClaim.event_id]: { status: "pass" },
      [emptyParent.event_id]: { status: "pass" },
      [stolenClaim.event_id]: { status: "pass" },
    },
  });
  assert.equal(audited.report.evidence.reproducible, 1);
  assert.equal(audited.report.evidence.cross_key_reviewed, 1);
  assert.equal(audited.report.events.find(event => event.event_id === resultViaClaim.event_id).evidence_level, "CROSS-KEY-REVIEWED");
  assert.equal(audited.report.events.find(event => event.event_id === emptyParent.event_id).evidence_level, "ATTRIBUTABLE");
  assert.equal(audited.report.events.find(event => event.event_id === stolenClaim.event_id).evidence_level, "ATTRIBUTABLE");
});

test("a PROMOTE signed before its cross-key PASS review cannot become retroactively accepted", () => {
  const coordinatorKey = privatePem();
  const authorKey = privatePem();
  const reviewerKey = privatePem();
  const coordinatorDid = didFromPrivateKey(coordinatorKey);
  const task = createEnvelope(payload("TASK", "replay", "2026-08-26T00:00:00.000Z", 16), coordinatorKey, { coordinatorDid });
  const hash = "7".repeat(64);
  const result = createEnvelope(resultPayload("replay", "2026-08-26T00:10:00.000Z", 17, task.event_id, hash), authorKey);
  const promote = createEnvelope(payload("PROMOTE", "replay", "2026-08-26T00:15:00.000Z", 18, {
    parent_event_ids: [result.event_id],
    content_sha256: hash,
  }), coordinatorKey, { coordinatorDid });
  const review = createEnvelope(payload("REVIEW", "replay", "2026-08-26T00:20:00.000Z", 19, {
    parent_event_ids: [result.event_id],
    content_sha256: hash,
    review: { target_event_id: result.event_id, verdict: "PASS" },
  }), reviewerKey);
  const audited = auditEvents([
    record(task, 1),
    record(result, 2),
    record(promote, 3),
    record(review, 4),
  ], {
    allowedRepositories: [REPOSITORY],
    coordinatorDid,
    startsAt: START,
    endsAt: END,
    artifactChecks: { [result.event_id]: { status: "pass" } },
  });
  assert.equal(audited.report.evidence.accepted, 0);
  assert.equal(audited.report.evidence.cross_key_reviewed, 1);
  assert.ok(audited.report.semantically_ignored.some(entry => (
    entry.event_id === promote.event_id && entry.reason === "promotion-requires-prior-cross-key-pass-review"
  )));
});

test("a pre-start transport timestamp stays ineligible when first polled after start", () => {
  const coordinatorKey = privatePem();
  const authorKey = privatePem();
  const coordinatorDid = didFromPrivateKey(coordinatorKey);
  const task = createEnvelope(payload("TASK", "verifier", "2026-08-26T00:00:00.000Z", 20), coordinatorKey, { coordinatorDid });
  const hash = "f".repeat(64);
  const prepositioned = createEnvelope(resultPayload("verifier", "2026-08-26T00:01:00.000Z", 21, task.event_id, hash), authorKey);
  const incomingAtFirstActivePoll = [
    record(task, 1, "2026-08-26T00:00:00.000Z", "2026-08-26T00:10:00.000Z"),
    record(prepositioned, 2, "2026-08-25T23:59:59.000Z", "2026-08-26T00:10:00.000Z"),
  ];
  const records = mergeProtocolRecords([], incomingAtFirstActivePoll, {
    protocolOptions: protocolOptions(coordinatorDid),
    sourceRoom: ROOM,
    coordinatorDid,
  });
  assert.equal(records.find(item => item.envelope === prepositioned.envelope).source_ts, "2026-08-25T23:59:59.000Z");
  const audited = auditEvents(records, {
    allowedRepositories: [REPOSITORY],
    coordinatorDid,
    startsAt: START,
    endsAt: END,
    artifactChecks: { [prepositioned.event_id]: { status: "pass" } },
  });
  assert.equal(audited.report.evidence.reproducible, 0);
  assert.ok(audited.report.semantically_ignored.some(entry => (
    entry.event_id === prepositioned.event_id && entry.reason === "source-time-outside-event-window"
  )));
});

test("a pre-start TASK cannot anchor post-start RESULT evidence", () => {
  const coordinatorKey = privatePem();
  const authorKey = privatePem();
  const coordinatorDid = didFromPrivateKey(coordinatorKey);
  const task = createEnvelope(payload("TASK", "audit-engine", "2026-08-25T23:59:00.000Z", 30), coordinatorKey, { coordinatorDid });
  const hash = "9".repeat(64);
  const result = createEnvelope(resultPayload("audit-engine", "2026-08-26T00:10:00.000Z", 31, task.event_id, hash), authorKey);
  const audited = auditEvents([
    record(task, 1, "2026-08-25T23:59:00.000Z"),
    record(result, 2, "2026-08-26T00:10:00.000Z"),
  ], {
    allowedRepositories: [REPOSITORY],
    coordinatorDid,
    startsAt: START,
    endsAt: END,
    artifactChecks: { [result.event_id]: { status: "pass" } },
  });
  assert.equal(audited.report.evidence.reproducible, 0);
  assert.ok(audited.report.semantically_ignored.some(entry => (
    entry.event_id === result.event_id && entry.reason === "result-parent-has-no-matching-task-ancestry"
  )));
});

test("a RESULT cannot precede its parent by signed time or same-room source sequence", () => {
  const coordinatorKey = privatePem();
  const authorKey = privatePem();
  const coordinatorDid = didFromPrivateKey(coordinatorKey);
  const lateTask = createEnvelope(payload("TASK", "methodology", "2026-08-26T00:20:00.000Z", 40), coordinatorKey, { coordinatorDid });
  const lateHash = "5".repeat(64);
  const beforeSignedParent = createEnvelope(resultPayload("methodology", "2026-08-26T00:10:00.000Z", 41, lateTask.event_id, lateHash), authorKey);
  const orderedTask = createEnvelope(payload("TASK", "observatory", "2026-08-26T00:00:00.000Z", 42), coordinatorKey, { coordinatorDid });
  const seqHash = "6".repeat(64);
  const beforeTransportParent = createEnvelope(resultPayload("observatory", "2026-08-26T00:10:00.000Z", 43, orderedTask.event_id, seqHash), authorKey);
  const audited = auditEvents([
    record(lateTask, 1),
    record(beforeSignedParent, 2),
    record(orderedTask, 10),
    record(beforeTransportParent, 9),
  ], {
    allowedRepositories: [REPOSITORY],
    coordinatorDid,
    startsAt: START,
    endsAt: END,
    artifactChecks: {
      [beforeSignedParent.event_id]: { status: "pass" },
      [beforeTransportParent.event_id]: { status: "pass" },
    },
  });
  assert.equal(audited.report.evidence.reproducible, 0);
  assert.equal(audited.report.semantically_ignored.filter(entry => entry.reason === "parent-does-not-precede-child").length, 2);
});

test("artifact selection reserves coordinator results and caps participant DID/task concentration", () => {
  const coordinatorKey = privatePem();
  const coordinatorDid = didFromPrivateKey(coordinatorKey);
  const tasks = [];
  const records = [];
  let seq = 1;
  for (let index = 0; index < 10; index += 1) {
    const task = createEnvelope(payload("TASK", `task-${index}`, "2026-08-26T00:00:00.000Z", 100 + index), coordinatorKey, { coordinatorDid });
    tasks.push(task);
    records.push(record(task, seq++));
  }
  for (let index = 0; index < 10; index += 1) {
    const hash = sha256Hex(`coordinator-${index}`);
    const result = createEnvelope(resultPayload(`task-${index}`, "2026-08-26T00:10:00.000Z", 200 + index, tasks[index].event_id, hash), coordinatorKey);
    records.push(record(result, seq++));
  }
  for (let signer = 0; signer < 30; signer += 1) {
    const key = privatePem();
    for (let item = 0; item < 3; item += 1) {
      const taskIndex = (signer + item) % tasks.length;
      const hash = sha256Hex(`participant-${signer}-${item}`);
      const result = createEnvelope(resultPayload(`task-${taskIndex}`, "2026-08-26T00:20:00.000Z", 1000 + signer * 3 + item, tasks[taskIndex].event_id, hash), key);
      records.push(record(result, seq++));
    }
  }
  const selection = selectArtifactCandidates(records, {
    protocolOptions: protocolOptions(coordinatorDid),
    startsAt: START,
    endsAt: END,
  });
  const selectedCoordinator = selection.selected.filter(event => event.payload.did === coordinatorDid);
  assert.equal(selectedCoordinator.length, 8);
  const countsByDid = new Map();
  const countsByTask = new Map();
  for (const event of selection.selected) {
    if (event.payload.did !== coordinatorDid) {
      countsByDid.set(event.payload.did, (countsByDid.get(event.payload.did) ?? 0) + 1);
    }
    countsByTask.set(event.payload.task_id, (countsByTask.get(event.payload.task_id) ?? 0) + 1);
  }
  assert.ok([...countsByDid.values()].every(count => count <= 2));
  assert.ok([...countsByTask.values()].every(count => count <= 8));
  assert.ok(selection.selected.length <= 64);
});

test("archive follows newest activity while preserving coordinator control capacity", () => {
  const coordinatorKey = privatePem();
  const participantKey = privatePem();
  const coordinatorDid = didFromPrivateKey(coordinatorKey);
  const options = protocolOptions(coordinatorDid);
  const controls = [];
  const participants = [];
  for (let index = 0; index < 4; index += 1) {
    controls.push(createEnvelope(payload("TASK", `control-${index}`, "2026-08-26T00:00:00.000Z", 2000 + index), coordinatorKey, { coordinatorDid }));
  }
  for (let index = 0; index < 15; index += 1) {
    participants.push(createEnvelope(payload("CLAIM", "collector", "2026-08-26T00:10:00.000Z", 3000 + index), participantKey));
  }
  const all = [...controls, ...participants].map((event, index) => record(
    event,
    index + 1,
    `2026-08-26T00:${String(index + 1).padStart(2, "0")}:00.000Z`,
    `2026-08-26T01:${String(index + 1).padStart(2, "0")}:00.000Z`,
  ));
  const merged = mergeProtocolRecords([], all, {
    protocolOptions: options,
    sourceRoom: ROOM,
    coordinatorDid,
    maximum: 12,
    coordinatorControlReservation: 4,
  });
  const retained = new Set(merged.map(item => item.envelope));
  assert.ok(controls.every(event => retained.has(event.envelope)));
  assert.equal(participants.filter(event => retained.has(event.envelope)).length, 8);
  assert.ok(participants.slice(-8).every(event => retained.has(event.envelope)));
  assert.ok(participants.slice(0, 7).every(event => !retained.has(event.envelope)));
  assert.ok(merged.every(item => Object.hasOwn(item, "source_ts")));
});

test("duplicate envelope observations merge earliest poll time independently from source metadata", () => {
  const coordinatorKey = privatePem();
  const participantKey = privatePem();
  const coordinatorDid = didFromPrivateKey(coordinatorKey);
  const options = protocolOptions(coordinatorDid);
  const repaired = createEnvelope(payload("CLAIM", "collector", "2026-08-26T00:01:00.000Z", 4000), participantKey);
  const minimumSeq = createEnvelope(payload("CLAIM", "protocol", "2026-08-26T00:01:00.000Z", 4001), participantKey);
  const conflict = createEnvelope(payload("CLAIM", "verifier", "2026-08-26T00:01:00.000Z", 4002), participantKey);
  const observations = [
    record(repaired, null, null, "2026-08-26T00:10:00.000Z"),
    record(repaired, 7, "2026-08-26T00:07:00.000Z", "2026-08-26T00:20:00.000Z"),
    record(minimumSeq, 12, "2026-08-26T00:12:00.000Z", "2026-08-26T00:05:00.000Z"),
    record(minimumSeq, 5, "2026-08-26T00:05:00.000Z", "2026-08-26T00:30:00.000Z"),
    record(conflict, 4, "2026-08-26T00:04:00.000Z", "2026-08-26T00:40:00.000Z"),
    record(conflict, 4, "2026-08-26T00:06:00.000Z", "2026-08-26T00:50:00.000Z"),
    // The conflict must remain sticky; a third matching observation cannot erase it.
    record(conflict, 4, "2026-08-26T00:04:00.000Z", "2026-08-26T00:45:00.000Z"),
  ];
  const merged = mergeProtocolRecords([], observations, {
    protocolOptions: options,
    sourceRoom: ROOM,
    coordinatorDid,
  });
  const byEnvelope = new Map(merged.map(item => [item.envelope, item]));
  assert.deepEqual(byEnvelope.get(repaired.envelope), {
    envelope: repaired.envelope,
    observed_at: "2026-08-26T00:10:00.000Z",
    source_ts: "2026-08-26T00:07:00.000Z",
    source_room: ROOM,
    source_seq: 7,
  });
  assert.deepEqual(byEnvelope.get(minimumSeq.envelope), {
    envelope: minimumSeq.envelope,
    observed_at: "2026-08-26T00:05:00.000Z",
    source_ts: "2026-08-26T00:05:00.000Z",
    source_room: ROOM,
    source_seq: 5,
  });
  assert.deepEqual(byEnvelope.get(conflict.envelope), {
    envelope: conflict.envelope,
    observed_at: "2026-08-26T00:40:00.000Z",
    source_ts: null,
    source_room: ROOM,
    source_seq: 4,
  });
});
