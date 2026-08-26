import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import test from "node:test";
import { auditEvents } from "../lib/audit.mjs";
import { canonicalize } from "../lib/canonical.mjs";
import { createEnvelope, verifyEnvelope } from "../lib/protocol.mjs";

const HASH_A = "a".repeat(64);
const HASH_B = "b".repeat(64);
const COMMIT = "c".repeat(40);
const REPOSITORY = "flop2026/swarmproof-48";

function privatePem() {
  const { privateKey } = generateKeyPairSync("ed25519");
  return privateKey.export({ format: "pem", type: "pkcs8" });
}

function basePayload(overrides = {}) {
  return {
    schema: "swarmproof-event-v1",
    type: "CLAIM",
    task_id: "collector",
    did: "did:key:z6Mkplaceholder",
    claimed_at: "2026-08-26T00:00:00.000Z",
    nonce: "1000",
    parent_event_ids: [],
    content_sha256: HASH_A,
    ...overrides,
  };
}

test("creates and verifies a self-contained SP1 envelope", () => {
  const key = privatePem();
  const created = createEnvelope(basePayload(), key, { allowedRepositories: new Set([REPOSITORY]) });
  assert.match(created.envelope, /^SP1\./u);
  assert.equal(created.event_id.length, 64);
  const verified = verifyEnvelope(created.envelope);
  assert.equal(verified.event_id, created.event_id);
  assert.equal(verified.payload.did, created.payload.did);
  assert.equal(verified.signature_valid, true);
});

test("rejects tampering and unknown payload fields", () => {
  const key = privatePem();
  const created = createEnvelope(basePayload(), key);
  const parts = created.envelope.split(".");
  const payload = JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8"));
  payload.extra = true;
  parts[1] = Buffer.from(canonicalize(payload)).toString("base64url");
  assert.throws(() => verifyEnvelope(parts.join(".")), /unknown field/u);

  const signatureTampered = `${created.envelope.slice(0, -1)}${created.envelope.endsWith("A") ? "B" : "A"}`;
  assert.throws(() => verifyEnvelope(signatureTampered), /signature/u);
});

test("rejects moving refs, path traversal, and repositories outside the allowlist", () => {
  const key = privatePem();
  const result = basePayload({
    type: "RESULT",
    artifact: {
      repository: REPOSITORY,
      commit: COMMIT,
      path: "../secret",
      sha256: HASH_B,
    },
  });
  assert.throws(() => createEnvelope(result, key), /artifact.path/u);

  result.artifact.path = "results/output.json";
  result.artifact.commit = "main";
  assert.throws(() => createEnvelope(result, key), /full lowercase commit SHA/u);

  result.artifact.commit = COMMIT;
  assert.throws(
    () => createEnvelope(result, key, { allowedRepositories: new Set(["different/repository"]) }),
    /not allowlisted/u,
  );
});

test("builds the evidence ladder without claiming reviewer independence", () => {
  const coordinatorKey = privatePem();
  const authorKey = privatePem();
  const reviewerKey = privatePem();
  const coordinatorDid = createEnvelope(basePayload(), coordinatorKey).payload.did;
  const task = createEnvelope(basePayload({
    type: "TASK",
    claimed_at: "2026-08-26T00:00:00.000Z",
    nonce: "1000",
  }), coordinatorKey, { coordinatorDid });
  const result = createEnvelope(basePayload({
    type: "RESULT",
    claimed_at: "2026-08-26T00:10:00.000Z",
    nonce: "2000",
    parent_event_ids: [task.event_id],
    content_sha256: HASH_B,
    artifact: {
      repository: REPOSITORY,
      commit: COMMIT,
      path: "results/output.json",
      sha256: HASH_B,
    },
  }), authorKey, { allowedRepositories: new Set([REPOSITORY]) });
  const review = createEnvelope(basePayload({
    type: "REVIEW",
    claimed_at: "2026-08-26T00:20:00.000Z",
    nonce: "3000",
    parent_event_ids: [result.event_id],
    content_sha256: HASH_B,
    review: { target_event_id: result.event_id, verdict: "PASS" },
  }), reviewerKey);
  const records = [task, result, review].map((event, index) => ({
    envelope: event.envelope,
    observed_at: "2026-08-26T01:00:00.000Z",
    source_room: "build",
    source_seq: index + 1,
  }));
  const audited = auditEvents(records, {
    allowedRepositories: [REPOSITORY],
    coordinatorDid,
    artifactChecks: { [result.event_id]: { status: "pass" } },
    acceptedIds: [result.event_id],
  });
  const summary = audited.report.events.find(event => event.event_id === result.event_id);
  assert.equal(summary.evidence_level, "ACCEPTED");
  assert.equal(summary.independence, "unknown");
  assert.equal(summary.cross_key_reviewers.length, 1);
  assert.equal(audited.report.evidence.cross_key_reviewed, 1);
});

test("binds privileged events to the coordinator and task manifest", () => {
  const coordinatorKey = privatePem();
  const otherKey = privatePem();
  const coordinatorDid = createEnvelope(basePayload(), coordinatorKey).payload.did;
  const unauthorizedTask = createEnvelope(basePayload({ type: "TASK" }), otherKey);
  assert.throws(
    () => verifyEnvelope(unauthorizedTask.envelope, { coordinatorDid }),
    /requires the configured coordinator DID/u,
  );
  const claim = createEnvelope(basePayload({ task_id: "unknown-task" }), otherKey);
  assert.throws(
    () => verifyEnvelope(claim.envelope, { allowedTasks: new Set(["collector"]) }),
    /signed task manifest/u,
  );
  const authorizedTask = createEnvelope(basePayload({ type: "TASK" }), coordinatorKey, {
    coordinatorDid,
    allowedTasks: new Set(["collector"]),
  });
  assert.equal(verifyEnvelope(authorizedTask.envelope, { coordinatorDid }).payload.type, "TASK");
});

test("rejects cross-project and non-canonical payload encodings", () => {
  const created = createEnvelope(basePayload(), privatePem());
  const projectParts = created.envelope.split(".");
  const projectPayload = JSON.parse(Buffer.from(projectParts[1], "base64url").toString("utf8"));
  projectPayload.experiment = "another-experiment";
  projectParts[1] = Buffer.from(canonicalize(projectPayload)).toString("base64url");
  assert.throws(() => verifyEnvelope(projectParts.join(".")), /experiment domain/u);

  const encodingParts = created.envelope.split(".");
  const encodingPayload = JSON.parse(Buffer.from(encodingParts[1], "base64url").toString("utf8"));
  encodingParts[1] = Buffer.from(JSON.stringify(encodingPayload, null, 2)).toString("base64url");
  assert.throws(() => verifyEnvelope(encodingParts.join(".")), /not canonical/u);
});

test("accepts only a matching coordinator promotion after replay and cross-key review", () => {
  const coordinatorKey = privatePem();
  const authorKey = privatePem();
  const reviewerKey = privatePem();
  const coordinatorDid = createEnvelope(basePayload(), coordinatorKey).payload.did;
  const task = createEnvelope(basePayload({
    type: "TASK",
    claimed_at: "2026-08-26T00:00:00.000Z",
    nonce: "3000",
  }), coordinatorKey, { coordinatorDid });
  const result = createEnvelope(basePayload({
    type: "RESULT",
    claimed_at: "2026-08-26T00:10:00.000Z",
    nonce: "4000",
    parent_event_ids: [task.event_id],
    content_sha256: HASH_B,
    artifact: {
      repository: REPOSITORY,
      commit: COMMIT,
      path: "results/output.json",
      sha256: HASH_B,
    },
  }), authorKey, { allowedRepositories: new Set([REPOSITORY]) });
  const review = createEnvelope(basePayload({
    type: "REVIEW",
    claimed_at: "2026-08-26T00:20:00.000Z",
    nonce: "5000",
    parent_event_ids: [result.event_id],
    content_sha256: HASH_B,
    review: { target_event_id: result.event_id, verdict: "PASS" },
  }), reviewerKey);
  const promote = createEnvelope(basePayload({
    type: "PROMOTE",
    claimed_at: "2026-08-26T00:30:00.000Z",
    nonce: "6000",
    parent_event_ids: [result.event_id],
    content_sha256: HASH_B,
  }), coordinatorKey, { coordinatorDid });
  const records = [task, result, review, promote].map((event, index) => ({
    envelope: event.envelope,
    observed_at: "2026-08-26T01:00:00.000Z",
    source_room: "build",
    source_seq: index + 1,
  }));
  const audited = auditEvents(records, {
    allowedRepositories: [REPOSITORY],
    coordinatorDid,
    artifactChecks: { [result.event_id]: { status: "pass" } },
  });
  assert.equal(
    audited.report.events.find(event => event.event_id === result.event_id).evidence_level,
    "ACCEPTED",
  );

  const mismatchedPromotion = createEnvelope(basePayload({
    type: "PROMOTE",
    claimed_at: "2026-08-26T00:30:00.000Z",
    nonce: "7000",
    parent_event_ids: [result.event_id],
    content_sha256: HASH_A,
  }), coordinatorKey, { coordinatorDid });
  const rejectedPromotionAudit = auditEvents([...records.slice(0, 3), {
    envelope: mismatchedPromotion.envelope,
    observed_at: "2026-08-26T01:00:00.000Z",
    source_room: "build",
    source_seq: 4,
  }], {
    allowedRepositories: [REPOSITORY],
    coordinatorDid,
    artifactChecks: { [result.event_id]: { status: "pass" } },
  });
  assert.equal(
    rejectedPromotionAudit.report.events.find(event => event.event_id === result.event_id).evidence_level,
    "CROSS-KEY-REVIEWED",
  );
  assert.equal(rejectedPromotionAudit.report.semantically_ignored.length, 1);
});

test("future-dated results cannot gain replay evidence", () => {
  const coordinatorKey = privatePem();
  const coordinatorDid = createEnvelope(basePayload(), coordinatorKey).payload.did;
  const task = createEnvelope(basePayload({ type: "TASK" }), coordinatorKey, { coordinatorDid });
  const future = createEnvelope(basePayload({
    type: "RESULT",
    claimed_at: "2099-01-01T00:00:00.000Z",
    parent_event_ids: [task.event_id],
    content_sha256: HASH_B,
    artifact: {
      repository: REPOSITORY,
      commit: COMMIT,
      path: "results/output.json",
      sha256: HASH_B,
    },
  }), privatePem(), { allowedRepositories: new Set([REPOSITORY]) });
  const audited = auditEvents([{
    envelope: task.envelope,
    observed_at: "2026-08-26T01:00:00.000Z",
    source_room: "build",
    source_seq: 1,
  }, {
    envelope: future.envelope,
    observed_at: "2026-08-26T01:00:00.000Z",
    source_room: "build",
    source_seq: 2,
  }], {
    allowedRepositories: [REPOSITORY],
    coordinatorDid,
    artifactChecks: { [future.event_id]: { status: "pass" } },
  });
  assert.equal(audited.report.evidence.reproducible, 0);
  assert.equal(audited.report.semantically_ignored[0].reason, "claimed-at-too-far-after-observation");
});
