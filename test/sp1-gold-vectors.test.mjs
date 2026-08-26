import assert from "node:assert/strict";
import { createPrivateKey } from "node:crypto";
import test from "node:test";
import { auditEvents } from "../lib/audit.mjs";
import { deriveMessageRecord } from "../lib/collector.mjs";
import { canonicalize } from "../lib/canonical.mjs";
import { canonicalPayloadJson, createEnvelope, createPayloadScaffold, verifyEnvelope } from "../lib/protocol.mjs";

const HASH_A = "a".repeat(64);
const HASH_B = "b".repeat(64);
const COMMIT = "c".repeat(40);
const REPOSITORY = "vector-lab/swarmproof-48";
const ALLOWED = { allowedRepositories: new Set([REPOSITORY]) };
const fixedSigner = createPrivateKey({
  key: Buffer.concat([
    Buffer.from("302e020100300506032b657004220420", "hex"),
    Buffer.from("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "hex"),
  ]),
  format: "der",
  type: "pkcs8",
});

function fixturePrivateKey(seedByte) {
  return createPrivateKey({
    key: Buffer.concat([
      Buffer.from("302e020100300506032b657004220420", "hex"),
      Buffer.alloc(32, seedByte),
    ]),
    format: "der",
    type: "pkcs8",
  });
}

function basePayload(overrides = {}) {
  return {
    schema: "swarmproof-event-v1",
    type: "CLAIM",
    task_id: "gold-vector",
    claimed_at: "2026-01-01T00:00:00.000Z",
    nonce: "1",
    parent_event_ids: [],
    content_sha256: HASH_A,
    ...overrides,
  };
}

function resultArtifact() {
  return {
    repository: REPOSITORY,
    commit: COMMIT,
    path: "results/vector.json",
    sha256: HASH_B,
  };
}

function payloadForType(type) {
  const payload = basePayload({ type });
  if (type === "RESULT") {
    payload.artifact = resultArtifact();
    payload.content_sha256 = payload.artifact.sha256;
  }
  if (type === "REVIEW") {
    payload.parent_event_ids = [HASH_B];
    payload.review = { target_event_id: HASH_B, verdict: "PASS" };
  }
  if (type === "PROMOTE") payload.parent_event_ids = [HASH_B];
  return payload;
}

function mutatePayload(envelope, mutate) {
  const parts = envelope.split(".");
  const payload = JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8"));
  mutate(payload);
  parts[1] = Buffer.from(canonicalize(payload), "utf8").toString("base64url");
  return parts.join(".");
}

const validVectors = ["TASK", "CLAIM", "RESULT", "REVIEW", "PROMOTE", "CHECKPOINT"];

for (const [index, type] of validVectors.entries()) {
  test(`SP1 valid gold vector ${index + 1}: ${type}`, () => {
    const created = createEnvelope(payloadForType(type), fixedSigner, ALLOWED);
    const verified = verifyEnvelope(created.envelope, ALLOWED);
    assert.equal(verified.payload.type, type);
    assert.equal(verified.event_id, created.event_id);
    assert.equal(verified.signature_valid, true);
  });
}

test("SP1 fixed conformance vector: canonical payload, signature, and event ID", () => {
  const created = createEnvelope(basePayload(), fixedSigner, ALLOWED);
  const expectedCanonical = "{\"claimed_at\":\"2026-01-01T00:00:00.000Z\",\"content_sha256\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"did\":\"did:key:z6MkehRgf7yJbgaGfYsdoAsKdBPE3dj2CYhowQdcjqSJgvVd\",\"experiment\":\"swarmproof-48-e463\",\"nonce\":\"1\",\"parent_event_ids\":[],\"schema\":\"swarmproof-event-v1\",\"task_id\":\"gold-vector\",\"type\":\"CLAIM\"}";
  assert.equal(created.canonical_payload, expectedCanonical);
  const [, payloadBase64, signatureBase64] = created.envelope.split(".");
  assert.equal(payloadBase64, Buffer.from(expectedCanonical, "utf8").toString("base64url"));
  assert.equal(signatureBase64, "TsdPaPQJxLQ4y9G_tddZsKbJM2crxtQrMVt8R6zeynuqK9uoet7GjVtrGHOB3eV6TQyy5L4SnvAne1zrhqoiCQ");
  assert.equal(created.event_id, "745aad66c17e3b40d14e1e2dbc241bc617b830c4b5807df7e23cc44092903fc2");
  assert.equal(canonicalPayloadJson(created.payload, ALLOWED), created.canonical_payload);
});

test("SP1 participant scaffold derives safe defaults without accepting identity fields", () => {
  const artifact = resultArtifact();
  const scaffold = createPayloadScaffold({
    type: "RESULT",
    task_id: "gold-vector",
    claimed_at: "2026-01-01T00:00:00.000Z",
    nonce: "42",
    parent_event_ids: [HASH_A],
    artifact,
  }, ALLOWED);
  assert.equal(scaffold.schema, "swarmproof-event-v1");
  assert.equal(scaffold.content_sha256, artifact.sha256);
  assert.equal("did" in scaffold, false);
  assert.equal("experiment" in scaffold, false);
  const signed = createEnvelope(scaffold, fixedSigner, ALLOWED);
  assert.equal(verifyEnvelope(signed.envelope, ALLOWED).signature_valid, true);
  assert.throws(
    () => createPayloadScaffold({ ...scaffold, did: signed.payload.did }, ALLOWED),
    /unknown field/u,
  );
  assert.throws(
    () => createPayloadScaffold({
      type: "CLAIM",
      task_id: "gold-vector",
      claimed_at: "2026-01-01T00:00:00.000Z",
      nonce: "43",
      content_sha256: HASH_A,
    }, ALLOWED),
    /requires exactly one/u,
  );
});

const baseline = () => createEnvelope(basePayload(), fixedSigner, ALLOWED).envelope;
const resultBaseline = () => createEnvelope(payloadForType("RESULT"), fixedSigner, ALLOWED).envelope;
const reviewBaseline = () => createEnvelope(payloadForType("REVIEW"), fixedSigner, ALLOWED).envelope;

const invalidPayloadVectors = [
  {
    name: "unknown top-level field",
    source: baseline,
    mutate: payload => { payload.free_text = "not allowed"; },
    expected: /unknown field/u,
  },
  {
    name: "unsupported schema",
    source: baseline,
    mutate: payload => { payload.schema = "swarmproof-event-v2"; },
    expected: /Unsupported payload schema/u,
  },
  {
    name: "unsupported event type",
    source: baseline,
    mutate: payload => { payload.type = "MESSAGE"; },
    expected: /Unsupported event type/u,
  },
  {
    name: "path-like task id",
    source: baseline,
    mutate: payload => { payload.task_id = "../vector"; },
    expected: /task_id is invalid/u,
  },
  {
    name: "unparseable timestamp",
    source: baseline,
    mutate: payload => { payload.claimed_at = "not-a-time"; },
    expected: /claimed_at is not canonical UTC/u,
  },
  {
    name: "non-decimal nonce",
    source: baseline,
    mutate: payload => { payload.nonce = "1e3"; },
    expected: /nonce is invalid/u,
  },
  {
    name: "duplicate parent ids",
    source: baseline,
    mutate: payload => { payload.parent_event_ids = [HASH_A, HASH_A]; },
    expected: /contains duplicates/u,
  },
  {
    name: "uppercase content digest",
    source: baseline,
    mutate: payload => { payload.content_sha256 = HASH_A.toUpperCase(); },
    expected: /content_sha256 is invalid/u,
  },
  {
    name: "RESULT without artifact",
    source: baseline,
    mutate: payload => { payload.type = "RESULT"; },
    expected: /RESULT requires artifact/u,
  },
  {
    name: "REVIEW without review object",
    source: baseline,
    mutate: payload => { payload.type = "REVIEW"; },
    expected: /REVIEW requires review/u,
  },
  {
    name: "review object on CLAIM",
    source: baseline,
    mutate: payload => { payload.review = { target_event_id: HASH_B, verdict: "PASS" }; },
    expected: /review is only allowed on REVIEW/u,
  },
  {
    name: "artifact path traversal",
    source: resultBaseline,
    mutate: payload => { payload.artifact.path = "../private/vector.json"; },
    expected: /artifact.path is invalid/u,
  },
  {
    name: "moving artifact ref",
    source: resultBaseline,
    mutate: payload => { payload.artifact.commit = "main"; },
    expected: /full lowercase commit SHA/u,
  },
  {
    name: "invalid review verdict",
    source: reviewBaseline,
    mutate: payload => { payload.review.verdict = "APPROVE"; },
    expected: /review.verdict is invalid/u,
  },
  {
    name: "unsafe .git artifact path segment",
    source: resultBaseline,
    mutate: payload => { payload.artifact.path = "results/.git/config"; },
    expected: /artifact.path is invalid/u,
  },
  {
    name: "artifact path with an empty segment",
    source: resultBaseline,
    mutate: payload => { payload.artifact.path = "results//vector.json"; },
    expected: /artifact.path is invalid/u,
  },
  {
    name: "non-canonical timestamp precision",
    source: baseline,
    mutate: payload => { payload.claimed_at = "2026-01-01T00:00:00Z"; },
    expected: /claimed_at is not canonical UTC/u,
  },
  {
    name: "nonce exceeds 19 decimal digits",
    source: baseline,
    mutate: payload => { payload.nonce = "1".repeat(20); },
    expected: /nonce is invalid/u,
  },
  {
    name: "RESULT digest differs from artifact digest",
    source: resultBaseline,
    mutate: payload => { payload.content_sha256 = HASH_A; },
    expected: /must match artifact.sha256/u,
  },
  {
    name: "REVIEW target is not a parent",
    source: reviewBaseline,
    mutate: payload => { payload.parent_event_ids = [HASH_A]; },
    expected: /must name its target as a parent/u,
  },
  {
    name: "TASK with a parent",
    source: baseline,
    mutate: payload => { payload.type = "TASK"; payload.parent_event_ids = [HASH_A]; },
    expected: /TASK cannot have a parent/u,
  },
  {
    name: "unknown artifact field",
    source: resultBaseline,
    mutate: payload => { payload.artifact.media_type = "application/json"; },
    expected: /artifact contains unknown field/u,
  },
];

for (const [index, vector] of invalidPayloadVectors.entries()) {
  test(`SP1 invalid gold vector ${index + 1}: ${vector.name}`, () => {
    const envelope = mutatePayload(vector.source(), vector.mutate);
    assert.throws(() => verifyEnvelope(envelope, ALLOWED), vector.expected);
  });
}

test(`SP1 invalid gold vector ${invalidPayloadVectors.length + 1}: non-canonical base64url`, () => {
  const parts = baseline().split(".");
  parts[1] += "=";
  assert.throws(() => verifyEnvelope(parts.join("."), ALLOWED), /not base64url/u);
});

test(`SP1 invalid gold vector ${invalidPayloadVectors.length + 2}: payload is not JSON`, () => {
  const parts = baseline().split(".");
  parts[1] = Buffer.from("{", "utf8").toString("base64url");
  assert.throws(() => verifyEnvelope(parts.join("."), ALLOWED), /not valid JSON/u);
});

test(`SP1 invalid gold vector ${invalidPayloadVectors.length + 3}: truncated signature`, () => {
  const parts = baseline().split(".");
  parts[2] = Buffer.alloc(63).toString("base64url");
  assert.throws(() => verifyEnvelope(parts.join("."), ALLOWED), /must be 64 bytes/u);
});

test(`SP1 invalid gold vector ${invalidPayloadVectors.length + 4}: signature bytes changed`, () => {
  const parts = baseline().split(".");
  const signature = Buffer.from(parts[2], "base64url");
  signature[0] ^= 1;
  parts[2] = signature.toString("base64url");
  assert.throws(() => verifyEnvelope(parts.join("."), ALLOWED), /signature is invalid/u);
});

test(`SP1 invalid gold vector ${invalidPayloadVectors.length + 5}: repository outside verifier allowlist`, () => {
  const envelope = resultBaseline();
  assert.throws(
    () => verifyEnvelope(envelope, { allowedRepositories: new Set(["vector-lab/other"]) }),
    /not allowlisted/u,
  );
});

test("SP1 adversarial stream: copies do not inflate evidence and concentrated reviews stay explicit", () => {
  const coordinatorKey = fixturePrivateKey(1);
  const authorKey = fixturePrivateKey(2);
  const concentratedReviewerKey = fixturePrivateKey(3);
  const secondReviewerKey = fixturePrivateKey(4);
  const coordinatorDid = createEnvelope(basePayload(), coordinatorKey).payload.did;
  const task = createEnvelope(payloadForType("TASK"), coordinatorKey, { ...ALLOWED, coordinatorDid });
  const resultPayload = payloadForType("RESULT");
  resultPayload.parent_event_ids = [task.event_id];
  resultPayload.claimed_at = "2026-01-01T00:01:00.000Z";
  const result = createEnvelope(resultPayload, authorKey, ALLOWED);
  const copiedPayload = {
    ...resultPayload,
    nonce: "2",
    claimed_at: "2026-01-01T00:02:00.000Z",
  };
  const copied = createEnvelope(copiedPayload, authorKey, ALLOWED);
  const reviewPayload = (verdict, nonce, claimedAt) => ({
    ...basePayload({
      type: "REVIEW",
      claimed_at: claimedAt,
      nonce,
      parent_event_ids: [result.event_id],
      content_sha256: result.payload.content_sha256,
    }),
    review: { target_event_id: result.event_id, verdict },
  });
  const reviews = [
    createEnvelope(reviewPayload("PASS", "3", "2026-01-01T00:03:00.000Z"), concentratedReviewerKey),
    createEnvelope(reviewPayload("CHANGES", "4", "2026-01-01T00:04:00.000Z"), concentratedReviewerKey),
    createEnvelope(reviewPayload("PASS", "5", "2026-01-01T00:05:00.000Z"), secondReviewerKey),
  ];
  const events = [task, result, copied, ...reviews];
  const observedTimes = [
    "2026-01-01T00:00:30.000Z",
    "2026-01-01T00:09:30.000Z",
    "2026-01-01T00:02:30.000Z",
    "2026-01-01T00:10:30.000Z",
    "2026-01-01T00:04:30.000Z",
    "2026-01-01T00:05:30.000Z",
  ];
  const records = events.map((event, index) => ({
    envelope: event.envelope,
    // Delayed polling deliberately disagrees with authoritative same-room sequence order.
    observed_at: observedTimes[index],
    source_ts: event.payload.claimed_at,
    source_room: "gold-vectors",
    source_seq: index + 1,
  }));
  const audited = auditEvents(records, {
    allowedRepositories: [REPOSITORY],
    coordinatorDid,
    startsAt: "2026-01-01T00:00:00.000Z",
    endsAt: "2026-01-03T00:00:00.000Z",
    artifactChecks: {
      [result.event_id]: { status: "pass" },
      [copied.event_id]: { status: "pass" },
    },
  });
  assert.equal(audited.report.evidence.reproducible, 1);
  assert.equal(audited.report.evidence.cross_key_reviewed, 1);
  assert.equal(audited.report.events.find(event => event.event_id === copied.event_id).evidence_level, "ATTRIBUTABLE");
  assert.deepEqual(audited.report.review_evidence.effective_cross_key_verdicts, {
    pass: 1,
    changes: 1,
    reject: 0,
  });
  assert.equal(audited.report.review_evidence.superseded_review_events, 1);
  assert.equal(audited.report.review_evidence.conflicting_reviewer_result_pairs, 1);
  assert.equal(audited.report.review_evidence.top_cross_key_reviewer_share_ppm, 500_000);
  assert.equal(audited.report.review_evidence.cross_key_reviewer_hhi_ppm, 500_000);
  assert.equal(audited.report.review_evidence.independence, "unknown");
});

test("collector gold vector 1: retains a valid SP1 envelope", () => {
  const envelope = baseline();
  const record = deriveMessageRecord("vector", {
    seq: 1,
    ts: "2026-01-01T00:00:00Z",
    from: "unsigned-transport",
    text: envelope,
  }, { protocolOptions: ALLOWED });
  assert.equal(record.protocol_envelope, envelope);
  assert.match(record.protocol_event_id, /^[0-9a-f]{64}$/u);
});

test("collector gold vector 2: rejects a malformed SP1 envelope as inert data", () => {
  const record = deriveMessageRecord("vector", {
    seq: 2,
    ts: "2026-01-01T00:00:01Z",
    from: "unsigned-transport",
    text: "SP1.invalid.invalid",
  }, { protocolOptions: ALLOWED });
  assert.equal(record.protocol_envelope, null);
  assert.equal(record.protocol_event_id, null);
  assert.equal("text" in record, false);
});

test("collector gold vector 3: applies the repository allowlist", () => {
  const envelope = resultBaseline();
  const record = deriveMessageRecord("vector", {
    seq: 3,
    ts: "2026-01-01T00:00:02Z",
    from: "unsigned-transport",
    text: envelope,
  }, { protocolOptions: { allowedRepositories: new Set(["vector-lab/other"]) } });
  assert.equal(record.protocol_envelope, null);
  assert.equal(record.protocol_event_id, null);
});

test("collector gold vector 4: never exposes a message URL", () => {
  const record = deriveMessageRecord("vector", {
    seq: 4,
    ts: "2026-01-01T00:00:03Z",
    from: "unsigned-transport",
    text: "https://invalid.example/write/path",
  });
  assert.equal("text" in record, false);
  assert.equal("url" in record, false);
  assert.match(record.message_sha256, /^[0-9a-f]{64}$/u);
});
