import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import test from "node:test";
import { deriveMessageRecord } from "../lib/collector.mjs";
import { canonicalize } from "../lib/canonical.mjs";
import { createEnvelope, verifyEnvelope } from "../lib/protocol.mjs";

const HASH_A = "a".repeat(64);
const HASH_B = "b".repeat(64);
const COMMIT = "c".repeat(40);
const REPOSITORY = "vector-lab/swarmproof-48";
const ALLOWED = { allowedRepositories: new Set([REPOSITORY]) };
const { privateKey } = generateKeyPairSync("ed25519");

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
    const created = createEnvelope(payloadForType(type), privateKey, ALLOWED);
    const verified = verifyEnvelope(created.envelope, ALLOWED);
    assert.equal(verified.payload.type, type);
    assert.equal(verified.event_id, created.event_id);
    assert.equal(verified.signature_valid, true);
  });
}

const baseline = () => createEnvelope(basePayload(), privateKey, ALLOWED).envelope;
const resultBaseline = () => createEnvelope(payloadForType("RESULT"), privateKey, ALLOWED).envelope;
const reviewBaseline = () => createEnvelope(payloadForType("REVIEW"), privateKey, ALLOWED).envelope;

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
];

for (const [index, vector] of invalidPayloadVectors.entries()) {
  test(`SP1 invalid gold vector ${index + 1}: ${vector.name}`, () => {
    const envelope = mutatePayload(vector.source(), vector.mutate);
    assert.throws(() => verifyEnvelope(envelope, ALLOWED), vector.expected);
  });
}

test("SP1 invalid gold vector 15: non-canonical base64url", () => {
  const parts = baseline().split(".");
  parts[1] += "=";
  assert.throws(() => verifyEnvelope(parts.join("."), ALLOWED), /not base64url/u);
});

test("SP1 invalid gold vector 16: payload is not JSON", () => {
  const parts = baseline().split(".");
  parts[1] = Buffer.from("{", "utf8").toString("base64url");
  assert.throws(() => verifyEnvelope(parts.join("."), ALLOWED), /not valid JSON/u);
});

test("SP1 invalid gold vector 17: truncated signature", () => {
  const parts = baseline().split(".");
  parts[2] = Buffer.alloc(63).toString("base64url");
  assert.throws(() => verifyEnvelope(parts.join("."), ALLOWED), /must be 64 bytes/u);
});

test("SP1 invalid gold vector 18: signature bytes changed", () => {
  const parts = baseline().split(".");
  const signature = Buffer.from(parts[2], "base64url");
  signature[0] ^= 1;
  parts[2] = signature.toString("base64url");
  assert.throws(() => verifyEnvelope(parts.join("."), ALLOWED), /signature is invalid/u);
});

test("SP1 invalid gold vector 19: repository outside verifier allowlist", () => {
  const envelope = resultBaseline();
  assert.throws(
    () => verifyEnvelope(envelope, { allowedRepositories: new Set(["vector-lab/other"]) }),
    /not allowlisted/u,
  );
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
