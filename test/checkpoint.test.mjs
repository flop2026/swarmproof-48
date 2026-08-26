import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import test from "node:test";
import { canonicalize } from "../lib/canonical.mjs";
import {
  assessCheckpointChain,
  assessCheckpointInputs,
  checkpointAgeSeconds,
  createCheckpointEnvelope,
  meaningfulCheckpointSha,
} from "../lib/checkpoint.mjs";
import { didFromPrivateKey, sha256Hex } from "../lib/crypto.mjs";
import { verifyEnvelope } from "../lib/protocol.mjs";

const NOW = new Date("2026-08-26T12:00:00.000Z");

function fixture() {
  const config = {
    state: "active",
    starts_at: "2026-08-26T00:00:00.000Z",
    ends_at: "2026-08-28T00:00:00.000Z",
    coordinator_did: "did:key:z6MkqNyQTuVH8ZqJc5HZ2M9FGDDWBmVupBrX96G3EA3J5gSw",
    official_room: "d-swarmproof-48-e463",
    repository: "flop2026/swarmproof-48",
    sample: { rooms: 200, messages_per_room: 200, network_snapshot_hours: 6 },
  };
  const report = {
    schema: "swarmproof-report-v1",
    source_event_count: 1,
    source_digest: "a".repeat(64),
    signing_keys: 1,
    evidence: { observed: 1, attributable: 1, reproducible: 0, cross_key_reviewed: 0, accepted: 0 },
    events: [{ event_id: "b".repeat(64), evidence_level: "ATTRIBUTABLE" }],
    rejected: [],
    generated_at: "2026-08-26T11:30:00.000Z",
    event_state: "active",
    unsigned_proposals_observed: 0,
    build_room: { messages_observed_in_tail: 1, collection_error: null },
    network_sample: {
      schema: "swarmproof-network-sample-v1",
      generated_at: "2026-08-26T11:29:00.000Z",
      selection: {
        rooms_requested: 200,
        rooms_returned: 200,
        messages_per_room_requested: 200,
        rooms_failed: 0,
      },
      aggregate: { messages: 5000, signing_keys: 900, exact_duplicate_share: 0.1 },
      failures: [],
    },
  };
  const status = {
    schema: "swarmproof-status-v1",
    state: "active",
    generated_at: report.generated_at,
    starts_at: config.starts_at,
    ends_at: config.ends_at,
    report_sha256: sha256Hex(canonicalize(report)),
    source_commit: "c".repeat(40),
    signing_keys: 1,
    reproducible_artifacts: 0,
    cross_key_reviews: 0,
    accepted_results: 0,
    stale_after_seconds: 2700,
  };
  return { config, report, status };
}

test("preparation state fails closed before requiring public artifacts", () => {
  assert.deepEqual(
    assessCheckpointInputs({ config: { state: "preparation" }, report: null, status: null, now: NOW }),
    { eligible: false, reason: "config_not_maintained" },
  );
});

test("daily maintenance cannot create or precede the launcher-owned event-start checkpoint", () => {
  assert.deepEqual(assessCheckpointChain([]), { eligible: false, reason: "awaiting_event_start" });
  const start = {
    event_id: "a".repeat(64),
    task_id: "event-start",
    parent_event_ids: [],
  };
  const daily = {
    event_id: "b".repeat(64),
    task_id: "daily-checkpoint",
    parent_event_ids: [start.event_id],
  };
  assert.deepEqual(assessCheckpointChain([start, daily]), { eligible: true, reason: "continuation" });
  assert.throws(() => assessCheckpointChain([daily]), /exactly one event-start/u);
  assert.throws(() => assessCheckpointChain([daily, start]), /first checkpoint/u);
  assert.throws(() => assessCheckpointChain([
    start,
    { ...daily, parent_event_ids: ["c".repeat(64)] },
  ]), /not linear/u);
  assert.equal(checkpointAgeSeconds({ posted_at: "2026-08-26T11:00:00.000Z" }, NOW), 3600);
});

test("accepts a fresh, published, full-size active snapshot", () => {
  const input = fixture();
  const assessed = assessCheckpointInputs({ ...input, now: NOW });
  assert.equal(assessed.eligible, true);
  assert.equal(assessed.report_sha256, input.status.report_sha256);
  assert.match(assessed.meaningful_sha256, /^[0-9a-f]{64}$/);
});

test("allows meaningful daily maintenance after the event is complete", () => {
  const input = fixture();
  input.config.state = "complete";
  input.report.event_state = "complete";
  input.status.state = "complete";
  input.config.ends_at = "2026-08-26T10:00:00.000Z";
  input.config.starts_at = "2026-08-24T10:00:00.000Z";
  input.status.starts_at = input.config.starts_at;
  input.status.ends_at = input.config.ends_at;
  input.report.generated_at = "2026-08-25T11:30:00.000Z";
  input.status.generated_at = input.report.generated_at;
  input.status.stale_after_seconds = 90_000;
  input.report.network_sample.generated_at = "2026-08-25T11:00:00.000Z";
  input.status.report_sha256 = sha256Hex(canonicalize(input.report));
  assert.equal(assessCheckpointInputs({ ...input, now: NOW }).eligible, true);
});

test("rejects an event window that is not exactly 48 hours", () => {
  const input = fixture();
  input.config.ends_at = "2026-08-29T00:00:00.000Z";
  input.status.ends_at = input.config.ends_at;
  assert.throws(() => assessCheckpointInputs({ ...input, now: NOW }), /exactly 48 hours/u);
});

test("rejects a report/status integrity mismatch", () => {
  const input = fixture();
  input.status.report_sha256 = "d".repeat(64);
  assert.throws(
    () => assessCheckpointInputs({ ...input, now: NOW }),
    /does not match report\.json/u,
  );
});

test("skips a sample that was not collected at the configured request size", () => {
  const input = fixture();
  input.report.network_sample.selection.rooms_requested = 3;
  input.status.report_sha256 = sha256Hex(canonicalize(input.report));
  assert.equal(assessCheckpointInputs({ ...input, now: NOW }).reason, "network_sample_incomplete");
});

test("skips a partial or failed network sample", () => {
  const partial = fixture();
  partial.report.network_sample.selection.rooms_returned = 199;
  partial.status.report_sha256 = sha256Hex(canonicalize(partial.report));
  assert.equal(assessCheckpointInputs({ ...partial, now: NOW }).reason, "network_sample_incomplete");

  const failed = fixture();
  failed.report.network_sample.selection.rooms_failed = 1;
  failed.report.network_sample.failures = [{ room_sha256: "f".repeat(64), reason: "read_failed" }];
  failed.status.report_sha256 = sha256Hex(canonicalize(failed.report));
  assert.equal(assessCheckpointInputs({ ...failed, now: NOW }).reason, "network_sample_incomplete");
});

test("skips a network sample older than the configured cadence plus grace", () => {
  const input = fixture();
  input.report.network_sample.generated_at = "2026-08-26T05:00:00.000Z";
  input.status.report_sha256 = sha256Hex(canonicalize(input.report));
  assert.equal(assessCheckpointInputs({ ...input, now: NOW }).reason, "network_sample_stale");
});

test("generation timestamps alone do not create a meaningful change", () => {
  const first = fixture();
  const second = structuredClone(first);
  second.report.generated_at = "2026-08-26T11:45:00.000Z";
  second.report.network_sample.generated_at = "2026-08-26T11:44:00.000Z";
  assert.equal(
    meaningfulCheckpointSha(first.config, first.report),
    meaningfulCheckpointSha(second.config, second.report),
  );
});

test("creates a verifiable CHECKPOINT whose content hash is the public report hash", () => {
  const input = fixture();
  const { privateKey } = generateKeyPairSync("ed25519");
  const pem = privateKey.export({ format: "pem", type: "pkcs8" });
  input.config.coordinator_did = didFromPrivateKey(pem);
  const created = createCheckpointEnvelope({
    config: input.config,
    reportSha256: input.status.report_sha256,
    privateKeyPem: pem,
    nonce: "1234567890",
    claimedAt: NOW.toISOString(),
  });
  const verified = verifyEnvelope(created.envelope);
  assert.equal(verified.payload.type, "CHECKPOINT");
  assert.equal(verified.payload.task_id, "event-start");
  assert.equal(verified.payload.content_sha256, input.status.report_sha256);
});

test("refuses to create a checkpoint with a key from another DID", () => {
  const input = fixture();
  const { privateKey } = generateKeyPairSync("ed25519");
  const pem = privateKey.export({ format: "pem", type: "pkcs8" });
  assert.throws(() => createCheckpointEnvelope({
    config: input.config,
    reportSha256: input.status.report_sha256,
    privateKeyPem: pem,
    nonce: "1234567890",
    claimedAt: NOW.toISOString(),
  }), /(?:does not match the coordinator DID|requires the configured coordinator DID)/u);
});
