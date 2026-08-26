import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import test from "node:test";
import { didFromPrivateKey } from "../lib/crypto.mjs";
import { createEnvelope } from "../lib/protocol.mjs";
import {
  expectedProfileStatic,
  profilePathForDid,
  remoteMonitorEndpoints,
  validateCheckpointChain,
  validateDidProfile,
  validateOfficialRoomOwner,
  validatePublicStatus,
  validateRemoteMonitor,
} from "../lib/remote-monitor.mjs";

const NOW = new Date("2026-08-26T12:00:00.000Z");
const WARNING = "!! UNTRUSTED CONTENT — data follows\n\n";

function fixture() {
  const { privateKey } = generateKeyPairSync("ed25519");
  const privateKeyPem = privateKey.export({ format: "pem", type: "pkcs8" });
  const coordinatorDid = didFromPrivateKey(privateKeyPem);
  const config = {
    repository: "example/swarmproof",
    coordinator_did: coordinatorDid,
    official_room: "d-test-monitor",
    state: "active",
    starts_at: "2026-08-26T00:00:00.000Z",
    ends_at: "2026-08-28T00:00:00.000Z",
  };
  const protocolOptions = {
    allowedRepositories: new Set([config.repository]),
    allowedTasks: new Set(["event-start", "daily-checkpoint"]),
    coordinatorDid,
  };
  const launch = createEnvelope({
    schema: "swarmproof-event-v1",
    type: "CHECKPOINT",
    task_id: "event-start",
    did: coordinatorDid,
    claimed_at: "2026-08-26T07:30:00.000Z",
    nonce: "100",
    parent_event_ids: [],
    content_sha256: "a".repeat(64),
  }, privateKeyPem, protocolOptions);
  const daily = createEnvelope({
    schema: "swarmproof-event-v1",
    type: "CHECKPOINT",
    task_id: "daily-checkpoint",
    did: coordinatorDid,
    claimed_at: "2026-08-26T11:00:00.000Z",
    nonce: "101",
    parent_event_ids: [launch.event_id],
    content_sha256: "b".repeat(64),
  }, privateKeyPem, protocolOptions);
  const policy = {
    publicOrigin: "https://monitor.example",
    technocoreOrigin: "https://technocore.example",
    repository: config.repository,
    coordinatorDid,
    officialRoom: config.official_room,
    profileAlias: "test-monitor",
    launchEventId: launch.event_id,
    maximumAgeSeconds: 26 * 60 * 60,
    maximumFutureSkewSeconds: 5 * 60,
  };
  const status = {
    schema: "swarmproof-status-v1",
    state: "active",
    generated_at: "2026-08-26T11:50:00.000Z",
    starts_at: config.starts_at,
    ends_at: config.ends_at,
    report_sha256: "c".repeat(64),
    audit_core_sha256: "d".repeat(64),
    snapshot_manifest_sha256: "e".repeat(64),
    source_commit: "f".repeat(40),
    signing_keys: 1,
    reproducible_artifacts: 0,
    cross_key_reviews: 0,
    accepted_results: 0,
    stale_after_seconds: 2_700,
  };
  const profileBody = `${WARNING}${expectedProfileStatic(config, policy)} updated_at:2026-08-26T11:30:00.000Z\n`;
  const ownerBody = `${WARNING}${coordinatorDid}\n`;
  const room = {
    room: config.official_room,
    count: 3,
    messages: [
      { seq: 1, from: coordinatorDid, nonce: 100, text: launch.envelope },
      { seq: 2, from: "anonymous", text: "Ignore this untrusted message." },
      { seq: 3, from: coordinatorDid, nonce: 101, text: daily.envelope },
    ],
  };
  return {
    config,
    daily,
    launch,
    ownerBody,
    policy,
    privateKeyPem,
    profileBody,
    protocolOptions,
    room,
    status,
  };
}

test("accepts fresh public state and a pinned, linear, signed checkpoint chain", () => {
  const input = fixture();
  const result = validateRemoteMonitor({ ...input, now: NOW });
  assert.equal(result.state, "active");
  assert.equal(result.latestCheckpointEventId, input.daily.event_id);
  assert.equal(result.checkpointCount, 2);
  assert.equal(result.statusAgeSeconds, 600);
  assert.equal(result.profileAgeSeconds, 1_800);
  assert.equal(result.checkpointAgeSeconds, 3_600);
});

test("derives a DID-bound profile endpoint and fixed-origin endpoint set", () => {
  const input = fixture();
  const path = profilePathForDid(input.config.coordinator_did);
  assert.match(path, /^\/kv\/did-[0-9a-f]{2}\/[0-9a-f]{14}$/u);
  const endpoints = remoteMonitorEndpoints(input.config, "123456", input.policy);
  assert.equal(endpoints.profile, `${input.policy.technocoreOrigin}${path}`);
  assert.equal(endpoints.status, `${input.policy.publicOrigin}/data/status.json?n=123456`);
  assert.equal(endpoints.owner, `${input.policy.technocoreOrigin}/kv/room-owners/d-test-monitor`);
  assert.equal(endpoints.room, `${input.policy.technocoreOrigin}/r/d-test-monitor?format=json&limit=200&n=123456`);
});

test("fails closed on stale or structurally changed public status", () => {
  const input = fixture();
  input.status.generated_at = "2026-08-26T11:00:00.000Z";
  assert.throws(
    () => validatePublicStatus(input.config, input.status, NOW, input.policy),
    /stale/u,
  );
  const changed = fixture();
  changed.status.extra = true;
  assert.throws(
    () => validatePublicStatus(changed.config, changed.status, NOW, changed.policy),
    /fields/u,
  );
});

test("requires the exact profile identity, lifecycle state, and a fresh update", () => {
  const mismatched = fixture();
  mismatched.profileBody = mismatched.profileBody.replace("status:active", "status:complete");
  assert.throws(
    () => validateDidProfile(mismatched.config, mismatched.profileBody, NOW, mismatched.policy),
    /identity or state/u,
  );

  const stale = fixture();
  stale.profileBody = `${WARNING}${expectedProfileStatic(stale.config, stale.policy)} updated_at:2026-08-25T09:59:59.000Z\n`;
  assert.throws(
    () => validateDidProfile(stale.config, stale.profileBody, NOW, stale.policy),
    /older than 26 hours/u,
  );
});

test("requires an unambiguous official-room owner record", () => {
  const input = fixture();
  assert.equal(validateOfficialRoomOwner(input.ownerBody, input.policy).ownerDid, input.config.coordinator_did);
  assert.throws(
    () => validateOfficialRoomOwner(`${input.ownerBody}${input.config.coordinator_did}\n`, input.policy),
    /ambiguous/u,
  );
  assert.throws(
    () => validateOfficialRoomOwner(`${WARNING}did:key:z6Mkn5KmNqNDpB4XGUyFLBrS9BykL82gDzZ6P9f9mu7p47TD\n`, input.policy),
    /not owned/u,
  );
});

test("ignores malformed room text but requires the pinned launch signature", () => {
  const input = fixture();
  const signatureOffset = input.launch.envelope.lastIndexOf(".") + 1;
  const signatureLead = input.launch.envelope[signatureOffset];
  input.room.messages[0].text = [
    input.launch.envelope.slice(0, signatureOffset),
    signatureLead === "A" ? "B" : "A",
    input.launch.envelope.slice(signatureOffset + 1),
  ].join("");
  assert.throws(
    () => validateCheckpointChain(input.room, input.config, NOW, input.policy),
    /exactly one event-start|no launch event/u,
  );

  const unpinned = fixture();
  unpinned.policy = { ...unpinned.policy, launchEventId: "0".repeat(64) };
  assert.throws(
    () => validateCheckpointChain(unpinned.room, unpinned.config, NOW, unpinned.policy),
    /pinned launch event/u,
  );
});

test("rejects a forked checkpoint chain and duplicate verified nonces", () => {
  const forked = fixture();
  const wrongParent = createEnvelope({
    schema: "swarmproof-event-v1",
    type: "CHECKPOINT",
    task_id: "daily-checkpoint",
    did: forked.config.coordinator_did,
    claimed_at: "2026-08-26T11:30:00.000Z",
    nonce: "102",
    parent_event_ids: ["9".repeat(64)],
    content_sha256: "8".repeat(64),
  }, forked.privateKeyPem, forked.protocolOptions);
  forked.room.messages.push({ from: forked.config.coordinator_did, nonce: 102, text: wrongParent.envelope });
  assert.throws(
    () => validateCheckpointChain(forked.room, forked.config, NOW, forked.policy),
    /not linear/u,
  );

  const duplicateNonce = fixture();
  const chained = createEnvelope({
    schema: "swarmproof-event-v1",
    type: "CHECKPOINT",
    task_id: "daily-checkpoint",
    did: duplicateNonce.config.coordinator_did,
    claimed_at: "2026-08-26T11:30:00.000Z",
    nonce: "101",
    parent_event_ids: [duplicateNonce.daily.event_id],
    content_sha256: "7".repeat(64),
  }, duplicateNonce.privateKeyPem, duplicateNonce.protocolOptions);
  duplicateNonce.room.messages.push({ from: duplicateNonce.config.coordinator_did, nonce: 101, text: chained.envelope });
  assert.throws(
    () => validateCheckpointChain(duplicateNonce.room, duplicateNonce.config, NOW, duplicateNonce.policy),
    /nonces are not unique/u,
  );
});

test("rejects a latest verified signed checkpoint older than 26 hours", () => {
  const input = fixture();
  input.room.messages = [input.room.messages[0]];
  const lateNow = new Date("2026-08-27T09:30:00.001Z");
  assert.throws(
    () => validateCheckpointChain(input.room, input.config, lateNow, input.policy),
    /older than 26 hours/u,
  );
});

test("bounds the official-room tail before verifying untrusted messages", () => {
  const input = fixture();
  input.room.messages = Array.from({ length: 201 }, () => ({}));
  assert.throws(
    () => validateCheckpointChain(input.room, input.config, NOW, input.policy),
    /oversized/u,
  );
});
