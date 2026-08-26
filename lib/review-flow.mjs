import { constants as fsConstants } from "node:fs";
import { open } from "node:fs/promises";
import { canonicalize } from "./canonical.mjs";
import {
  didFromPrivateKey,
  parsePrivateKeyAndZeroInput,
  publicKeyBytesFromDid,
  sha256Hex,
  signUtf8,
  verifyUtf8,
} from "./crypto.mjs";
import {
  EXPERIMENT,
  SCHEMA,
  createEnvelope,
  createPayloadScaffold,
  validatePayload,
  verifyEnvelope,
} from "./protocol.mjs";
import {
  REVIEW_BUILD_ROOM,
  REVIEW_REPOSITORY,
  REVIEW_TECHNOCORE_ORIGIN,
  analyzedReviewRoom,
  fetchReviewRoom,
  maximumSafeRoomNonce,
  stableTargetBinding,
} from "./review.mjs";
import { launchTaskContentSha } from "./launch.mjs";
import { compareEventChronology } from "./semantics.mjs";

export const REVIEW_TARGET_PACKET_SCHEMA = "swarmproof-review-target-v1";
export const REVIEW_SIGNING_REQUEST_SCHEMA = "swarmproof-review-signing-request-v1";
export const REVIEW_TRANSPORT_SCHEMA = "swarmproof-review-transport-v1";
export const PROMOTION_MATERIAL_SCHEMA = SCHEMA;
export const REVIEW_DOCUMENT_MAX_BYTES = 1024 * 1024;

const HASH_RE = /^[0-9a-f]{64}$/u;
const COMMIT_RE = /^[0-9a-f]{40}$/u;
const NONCE_RE = /^[1-9][0-9]{0,15}$/u;
const BASE64URL_RE = /^[A-Za-z0-9_-]+$/u;
const DID_RE = /^did:key:z6Mk[1-9A-HJ-NP-Za-km-z]+$/u;
const REVIEW_RECEIPT_DOMAIN = "swarmproof-review-receipt-v1";
const EVENT_LEVELS = new Set(["REPRODUCIBLE", "CROSS-KEY-REVIEWED", "ACCEPTED"]);
const PACKET_KEYS = new Set([
  "schema", "experiment", "project", "decision", "protocol_verdict", "target",
  "snapshot", "target_binding", "limitations",
]);
const PROJECT_KEYS = new Set([
  "repository", "room", "coordinator_did", "starts_at", "ends_at",
]);
const TARGET_KEYS = new Set([
  "event_id", "envelope", "payload", "source_ts", "source_seq", "task_event_id",
  "task_envelope", "task_payload", "task_source_ts", "task_source_seq", "task_manifest_entry",
  "claim", "acceptance", "artifact_check_status", "evidence_level",
]);
const CLAIM_KEYS = new Set(["event_id", "envelope", "payload", "source_ts", "source_seq"]);
const TASK_ENTRY_REQUIRED_KEYS = new Set(["id", "title", "acceptance"]);
const TASK_ENTRY_ALLOWED_KEYS = new Set(["id", "title", "acceptance", "replay_check"]);
const SNAPSHOT_KEYS = new Set([
  "report_sha256", "snapshot_manifest_sha256", "source_commit", "evidence_commit", "generated_at",
]);
const LIMITATION_KEYS = new Set([
  "key_distinctness", "operator_independence", "review_quality", "reward_eligibility",
]);
const REQUEST_KEYS = new Set(["schema", "target_packet_sha256", "reviewer_did", "payload"]);
const TRANSPORT_KEYS = new Set([
  "schema", "target_packet_sha256", "signing_request_sha256", "room", "did", "nonce",
  "event_id", "envelope", "receipt_signature", "transport_signature",
]);
const PROMOTION_KEYS = new Set([
  "schema", "type", "task_id", "claimed_at", "nonce", "parent_event_ids", "content_sha256",
]);

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function isPlainObject(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function assertExactObject(value, keys, label) {
  assert(isPlainObject(value), `${label} must be a plain object.`);
  const actual = Object.keys(value);
  assert(actual.length === keys.size, `${label} has an invalid field set.`);
  for (const key of actual) assert(keys.has(key), `${label} contains an unknown field: ${key}`);
  for (const key of keys) assert(Object.hasOwn(value, key), `${label} is missing field: ${key}`);
}

function assertHash(value, label) {
  assert(typeof value === "string" && HASH_RE.test(value), `${label} must be a lowercase SHA-256.`);
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

function canonicalDid(value, label) {
  assert(typeof value === "string" && DID_RE.test(value), `${label} is invalid.`);
  try {
    publicKeyBytesFromDid(value);
  } catch {
    throw new Error(`${label} must be a canonical Ed25519 did:key.`);
  }
  return value;
}

function canonicalNonce(value, label) {
  assert(typeof value === "string" && NONCE_RE.test(value), `${label} must be a safe positive decimal string.`);
  const nonce = BigInt(value);
  assert(nonce > 0n && nonce <= BigInt(Number.MAX_SAFE_INTEGER), `${label} exceeds the safe transport range.`);
  return nonce;
}

function protocolOptions(packet) {
  return {
    allowedRepositories: new Set([packet.project.repository]),
    allowedTasks: new Set([packet.target.payload.task_id]),
    coordinatorDid: packet.project.coordinator_did,
  };
}

export function canonicalReviewDocument(value) {
  return `${canonicalize(value)}\n`;
}

export function reviewDocumentSha256(value) {
  return sha256Hex(canonicalReviewDocument(value));
}

export function parseCanonicalReviewDocument(text, validator, label = "Review document") {
  assert(typeof text === "string", `${label} bytes are missing.`);
  assert(Buffer.byteLength(text, "utf8") <= REVIEW_DOCUMENT_MAX_BYTES, `${label} is oversized.`);
  assert(text.endsWith("\n") && !text.endsWith("\n\n"), `${label} must end with exactly one LF.`);
  let value;
  try {
    value = JSON.parse(text);
  } catch {
    throw new Error(`${label} is not valid JSON.`);
  }
  assert(canonicalReviewDocument(value) === text, `${label} is not canonical JSON plus one LF.`);
  return validator(value);
}

function packetBinding(packet) {
  return sha256Hex(canonicalize({
    experiment: packet.experiment,
    room: packet.project.room,
    target_event_id: packet.target.event_id,
    target_author_did: packet.target.payload.did,
    task_id: packet.target.payload.task_id,
    task_event_id: packet.target.task_event_id,
    target_parent_event_id: packet.target.payload.parent_event_ids[0],
    content_sha256: packet.target.payload.content_sha256,
    artifact: packet.target.payload.artifact,
    decision: packet.decision,
    protocol_verdict: packet.protocol_verdict,
  }));
}

function reviewReceiptInput(packetSha256, requestSha256, eventId) {
  return `${REVIEW_RECEIPT_DOMAIN}|${packetSha256}|${requestSha256}|${eventId}`;
}

export function createReviewTargetPacket(context) {
  const summary = context.report.events.find(event => event?.event_id === context.target.event_id);
  assert(summary, "Target RESULT summary is missing from the replayed report.");
  const directParentId = context.target.payload.parent_event_ids[0];
  const claim = directParentId === context.task.event_id
    ? null
    : context.verified.find(event => event.event_id === directParentId);
  assert(directParentId === context.task.event_id || claim?.payload.type === "CLAIM", "Target RESULT signed ancestry is incomplete.");
  const packet = {
    schema: REVIEW_TARGET_PACKET_SCHEMA,
    experiment: EXPERIMENT,
    project: {
      repository: context.config.repository,
      room: context.config.build_room,
      coordinator_did: context.config.coordinator_did,
      starts_at: context.config.starts_at,
      ends_at: context.config.ends_at,
    },
    decision: context.decision,
    protocol_verdict: context.protocolVerdict,
    target: {
      event_id: context.target.event_id,
      envelope: context.target.envelope,
      payload: context.target.payload,
      source_ts: context.target.source_ts,
      source_seq: context.target.source_seq,
      task_event_id: context.task.event_id,
      task_envelope: context.task.envelope,
      task_payload: context.task.payload,
      task_source_ts: context.task.source_ts,
      task_source_seq: context.task.source_seq,
      task_manifest_entry: context.taskManifestEntry,
      claim: claim === null ? null : {
        event_id: claim.event_id,
        envelope: claim.envelope,
        payload: claim.payload,
        source_ts: claim.source_ts,
        source_seq: claim.source_seq,
      },
      acceptance: context.taskManifestEntry.acceptance,
      artifact_check_status: summary.artifact_check?.status ?? null,
      evidence_level: summary.evidence_level,
    },
    snapshot: {
      report_sha256: context.reportSha256,
      snapshot_manifest_sha256: context.manifestSha256,
      source_commit: context.sourceCommit,
      evidence_commit: context.evidenceCommit,
      generated_at: context.report.generated_at,
    },
    target_binding: stableTargetBinding(context),
    limitations: {
      key_distinctness: "required",
      operator_independence: "unknown",
      review_quality: "not-established-by-signature",
      reward_eligibility: "not-evaluated",
    },
  };
  return validateReviewTargetPacket(packet);
}

export function validateReviewTargetPacket(packet) {
  assertExactObject(packet, PACKET_KEYS, "Review target packet");
  assert(packet.schema === REVIEW_TARGET_PACKET_SCHEMA, "Review target packet schema is unsupported.");
  assert(packet.experiment === EXPERIMENT, "Review target packet experiment is unsupported.");
  assertExactObject(packet.project, PROJECT_KEYS, "Review target packet project");
  assert(packet.project.repository === REVIEW_REPOSITORY, "Review target packet repository is unsupported.");
  assert(packet.project.room === REVIEW_BUILD_ROOM, "Review target packet room is unsupported.");
  canonicalDid(packet.project.coordinator_did, "Review target packet coordinator DID");
  const startsAt = canonicalTime(packet.project.starts_at, "Review target packet starts_at");
  const endsAt = canonicalTime(packet.project.ends_at, "Review target packet ends_at");
  assert(endsAt - startsAt === 48 * 60 * 60 * 1000, "Review target packet event window is invalid.");
  assert(packet.decision === "PASS" || packet.decision === "FAIL", "Review target packet decision is invalid.");
  assert(
    packet.protocol_verdict === (packet.decision === "PASS" ? "PASS" : "REJECT"),
    "Review target packet protocol verdict does not match its decision.",
  );

  assertExactObject(packet.target, TARGET_KEYS, "Review target packet target");
  assertHash(packet.target.event_id, "Review target packet target event ID");
  assertHash(packet.target.task_event_id, "Review target packet TASK event ID");
  assert(typeof packet.target.envelope === "string" && packet.target.envelope.length <= 4096, "Review target packet RESULT envelope is invalid.");
  assert(typeof packet.target.task_envelope === "string" && packet.target.task_envelope.length <= 4096, "Review target packet TASK envelope is invalid.");
  assert(Number.isSafeInteger(packet.target.source_seq) && packet.target.source_seq >= 1, "Review target packet source sequence is invalid.");
  const targetSourceMs = canonicalTime(packet.target.source_ts, "Review target packet source_ts");
  assert(Number.isSafeInteger(packet.target.task_source_seq) && packet.target.task_source_seq >= 1, "Review target packet TASK source sequence is invalid.");
  const taskSourceMs = canonicalTime(packet.target.task_source_ts, "Review target packet TASK source_ts");
  const targetClaimedMs = canonicalTime(packet.target.payload.claimed_at, "Review target packet RESULT claimed_at");
  const taskClaimedMs = canonicalTime(packet.target.task_payload.claimed_at, "Review target packet TASK claimed_at");
  assert(Array.isArray(packet.target.acceptance) && packet.target.acceptance.length > 0 && packet.target.acceptance.length <= 32, "Review target packet acceptance criteria are invalid.");
  for (const criterion of packet.target.acceptance) {
    assert(typeof criterion === "string" && criterion.length > 0 && criterion.length <= 1024, "Review target packet acceptance criterion is invalid.");
  }
  assert(typeof packet.target.artifact_check_status === "string", "Review target packet artifact status is invalid.");
  assert(typeof packet.target.evidence_level === "string", "Review target packet evidence level is invalid.");
  validatePayload(packet.target.payload, protocolOptions(packet));
  validatePayload(packet.target.task_payload, protocolOptions(packet));
  const verifiedTarget = verifyEnvelope(packet.target.envelope, protocolOptions(packet));
  const verifiedTask = verifyEnvelope(packet.target.task_envelope, protocolOptions(packet));
  assert(verifiedTarget.event_id === packet.target.event_id, "Review target packet RESULT event ID does not match its signed envelope.");
  assert(verifiedTask.event_id === packet.target.task_event_id, "Review target packet TASK event ID does not match its signed envelope.");
  assert(canonicalize(verifiedTarget.payload) === canonicalize(packet.target.payload), "Review target packet RESULT payload differs from its signed envelope.");
  assert(canonicalize(verifiedTask.payload) === canonicalize(packet.target.task_payload), "Review target packet TASK payload differs from its signed envelope.");
  assert(packet.target.payload.type === "RESULT", "Review target packet target is not a RESULT.");
  assert(packet.target.task_payload.type === "TASK", "Review target packet TASK root is not a TASK.");
  assert(packet.target.task_payload.did === packet.project.coordinator_did, "Review target packet TASK root is not coordinator-signed.");
  assert(packet.target.payload.task_id === packet.target.task_payload.task_id, "Review target packet task binding is inconsistent.");
  assert(packet.target.payload.parent_event_ids.length === 1, "Review target packet RESULT parent is invalid.");
  assert(packet.target.payload.content_sha256 === packet.target.payload.artifact.sha256, "Review target packet content binding is inconsistent.");
  assert(isPlainObject(packet.target.task_manifest_entry), "Review target packet task manifest entry must be a plain object.");
  for (const key of Object.keys(packet.target.task_manifest_entry)) {
    assert(TASK_ENTRY_ALLOWED_KEYS.has(key), `Review target packet task manifest entry contains an unknown field: ${key}`);
  }
  for (const key of TASK_ENTRY_REQUIRED_KEYS) {
    assert(Object.hasOwn(packet.target.task_manifest_entry, key), `Review target packet task manifest entry is missing field: ${key}`);
  }
  assert(packet.target.task_manifest_entry.id === packet.target.payload.task_id, "Review target packet task manifest ID is inconsistent.");
  assert(typeof packet.target.task_manifest_entry.title === "string" && packet.target.task_manifest_entry.title.length >= 1 && packet.target.task_manifest_entry.title.length <= 160, "Review target packet task title is invalid.");
  assert(Array.isArray(packet.target.task_manifest_entry.acceptance) && packet.target.task_manifest_entry.acceptance.length >= 1 && packet.target.task_manifest_entry.acceptance.length <= 16, "Review target packet manifest acceptance criteria are invalid.");
  for (const criterion of packet.target.task_manifest_entry.acceptance) {
    assert(typeof criterion === "string" && criterion.length >= 1 && criterion.length <= 240, "Review target packet manifest acceptance criterion is invalid.");
  }
  if (Object.hasOwn(packet.target.task_manifest_entry, "replay_check")) {
    assert(
      canonicalize(packet.target.task_manifest_entry.replay_check) === canonicalize(["node", "--test"]),
      "Review target packet task replay check is invalid.",
    );
  }
  assert(
    packet.target.task_payload.content_sha256 === launchTaskContentSha(packet.target.task_manifest_entry),
    "Review target packet task manifest entry does not match the coordinator-signed TASK digest.",
  );
  assert(
    canonicalize(packet.target.acceptance) === canonicalize(packet.target.task_manifest_entry.acceptance),
    "Review target packet displayed acceptance criteria differ from the signed task manifest entry.",
  );
  assert(taskSourceMs <= targetSourceMs, "Review target packet TASK source time follows its RESULT.");
  assert(packet.target.task_source_seq < packet.target.source_seq, "Review target packet TASK source sequence does not precede its RESULT.");
  assert(taskClaimedMs <= targetClaimedMs, "Review target packet TASK signed time follows its RESULT.");
  assert(taskSourceMs >= startsAt && taskSourceMs <= endsAt, "Review target packet TASK source time is outside the event window.");
  assert(targetSourceMs >= startsAt && targetSourceMs <= endsAt, "Review target packet RESULT source time is outside the event window.");
  assert(taskClaimedMs >= startsAt && taskClaimedMs <= endsAt, "Review target packet TASK signed time is outside the event window.");
  assert(targetClaimedMs >= startsAt && targetClaimedMs <= endsAt, "Review target packet RESULT signed time is outside the event window.");
  assert(taskClaimedMs <= taskSourceMs + 5 * 60 * 1000, "Review target packet TASK signed time is too far after transport observation.");
  assert(targetClaimedMs <= targetSourceMs + 5 * 60 * 1000, "Review target packet RESULT signed time is too far after transport observation.");
  if (packet.target.claim === null) {
    assert(packet.target.payload.parent_event_ids[0] === packet.target.task_event_id, "Review target packet direct RESULT parent is not its TASK root.");
  } else {
    assertExactObject(packet.target.claim, CLAIM_KEYS, "Review target packet CLAIM ancestry");
    assertHash(packet.target.claim.event_id, "Review target packet CLAIM event ID");
    assert(typeof packet.target.claim.envelope === "string" && packet.target.claim.envelope.length <= 4096, "Review target packet CLAIM envelope is invalid.");
    assert(Number.isSafeInteger(packet.target.claim.source_seq) && packet.target.claim.source_seq >= 1, "Review target packet CLAIM source sequence is invalid.");
    const claimSourceMs = canonicalTime(packet.target.claim.source_ts, "Review target packet CLAIM source_ts");
    const claimClaimedMs = canonicalTime(packet.target.claim.payload.claimed_at, "Review target packet CLAIM claimed_at");
    validatePayload(packet.target.claim.payload, protocolOptions(packet));
    const verifiedClaim = verifyEnvelope(packet.target.claim.envelope, protocolOptions(packet));
    assert(verifiedClaim.event_id === packet.target.claim.event_id, "Review target packet CLAIM event ID does not match its signed envelope.");
    assert(canonicalize(verifiedClaim.payload) === canonicalize(packet.target.claim.payload), "Review target packet CLAIM payload differs from its signed envelope.");
    assert(packet.target.claim.payload.type === "CLAIM", "Review target packet intermediate ancestor is not a CLAIM.");
    assert(packet.target.payload.parent_event_ids[0] === packet.target.claim.event_id, "Review target packet RESULT does not name the included CLAIM.");
    assert(canonicalize(packet.target.claim.payload.parent_event_ids) === canonicalize([packet.target.task_event_id]), "Review target packet CLAIM does not name the TASK root.");
    assert(packet.target.claim.payload.did === packet.target.payload.did, "Review target packet CLAIM and RESULT authors differ.");
    assert(packet.target.claim.payload.task_id === packet.target.payload.task_id, "Review target packet CLAIM task binding is inconsistent.");
    assert(taskSourceMs <= claimSourceMs && claimSourceMs <= targetSourceMs, "Review target packet signed ancestry source times are out of order.");
    assert(taskClaimedMs <= claimClaimedMs && claimClaimedMs <= targetClaimedMs, "Review target packet signed ancestry claimed times are out of order.");
    assert(claimSourceMs >= startsAt && claimSourceMs <= endsAt, "Review target packet CLAIM source time is outside the event window.");
    assert(claimClaimedMs >= startsAt && claimClaimedMs <= endsAt, "Review target packet CLAIM signed time is outside the event window.");
    assert(claimClaimedMs <= claimSourceMs + 5 * 60 * 1000, "Review target packet CLAIM signed time is too far after transport observation.");
    assert(
      packet.target.task_source_seq < packet.target.claim.source_seq
        && packet.target.claim.source_seq < packet.target.source_seq,
      "Review target packet signed ancestry source sequences are out of order.",
    );
  }
  if (packet.decision === "PASS") {
    assert(packet.target.artifact_check_status === "pass", "PASS target packet requires a passing reproducibility check.");
    assert(EVENT_LEVELS.has(packet.target.evidence_level), "PASS target packet requires a reproducible evidence level.");
  }

  assertExactObject(packet.snapshot, SNAPSHOT_KEYS, "Review target packet snapshot");
  assertHash(packet.snapshot.report_sha256, "Review target packet report SHA-256");
  assertHash(packet.snapshot.snapshot_manifest_sha256, "Review target packet manifest SHA-256");
  assert(COMMIT_RE.test(packet.snapshot.source_commit ?? ""), "Review target packet source commit is invalid.");
  assert(COMMIT_RE.test(packet.snapshot.evidence_commit ?? ""), "Review target packet evidence commit is invalid.");
  canonicalTime(packet.snapshot.generated_at, "Review target packet generated_at");
  assertHash(packet.target_binding, "Review target packet target binding");
  assert(packet.target_binding === packetBinding(packet), "Review target packet binding does not replay.");

  assertExactObject(packet.limitations, LIMITATION_KEYS, "Review target packet limitations");
  assert(packet.limitations.key_distinctness === "required", "Review target packet key-distinctness limitation is invalid.");
  assert(packet.limitations.operator_independence === "unknown", "Review target packet must not claim operator independence.");
  assert(packet.limitations.review_quality === "not-established-by-signature", "Review target packet review-quality limitation is invalid.");
  assert(packet.limitations.reward_eligibility === "not-evaluated", "Review target packet must not claim reward eligibility.");
  return packet;
}

function expectedReviewPayload(packet, reviewerDid, claimedAt, nonce) {
  const scaffold = createPayloadScaffold({
    type: "REVIEW",
    task_id: packet.target.payload.task_id,
    claimed_at: claimedAt,
    nonce,
    parent_event_ids: [packet.target.event_id],
    content_sha256: packet.target.payload.content_sha256,
    review: {
      target_event_id: packet.target.event_id,
      verdict: packet.protocol_verdict,
    },
  }, { ...protocolOptions(packet), did: reviewerDid });
  return { ...scaffold, experiment: EXPERIMENT, did: reviewerDid };
}

export function createReviewSigningRequest({ packet, reviewerDid, claimedAt, nonce }) {
  validateReviewTargetPacket(packet);
  canonicalDid(reviewerDid, "Reviewer DID");
  canonicalTime(claimedAt, "Review claimed_at");
  canonicalNonce(nonce, "Review nonce");
  const request = {
    schema: REVIEW_SIGNING_REQUEST_SCHEMA,
    target_packet_sha256: reviewDocumentSha256(packet),
    reviewer_did: reviewerDid,
    payload: expectedReviewPayload(packet, reviewerDid, claimedAt, nonce),
  };
  return validateReviewSigningRequest(request, packet);
}

export function validateReviewSigningRequest(request, packet) {
  validateReviewTargetPacket(packet);
  assertExactObject(request, REQUEST_KEYS, "Review signing request");
  assert(request.schema === REVIEW_SIGNING_REQUEST_SCHEMA, "Review signing request schema is unsupported.");
  assertHash(request.target_packet_sha256, "Review signing request target-packet hash");
  assert(request.target_packet_sha256 === reviewDocumentSha256(packet), "Review signing request targets different packet bytes.");
  canonicalDid(request.reviewer_did, "Review signing request reviewer DID");
  assert(request.reviewer_did !== packet.target.payload.did, "Reviewer DID must differ from the RESULT author DID.");
  assert(request.reviewer_did !== packet.project.coordinator_did, "Reviewer DID must differ from the project controller DID.");
  validatePayload(request.payload, protocolOptions(packet));
  assert(request.payload.did === request.reviewer_did, "Review signing request DID binding is inconsistent.");
  const claimedAt = canonicalTime(request.payload.claimed_at, "Review signing request claimed_at");
  const startsAt = Date.parse(packet.project.starts_at);
  const endsAt = Date.parse(packet.project.ends_at);
  assert(claimedAt >= startsAt && claimedAt <= endsAt, "Review signing request is outside the event window.");
  assert(claimedAt >= Date.parse(packet.target.payload.claimed_at), "Review signing request predates its target RESULT.");
  assert(claimedAt >= Date.parse(packet.target.source_ts), "Review signing request predates the target transport observation.");
  canonicalNonce(request.payload.nonce, "Review signing request nonce");
  const expected = expectedReviewPayload(
    packet,
    request.reviewer_did,
    request.payload.claimed_at,
    request.payload.nonce,
  );
  assert(canonicalize(request.payload) === canonicalize(expected), "Review signing request payload does not match the target packet.");
  return request;
}

export async function readSecureReviewKeyObject(path) {
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
    if (typeof process.getuid === "function") {
      assert(metadata.uid === process.getuid(), "Private key must be owned by the current user.");
    }
    assert(metadata.size > 0 && metadata.size <= 16_384, "Private key size is invalid.");
    let bytes;
    try {
      bytes = await handle.readFile();
      assert(bytes.length > 0 && bytes.length <= 16_384, "Private key size changed during its safe read.");
      return parsePrivateKeyAndZeroInput(bytes);
    } finally {
      bytes?.fill(0);
    }
  } finally {
    await handle.close();
  }
}

export function createReviewTransport({ packet, request, privateKey }) {
  validateReviewSigningRequest(request, packet);
  const reviewerDid = didFromPrivateKey(privateKey);
  assert(reviewerDid === request.reviewer_did, "Private key does not match the review signing request DID.");
  const created = createEnvelope(request.payload, privateKey, protocolOptions(packet));
  assert(canonicalize(created.payload) === canonicalize(request.payload), "Signed REVIEW payload changed during signing.");
  const transportSignature = signUtf8(
    privateKey,
    `${packet.project.room}|${created.payload.nonce}|${created.envelope}`,
  ).toString("base64url");
  const targetPacketSha256 = reviewDocumentSha256(packet);
  const signingRequestSha256 = reviewDocumentSha256(request);
  const receiptSignature = signUtf8(
    privateKey,
    reviewReceiptInput(targetPacketSha256, signingRequestSha256, created.event_id),
  ).toString("base64url");
  const transport = {
    schema: REVIEW_TRANSPORT_SCHEMA,
    target_packet_sha256: targetPacketSha256,
    signing_request_sha256: signingRequestSha256,
    room: packet.project.room,
    did: reviewerDid,
    nonce: created.payload.nonce,
    event_id: created.event_id,
    envelope: created.envelope,
    receipt_signature: receiptSignature,
    transport_signature: transportSignature,
  };
  return validateReviewTransport(transport, packet, request);
}

export function validateReviewTransport(transport, packet, request) {
  validateReviewSigningRequest(request, packet);
  assertExactObject(transport, TRANSPORT_KEYS, "Review transport");
  assert(transport.schema === REVIEW_TRANSPORT_SCHEMA, "Review transport schema is unsupported.");
  assert(transport.target_packet_sha256 === reviewDocumentSha256(packet), "Review transport targets different packet bytes.");
  assert(transport.signing_request_sha256 === reviewDocumentSha256(request), "Review transport targets different signing-request bytes.");
  assert(transport.room === packet.project.room, "Review transport room binding is inconsistent.");
  assert(transport.did === request.reviewer_did, "Review transport DID binding is inconsistent.");
  assert(transport.nonce === request.payload.nonce, "Review transport nonce binding is inconsistent.");
  canonicalNonce(transport.nonce, "Review transport nonce");
  assertHash(transport.event_id, "Review transport event ID");
  assert(typeof transport.envelope === "string" && transport.envelope.length <= 4096, "Review transport envelope is invalid.");
  const verified = verifyEnvelope(transport.envelope, protocolOptions(packet));
  assert(verified.event_id === transport.event_id, "Review transport event ID does not match its envelope.");
  assert(canonicalize(verified.payload) === canonicalize(request.payload), "Review transport envelope does not sign the reviewed payload.");
  assert(typeof transport.receipt_signature === "string" && BASE64URL_RE.test(transport.receipt_signature), "Review receipt signature is not canonical base64url.");
  const receiptSignature = Buffer.from(transport.receipt_signature, "base64url");
  assert(receiptSignature.length === 64 && receiptSignature.toString("base64url") === transport.receipt_signature, "Review receipt signature is invalid.");
  assert(verifyUtf8(
    transport.did,
    reviewReceiptInput(transport.target_packet_sha256, transport.signing_request_sha256, transport.event_id),
    receiptSignature,
  ), "Review receipt signature verification failed.");
  assert(typeof transport.transport_signature === "string" && BASE64URL_RE.test(transport.transport_signature), "Review transport signature is not canonical base64url.");
  const signature = Buffer.from(transport.transport_signature, "base64url");
  assert(signature.length === 64 && signature.toString("base64url") === transport.transport_signature, "Review transport signature is invalid.");
  assert(verifyUtf8(
    transport.did,
    `${transport.room}|${transport.nonce}|${transport.envelope}`,
    signature,
  ), "Review transport signature verification failed.");
  return transport;
}

function assertStablePacketTarget(context, packet) {
  assert(stableTargetBinding(context) === packet.target_binding, "Public target binding changed after packet inspection; inspect again.");
  assert(context.config.coordinator_did === packet.project.coordinator_did, "Project controller changed after packet inspection.");
  const freshPacket = createReviewTargetPacket(context);
  const inspectionMaterial = value => {
    const { evidence_level: _evidenceLevel, ...stableTarget } = value.target;
    return {
      experiment: value.experiment,
      project: value.project,
      decision: value.decision,
      protocol_verdict: value.protocol_verdict,
      target: stableTarget,
      limitations: value.limitations,
    };
  };
  assert(
    canonicalize(inspectionMaterial(freshPacket)) === canonicalize(inspectionMaterial(packet)),
    "Public inspection material changed after packet inspection; inspect again.",
  );
  return freshPacket;
}

function assertFreshPacketBinding(context, packet) {
  const freshPacket = assertStablePacketTarget(context, packet);
  assert(
    canonicalize(freshPacket) === canonicalize(packet),
    "Public snapshot or evidence level changed after packet inspection; inspect and sign again.",
  );
}

function boundedText(response, maximumBytes, label) {
  return (async () => {
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
  })();
}

function reviewObservation(context, roomData, transport, observedAt) {
  const analyzed = analyzedReviewRoom(context, roomData, observedAt);
  const exact = analyzed.graph.validReviewIds.has(transport.event_id)
    ? analyzed.graph.eventById.get(transport.event_id) ?? null
    : null;
  const latest = analyzed.graph.verified
    .filter(event => (
      analyzed.graph.validReviewIds.has(event.event_id)
      && event.payload.did === transport.did
      && event.payload.review.target_event_id === context.target.event_id
    ))
    .sort(compareEventChronology)
    .at(-1) ?? null;
  const live = analyzed.liveEventIds.has(transport.event_id);
  const archived = context.verified.some(event => event.event_id === transport.event_id);
  const observed = exact && (live || archived) ? exact : null;
  return {
    observed,
    observationSource: observed ? (live ? "live-room" : "trusted-archive") : null,
    effective: observed !== null && latest?.event_id === observed.event_id,
    latest,
  };
}

function assertPostTime(context, request, now) {
  const nowMs = new Date(now).getTime();
  assert(Number.isFinite(nowMs), "Review post time is invalid.");
  assert(
    context.config.state === "active"
      && nowMs >= Date.parse(context.config.starts_at)
      && nowMs <= Date.parse(context.config.ends_at),
    "Review posting is outside the active event window.",
  );
  assert(
    Date.parse(request.payload.claimed_at) <= nowMs,
    "Review transport claimed_at is still in the future; wait before posting.",
  );
}

export async function readBackReviewTransport({
  context,
  packet,
  request,
  transport,
  fetchImpl = fetch,
  technocoreOrigin = REVIEW_TECHNOCORE_ORIGIN,
}) {
  validateReviewTransport(transport, packet, request);
  assertStablePacketTarget(context, packet);
  const roomData = await fetchReviewRoom({
    room: packet.project.room,
    fetchImpl,
    technocoreOrigin,
    cacheBust: Date.now(),
  });
  const observation = reviewObservation(context, roomData, transport, new Date());
  if (!observation.observed) {
    return {
      status: "not-observed",
      observed: null,
      effective: false,
      effectiveReview: observation.latest,
      observationSource: null,
      wroteNetwork: false,
    };
  }
  return {
    status: observation.effective ? "observed-effective" : "observed-superseded",
    observed: observation.observed,
    effective: observation.effective,
    effectiveReview: observation.latest,
    observationSource: observation.observationSource,
    wroteNetwork: false,
  };
}

export async function postReviewTransport({
  context,
  packet,
  request,
  transport,
  fetchImpl = fetch,
  technocoreOrigin = REVIEW_TECHNOCORE_ORIGIN,
  clock = () => new Date(),
}) {
  validateReviewTransport(transport, packet, request);
  assertFreshPacketBinding(context, packet);
  assertPostTime(context, request, clock());
  const origin = new URL(technocoreOrigin);
  const fixedOrigin = new URL(REVIEW_TECHNOCORE_ORIGIN);
  assert(
    origin.origin === fixedOrigin.origin
      && origin.protocol === "https:"
      && origin.pathname === "/"
      && !origin.username
      && !origin.password
      && !origin.search
      && !origin.hash,
    "Technocore origin is invalid.",
  );
  const roomData = await fetchReviewRoom({
    room: packet.project.room,
    fetchImpl,
    technocoreOrigin,
    cacheBust: Date.now(),
  });
  const initialObservation = reviewObservation(context, roomData, transport, clock());
  if (initialObservation.observed) {
    return {
      status: initialObservation.effective ? "already-observed" : "already-observed-superseded",
      observed: initialObservation.observed,
      effective: initialObservation.effective,
      effectiveReview: initialObservation.latest,
      observationSource: initialObservation.observationSource,
      wroteNetwork: false,
    };
  }
  const latest = initialObservation.latest;
  if (latest) {
    if (latest.payload.review.verdict === request.payload.review.verdict) {
      return {
        status: "equivalent-review-exists",
        observed: latest,
        effective: true,
        effectiveReview: latest,
        observationSource: context.verified.some(event => event.event_id === latest.event_id)
          ? "trusted-archive"
          : "live-room",
        wroteNetwork: false,
      };
    }
    assert(
      Date.parse(request.payload.claimed_at) >= Date.parse(latest.payload.claimed_at)
        && Date.parse(request.payload.claimed_at) >= Date.parse(latest.source_ts ?? ""),
      "The prepared verdict predates the currently effective verdict from this reviewer; inspect and prepare again.",
    );
  }
  const maximumNonce = maximumSafeRoomNonce(roomData, transport.did);
  assert(BigInt(transport.nonce) > maximumNonce, "Prepared review nonce is no longer greater than the live reviewer nonce; prepare and sign again.");
  assertPostTime(context, request, clock());

  const url = new URL(`/r/${encodeURIComponent(packet.project.room)}`, origin);
  url.searchParams.set("format", "json");
  let response = null;
  let responseText = "";
  let requestError = null;
  try {
    response = await fetchImpl(url, {
      method: "POST",
      headers: { "content-type": "application/json", accept: "application/json" },
      body: JSON.stringify({
        did: transport.did,
        sig: transport.transport_signature,
        nonce: transport.nonce,
        text: transport.envelope,
      }),
      redirect: "error",
      signal: AbortSignal.timeout(20_000),
    });
    assert(
      response.url === "" || new URL(response.url).origin === origin.origin,
      "Signed REVIEW write escaped Technocore.",
    );
    responseText = await boundedText(response, 4096, "Signed REVIEW write response");
  } catch (error) {
    requestError = error;
  }

  for (let attempt = 1; attempt <= 4; attempt += 1) {
    const observedRoom = await fetchReviewRoom({
      room: packet.project.room,
      fetchImpl,
      technocoreOrigin,
      cacheBust: `${Date.now()}-${attempt}`,
    });
    const observation = reviewObservation(context, observedRoom, transport, clock());
    if (observation.observed) {
      return {
        status: observation.effective ? "posted-and-observed" : "posted-and-observed-superseded",
        observed: observation.observed,
        effective: observation.effective,
        effectiveReview: observation.latest,
        observationSource: observation.observationSource,
        wroteNetwork: true,
      };
    }
    if (attempt < 4) await new Promise(resolve => setTimeout(resolve, attempt * 500));
  }
  if (requestError) throw new Error("Signed REVIEW outcome is unknown and read-back did not observe it.");
  throw new Error(`Signed REVIEW was not observed (HTTP ${response.status}, response SHA-256 ${sha256Hex(responseText)}).`);
}

function maximumKnownNonce(context, roomData, did) {
  let maximum = maximumSafeRoomNonce(roomData, did);
  for (const event of context.verified) {
    if (event.payload.did !== did || !NONCE_RE.test(event.payload.nonce)) continue;
    const nonce = BigInt(event.payload.nonce);
    assert(nonce <= BigInt(Number.MAX_SAFE_INTEGER), "Known project nonce exceeds the safe transport range.");
    if (nonce > maximum) maximum = nonce;
  }
  return maximum;
}

export function createPromotionMaterial({ context, roomData, reviewEventId, claimedAt, nonce }) {
  assert(context.decision === "PASS" && context.protocolVerdict === "PASS", "Promotion inspection requires a PASS target context.");
  assertHash(reviewEventId, "Qualifying REVIEW event ID");
  const claimedMs = canonicalTime(claimedAt, "Promotion claimed_at");
  const promotionNonce = canonicalNonce(nonce, "Promotion nonce");
  const { graph } = analyzedReviewRoom(context, roomData, new Date());
  const review = graph.eventById.get(reviewEventId);
  assert(review?.payload.type === "REVIEW" && graph.validReviewIds.has(reviewEventId), "Qualifying REVIEW is not a valid observed project REVIEW.");
  assert(review.payload.review.target_event_id === context.target.event_id, "Qualifying REVIEW targets a different RESULT.");
  assert(review.payload.review.verdict === "PASS", "Qualifying REVIEW verdict is not PASS.");
  assert(review.payload.did !== context.target.payload.did, "Qualifying REVIEW must use a DID different from the RESULT author.");
  assert(review.payload.did !== context.config.coordinator_did, "Qualifying REVIEW must use a DID different from the project controller.");
  assert(review.source_room === context.config.build_room && Number.isSafeInteger(review.source_seq) && review.source_seq >= 1, "Qualifying REVIEW lacks authoritative room ordering.");
  canonicalTime(review.source_ts, "Qualifying REVIEW source_ts");
  const latest = graph.verified
    .filter(event => (
      graph.validReviewIds.has(event.event_id)
      && event.payload.did === review.payload.did
      && event.payload.review.target_event_id === context.target.event_id
    ))
    .sort(compareEventChronology)
    .at(-1);
  assert(latest?.event_id === reviewEventId, "Qualifying PASS was superseded by a later verdict from the same reviewer DID.");
  assert(!graph.promotedResultIds.has(context.target.event_id), "Target RESULT is already promoted in the observed project graph.");
  assert(claimedMs >= Date.parse(review.payload.claimed_at), "Promotion claimed_at predates the qualifying REVIEW.");
  assert(claimedMs >= Date.parse(review.source_ts), "Promotion claimed_at predates the qualifying REVIEW observation.");
  assert(claimedMs >= Date.parse(context.config.starts_at) && claimedMs <= Date.parse(context.config.ends_at), "Promotion claimed_at is outside the active event window.");
  assert(
    promotionNonce > maximumKnownNonce(context, roomData, context.config.coordinator_did),
    "Promotion nonce is not greater than the known project-controller nonce.",
  );
  const material = {
    schema: PROMOTION_MATERIAL_SCHEMA,
    type: "PROMOTE",
    task_id: context.target.payload.task_id,
    claimed_at: claimedAt,
    nonce,
    parent_event_ids: [context.target.event_id],
    content_sha256: context.target.payload.content_sha256,
  };
  return {
    material: validatePromotionMaterial(material, context),
    qualifyingReview: review,
  };
}

export function validatePromotionMaterial(material, context) {
  assertExactObject(material, PROMOTION_KEYS, "Promotion material");
  assert(material.schema === SCHEMA && material.type === "PROMOTE", "Promotion material type is unsupported.");
  canonicalTime(material.claimed_at, "Promotion material claimed_at");
  canonicalNonce(material.nonce, "Promotion material nonce");
  assert(material.task_id === context.target.payload.task_id, "Promotion material task binding is inconsistent.");
  assert(canonicalize(material.parent_event_ids) === canonicalize([context.target.event_id]), "Promotion material target binding is inconsistent.");
  assert(material.content_sha256 === context.target.payload.content_sha256, "Promotion material content binding is inconsistent.");
  validatePayload({
    ...material,
    experiment: EXPERIMENT,
    did: context.config.coordinator_did,
  }, {
    allowedRepositories: new Set([context.config.repository]),
    allowedTasks: new Set(context.manifest.tasks.map(task => task.id)),
    coordinatorDid: context.config.coordinator_did,
  });
  return material;
}
