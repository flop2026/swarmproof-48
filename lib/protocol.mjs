import { randomInt } from "node:crypto";
import { readFile } from "node:fs/promises";
import { canonicalize } from "./canonical.mjs";
import { didFromPrivateKey, sha256Hex, signUtf8, verifyUtf8 } from "./crypto.mjs";

export const SCHEMA = "swarmproof-event-v1";
export const EXPERIMENT = "swarmproof-48-e463";
export const ENVELOPE_PREFIX = "SP1";
export const SIGNING_DOMAIN = `${SCHEMA}|${EXPERIMENT}`;
export const EVENT_TYPES = new Set(["TASK", "CLAIM", "RESULT", "REVIEW", "PROMOTE", "CHECKPOINT"]);
const COORDINATOR_TYPES = new Set(["TASK", "PROMOTE", "CHECKPOINT"]);
const PARTICIPANT_TYPES = new Set(["CLAIM", "RESULT", "REVIEW"]);

const DID_RE = /^did:key:z6Mk[1-9A-HJ-NP-Za-km-z]+$/;
const HASH_RE = /^[0-9a-f]{64}$/;
const COMMIT_RE = /^[0-9a-f]{40}$/;
const NONCE_RE = /^[0-9]{1,19}$/;
const TASK_RE = /^[a-z0-9][a-z0-9_-]{0,63}$/;
const REPOSITORY_RE = /^[A-Za-z0-9_.-]{1,39}\/[A-Za-z0-9_.-]{1,100}$/;
const PATH_RE = /^[A-Za-z0-9._/-]{1,240}$/;
const BASE64URL_RE = /^[A-Za-z0-9_-]+$/;
const CANONICAL_TIME_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const TOP_LEVEL_KEYS = new Set([
  "schema",
  "experiment",
  "type",
  "task_id",
  "did",
  "claimed_at",
  "nonce",
  "parent_event_ids",
  "content_sha256",
  "artifact",
  "review",
]);
const SCAFFOLD_KEYS = new Set([
  "type",
  "task_id",
  "claimed_at",
  "nonce",
  "parent_event_ids",
  "content_sha256",
  "artifact",
  "review",
]);
const SCAFFOLD_VALIDATION_DID = "did:key:z6Mk11111111111111111111111111111111111111111111";

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function assertExactKeys(value, allowed, label) {
  for (const key of Object.keys(value)) {
    assert(allowed.has(key), `${label} contains unknown field: ${key}`);
  }
}

function decodeBase64UrlCanonical(value, label) {
  assert(typeof value === "string" && BASE64URL_RE.test(value), `${label} is not base64url.`);
  const decoded = Buffer.from(value, "base64url");
  assert(decoded.toString("base64url") === value, `${label} is not canonical base64url.`);
  return decoded;
}

function isSafeArtifactPath(value) {
  if (!PATH_RE.test(value ?? "") || value.startsWith("/") || value.endsWith("/")) return false;
  return value.split("/").every(segment => (
    segment.length > 0
    && segment !== "."
    && segment !== ".."
    && segment.toLowerCase() !== ".git"
  ));
}

function validateArtifact(artifact, allowedRepositories) {
  assert(artifact && typeof artifact === "object" && !Array.isArray(artifact), "artifact must be an object.");
  assertExactKeys(artifact, new Set(["repository", "commit", "path", "sha256"]), "artifact");
  assert(REPOSITORY_RE.test(artifact.repository ?? ""), "artifact.repository is invalid.");
  if (allowedRepositories) {
    assert(allowedRepositories.has(artifact.repository), "artifact.repository is not allowlisted.");
  }
  assert(COMMIT_RE.test(artifact.commit ?? ""), "artifact.commit must be a full lowercase commit SHA.");
  assert(isSafeArtifactPath(artifact.path), "artifact.path is invalid.");
  assert(HASH_RE.test(artifact.sha256 ?? ""), "artifact.sha256 is invalid.");
}

function validateReview(review) {
  assert(review && typeof review === "object" && !Array.isArray(review), "review must be an object.");
  assertExactKeys(review, new Set(["target_event_id", "verdict"]), "review");
  assert(HASH_RE.test(review.target_event_id ?? ""), "review.target_event_id is invalid.");
  assert(["PASS", "CHANGES", "REJECT"].includes(review.verdict), "review.verdict is invalid.");
}

export function validatePayload(payload, options = {}) {
  assert(payload && typeof payload === "object" && !Array.isArray(payload), "payload must be an object.");
  assertExactKeys(payload, TOP_LEVEL_KEYS, "payload");
  assert(payload.schema === SCHEMA, "Unsupported payload schema.");
  assert(payload.experiment === EXPERIMENT, "Unsupported experiment domain.");
  assert(EVENT_TYPES.has(payload.type), "Unsupported event type.");
  assert(TASK_RE.test(payload.task_id ?? ""), "task_id is invalid.");
  if (options.allowedTasks) {
    const allowedTasks = options.allowedTasks instanceof Set
      ? options.allowedTasks
      : new Set(options.allowedTasks);
    assert(allowedTasks.has(payload.task_id), "task_id is not in the signed task manifest.");
  }
  assert(DID_RE.test(payload.did ?? ""), "did is not an Ed25519 did:key.");
  assert(CANONICAL_TIME_RE.test(payload.claimed_at ?? ""), "claimed_at is not canonical UTC.");
  const claimedAt = new Date(payload.claimed_at);
  assert(!Number.isNaN(claimedAt.getTime()) && claimedAt.toISOString() === payload.claimed_at, "claimed_at is invalid.");
  assert(NONCE_RE.test(payload.nonce ?? ""), "nonce is invalid.");
  assert(Array.isArray(payload.parent_event_ids), "parent_event_ids must be an array.");
  assert(payload.parent_event_ids.length <= 16, "parent_event_ids exceeds 16 items.");
  assert(new Set(payload.parent_event_ids).size === payload.parent_event_ids.length, "parent_event_ids contains duplicates.");
  for (const parent of payload.parent_event_ids) assert(HASH_RE.test(parent), "parent_event_ids contains an invalid hash.");
  assert(HASH_RE.test(payload.content_sha256 ?? ""), "content_sha256 is invalid.");

  if (payload.artifact !== undefined) validateArtifact(payload.artifact, options.allowedRepositories);
  if (payload.review !== undefined) validateReview(payload.review);
  assert(payload.type !== "RESULT" || payload.artifact !== undefined, "RESULT requires artifact.");
  assert(payload.type === "RESULT" || payload.artifact === undefined, "artifact is only allowed on RESULT.");
  if (payload.type === "RESULT") {
    assert(payload.content_sha256 === payload.artifact.sha256, "RESULT content_sha256 must match artifact.sha256.");
  }
  assert(payload.type !== "REVIEW" || payload.review !== undefined, "REVIEW requires review.");
  assert(payload.type === "REVIEW" || payload.review === undefined, "review is only allowed on REVIEW.");
  if (payload.type === "REVIEW") {
    assert(payload.parent_event_ids.includes(payload.review.target_event_id), "REVIEW must name its target as a parent.");
  }
  if (payload.type === "PROMOTE") {
    assert(payload.parent_event_ids.length === 1, "PROMOTE requires exactly one parent result.");
  }
  if (payload.type === "CHECKPOINT") {
    assert(payload.parent_event_ids.length <= 1, "CHECKPOINT accepts at most one prior checkpoint parent.");
  }
  if (payload.type === "TASK") {
    assert(payload.parent_event_ids.length === 0, "TASK cannot have a parent event.");
  }
  if (options.coordinatorDid && COORDINATOR_TYPES.has(payload.type)) {
    assert(payload.did === options.coordinatorDid, `${payload.type} requires the configured coordinator DID.`);
  }

  return payload;
}

/**
 * Build the unsigned JSON file consumed by `swarmproof sign` for participant events.
 * The signer derives `did` from the private key and injects the experiment domain, so neither
 * identity field is accepted here. Defaults are ergonomic, while all protocol constraints are
 * checked before the scaffold is returned.
 */
export function createPayloadScaffold(input, options = {}) {
  assert(input && typeof input === "object" && !Array.isArray(input), "scaffold input must be an object.");
  assertExactKeys(input, SCAFFOLD_KEYS, "scaffold input");
  assert(PARTICIPANT_TYPES.has(input.type), "scaffold type must be CLAIM, RESULT, or REVIEW.");

  const now = input.claimed_at === undefined ? new Date(options.now ?? Date.now()) : null;
  if (now) assert(!Number.isNaN(now.getTime()), "scaffold now is invalid.");
  const claimedAt = input.claimed_at ?? now.toISOString();
  const claimedMillis = Date.parse(claimedAt);
  assert(Number.isSafeInteger(claimedMillis) && claimedMillis >= 0, "scaffold claimed_at is invalid.");
  const nonce = input.nonce ?? String(
    BigInt(claimedMillis) * 1_000_000n + BigInt(randomInt(0, 1_000_000)),
  );
  const parentEventIds = input.parent_event_ids
    ?? (input.type === "REVIEW" && input.review?.target_event_id
      ? [input.review.target_event_id]
      : []);
  const contentSha256 = input.content_sha256
    ?? (input.type === "RESULT" ? input.artifact?.sha256 : undefined);
  assert(parentEventIds.length === 1, `scaffold ${input.type} requires exactly one TASK, CLAIM, or RESULT parent.`);
  const scaffold = {
    schema: SCHEMA,
    type: input.type,
    task_id: input.task_id,
    claimed_at: claimedAt,
    nonce,
    parent_event_ids: parentEventIds,
    content_sha256: contentSha256,
    ...(input.artifact === undefined ? {} : { artifact: input.artifact }),
    ...(input.review === undefined ? {} : { review: input.review }),
  };

  validatePayload({
    ...scaffold,
    experiment: EXPERIMENT,
    did: options.did ?? SCAFFOLD_VALIDATION_DID,
  }, options);
  return scaffold;
}

export function canonicalPayloadJson(payload, options = {}) {
  validatePayload(payload, options);
  return canonicalize(payload);
}

export function encodePayload(payload, options = {}) {
  return Buffer.from(canonicalPayloadJson(payload, options), "utf8").toString("base64url");
}

export function createEnvelope(payloadInput, privateKeyPem, options = {}) {
  const did = didFromPrivateKey(privateKeyPem);
  const payload = { ...payloadInput, experiment: EXPERIMENT, did };
  const encodedPayload = encodePayload(payload, options);
  const signingInput = `${SIGNING_DOMAIN}|${encodedPayload}`;
  const signature = signUtf8(privateKeyPem, signingInput).toString("base64url");
  const envelope = `${ENVELOPE_PREFIX}.${encodedPayload}.${signature}`;
  assert(envelope.length <= 4096, "Envelope exceeds the Technocore message limit.");
  return {
    envelope,
    event_id: sha256Hex(envelope),
    payload,
    canonical_payload: canonicalPayloadJson(payload, options),
  };
}

export function verifyEnvelope(envelope, options = {}) {
  assert(typeof envelope === "string" && envelope.length <= 4096, "Envelope is invalid or oversized.");
  const parts = envelope.split(".");
  assert(parts.length === 3 && parts[0] === ENVELOPE_PREFIX, "Envelope prefix is invalid.");
  const payloadBytes = decodeBase64UrlCanonical(parts[1], "payload");
  assert(payloadBytes.length <= 3072, "Encoded payload is oversized.");
  const signature = decodeBase64UrlCanonical(parts[2], "signature");
  assert(signature.length === 64, "Ed25519 signature must be 64 bytes.");

  let payload;
  try {
    payload = JSON.parse(payloadBytes.toString("utf8"));
  } catch {
    throw new Error("Payload is not valid JSON.");
  }
  assert(canonicalize(payload) === payloadBytes.toString("utf8"), "Payload JSON is not canonical.");
  validatePayload(payload, options);
  const valid = verifyUtf8(payload.did, `${SIGNING_DOMAIN}|${parts[1]}`, signature);
  assert(valid, "Envelope signature is invalid.");
  return { envelope, event_id: sha256Hex(envelope), payload, signature_valid: true };
}

export async function createEnvelopeFromFiles(payloadPath, keyPath, options = {}) {
  const [payloadText, privateKeyPem] = await Promise.all([
    readFile(payloadPath, "utf8"),
    readFile(keyPath, "utf8"),
  ]);
  return createEnvelope(JSON.parse(payloadText), privateKeyPem, options);
}
