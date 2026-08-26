import { createHash } from "node:crypto";
import { canonicalize } from "./canonical.mjs";
import {
  base58Encode,
  didFromPrivateKey,
  publicKeyBytesFromDid,
  signUtf8,
  verifyUtf8,
} from "./crypto.mjs";

export const CONTROL_CLAIM_SCHEMA = "swarmproof-control-claim-v1";
export const CONTROL_CLAIM_PROJECT = "swarmproof-48-e463";
export const CONTROL_CLAIM_PURPOSE = "project-resource-binding";
export const CONTROL_CLAIM_CONTROLLER = "did:key:z6MkqNyQTuVH8ZqJc5HZ2M9FGDDWBmVupBrX96G3EA3J5gSw";
export const CONTROL_CLAIM_DOMAIN = "SWARMPROOF-CONTROL-CLAIM-V1\n";
export const CONTROL_CLAIM_MAX_BYTES = 8 * 1024;
export const CONTROL_CLAIM_MAX_VALIDITY_MS = 366 * 24 * 60 * 60 * 1000;
export const CONTROL_CLAIM_CLOCK_SKEW_MS = 5 * 60 * 1000;
export const CONTROL_CLAIM_RELATIVE_PATH = "public/.well-known/swarmproof-control-claim-v1.json";

export const CONTROL_CLAIM_RESOURCES = Object.freeze([
  Object.freeze({
    type: "github-repository",
    uri: "https://github.com/flop2026/swarmproof-48",
  }),
  Object.freeze({
    type: "https-origin",
    uri: "https://swarmproof-48-e463.pages.dev",
  }),
]);

// These URLs are implementation constants rather than claim-supplied fetch targets. Keeping the
// network surface fixed prevents a signed document from turning verification into an SSRF gadget.
export const CONTROL_CLAIM_PUBLICATIONS = Object.freeze([
  Object.freeze({
    type: "github-repository",
    url: "https://raw.githubusercontent.com/flop2026/swarmproof-48/main/public/.well-known/swarmproof-control-claim-v1.json",
  }),
  Object.freeze({
    type: "https-origin",
    url: "https://swarmproof-48-e463.pages.dev/.well-known/swarmproof-control-claim-v1.json",
  }),
]);

const DOCUMENT_KEYS = new Set(["payload", "proof"]);
const PAYLOAD_KEYS = new Set([
  "schema",
  "project",
  "purpose",
  "controller",
  "issued_at",
  "expires_at",
  "resources",
]);
const RESOURCE_KEYS = new Set(["type", "uri"]);
const PROOF_KEYS = new Set(["type", "encoding", "value"]);
const BASE64URL_RE = /^[A-Za-z0-9_-]+$/u;
const CANONICAL_TIME_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u;
const ED25519_MULTICODEC = Buffer.from([0xed, 0x01]);

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

function canonicalTimeMillis(value, label) {
  assert(typeof value === "string" && CANONICAL_TIME_RE.test(value), `${label} must be canonical UTC.`);
  const milliseconds = Date.parse(value);
  assert(Number.isFinite(milliseconds) && new Date(milliseconds).toISOString() === value, `${label} is invalid.`);
  return milliseconds;
}

function canonicalEd25519Did(did, label) {
  assert(typeof did === "string", `${label} is invalid.`);
  let publicKey;
  try {
    publicKey = publicKeyBytesFromDid(did);
  } catch {
    throw new Error(`${label} must be a canonical Ed25519 did:key.`);
  }
  const canonical = `did:key:z${base58Encode(Buffer.concat([ED25519_MULTICODEC, publicKey]))}`;
  assert(did === canonical, `${label} must be a canonical Ed25519 did:key.`);
  return publicKey;
}

function decodeCanonicalBase64Url(value, label) {
  assert(typeof value === "string" && BASE64URL_RE.test(value), `${label} must be unpadded base64url.`);
  const decoded = Buffer.from(value, "base64url");
  assert(decoded.toString("base64url") === value, `${label} must be canonical base64url.`);
  return decoded;
}

function instantMillis(value, label) {
  if (typeof value === "string") {
    return canonicalTimeMillis(value, label);
  }
  const date = value instanceof Date ? value : new Date(value);
  const milliseconds = date.getTime();
  assert(Number.isFinite(milliseconds), `${label} is invalid.`);
  return milliseconds;
}

export function validateControlClaimPayload(payload, options = {}) {
  assertExactObject(payload, PAYLOAD_KEYS, "Control-claim payload");
  assert(payload.schema === CONTROL_CLAIM_SCHEMA, "Control-claim schema is unsupported.");
  assert(payload.project === CONTROL_CLAIM_PROJECT, "Control-claim project domain is invalid.");
  assert(payload.purpose === CONTROL_CLAIM_PURPOSE, "Control-claim purpose is invalid.");

  const expectedController = options.expectedController ?? CONTROL_CLAIM_CONTROLLER;
  canonicalEd25519Did(payload.controller, "Control-claim controller");
  assert(payload.controller === expectedController, "Control-claim controller is not the configured project DID.");

  const issuedAt = canonicalTimeMillis(payload.issued_at, "Control-claim issued_at");
  const expiresAt = canonicalTimeMillis(payload.expires_at, "Control-claim expires_at");
  assert(expiresAt > issuedAt, "Control-claim expires_at must be after issued_at.");
  assert(
    expiresAt - issuedAt <= CONTROL_CLAIM_MAX_VALIDITY_MS,
    "Control-claim validity exceeds 366 days.",
  );

  assert(Array.isArray(payload.resources), "Control-claim resources must be an array.");
  assert(
    payload.resources.length === CONTROL_CLAIM_RESOURCES.length,
    "Control-claim resources have an invalid length.",
  );
  payload.resources.forEach((resource, index) => {
    assertExactObject(resource, RESOURCE_KEYS, `Control-claim resource ${index + 1}`);
    const expected = CONTROL_CLAIM_RESOURCES[index];
    assert(
      resource.type === expected.type && resource.uri === expected.uri,
      `Control-claim resource ${index + 1} is not the configured resource.`,
    );
  });

  return payload;
}

export function canonicalControlClaimPayload(payload, options = {}) {
  validateControlClaimPayload(payload, options);
  return canonicalize(payload);
}

export function controlClaimSigningInput(payload, options = {}) {
  return `${CONTROL_CLAIM_DOMAIN}${canonicalControlClaimPayload(payload, options)}`;
}

export function serializeControlClaim(document, options = {}) {
  validateControlClaimDocument(document, options);
  return `${canonicalize(document)}\n`;
}

export function createControlClaim(privateKey, options = {}) {
  const issuedAtMillis = instantMillis(options.issuedAt ?? Date.now(), "Control-claim issued_at");
  const expiresAtMillis = options.expiresAt === undefined
    ? issuedAtMillis + CONTROL_CLAIM_MAX_VALIDITY_MS
    : instantMillis(options.expiresAt, "Control-claim expires_at");
  const controller = didFromPrivateKey(privateKey);
  const expectedController = options.expectedController ?? CONTROL_CLAIM_CONTROLLER;
  assert(controller === expectedController, "Private key does not match the configured project DID.");

  const payload = {
    schema: CONTROL_CLAIM_SCHEMA,
    project: CONTROL_CLAIM_PROJECT,
    purpose: CONTROL_CLAIM_PURPOSE,
    controller,
    issued_at: new Date(issuedAtMillis).toISOString(),
    expires_at: new Date(expiresAtMillis).toISOString(),
    resources: CONTROL_CLAIM_RESOURCES.map(resource => ({ ...resource })),
  };
  const proof = {
    type: "Ed25519",
    encoding: "base64url",
    value: signUtf8(privateKey, controlClaimSigningInput(payload, { expectedController })).toString("base64url"),
  };
  const document = { payload, proof };
  const serialized = serializeControlClaim(document, { expectedController });
  return {
    document,
    serialized,
    claim_sha256: createHash("sha256").update(serialized, "utf8").digest("hex"),
  };
}

export function validateControlClaimDocument(document, options = {}) {
  assertExactObject(document, DOCUMENT_KEYS, "Control-claim document");
  validateControlClaimPayload(document.payload, options);
  assertExactObject(document.proof, PROOF_KEYS, "Control-claim proof");
  assert(document.proof.type === "Ed25519", "Control-claim proof type is invalid.");
  assert(document.proof.encoding === "base64url", "Control-claim proof encoding is invalid.");
  const signature = decodeCanonicalBase64Url(document.proof.value, "Control-claim signature");
  assert(signature.length === 64, "Control-claim Ed25519 signature must be 64 bytes.");
  return { signature };
}

export function parseControlClaim(text, options = {}) {
  assert(typeof text === "string", "Control-claim file must be UTF-8 text.");
  assert(Buffer.byteLength(text, "utf8") <= CONTROL_CLAIM_MAX_BYTES, "Control-claim file is oversized.");
  let document;
  try {
    document = JSON.parse(text);
  } catch {
    throw new Error("Control-claim file is not valid JSON.");
  }
  validateControlClaimDocument(document, options);
  assert(text === `${canonicalize(document)}\n`, "Control-claim file is not canonical JSON with one trailing LF.");
  return document;
}

export function verifyControlClaim(input, options = {}) {
  const document = typeof input === "string" ? parseControlClaim(input, options) : input;
  const { signature } = validateControlClaimDocument(document, options);
  const signatureValid = verifyUtf8(
    document.payload.controller,
    controlClaimSigningInput(document.payload, options),
    signature,
  );
  assert(signatureValid, "Control-claim signature is invalid.");

  const at = instantMillis(options.at ?? Date.now(), "Control-claim verification time");
  const issuedAt = Date.parse(document.payload.issued_at);
  const expiresAt = Date.parse(document.payload.expires_at);
  assert(issuedAt <= at + CONTROL_CLAIM_CLOCK_SKEW_MS, "Control-claim is not yet valid.");
  assert(at < expiresAt, "Control-claim has expired.");

  const serialized = `${canonicalize(document)}\n`;
  return {
    document,
    serialized,
    claim_sha256: createHash("sha256").update(serialized, "utf8").digest("hex"),
    signature_valid: true,
    valid_at: new Date(at).toISOString(),
  };
}

async function readBoundedResponse(response, maximumBytes) {
  assert(response?.ok === true && response.status === 200, "Control-claim publication did not return HTTP 200.");
  const declaredLength = response.headers?.get?.("content-length");
  if (declaredLength !== null && declaredLength !== undefined) {
    assert(/^\d+$/u.test(declaredLength), "Control-claim publication Content-Length is invalid.");
    assert(Number(declaredLength) <= maximumBytes, "Control-claim publication is oversized.");
  }
  assert(response.body && typeof response.body.getReader === "function", "Control-claim publication has no readable body.");
  const reader = response.body.getReader();
  const chunks = [];
  let bytes = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      const chunk = Buffer.from(value);
      bytes += chunk.length;
      assert(bytes <= maximumBytes, "Control-claim publication is oversized.");
      chunks.push(chunk);
    }
  } catch (error) {
    reader.cancel().catch(() => {});
    throw error;
  }
  return Buffer.concat(chunks).toString("utf8");
}

async function fetchFixedPublication(publication, fetchImplementation, timeoutMs) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetchImplementation(publication.url, {
      method: "GET",
      redirect: "error",
      signal: controller.signal,
      headers: {
        accept: "application/json, text/plain;q=0.9",
        "user-agent": "swarmproof-control-claim-v1",
      },
    });
    return await readBoundedResponse(response, CONTROL_CLAIM_MAX_BYTES);
  } finally {
    clearTimeout(timeout);
  }
}

export async function verifyControlClaimPublications(referenceText, options = {}) {
  const verified = verifyControlClaim(referenceText, options);
  const fetchImplementation = options.fetchImplementation ?? globalThis.fetch;
  assert(typeof fetchImplementation === "function", "A fetch implementation is required.");
  const timeoutMs = options.timeoutMs ?? 10_000;
  assert(Number.isSafeInteger(timeoutMs) && timeoutMs >= 1 && timeoutMs <= 30_000, "Publication timeout is invalid.");

  const copies = await Promise.all(CONTROL_CLAIM_PUBLICATIONS.map(async publication => {
    const text = await fetchFixedPublication(publication, fetchImplementation, timeoutMs);
    assert(text === verified.serialized, `Control-claim publication mismatch at ${publication.type}.`);
    // Parse and verify every copy independently, rather than treating byte equality as enough.
    const copy = verifyControlClaim(text, options);
    assert(copy.claim_sha256 === verified.claim_sha256, "Control-claim publication digest mismatch.");
    return {
      type: publication.type,
      url: publication.url,
      claim_sha256: copy.claim_sha256,
      status: "pass",
    };
  }));

  return { ...verified, publications: copies };
}
