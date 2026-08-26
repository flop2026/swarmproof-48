import assert from "node:assert/strict";
import {
  createPrivateKey,
  createPublicKey,
} from "node:crypto";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { canonicalize } from "../lib/canonical.mjs";
import {
  CONTRIBUTION_INDEX_DOMAIN,
  contributionIdForSubject,
  verifyContributionIndex,
  verifyContributionIndexHistory,
} from "../lib/contribution-index.mjs";
import {
  didFromPrivateKey,
  sha256Hex,
} from "../lib/crypto.mjs";
import { SIGNING_DOMAIN, verifyEnvelope } from "../lib/protocol.mjs";

const ROOT = new URL("../public/conformance/v1/", import.meta.url);
const manifest = JSON.parse(await readFile(new URL("manifest.json", ROOT), "utf8"));
const expectedController = manifest.fixture_key.did;
const indexOptions = { expectedController };

function classifyEventError(error) {
  const message = String(error?.message ?? error);
  if (/Payload JSON is not canonical/u.test(message)) return "payload_json_not_canonical";
  if (/not base64url/u.test(message)) return "base64url_invalid";
  if (/signature must be 64 bytes/u.test(message)) return "signature_length_invalid";
  if (/did is not an Ed25519 did:key/u.test(message)) return "did_invalid";
  if (/Envelope signature is invalid/u.test(message)) return "signature_invalid";
  return "unclassified";
}

function classifyIndexError(error) {
  const message = String(error?.message ?? error);
  if (/file is not canonical JSON/u.test(message)) return "canonical_file_invalid";
  if (/signature is invalid/u.test(message)) return "signature_invalid";
  return "unclassified";
}

function classifyHistoryError(error) {
  const message = String(error?.message ?? error);
  if (/file is not canonical JSON/u.test(message)) return "canonical_file_invalid";
  if (/signature is invalid/u.test(message)) return "signature_invalid";
  if (/must begin at sequence 1/u.test(message)) return "history_root_invalid";
  if (/sequence must increment by exactly one/u.test(message)) return "history_sequence_gap";
  if (/link does not name the preceding index/u.test(message)) return "history_link_mismatch";
  return "unclassified";
}

test("public conformance key derives the declared raw key and did:key", () => {
  assert.equal(manifest.schema, "swarmproof-conformance-vectors-v1");
  assert.match(manifest.fixture_key.classification, /PUBLIC TEST KEY/u);
  const pkcs8 = Buffer.from(manifest.fixture_key.pkcs8_der_hex, "hex");
  assert.equal(
    pkcs8.subarray(-32).toString("hex"),
    manifest.fixture_key.seed_hex,
  );
  const fixtureSigner = createPrivateKey({ key: pkcs8, format: "der", type: "pkcs8" });
  const rawPublicKey = createPublicKey(fixtureSigner)
    .export({ format: "der", type: "spki" })
    .subarray(-32);
  assert.equal(rawPublicKey.toString("hex"), manifest.fixture_key.raw_public_key_hex);
  assert.equal(
    `${manifest.fixture_key.multicodec_prefix_hex}${rawPublicKey.toString("hex")}`,
    manifest.fixture_key.multicodec_public_key_hex,
  );
  assert.equal(didFromPrivateKey(fixtureSigner), expectedController);
});

test("canonical JSON cases bind exact UTF-8 bytes and hashes", () => {
  for (const vector of manifest.canonical_json.cases) {
    const actual = canonicalize(vector.input);
    assert.equal(actual, vector.expected.utf8, vector.id);
    assert.equal(Buffer.from(actual, "utf8").toString("hex"), vector.expected.utf8_hex, vector.id);
    assert.equal(sha256Hex(actual), vector.expected.sha256, vector.id);
  }
});

test("SP1 conformance cases have deterministic acceptance and rejection outcomes", () => {
  for (const vector of manifest.event.cases) {
    const options = vector.verification_options?.allowed_repositories
      ? { allowedRepositories: new Set(vector.verification_options.allowed_repositories) }
      : {};
    if (vector.expected.valid) {
      const verified = verifyEnvelope(vector.envelope, options);
      assert.equal(verified.signature_valid, true, vector.id);
      assert.equal(verified.event_id, vector.expected.event_id, vector.id);
      assert.equal(verified.payload.did, vector.expected.did, vector.id);
      assert.equal(
        sha256Hex(canonicalize(verified.payload)),
        vector.expected.canonical_payload_sha256,
        vector.id,
      );
      assert.equal(
        sha256Hex(`${SIGNING_DOMAIN}|${vector.envelope.split(".")[1]}`),
        vector.expected.signing_input_sha256,
        vector.id,
      );
      continue;
    }
    let error;
    try {
      verifyEnvelope(vector.envelope, options);
    } catch (caught) {
      error = caught;
    }
    assert.ok(error, `${vector.id} unexpectedly verified`);
    assert.equal(classifyEventError(error), vector.expected.code, vector.id);
  }
});

test("contribution subject IDs and standalone document vectors are deterministic", async () => {
  assert.equal(
    contributionIdForSubject(manifest.contribution_index.subject.value),
    manifest.contribution_index.subject.contribution_id,
  );
  assert.equal(
    canonicalize({
      ...manifest.contribution_index.subject.value,
      repository: manifest.contribution_index.subject.value.repository.toLowerCase(),
    }),
    manifest.contribution_index.subject.signing_identity_canonical_json,
  );

  for (const vector of manifest.contribution_index.document_cases) {
    const text = await readFile(new URL(vector.file, ROOT), "utf8");
    assert.equal(sha256Hex(text), vector.file_sha256, vector.id);
    if (vector.expected.valid) {
      const verified = verifyContributionIndex(text, indexOptions);
      assert.equal(verified.signature_valid, true, vector.id);
      assert.equal(verified.index_sha256, vector.expected.index_sha256, vector.id);
      assert.equal(verified.document.payload.sequence, vector.expected.sequence, vector.id);
      assert.equal(
        sha256Hex(`${CONTRIBUTION_INDEX_DOMAIN}${canonicalize(verified.document.payload)}`),
        vector.expected.signing_input_sha256,
        vector.id,
      );
      continue;
    }
    let error;
    try {
      verifyContributionIndex(text, indexOptions);
    } catch (caught) {
      error = caught;
    }
    assert.ok(error, `${vector.id} unexpectedly verified`);
    assert.equal(classifyIndexError(error), vector.expected.code, vector.id);
  }
});

test("complete index-history vectors distinguish signature, root, sequence, and link failures", async () => {
  for (const vector of manifest.contribution_index.history_cases) {
    const files = await Promise.all(vector.files.map(file => readFile(new URL(file, ROOT), "utf8")));
    const current = files.at(-1);
    const previous = files.slice(0, -1);
    if (vector.expected.valid) {
      const verified = verifyContributionIndexHistory(previous, current, indexOptions);
      assert.equal(verified.status, "pass", vector.id);
      assert.equal(verified.index_count, vector.expected.index_count, vector.id);
      assert.equal(verified.first_sequence, vector.expected.first_sequence, vector.id);
      assert.equal(verified.current_sequence, vector.expected.current_sequence, vector.id);
      continue;
    }
    let error;
    try {
      verifyContributionIndexHistory(previous, current, indexOptions);
    } catch (caught) {
      error = caught;
    }
    assert.ok(error, `${vector.id} unexpectedly verified`);
    assert.equal(classifyHistoryError(error), vector.expected.code, vector.id);
  }
});

test("fixture corpus does not contain the configured production controller DID", async () => {
  const productionController = "did:key:z6MkqNyQTuVH8ZqJc5HZ2M9FGDDWBmVupBrX96G3EA3J5gSw";
  const texts = await Promise.all([
    readFile(new URL("manifest.json", ROOT), "utf8"),
    ...manifest.contribution_index.document_cases.map(vector => readFile(new URL(vector.file, ROOT), "utf8")),
  ]);
  assert.ok(texts.every(text => !text.includes(productionController)));
});
