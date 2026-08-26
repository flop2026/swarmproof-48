import {
  createPrivateKey,
  createPublicKey,
} from "node:crypto";
import {
  mkdir,
  readFile,
  writeFile,
} from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { canonicalize } from "../lib/canonical.mjs";
import {
  CONTRIBUTION_INDEX_DOMAIN,
  CONTRIBUTION_SUBJECT_DOMAIN,
  createContributionIndex,
} from "../lib/contribution-index.mjs";
import {
  didFromPrivateKey,
  sha256Hex,
  signUtf8,
} from "../lib/crypto.mjs";
import {
  createEnvelope,
  SIGNING_DOMAIN,
} from "../lib/protocol.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const OUTPUT_ROOT = path.join(ROOT, "public", "conformance", "v1");
const CHECK = process.argv.includes("--check");
const SEED_HEX = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
const PKCS8_PREFIX_HEX = "302e020100300506032b657004220420";
const ED25519_MULTICODEC_HEX = "ed01";
const HASH_A = "a".repeat(64);
const HASH_B = "b".repeat(64);
const HASH_C = "c".repeat(64);
const HASH_D = "d".repeat(64);
const REPOSITORY = "vector-lab/swarmproof-48";
const PUBLICATION_COMMIT = "c".repeat(40);
const generated = new Map();

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

function base64url(value) {
  return Buffer.from(value).toString("base64url");
}

function utf8Metadata(value) {
  return {
    utf8: value,
    utf8_hex: Buffer.from(value, "utf8").toString("hex"),
    sha256: sha256Hex(value),
  };
}

function mutateSignature(envelope) {
  const parts = envelope.split(".");
  const signature = Buffer.from(parts[2], "base64url");
  signature[0] ^= 1;
  parts[2] = signature.toString("base64url");
  return parts.join(".");
}

function envelopeFromPayloadBytes(payloadBytes, signer, domain = SIGNING_DOMAIN) {
  const encoded = base64url(payloadBytes);
  const signature = signUtf8(signer, `${domain}|${encoded}`).toString("base64url");
  return `SP1.${encoded}.${signature}`;
}

function canonicalEnvelopeWithOriginalSignature(envelope, mutate) {
  const parts = envelope.split(".");
  const payload = JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8"));
  mutate(payload);
  parts[1] = base64url(canonicalize(payload));
  return parts.join(".");
}

function mutateIndexSignature(document) {
  const next = clone(document);
  const signature = Buffer.from(next.proof.value, "base64url");
  signature[0] ^= 1;
  next.proof.value = signature.toString("base64url");
  return next;
}

function canonicalFile(document) {
  return `${canonicalize(document)}\n`;
}

function addGenerated(relativePath, contents) {
  generated.set(relativePath, contents);
}

async function materialize() {
  for (const [relativePath, contents] of generated) {
    const target = path.join(OUTPUT_ROOT, relativePath);
    if (CHECK) {
      let actual;
      try {
        actual = await readFile(target, "utf8");
      } catch {
        throw new Error(`Missing generated conformance vector: ${relativePath}`);
      }
      if (actual !== contents) throw new Error(`Stale generated conformance vector: ${relativePath}`);
      continue;
    }
    await mkdir(path.dirname(target), { recursive: true });
    await writeFile(target, contents, { encoding: "utf8", mode: 0o644 });
  }
}

const seed = Buffer.from(SEED_HEX, "hex");
const pkcs8Der = Buffer.from(`${PKCS8_PREFIX_HEX}${SEED_HEX}`, "hex");
const fixtureSigner = createPrivateKey({ key: pkcs8Der, format: "der", type: "pkcs8" });
const publicKey = createPublicKey(fixtureSigner).export({ format: "der", type: "spki" }).subarray(-32);
const fixtureDid = didFromPrivateKey(fixtureSigner);
const verifyOptions = { expectedController: fixtureDid };

const claim = createEnvelope({
  schema: "swarmproof-event-v1",
  type: "CLAIM",
  task_id: "conformance",
  claimed_at: "2026-01-01T00:00:00.000Z",
  nonce: "9007199254740993",
  parent_event_ids: [HASH_A],
  content_sha256: HASH_B,
}, fixtureSigner);

const result = createEnvelope({
  schema: "swarmproof-event-v1",
  type: "RESULT",
  task_id: "conformance",
  claimed_at: "2026-01-01T00:01:00.000Z",
  nonce: "9007199254740994",
  parent_event_ids: [claim.event_id],
  content_sha256: HASH_C,
  artifact: {
    repository: REPOSITORY,
    commit: PUBLICATION_COMMIT,
    path: "vectors/result.json",
    sha256: HASH_C,
  },
}, fixtureSigner, { allowedRepositories: new Set([REPOSITORY]) });

const noncanonicalClaimBytes = JSON.stringify(claim.payload);
const invalidDidPayload = { ...claim.payload, did: "did:key:znot-an-ed25519-key" };
const validClaimParts = claim.envelope.split(".");
const paddedPayloadEnvelope = [
  validClaimParts[0],
  `${validClaimParts[1]}=`,
  validClaimParts[2],
].join(".");
const truncatedSignatureEnvelope = [
  validClaimParts[0],
  validClaimParts[1],
  Buffer.alloc(63).toString("base64url"),
].join(".");

const subject = {
  type: "git-content",
  repository: REPOSITORY,
  content_sha256: HASH_C,
};
const contributions = [{
  subject,
  evidence: [{
    kind: "swarmproof-result-snapshot",
    result_event_id: result.event_id,
    publication_commit: PUBLICATION_COMMIT,
    report_sha256: HASH_A,
    snapshot_manifest_sha256: HASH_B,
  }],
}];
const index1 = createContributionIndex(contributions, fixtureSigner, {
  issuedAt: "2026-01-01T01:00:00.000Z",
  sequence: "1",
  previousIndexSha256: null,
  controlClaimSha256: HASH_D,
  ...verifyOptions,
});
const index2 = createContributionIndex(contributions, fixtureSigner, {
  issuedAt: "2026-01-01T02:00:00.000Z",
  sequence: "2",
  previousIndexSha256: index1.index_sha256,
  controlClaimSha256: HASH_D,
  ...verifyOptions,
});
const index3 = createContributionIndex(contributions, fixtureSigner, {
  issuedAt: "2026-01-01T03:00:00.000Z",
  sequence: "3",
  previousIndexSha256: index2.index_sha256,
  controlClaimSha256: HASH_D,
  ...verifyOptions,
});
const brokenLink3 = createContributionIndex(contributions, fixtureSigner, {
  issuedAt: "2026-01-01T03:00:00.000Z",
  sequence: "3",
  previousIndexSha256: "f".repeat(64),
  controlClaimSha256: HASH_D,
  ...verifyOptions,
});
const gap3 = createContributionIndex(contributions, fixtureSigner, {
  issuedAt: "2026-01-01T03:00:00.000Z",
  sequence: "3",
  previousIndexSha256: index1.index_sha256,
  controlClaimSha256: HASH_D,
  ...verifyOptions,
});
const badSignature1 = canonicalFile(mutateIndexSignature(index1.document));
const tampered1Document = clone(index1.document);
tampered1Document.payload.issued_at = "2026-01-01T01:00:01.000Z";
const tampered1 = canonicalFile(tampered1Document);
const pretty1 = `${JSON.stringify(index1.document, null, 2)}\n`;

const indexFiles = new Map([
  ["index/sequence-1.json", index1.serialized],
  ["index/sequence-2.json", index2.serialized],
  ["index/sequence-3.json", index3.serialized],
  ["index/broken-link-sequence-3.json", brokenLink3.serialized],
  ["index/gap-sequence-3.json", gap3.serialized],
  ["index/bad-signature-sequence-1.json", badSignature1],
  ["index/tampered-payload-sequence-1.json", tampered1],
  ["index/noncanonical-pretty-sequence-1.json", pretty1],
]);
for (const [name, contents] of indexFiles) addGenerated(name, contents);

const canonicalClaim = canonicalize(claim.payload);
const canonicalIndexPayload = canonicalize(index1.document.payload);
const manifest = {
  schema: "swarmproof-conformance-vectors-v1",
  generated_by: "scripts/generate-conformance-vectors.mjs",
  fixture_key: {
    classification: "PUBLIC TEST KEY; NEVER USE FOR REAL IDENTITY, VALUE, OR ACCESS",
    algorithm: "Ed25519",
    seed_hex: SEED_HEX,
    pkcs8_der_hex: pkcs8Der.toString("hex"),
    raw_public_key_hex: publicKey.toString("hex"),
    multicodec_prefix_hex: ED25519_MULTICODEC_HEX,
    multicodec_public_key_hex: `${ED25519_MULTICODEC_HEX}${publicKey.toString("hex")}`,
    did: fixtureDid,
  },
  canonical_json: {
    algorithm_profile: "recursively sorted object keys; array order preserved; compact JSON; UTF-8",
    cases: [
      {
        id: "event-claim-payload",
        input: claim.payload,
        expected: utf8Metadata(canonicalClaim),
      },
      {
        id: "contribution-index-sequence-1-payload",
        input: index1.document.payload,
        expected: utf8Metadata(canonicalIndexPayload),
      },
    ],
  },
  event: {
    schema: "swarmproof-event-v1",
    experiment: "swarmproof-48-e463",
    envelope_prefix: "SP1",
    signing_input: "UTF8('swarmproof-event-v1|swarmproof-48-e463|' + BASE64URL(canonical_payload_utf8))",
    cases: [
      {
        id: "valid-claim",
        envelope: claim.envelope,
        expected: {
          valid: true,
          code: "ok",
          event_id: claim.event_id,
          did: fixtureDid,
          canonical_payload_sha256: sha256Hex(claim.canonical_payload),
          signing_input_sha256: sha256Hex(`${SIGNING_DOMAIN}|${validClaimParts[1]}`),
        },
      },
      {
        id: "valid-result-with-allowlisted-repository",
        envelope: result.envelope,
        verification_options: { allowed_repositories: [REPOSITORY] },
        expected: {
          valid: true,
          code: "ok",
          event_id: result.event_id,
          did: fixtureDid,
          canonical_payload_sha256: sha256Hex(result.canonical_payload),
          signing_input_sha256: sha256Hex(`${SIGNING_DOMAIN}|${result.envelope.split(".")[1]}`),
        },
      },
      {
        id: "tampered-signature",
        envelope: mutateSignature(claim.envelope),
        expected: { valid: false, code: "signature_invalid" },
      },
      {
        id: "tampered-canonical-payload-with-original-signature",
        envelope: canonicalEnvelopeWithOriginalSignature(claim.envelope, payload => { payload.nonce = "9007199254740995"; }),
        expected: { valid: false, code: "signature_invalid" },
      },
      {
        id: "valid-signature-over-noncanonical-json",
        envelope: envelopeFromPayloadBytes(noncanonicalClaimBytes, fixtureSigner),
        expected: { valid: false, code: "payload_json_not_canonical" },
      },
      {
        id: "signature-over-wrong-domain",
        envelope: envelopeFromPayloadBytes(canonicalClaim, fixtureSigner, "swarmproof-event-v1|wrong-experiment"),
        expected: { valid: false, code: "signature_invalid" },
      },
      {
        id: "noncanonical-padded-base64url-payload",
        envelope: paddedPayloadEnvelope,
        expected: { valid: false, code: "base64url_invalid" },
      },
      {
        id: "truncated-signature",
        envelope: truncatedSignatureEnvelope,
        expected: { valid: false, code: "signature_length_invalid" },
      },
      {
        id: "invalid-did",
        envelope: envelopeFromPayloadBytes(canonicalize(invalidDidPayload), fixtureSigner),
        expected: { valid: false, code: "did_invalid" },
      },
    ],
  },
  contribution_index: {
    schema: "swarmproof-contribution-index-v1",
    fixture_verification_profile: {
      expected_controller: fixtureDid,
      caveat: "The deployment JSON Schema pins the production controller. These cryptographic fixtures use an explicit test-controller override and are not production index documents.",
    },
    subject_id_input: `UTF8('${CONTRIBUTION_SUBJECT_DOMAIN}' + canonical_json(lowercase_repository_subject))`,
    index_signing_input: `UTF8('${CONTRIBUTION_INDEX_DOMAIN}' + canonical_payload_json)`,
    subject: {
      value: subject,
      contribution_id: index1.document.payload.contributions[0].contribution_id,
      signing_identity_canonical_json: canonicalize({ ...subject, repository: subject.repository.toLowerCase() }),
    },
    document_cases: [
      ...[
        ["valid-sequence-1", "index/sequence-1.json", index1, "root"],
        ["valid-sequence-2-standalone", "index/sequence-2.json", index2, "not-checked"],
        ["valid-sequence-3-standalone", "index/sequence-3.json", index3, "not-checked"],
        ["broken-link-sequence-3-is-standalone-valid", "index/broken-link-sequence-3.json", brokenLink3, "not-checked"],
        ["sequence-gap-3-is-standalone-valid", "index/gap-sequence-3.json", gap3, "not-checked"],
      ].map(([id, file, index, history_status]) => ({
        id,
        file,
        file_sha256: sha256Hex(index.serialized),
        expected: {
          valid: true,
          code: "ok",
          sequence: index.document.payload.sequence,
          index_sha256: index.index_sha256,
          signing_input_sha256: sha256Hex(`${CONTRIBUTION_INDEX_DOMAIN}${canonicalize(index.document.payload)}`),
          history_status,
        },
      })),
      {
        id: "bad-signature",
        file: "index/bad-signature-sequence-1.json",
        file_sha256: sha256Hex(badSignature1),
        expected: { valid: false, code: "signature_invalid" },
      },
      {
        id: "tampered-payload-with-original-signature",
        file: "index/tampered-payload-sequence-1.json",
        file_sha256: sha256Hex(tampered1),
        expected: { valid: false, code: "signature_invalid" },
      },
      {
        id: "noncanonical-pretty-json",
        file: "index/noncanonical-pretty-sequence-1.json",
        file_sha256: sha256Hex(pretty1),
        expected: { valid: false, code: "canonical_file_invalid" },
      },
    ],
    history_cases: [
      {
        id: "valid-complete-chain",
        files: ["index/sequence-1.json", "index/sequence-2.json", "index/sequence-3.json"],
        expected: { valid: true, code: "ok", index_count: 3, first_sequence: "1", current_sequence: "3" },
      },
      {
        id: "history-does-not-start-at-one",
        files: ["index/sequence-2.json", "index/sequence-3.json"],
        expected: { valid: false, code: "history_root_invalid" },
      },
      {
        id: "history-link-mismatch",
        files: ["index/sequence-1.json", "index/sequence-2.json", "index/broken-link-sequence-3.json"],
        expected: { valid: false, code: "history_link_mismatch" },
      },
      {
        id: "history-sequence-gap",
        files: ["index/sequence-1.json", "index/gap-sequence-3.json"],
        expected: { valid: false, code: "history_sequence_gap" },
      },
      {
        id: "history-tampered-root",
        files: ["index/tampered-payload-sequence-1.json", "index/sequence-2.json"],
        expected: { valid: false, code: "signature_invalid" },
      },
      {
        id: "history-noncanonical-root",
        files: ["index/noncanonical-pretty-sequence-1.json", "index/sequence-2.json"],
        expected: { valid: false, code: "canonical_file_invalid" },
      },
    ],
  },
};

addGenerated("manifest.json", `${JSON.stringify(manifest, null, 2)}\n`);
await materialize();
console.log(`${CHECK ? "Verified" : "Generated"} ${generated.size} conformance-vector files.`);
