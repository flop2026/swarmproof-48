import { canonicalize } from "./canonical.mjs";
import {
  base58Encode,
  didFromPrivateKey,
  publicKeyBytesFromDid,
  sha256Hex,
  signUtf8,
  verifyUtf8,
} from "./crypto.mjs";
import { verifyControlClaim } from "./control-claim.mjs";
import { analyzeEventSemantics, compareEventChronology } from "./semantics.mjs";

export const CONTRIBUTION_INDEX_SCHEMA = "swarmproof-contribution-index-v1";
export const CONTRIBUTION_INDEX_PROJECT = "swarmproof-48-e463";
export const CONTRIBUTION_INDEX_PURPOSE = "controller-curated-contribution-evidence-index";
export const CONTRIBUTION_INDEX_CONTROLLER = "did:key:z6MkqNyQTuVH8ZqJc5HZ2M9FGDDWBmVupBrX96G3EA3J5gSw";
export const CONTRIBUTION_INDEX_DOMAIN = "SWARMPROOF-CONTRIBUTION-INDEX-V1\n";
export const CONTRIBUTION_SUBJECT_DOMAIN = "SWARMPROOF-CONTRIBUTION-SUBJECT-V1\n";
export const CONTRIBUTION_INDEX_MAX_BYTES = 256 * 1024;
export const CONTRIBUTION_INDEX_MAX_CONTRIBUTIONS = 512;
export const CONTRIBUTION_INDEX_MAX_EVIDENCE_PER_CONTRIBUTION = 64;
export const CONTRIBUTION_INDEX_RELATIVE_PATH = "public/.well-known/swarmproof-contribution-index-v1.json";

export const CONTRIBUTION_INDEX_PUBLICATIONS = Object.freeze([
  Object.freeze({
    type: "github-repository",
    url: "https://raw.githubusercontent.com/flop2026/swarmproof-48/main/public/.well-known/swarmproof-contribution-index-v1.json",
  }),
  Object.freeze({
    type: "https-origin",
    url: "https://swarmproof-48-e463.pages.dev/.well-known/swarmproof-contribution-index-v1.json",
  }),
]);

const DOCUMENT_KEYS = new Set(["payload", "proof"]);
const PAYLOAD_KEYS = new Set([
  "schema",
  "project",
  "purpose",
  "controller",
  "issued_at",
  "sequence",
  "previous_index_sha256",
  "control_claim_sha256",
  "contributions",
]);
const CONTRIBUTION_KEYS = new Set(["contribution_id", "subject", "evidence"]);
const SUBJECT_KEYS = new Set(["type", "repository", "content_sha256"]);
const PROOF_KEYS = new Set(["type", "encoding", "value"]);
const SWARMPROOF_RESULT_KEYS = new Set([
  "kind", "result_event_id", "publication_commit", "report_sha256", "snapshot_manifest_sha256",
]);
const SERVER_OBSERVATION_KEYS = new Set([
  "kind", "service", "room", "source_seq", "source_ts", "message_sha256",
  "transport_authentication",
]);
const CROSS_KEY_REVIEW_KEYS = new Set([
  "kind", "review_event_id", "target_event_id", "publication_commit", "report_sha256",
  "snapshot_manifest_sha256",
]);
const UPSTREAM_ACCEPTANCE_KEYS = new Set([
  "kind", "forge", "repository", "pull_request", "accepted_commit", "path", "content_sha256",
]);
const EXTERNAL_ADOPTION_KEYS = new Set([
  "kind", "forge", "repository", "commit", "path", "content_sha256", "relation", "marker",
]);
const OFFICIAL_TASK_KEYS = new Set([
  "kind", "authority", "task_uri", "task_source_sha256", "submission_uri",
  "submission_sha256", "stage", "official_acceptance", "reward_status",
]);
const EVIDENCE_KINDS = new Set([
  "swarmproof-result-snapshot",
  "server-observation",
  "cross-key-review",
  "upstream-acceptance",
  "external-adoption",
  "official-task",
]);
const HASH_RE = /^[0-9a-f]{64}$/u;
const COMMIT_RE = /^[0-9a-f]{40}$/u;
const POSITIVE_DECIMAL_RE = /^[1-9][0-9]{0,18}$/u;
const PR_RE = /^[1-9][0-9]{0,9}$/u;
const DID_RE = /^did:key:z6Mk[1-9A-HJ-NP-Za-km-z]+$/u;
const REPOSITORY_RE = /^[A-Za-z0-9_.-]{1,39}\/[A-Za-z0-9_.-]{1,100}$/u;
const ROOM_RE = /^[a-z0-9][a-z0-9_-]{0,47}$/u;
const PATH_RE = /^[A-Za-z0-9._/-]{1,240}$/u;
const FIXED_SUBMISSION_URI_RE = /^https:\/\/(?:github\.com\/flop2026\/swarmproof-48(?:\/[^?#]*)?|swarmproof-48-e463\.pages\.dev(?:\/[^?#]*)?|technocore\.chat\/r\/[a-z0-9][a-z0-9_-]{0,47})$/u;
const BASE64URL_RE = /^[A-Za-z0-9_-]+$/u;
const CANONICAL_TIME_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u;
const ED25519_MULTICODEC = Buffer.from([0xed, 0x01]);
const EVIDENCE_LEVELS = new Set([
  "OBSERVED", "ATTRIBUTABLE", "REPRODUCIBLE", "CROSS-KEY-REVIEWED", "ACCEPTED",
]);
const EXTERNAL_RELATIONS = new Set(["dependency", "invocation", "citation"]);
const ADOPTION_MARKERS = new Set([
  "https://github.com/flop2026/swarmproof-48",
  "https://swarmproof-48-e463.pages.dev",
  CONTRIBUTION_INDEX_CONTROLLER,
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

function canonicalTimeMillis(value, label) {
  assert(typeof value === "string" && CANONICAL_TIME_RE.test(value), `${label} must be canonical UTC.`);
  const milliseconds = Date.parse(value);
  assert(Number.isFinite(milliseconds) && new Date(milliseconds).toISOString() === value, `${label} is invalid.`);
  return milliseconds;
}

function canonicalEd25519Did(did, label) {
  assert(typeof did === "string" && DID_RE.test(did), `${label} is invalid.`);
  let publicKey;
  try {
    publicKey = publicKeyBytesFromDid(did);
  } catch {
    throw new Error(`${label} must be a canonical Ed25519 did:key.`);
  }
  const canonical = `did:key:z${base58Encode(Buffer.concat([ED25519_MULTICODEC, publicKey]))}`;
  assert(did === canonical, `${label} must be a canonical Ed25519 did:key.`);
  return did;
}

function decodeCanonicalBase64Url(value, label) {
  assert(typeof value === "string" && BASE64URL_RE.test(value), `${label} must be unpadded base64url.`);
  const decoded = Buffer.from(value, "base64url");
  assert(decoded.toString("base64url") === value, `${label} must be canonical base64url.`);
  return decoded;
}

function assertHash(value, label) {
  assert(typeof value === "string" && HASH_RE.test(value), `${label} must be a lowercase SHA-256.`);
}

function assertRepository(value, label) {
  assert(typeof value === "string" && REPOSITORY_RE.test(value), `${label} is invalid.`);
}

function sameRepository(left, right) {
  return left.toLowerCase() === right.toLowerCase();
}

function assertSafePath(value, label) {
  assert(typeof value === "string" && PATH_RE.test(value), `${label} is invalid.`);
  assert(!value.startsWith("/") && !value.endsWith("/"), `${label} is invalid.`);
  assert(value.split("/").every(segment => (
    segment.length > 0 && segment !== "." && segment !== ".." && segment.toLowerCase() !== ".git"
  )), `${label} is invalid.`);
}

function validateFixedSubmissionUri(value) {
  assert(typeof value === "string", "official-task submission_uri is invalid.");
  assert(
    FIXED_SUBMISSION_URI_RE.test(value),
    "official-task submission_uri is not an allowlisted project resource.",
  );
  let url;
  try {
    url = new URL(value);
  } catch {
    throw new Error("official-task submission_uri is invalid.");
  }
  assert(
    url.protocol === "https:"
      && !url.username
      && !url.password
      && !url.port
      && !url.search
      && !url.hash,
    "official-task submission_uri is invalid.",
  );
}

function validateEvidence(evidence, subject, label) {
  assert(isPlainObject(evidence), `${label} must be a plain object.`);
  assert(EVIDENCE_KINDS.has(evidence.kind), `${label}.kind is unsupported.`);
  switch (evidence.kind) {
    case "swarmproof-result-snapshot":
      assertExactObject(evidence, SWARMPROOF_RESULT_KEYS, label);
      assertHash(evidence.result_event_id, `${label}.result_event_id`);
      assert(typeof evidence.publication_commit === "string" && COMMIT_RE.test(evidence.publication_commit), `${label}.publication_commit is invalid.`);
      assertHash(evidence.report_sha256, `${label}.report_sha256`);
      assertHash(evidence.snapshot_manifest_sha256, `${label}.snapshot_manifest_sha256`);
      break;
    case "server-observation":
      assertExactObject(evidence, SERVER_OBSERVATION_KEYS, label);
      assert(evidence.service === "technocore.chat", `${label}.service is unsupported.`);
      assert(typeof evidence.room === "string" && ROOM_RE.test(evidence.room), `${label}.room is invalid.`);
      assert(typeof evidence.source_seq === "string" && POSITIVE_DECIMAL_RE.test(evidence.source_seq), `${label}.source_seq is invalid.`);
      canonicalTimeMillis(evidence.source_ts, `${label}.source_ts`);
      assertHash(evidence.message_sha256, `${label}.message_sha256`);
      assert(evidence.transport_authentication === "server-reported", `${label}.transport_authentication must remain server-reported.`);
      break;
    case "cross-key-review":
      assertExactObject(evidence, CROSS_KEY_REVIEW_KEYS, label);
      assertHash(evidence.review_event_id, `${label}.review_event_id`);
      assertHash(evidence.target_event_id, `${label}.target_event_id`);
      assert(typeof evidence.publication_commit === "string" && COMMIT_RE.test(evidence.publication_commit), `${label}.publication_commit is invalid.`);
      assertHash(evidence.report_sha256, `${label}.report_sha256`);
      assertHash(evidence.snapshot_manifest_sha256, `${label}.snapshot_manifest_sha256`);
      break;
    case "upstream-acceptance":
      assertExactObject(evidence, UPSTREAM_ACCEPTANCE_KEYS, label);
      assert(evidence.forge === "github", `${label}.forge is unsupported.`);
      assertRepository(evidence.repository, `${label}.repository`);
      assert(!sameRepository(evidence.repository, subject.repository), `${label}.repository must be an upstream repository.`);
      assert(typeof evidence.pull_request === "string" && PR_RE.test(evidence.pull_request), `${label}.pull_request is invalid.`);
      assert(typeof evidence.accepted_commit === "string" && COMMIT_RE.test(evidence.accepted_commit), `${label}.accepted_commit is invalid.`);
      assertSafePath(evidence.path, `${label}.path`);
      assertHash(evidence.content_sha256, `${label}.content_sha256`);
      assert(evidence.content_sha256 === subject.content_sha256, `${label}.content_sha256 must identify the indexed subject.`);
      break;
    case "external-adoption":
      assertExactObject(evidence, EXTERNAL_ADOPTION_KEYS, label);
      assert(evidence.forge === "github", `${label}.forge is unsupported.`);
      assertRepository(evidence.repository, `${label}.repository`);
      assert(!evidence.repository.toLowerCase().startsWith("flop2026/"), `${label}.repository must use an external namespace.`);
      assert(typeof evidence.commit === "string" && COMMIT_RE.test(evidence.commit), `${label}.commit is invalid.`);
      assertSafePath(evidence.path, `${label}.path`);
      assertHash(evidence.content_sha256, `${label}.content_sha256`);
      assert(EXTERNAL_RELATIONS.has(evidence.relation), `${label}.relation is unsupported.`);
      assert(ADOPTION_MARKERS.has(evidence.marker), `${label}.marker is not a configured project identifier.`);
      break;
    case "official-task": {
      assertExactObject(evidence, OFFICIAL_TASK_KEYS, label);
      assert(["flop-labs-x", "crypto-hayes-x"].includes(evidence.authority), `${label}.authority is unsupported.`);
      const account = evidence.authority === "flop-labs-x" ? "flop_labs" : "CryptoHayes";
      assert(
        new RegExp(`^https://x\\.com/${account}/status/[1-9][0-9]{1,24}$`, "u").test(evidence.task_uri ?? ""),
        `${label}.task_uri is not a pinned status from the configured authority.`,
      );
      assertHash(evidence.task_source_sha256, `${label}.task_source_sha256`);
      validateFixedSubmissionUri(evidence.submission_uri);
      assertHash(evidence.submission_sha256, `${label}.submission_sha256`);
      assert(evidence.submission_sha256 === subject.content_sha256, `${label}.submission_sha256 must identify the indexed subject.`);
      assert(evidence.stage === "submitted", `${label}.stage may only be submitted in v1.`);
      assert(evidence.official_acceptance === "not-claimed", `${label}.official_acceptance must not be self-claimed.`);
      assert(evidence.reward_status === "not-claimed", `${label}.reward_status must not be self-claimed.`);
      break;
    }
    default:
      throw new Error(`${label}.kind is unsupported.`);
  }
  return evidence;
}

export function contributionIdForSubject(subject) {
  validateSubject(subject, "Contribution subject");
  const identity = { ...subject, repository: subject.repository.toLowerCase() };
  return sha256Hex(`${CONTRIBUTION_SUBJECT_DOMAIN}${canonicalize(identity)}`);
}

export function validateSubject(subject, label = "Contribution subject") {
  assertExactObject(subject, SUBJECT_KEYS, label);
  assert(subject.type === "git-content", `${label}.type is unsupported.`);
  assertRepository(subject.repository, `${label}.repository`);
  assertHash(subject.content_sha256, `${label}.content_sha256`);
  return subject;
}

function evidenceSortKey(evidence) {
  return `${evidence.kind}\u0000${canonicalize(evidence)}`;
}

export function validateContributionIndexPayload(payload, options = {}) {
  assertExactObject(payload, PAYLOAD_KEYS, "Contribution-index payload");
  assert(payload.schema === CONTRIBUTION_INDEX_SCHEMA, "Contribution-index schema is unsupported.");
  assert(payload.project === CONTRIBUTION_INDEX_PROJECT, "Contribution-index project domain is invalid.");
  assert(payload.purpose === CONTRIBUTION_INDEX_PURPOSE, "Contribution-index purpose is invalid.");
  canonicalEd25519Did(payload.controller, "Contribution-index controller");
  const expectedController = options.expectedController ?? CONTRIBUTION_INDEX_CONTROLLER;
  assert(payload.controller === expectedController, "Contribution-index controller is not the configured project DID.");
  canonicalTimeMillis(payload.issued_at, "Contribution-index issued_at");
  assert(typeof payload.sequence === "string" && POSITIVE_DECIMAL_RE.test(payload.sequence), "Contribution-index sequence is invalid.");
  if (payload.previous_index_sha256 !== null) {
    assertHash(payload.previous_index_sha256, "Contribution-index previous_index_sha256");
  }
  if (payload.sequence === "1") {
    assert(payload.previous_index_sha256 === null, "Contribution-index sequence 1 cannot name a previous index.");
  } else {
    assert(payload.previous_index_sha256 !== null, "Contribution-index sequence after 1 requires a previous index hash.");
  }
  assertHash(payload.control_claim_sha256, "Contribution-index control_claim_sha256");
  assert(Array.isArray(payload.contributions), "Contribution-index contributions must be an array.");
  assert(payload.contributions.length >= 1, "Contribution-index must contain at least one contribution.");
  assert(payload.contributions.length <= CONTRIBUTION_INDEX_MAX_CONTRIBUTIONS, "Contribution-index contribution limit exceeded.");

  const contributionIds = new Set();
  const snapshotPublicationCommits = new Set();
  let previousContributionId = null;
  payload.contributions.forEach((contribution, contributionIndex) => {
    const label = `Contribution ${contributionIndex + 1}`;
    assertExactObject(contribution, CONTRIBUTION_KEYS, label);
    validateSubject(contribution.subject, `${label}.subject`);
    assertHash(contribution.contribution_id, `${label}.contribution_id`);
    assert(
      contribution.contribution_id === contributionIdForSubject(contribution.subject),
      `${label}.contribution_id does not match its subject.`,
    );
    assert(!contributionIds.has(contribution.contribution_id), `${label}.contribution_id is duplicated.`);
    contributionIds.add(contribution.contribution_id);
    assert(
      previousContributionId === null || previousContributionId < contribution.contribution_id,
      "Contribution-index contributions are not in canonical contribution_id order.",
    );
    previousContributionId = contribution.contribution_id;
    assert(Array.isArray(contribution.evidence) && contribution.evidence.length >= 1, `${label}.evidence must be a non-empty array.`);
    assert(
      contribution.evidence.length <= CONTRIBUTION_INDEX_MAX_EVIDENCE_PER_CONTRIBUTION,
      `${label}.evidence limit exceeded.`,
    );
    const seenEvidence = new Set();
    let previousEvidenceKey = null;
    contribution.evidence.forEach((evidence, evidenceIndex) => {
      validateEvidence(evidence, contribution.subject, `${label}.evidence[${evidenceIndex}]`);
      if (["swarmproof-result-snapshot", "cross-key-review"].includes(evidence.kind)) {
        snapshotPublicationCommits.add(evidence.publication_commit);
      }
      const key = evidenceSortKey(evidence);
      assert(!seenEvidence.has(key), `${label}.evidence contains a duplicate.`);
      seenEvidence.add(key);
      assert(previousEvidenceKey === null || previousEvidenceKey < key, `${label}.evidence is not in canonical order.`);
      previousEvidenceKey = key;
    });
  });
  assert(
    snapshotPublicationCommits.size <= 1,
    "Contribution-index v1 may bind SwarmProof evidence from only one immutable publication commit.",
  );
  return payload;
}

export function canonicalContributionIndexPayload(payload, options = {}) {
  validateContributionIndexPayload(payload, options);
  return canonicalize(payload);
}

export function contributionIndexSigningInput(payload, options = {}) {
  return `${CONTRIBUTION_INDEX_DOMAIN}${canonicalContributionIndexPayload(payload, options)}`;
}

export function validateContributionIndexDocument(document, options = {}) {
  assertExactObject(document, DOCUMENT_KEYS, "Contribution-index document");
  validateContributionIndexPayload(document.payload, options);
  assertExactObject(document.proof, PROOF_KEYS, "Contribution-index proof");
  assert(document.proof.type === "Ed25519", "Contribution-index proof type is invalid.");
  assert(document.proof.encoding === "base64url", "Contribution-index proof encoding is invalid.");
  const signature = decodeCanonicalBase64Url(document.proof.value, "Contribution-index signature");
  assert(signature.length === 64, "Contribution-index Ed25519 signature must be 64 bytes.");
  return { signature };
}

export function serializeContributionIndex(document, options = {}) {
  validateContributionIndexDocument(document, options);
  const serialized = `${canonicalize(document)}\n`;
  assert(Buffer.byteLength(serialized, "utf8") <= CONTRIBUTION_INDEX_MAX_BYTES, "Contribution-index file is oversized.");
  return serialized;
}

export function parseContributionIndex(text, options = {}) {
  assert(typeof text === "string", "Contribution-index file must be UTF-8 text.");
  assert(Buffer.byteLength(text, "utf8") <= CONTRIBUTION_INDEX_MAX_BYTES, "Contribution-index file is oversized.");
  let document;
  try {
    document = JSON.parse(text);
  } catch {
    throw new Error("Contribution-index file is not valid JSON.");
  }
  validateContributionIndexDocument(document, options);
  assert(text === `${canonicalize(document)}\n`, "Contribution-index file is not canonical JSON with one trailing LF.");
  return document;
}

function instantMillis(value, label) {
  const date = value instanceof Date ? value : new Date(value);
  const milliseconds = date.getTime();
  assert(Number.isFinite(milliseconds), `${label} is invalid.`);
  return milliseconds;
}

export function normalizeContributions(contributions) {
  assert(Array.isArray(contributions), "Contributions must be an array.");
  return contributions.map(contribution => {
    assert(isPlainObject(contribution), "Contribution input must be a plain object.");
    assertExactObject(contribution, new Set(["subject", "evidence"]), "Contribution input");
    const subject = structuredClone(contribution.subject);
    validateSubject(subject);
    const evidence = contribution.evidence.map(item => structuredClone(item));
    evidence.forEach((item, index) => validateEvidence(item, subject, `Contribution input evidence[${index}]`));
    evidence.sort((left, right) => evidenceSortKey(left).localeCompare(evidenceSortKey(right)));
    return {
      contribution_id: contributionIdForSubject(subject),
      subject,
      evidence,
    };
  }).sort((left, right) => left.contribution_id.localeCompare(right.contribution_id));
}

export function createContributionIndex(contributions, privateKey, options = {}) {
  const controller = didFromPrivateKey(privateKey);
  const expectedController = options.expectedController ?? CONTRIBUTION_INDEX_CONTROLLER;
  assert(controller === expectedController, "Private key does not match the configured contribution-index DID.");
  const issuedAt = new Date(instantMillis(options.issuedAt ?? Date.now(), "Contribution-index issued_at")).toISOString();
  const payload = {
    schema: CONTRIBUTION_INDEX_SCHEMA,
    project: CONTRIBUTION_INDEX_PROJECT,
    purpose: CONTRIBUTION_INDEX_PURPOSE,
    controller,
    issued_at: issuedAt,
    sequence: String(options.sequence ?? "1"),
    previous_index_sha256: options.previousIndexSha256 ?? null,
    control_claim_sha256: options.controlClaimSha256,
    contributions: normalizeContributions(contributions),
  };
  validateContributionIndexPayload(payload, { expectedController });
  const document = {
    payload,
    proof: {
      type: "Ed25519",
      encoding: "base64url",
      value: signUtf8(privateKey, contributionIndexSigningInput(payload, { expectedController })).toString("base64url"),
    },
  };
  const serialized = serializeContributionIndex(document, { expectedController });
  return {
    document,
    serialized,
    index_sha256: sha256Hex(serialized),
  };
}

export function verifyContributionIndex(input, options = {}) {
  const document = typeof input === "string" ? parseContributionIndex(input, options) : input;
  const { signature } = validateContributionIndexDocument(document, options);
  assert(
    verifyUtf8(document.payload.controller, contributionIndexSigningInput(document.payload, options), signature),
    "Contribution-index signature is invalid.",
  );
  const serialized = `${canonicalize(document)}\n`;
  return {
    document,
    serialized,
    index_sha256: sha256Hex(serialized),
    signature_valid: true,
  };
}

export function verifyContributionIndexReplacement(previousInput, nextLink, options = {}) {
  assertExactObject(
    nextLink,
    new Set(["sequence", "previous_index_sha256"]),
    "Contribution-index replacement link",
  );
  assert(
    typeof nextLink.sequence === "string" && POSITIVE_DECIMAL_RE.test(nextLink.sequence),
    "Replacement sequence is invalid.",
  );
  assertHash(nextLink.previous_index_sha256, "Replacement previous_index_sha256");
  const previous = verifyContributionIndex(previousInput, options);
  assert(
    BigInt(nextLink.sequence) === BigInt(previous.document.payload.sequence) + 1n,
    "Replacement sequence must increment the existing index by exactly one.",
  );
  assert(
    nextLink.previous_index_sha256 === previous.index_sha256,
    "Replacement previous_index_sha256 does not name the existing index.",
  );
  return previous;
}

export function verifyContributionIndexControlClaim(indexInput, controlClaimText, options = {}) {
  const index = verifyContributionIndex(indexInput, options);
  const controlClaim = verifyControlClaim(controlClaimText, {
    expectedController: options.expectedController ?? CONTRIBUTION_INDEX_CONTROLLER,
    at: index.document.payload.issued_at,
  });
  assert(
    controlClaim.claim_sha256 === index.document.payload.control_claim_sha256,
    "Contribution-index control-claim hash does not match the supplied claim.",
  );
  assert(
    controlClaim.document.payload.controller === index.document.payload.controller,
    "Contribution-index and control-claim controllers differ.",
  );
  return { ...index, control_claim: controlClaim };
}

function parseEventArchive(text) {
  assert(typeof text === "string" && Buffer.byteLength(text, "utf8") <= 16 * 1024 * 1024, "Event archive is invalid or oversized.");
  return text.split("\n").filter(Boolean).map((line, index) => {
    try {
      return JSON.parse(line);
    } catch {
      throw new Error(`Event archive line ${index + 1} is invalid JSON.`);
    }
  });
}

function reportBindings(report, status) {
  assert(isPlainObject(report) && report.schema === "swarmproof-report-v1", "Public report is invalid.");
  assert(isPlainObject(status) && status.schema === "swarmproof-status-v1", "Public status is invalid.");
  const reportSha256 = sha256Hex(canonicalize(report));
  assert(status.report_sha256 === reportSha256, "Public report hash does not match status.");
  const snapshotManifestSha256 = sha256Hex(canonicalize(report.snapshot_manifest));
  assert(report.snapshot_manifest_sha256 === snapshotManifestSha256, "Public snapshot manifest hash is invalid.");
  assert(status.snapshot_manifest_sha256 === snapshotManifestSha256, "Public snapshot manifest hash does not match status.");
  assert(Array.isArray(report.events), "Public report events are invalid.");
  assert(Array.isArray(report.semantically_ignored), "Public report semantic exclusions are invalid.");
  return { reportSha256, snapshotManifestSha256 };
}

function resultFacetFromLevel(level) {
  assert(EVIDENCE_LEVELS.has(level), "SwarmProof RESULT evidence level is invalid.");
  return {
    attributable: level !== "OBSERVED",
    reproducible: ["REPRODUCIBLE", "CROSS-KEY-REVIEWED", "ACCEPTED"].includes(level),
    cross_key_reviewed: ["CROSS-KEY-REVIEWED", "ACCEPTED"].includes(level),
    swarmproof_internal_accepted: level === "ACCEPTED",
  };
}

export function deriveContributionFacets(indexInput, project) {
  const index = typeof indexInput === "string" ? verifyContributionIndex(indexInput) : indexInput;
  const payload = index.document?.payload ?? index.payload ?? index;
  validateContributionIndexPayload(payload, { expectedController: project.config.coordinator_did });
  const { reportSha256, snapshotManifestSha256 } = reportBindings(project.report, project.status);
  assert(
    project.reportVerification?.schema === "swarmproof-report-verification-v1"
      && project.reportVerification.validation_scope === "project-context"
      && project.reportVerification.report_sha256 === reportSha256
      && project.reportVerification.snapshot_manifest_sha256 === snapshotManifestSha256
      && project.reportVerification.checks?.report_status_binding === "pass"
      && project.reportVerification.checks?.audit_core_replay === "pass"
      && project.reportVerification.checks?.archive_manifest_binding === "pass"
      && project.reportVerification.checks?.evidence_status_binding === "pass",
    "Contribution facets require the matching full project report replay verification.",
  );
  const records = Array.isArray(project.events) ? project.events : parseEventArchive(project.events);
  const graph = analyzeEventSemantics(records, {
    allowedRepositories: new Set([project.config.repository]),
    allowedTasks: new Set(project.tasks.tasks.map(task => task.id)),
    coordinatorDid: project.config.coordinator_did,
    startsAt: project.config.starts_at,
    endsAt: project.config.ends_at,
  });
  const effectiveReviewByPair = new Map();
  for (const review of graph.verified
    .filter(event => graph.validReviewIds.has(event.event_id))
    .sort(compareEventChronology)) {
    effectiveReviewByPair.set(
      `${review.payload.review.target_event_id}\u0000${review.payload.did}`,
      review,
    );
  }
  const reportById = new Map(project.report.events.map(event => [event.event_id, event]));
  const results = [];

  for (const contribution of payload.contributions) {
    const facets = {
      controller_assertion: "signed-index",
      server_observations: [],
      swarmproof: null,
      cross_key_reviews: [],
      upstream_acceptances: [],
      external_adoptions: [],
      official_tasks: [],
    };
    let boundResultId = null;
    for (const evidence of contribution.evidence) {
      if (evidence.kind === "swarmproof-result-snapshot") {
        assert(facets.swarmproof === null, "A contribution may bind only one SwarmProof RESULT snapshot.");
        assert(evidence.publication_commit === project.publicationCommit, "SwarmProof evidence publication commit does not match the loaded snapshot.");
        assert(evidence.report_sha256 === reportSha256, "SwarmProof evidence report hash is stale or mismatched.");
        assert(evidence.snapshot_manifest_sha256 === snapshotManifestSha256, "SwarmProof evidence snapshot hash is stale or mismatched.");
        const summary = reportById.get(evidence.result_event_id);
        const event = graph.eventById.get(evidence.result_event_id);
        assert(summary?.type === "RESULT" && event?.payload.type === "RESULT", "Indexed SwarmProof RESULT is missing.");
        assert(graph.validResultIds.has(evidence.result_event_id), "Indexed SwarmProof RESULT lacks valid TASK ancestry.");
        assert(event.payload.did === payload.controller, "Indexed SwarmProof RESULT was not signed by the index controller.");
        assert(summary.did === event.payload.did, "Indexed SwarmProof RESULT author differs between archive and report.");
        assert(
          typeof summary.artifact?.repository === "string"
            && sameRepository(summary.artifact.repository, contribution.subject.repository),
          "Indexed SwarmProof RESULT repository does not match its subject.",
        );
        assert(summary.artifact?.sha256 === contribution.subject.content_sha256, "Indexed SwarmProof RESULT bytes do not match its subject.");
        assert(!project.report.semantically_ignored.some(entry => (
          entry.event_id === evidence.result_event_id && entry.reason === "duplicate-result-artifact"
        )), "Indexed SwarmProof RESULT is a duplicate artifact representative.");
        const levelFacets = resultFacetFromLevel(summary.evidence_level);
        if (levelFacets.reproducible) {
          assert(summary.artifact_check?.status === "pass", "Reproducible SwarmProof evidence lacks a passing artifact check.");
        }
        facets.swarmproof = {
          result_event_id: evidence.result_event_id,
          evidence_level: summary.evidence_level,
          ...levelFacets,
          source_transport: summary.source_ts === null ? "missing" : "server-reported",
          independence: "unknown",
        };
        boundResultId = evidence.result_event_id;
      } else if (evidence.kind === "cross-key-review") {
        assert(evidence.report_sha256 === reportSha256, "Cross-key review report hash is stale or mismatched.");
        assert(evidence.publication_commit === project.publicationCommit, "Cross-key review publication commit does not match the loaded snapshot.");
        assert(evidence.snapshot_manifest_sha256 === snapshotManifestSha256, "Cross-key review snapshot hash is stale or mismatched.");
        assert(boundResultId === null || boundResultId === evidence.target_event_id, "Cross-key review targets a different contribution RESULT.");
        const review = graph.eventById.get(evidence.review_event_id);
        const target = graph.eventById.get(evidence.target_event_id);
        assert(review?.payload.type === "REVIEW" && graph.validReviewIds.has(review.event_id), "Indexed cross-key REVIEW is not semantically valid.");
        assert(target?.payload.type === "RESULT" && graph.validResultIds.has(target.event_id), "Indexed cross-key REVIEW target is invalid.");
        assert(review.payload.review.target_event_id === target.event_id, "Indexed cross-key REVIEW target does not match.");
        assert(review.payload.did !== target.payload.did, "Indexed review is self-review, not cross-key evidence.");
        const effectiveReview = effectiveReviewByPair.get(`${target.event_id}\u0000${review.payload.did}`);
        assert(
          effectiveReview?.event_id === review.event_id,
          "Indexed cross-key REVIEW was superseded by a later valid verdict from the same reviewer key.",
        );
        assert(
          sameRepository(target.payload.artifact.repository, contribution.subject.repository),
          "Cross-key REVIEW target repository differs from the subject.",
        );
        assert(target.payload.artifact.sha256 === contribution.subject.content_sha256, "Cross-key REVIEW target bytes differ from the subject.");
        if (review.payload.review.verdict === "PASS") {
          const targetSummary = reportById.get(target.event_id);
          assert(
            Array.isArray(targetSummary?.cross_key_reviewers)
              && targetSummary.cross_key_reviewers.includes(review.payload.did),
            "Effective PASS reviewer is missing from the replayed RESULT summary.",
          );
        }
        facets.cross_key_reviews.push({
          review_event_id: review.event_id,
          target_event_id: target.event_id,
          reviewer_did: review.payload.did,
          verdict: review.payload.review.verdict,
          effective: true,
          different_signing_key: true,
          independence: "unknown",
        });
      } else if (evidence.kind === "server-observation") {
        facets.server_observations.push({
          service: evidence.service,
          room: evidence.room,
          source_seq: evidence.source_seq,
          source_ts: evidence.source_ts,
          message_sha256: evidence.message_sha256,
          transport_authentication: "server-reported",
          endorsement: "not-established",
        });
      } else if (evidence.kind === "upstream-acceptance") {
        facets.upstream_acceptances.push({
          repository: evidence.repository,
          pull_request: evidence.pull_request,
          accepted_commit: evidence.accepted_commit,
          validation: "not-checked-offline",
          authorship: "controller-self-asserted",
        });
      } else if (evidence.kind === "external-adoption") {
        facets.external_adoptions.push({
          repository: evidence.repository,
          commit: evidence.commit,
          relation: evidence.relation,
          validation: "not-checked-offline",
          operator_independence: "unknown",
        });
      } else if (evidence.kind === "official-task") {
        facets.official_tasks.push({
          authority: evidence.authority,
          task_uri: evidence.task_uri,
          stage: "submitted",
          task_source_validation: "not-checked-offline",
          submission_validation: "not-checked-offline",
          official_acceptance: "not-claimed",
          reward_status: "not-claimed",
        });
      }
    }
    for (const review of facets.cross_key_reviews) {
      assert(boundResultId === review.target_event_id, "Cross-key review requires the matching SwarmProof RESULT evidence on the same contribution.");
    }
    results.push({
      contribution_id: contribution.contribution_id,
      subject: contribution.subject,
      facets,
    });
  }
  const counts = {
    unique_contributions: results.length,
    with_swarmproof_attribution: results.filter(item => item.facets.swarmproof?.attributable).length,
    with_reproducible_artifact: results.filter(item => item.facets.swarmproof?.reproducible).length,
    with_cross_key_review: results.filter(item => item.facets.cross_key_reviews.length > 0 || item.facets.swarmproof?.cross_key_reviewed).length,
    with_cross_key_pass_review: results.filter(item => (
      item.facets.cross_key_reviews.some(review => review.verdict === "PASS")
      || item.facets.swarmproof?.cross_key_reviewed
    )).length,
    with_swarmproof_internal_acceptance: results.filter(item => item.facets.swarmproof?.swarmproof_internal_accepted).length,
    with_upstream_acceptance_reference: results.filter(item => item.facets.upstream_acceptances.length > 0).length,
    with_external_adoption_reference: results.filter(item => item.facets.external_adoptions.length > 0).length,
    with_official_task_submission: results.filter(item => item.facets.official_tasks.length > 0).length,
  };
  return {
    schema: "swarmproof-contribution-index-project-verification-v1",
    validation_scope: "facets-after-matching-full-project-replay",
    controller: payload.controller,
    report_sha256: reportSha256,
    snapshot_manifest_sha256: snapshotManifestSha256,
    counts,
    contributions: results,
    limitations: [
      "Counts are per unique contribution subject; evidence facets are never added together as separate contributions.",
      "A DID signature proves control of a key, not a person, author, model, or independent operator.",
      "Technocore source metadata is server-reported and is not covered by the inner SP1 signature.",
      "Cross-key means a different signing key only; reviewer independence and review quality remain unknown.",
      "SwarmProof internal acceptance is not upstream acceptance, official task acceptance, endorsement, or reward eligibility.",
      "Upstream, adoption, and official-task references require separate source-specific checks; this offline scope does not validate them.",
    ],
  };
}

export function contributionsFromSwarmproofReport(report, status, publicationCommit) {
  assert(typeof publicationCommit === "string" && COMMIT_RE.test(publicationCommit), "SwarmProof publication commit is invalid.");
  const { reportSha256, snapshotManifestSha256 } = reportBindings(report, status);
  const seen = new Set();
  const contributions = [];
  for (const event of [...report.events].sort((left, right) => left.event_id.localeCompare(right.event_id))) {
    if (
      event.type !== "RESULT"
      || !event.artifact
      || !["REPRODUCIBLE", "CROSS-KEY-REVIEWED", "ACCEPTED"].includes(event.evidence_level)
    ) continue;
    if (report.semantically_ignored.some(entry => (
      entry.event_id === event.event_id && entry.reason === "duplicate-result-artifact"
    ))) continue;
    const subject = {
      type: "git-content",
      repository: event.artifact.repository,
      content_sha256: event.artifact.sha256,
    };
    const contributionId = contributionIdForSubject(subject);
    if (seen.has(contributionId)) continue;
    seen.add(contributionId);
    contributions.push({
      subject,
      evidence: [{
        kind: "swarmproof-result-snapshot",
        result_event_id: event.event_id,
        publication_commit: publicationCommit,
        report_sha256: reportSha256,
        snapshot_manifest_sha256: snapshotManifestSha256,
      }],
    });
  }
  return normalizeContributions(contributions);
}

async function readBoundedResponse(response, maximumBytes) {
  assert(response?.ok === true && response.status === 200, "Contribution-index publication did not return HTTP 200.");
  const declaredLength = response.headers?.get?.("content-length");
  if (declaredLength !== null && declaredLength !== undefined) {
    assert(/^\d+$/u.test(declaredLength), "Contribution-index publication Content-Length is invalid.");
    assert(Number(declaredLength) <= maximumBytes, "Contribution-index publication is oversized.");
  }
  assert(response.body && typeof response.body.getReader === "function", "Contribution-index publication has no readable body.");
  const reader = response.body.getReader();
  const chunks = [];
  let bytes = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      const chunk = Buffer.from(value);
      bytes += chunk.length;
      assert(bytes <= maximumBytes, "Contribution-index publication is oversized.");
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
        "user-agent": "swarmproof-contribution-index-v1",
      },
    });
    return await readBoundedResponse(response, CONTRIBUTION_INDEX_MAX_BYTES);
  } finally {
    clearTimeout(timeout);
  }
}

export async function verifyContributionIndexPublications(referenceText, options = {}) {
  const verified = verifyContributionIndex(referenceText, options);
  const fetchImplementation = options.fetchImplementation ?? globalThis.fetch;
  assert(typeof fetchImplementation === "function", "A fetch implementation is required.");
  const timeoutMs = options.timeoutMs ?? 10_000;
  assert(Number.isSafeInteger(timeoutMs) && timeoutMs >= 1 && timeoutMs <= 30_000, "Publication timeout is invalid.");
  const publications = await Promise.all(CONTRIBUTION_INDEX_PUBLICATIONS.map(async publication => {
    const text = await fetchFixedPublication(publication, fetchImplementation, timeoutMs);
    assert(text === verified.serialized, `Contribution-index publication mismatch at ${publication.type}.`);
    const copy = verifyContributionIndex(text, options);
    assert(copy.index_sha256 === verified.index_sha256, "Contribution-index publication digest mismatch.");
    return {
      type: publication.type,
      url: publication.url,
      index_sha256: copy.index_sha256,
      status: "pass",
    };
  }));
  return {
    ...verified,
    publications,
    limitations: [
      "Publication verification proves exact signed bytes were served from configured resources at verification time; it does not validate every evidence source.",
      "GitHub and Pages share a deployment chain and are correlated copies, not independent witnesses.",
      "The verifier never follows a URL supplied by the contribution index.",
    ],
  };
}
