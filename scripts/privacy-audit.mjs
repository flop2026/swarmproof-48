#!/usr/bin/env node

import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { readdir, readFile } from "node:fs/promises";
import path from "node:path";
import { promisify } from "node:util";
import { canonicalize } from "../lib/canonical.mjs";
import { verifyEnvelope } from "../lib/protocol.mjs";

const executeFile = promisify(execFile);
const ROOT = process.cwd();
const INCLUDE_DIST = process.env.SWARMPROOF_AUDIT_DIST === "1";
const EXCLUDED_DIRECTORIES = new Set([".git", "node_modules", "coverage", "tmp", "data-private"]);
const ALLOWED_EMAIL_RE = /^(?:\d+\+)?flop2026@users\.noreply\.github\.com$/i;
const EMAIL_RE = /[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/giu;
const HASH_RE = /^[0-9a-f]{64}$/u;
const COMMIT_RE = /^[0-9a-f]{40}$/u;
const DID_RE = /^did:key:z6Mk[1-9A-HJ-NP-Za-km-z]+$/u;
const ROOM_RE = /^[a-z0-9][a-z0-9_-]{0,47}$/u;
const TASK_RE = /^[a-z0-9][a-z0-9_-]{0,63}$/u;
const CANONICAL_TIME_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u;
const UTC_TIME_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/u;
const EVENT_TYPES = new Set(["TASK", "CLAIM", "RESULT", "REVIEW", "PROMOTE", "CHECKPOINT"]);
const EVENT_STATES = new Set(["preparation", "active", "complete"]);
const EVIDENCE_LEVELS = new Set([
  "OBSERVED",
  "ATTRIBUTABLE",
  "REPRODUCIBLE",
  "CROSS-KEY-REVIEWED",
  "ACCEPTED",
]);
const REVIEWED_BINARY_SHA256 = new Map([
  ["public/og-card.png", "9293dbd0bafc9ef8158e770ae9f00b97e410a9c77c80bfcc511c5fcd392ac490"],
  ["dist/og-card.png", "9293dbd0bafc9ef8158e770ae9f00b97e410a9c77c80bfcc511c5fcd392ac490"],
]);

const TEXT_RULES = [
  ["absolute-home-path", /(?:\/Users\/|\/home\/|[A-Za-z]:\\Users\\)/u],
  ["private-key-material", /-----BEGIN (?:(?:[A-Z0-9]+ )*PRIVATE KEY|PGP PRIVATE KEY BLOCK)-----/u],
  ["github-token", /\b(?:github_pat_[A-Za-z0-9_]{20,}|gh[oprsu]_[A-Za-z0-9]{20,})\b/u],
  ["gitlab-token", /\bglpat-[A-Za-z0-9_-]{20,}\b/u],
  ["huggingface-token", /\bhf_[A-Za-z0-9]{30,}\b/u],
  ["npm-token", /\bnpm_[A-Za-z0-9]{30,}\b/u],
  ["pypi-token", /\bpypi-[A-Za-z0-9_-]{40,}\b/u],
  ["aws-access-key-id", /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/u],
  ["google-api-key", /\bAIza[0-9A-Za-z_-]{35}\b/u],
  ["slack-token", /\bxox[baprs]-[A-Za-z0-9-]{20,}\b/u],
  ["provider-secret-key", /\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b/u],
  ["generic-api-key", /\bsk-[A-Za-z0-9_-]{20,}\b/u],
  ["jwt-like-token", /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/u],
  ["credential-assignment", /\b(?:authorization|api[_-]?key|client[_-]?secret|access[_-]?token|private[_-]?key)\s*[:=]\s*["']?(?:bearer\s+)?[A-Za-z0-9_./+=:-]{16,}/iu],
  ["wallet-seed-label", /\b(?:seed phrase|mnemonic)\s*[:=]/iu],
  ["source-map-reference", /sourceMappingURL=/u],
];

const SENSITIVE_FILENAME_RE = /(?:^|\/)(?:\.env(?:\.[^/]*)?|id_(?:rsa|dsa|ecdsa|ed25519)|[^/]+\.(?:pem|key|p12|pfx|kdbx))$/iu;
const BINARY_EXTENSION_RE = /\.(?:png|jpe?g|gif|webp|avif|bmp|tiff?|ico|woff2?|ttf|otf|eot|pdf|wasm|zip|gz|bz2?|xz|7z|rar|tar|mp[34]|mov|webm|avi|mkv|flac|wav|docx?|xlsx?|pptx?)$/iu;

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function relativePath(file) {
  return path.relative(ROOT, file).split(path.sep).join("/");
}

function recordViolation(violations, file, rule) {
  violations.push({ file: relativePath(file), rule });
}

function recordSchemaViolation(violations, file, rule, error) {
  recordViolation(violations, file, rule);
  if (process.env.SWARMPROOF_AUDIT_DEBUG === "1") {
    console.error(`privacy audit debug: ${relativePath(file)}: ${error.message}`);
  }
}

function isPlainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function assertExactObject(value, requiredKeys, optionalKeys, label) {
  assert(isPlainObject(value), `${label} must be an object.`);
  const allowed = new Set([...requiredKeys, ...optionalKeys]);
  for (const key of requiredKeys) assert(Object.hasOwn(value, key), `${label} is missing a required field.`);
  for (const key of Object.keys(value)) assert(allowed.has(key), `${label} contains an unknown field.`);
}

function assertCounter(value, label) {
  assert(Number.isSafeInteger(value) && value >= 0, `${label} must be a non-negative safe integer.`);
}

function assertRatio(value, label) {
  assert(value === null || (Number.isFinite(value) && value >= 0 && value <= 1), `${label} must be null or a ratio.`);
}

function assertDerivedRatio(value, numerator, denominator, label) {
  assertRatio(value, label);
  if (denominator === 0) {
    assert(value === null, `${label} must be null when the sample is empty.`);
    return;
  }
  assert(value !== null, `${label} must be present when the sample is non-empty.`);
  assert(Math.abs(value - numerator / denominator) <= 1e-12, `${label} is inconsistent with its count.`);
}

function assertHash(value, label) {
  assert(typeof value === "string" && HASH_RE.test(value), `${label} must be a lowercase SHA-256.`);
}

function assertCanonicalTime(value, label) {
  assert(typeof value === "string" && CANONICAL_TIME_RE.test(value), `${label} must be canonical UTC.`);
  const parsed = new Date(value);
  assert(!Number.isNaN(parsed.getTime()) && parsed.toISOString() === value, `${label} is not a valid time.`);
}

function assertUtcTime(value, label) {
  assert(typeof value === "string" && UTC_TIME_RE.test(value), `${label} must be UTC.`);
  assert(Number.isFinite(Date.parse(value)), `${label} is not a valid time.`);
}

function assertBoundedText(value, label, maximum = 512) {
  assert(typeof value === "string" && value.length > 0 && value.length <= maximum, `${label} must be bounded text.`);
  assert(!/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/u.test(value), `${label} contains control characters.`);
}

function assertStringArray(value, label, maximumItems = 64, maximumLength = 512) {
  assert(Array.isArray(value) && value.length <= maximumItems, `${label} must be a bounded array.`);
  for (const item of value) assertBoundedText(item, `${label} item`, maximumLength);
}

function sha256Hex(value) {
  return createHash("sha256").update(value).digest("hex");
}

async function walk(directory, violations) {
  const entries = await readdir(directory, { withFileTypes: true });
  const files = [];
  for (const entry of entries.sort((left, right) => left.name.localeCompare(right.name))) {
    const absolute = path.join(directory, entry.name);
    if (directory === ROOT && entry.name === ".git") continue;
    if (entry.isSymbolicLink()) {
      recordViolation(violations, absolute, "symbolic-link-forbidden");
      continue;
    }
    if (entry.isDirectory()) {
      if (EXCLUDED_DIRECTORIES.has(entry.name)) continue;
      if (entry.name === "dist" && !INCLUDE_DIST) continue;
      files.push(...await walk(absolute, violations));
    } else if (entry.isFile()) {
      files.push(absolute);
    }
  }
  return files;
}

function scanFilename(file, deniedValues, violations) {
  const relative = relativePath(file);
  if (SENSITIVE_FILENAME_RE.test(relative)) recordViolation(violations, file, "sensitive-filename");
  for (const [rule, expression] of TEXT_RULES) {
    if (expression.test(relative)) recordViolation(violations, file, `${rule}-in-filename`);
  }
  for (const email of relative.match(EMAIL_RE) ?? []) {
    if (!ALLOWED_EMAIL_RE.test(email)) recordViolation(violations, file, "non-pseudonymous-email-in-filename");
  }
  const folded = relative.toLocaleLowerCase("en-US");
  if (deniedValues.some(value => folded.includes(value.toLocaleLowerCase("en-US")))) {
    recordViolation(violations, file, "local-denylist-match-in-filename");
  }
}

async function scanFile(file, violations) {
  const relative = relativePath(file);
  if (relative === "scripts/privacy-audit.mjs") return;
  const bytes = await readFile(file);
  if (BINARY_EXTENSION_RE.test(relative) || bytes.includes(0)) {
    const digest = sha256Hex(bytes);
    if (REVIEWED_BINARY_SHA256.get(relative) !== digest) {
      recordViolation(violations, file, "binary-media-requires-explicit-metadata-review");
    }
    return;
  }
  const content = bytes.toString("utf8");
  for (const [rule, expression] of TEXT_RULES) {
    if (expression.test(content)) recordViolation(violations, file, rule);
  }
  for (const email of content.match(EMAIL_RE) ?? []) {
    if (!ALLOWED_EMAIL_RE.test(email)) recordViolation(violations, file, "non-pseudonymous-email");
  }
  if (relative.endsWith(".map")) recordViolation(violations, file, "production-source-map");
}

async function loadLocalDenylist() {
  try {
    const content = await readFile(path.join(ROOT, "data-private/privacy-denylist.txt"), "utf8");
    return content.split("\n").map(value => value.trim()).filter(Boolean);
  } catch (error) {
    if (error.code === "ENOENT") return [];
    throw error;
  }
}

async function scanLocalDenylist(files, deniedValues, violations) {
  for (const file of files) {
    if (relativePath(file) === "scripts/privacy-audit.mjs") continue;
    const content = await readFile(file, "utf8").catch(() => null);
    if (content === null) continue;
    const folded = content.toLocaleLowerCase("en-US");
    if (deniedValues.some(value => folded.includes(value.toLocaleLowerCase("en-US")))) {
      recordViolation(violations, file, "local-denylist-match");
    }
  }
}

function parseJsonLines(content, label) {
  if (content === "") return [];
  const lines = content.endsWith("\n") ? content.slice(0, -1).split("\n") : content.split("\n");
  assert(lines.every(line => line.length > 0), `${label} contains a blank record.`);
  return lines.map(line => JSON.parse(line));
}

function validateArtifact(artifact, label) {
  assertExactObject(artifact, ["repository", "commit", "path", "sha256"], [], label);
  assert(/^[A-Za-z0-9_.-]{1,39}\/[A-Za-z0-9_.-]{1,100}$/u.test(artifact.repository), `${label}.repository is invalid.`);
  assert(COMMIT_RE.test(artifact.commit ?? ""), `${label}.commit is invalid.`);
  assert(/^(?!\/)(?!.*(?:^|\/)\.\.(?:\/|$))[A-Za-z0-9._/-]{1,240}$/u.test(artifact.path), `${label}.path is invalid.`);
  assertHash(artifact.sha256, `${label}.sha256`);
}

function validateReview(review, label) {
  assertExactObject(review, ["target_event_id", "verdict"], [], label);
  assertHash(review.target_event_id, `${label}.target_event_id`);
  assert(["PASS", "CHANGES", "REJECT"].includes(review.verdict), `${label}.verdict is invalid.`);
}

function validateArtifactCheck(check, label) {
  assert(isPlainObject(check), `${label} must be an object.`);
  if (check.status === "pass") {
    assertExactObject(check, ["status", "integrity", "replay"], [], label);
    validateIntegrityCheck(check.integrity, `${label}.integrity`);
    validateReplayCheck(check.replay, `${label}.replay`);
    assert(check.integrity.status === "pass" && check.replay.status === "pass", `${label} pass evidence is inconsistent.`);
  } else if (check.status === "fail") {
    assertExactObject(check, ["status", "reason", "integrity"], ["replay"], label);
    assert(/^[a-z0-9-]{1,80}$/u.test(check.reason), `${label}.reason is invalid.`);
    validateIntegrityCheck(check.integrity, `${label}.integrity`);
    if (check.replay !== undefined) validateReplayCheck(check.replay, `${label}.replay`);
  } else {
    assert(check.status === "not-checked", `${label}.status is invalid.`);
    assertExactObject(check, ["status"], ["reason", "representative_event_id"], label);
    if (check.reason !== undefined) assert(/^[a-z0-9-]{1,80}$/u.test(check.reason), `${label}.reason is invalid.`);
    if (check.representative_event_id !== undefined) {
      assert(check.reason === "duplicate-result-artifact", `${label}.representative_event_id is only valid for a duplicate.`);
      assertHash(check.representative_event_id, `${label}.representative_event_id`);
    }
  }
}

function validateIntegrityCheck(check, label) {
  assert(isPlainObject(check), `${label} must be an object.`);
  if (check.status === "pass") {
    assertExactObject(check, ["status", "sha256", "bytes"], [], label);
    assertHash(check.sha256, `${label}.sha256`);
    assertCounter(check.bytes, `${label}.bytes`);
    return;
  }
  assert(check.status === "fail", `${label}.status is invalid.`);
  assertExactObject(check, ["status", "reason"], ["actual_sha256"], label);
  assert(/^[a-z0-9-]{1,80}$/u.test(check.reason), `${label}.reason is invalid.`);
  if (check.actual_sha256 !== undefined) assertHash(check.actual_sha256, `${label}.actual_sha256`);
}

function validateReplayCheck(check, label) {
  assert(isPlainObject(check), `${label} must be an object.`);
  if (check.status === "pass") {
    assertExactObject(check, ["status", "check", "commit", "isolation"], [], label);
    assert(check.check === "node --test", `${label}.check is invalid.`);
    assert(COMMIT_RE.test(check.commit ?? ""), `${label}.commit is invalid.`);
    assert(check.isolation === "fresh-git-archive-secretless-process", `${label}.isolation is invalid.`);
    return;
  }
  assert(check.status === "fail", `${label}.status is invalid.`);
  assertExactObject(check, ["status", "reason", "commit"], [], label);
  assert(/^[a-z0-9-]{1,80}$/u.test(check.reason), `${label}.reason is invalid.`);
  assert(COMMIT_RE.test(check.commit ?? ""), `${label}.commit is invalid.`);
}

function validateEvidence(evidence, label) {
  const keys = ["observed", "attributable", "reproducible", "cross_key_reviewed", "accepted"];
  assertExactObject(evidence, keys, [], label);
  for (const key of keys) assertCounter(evidence[key], `${label}.${key}`);
  assert(evidence.attributable <= evidence.observed, `${label} attribution count is inconsistent.`);
  assert(evidence.reproducible <= evidence.attributable, `${label} reproducibility count is inconsistent.`);
  assert(evidence.cross_key_reviewed <= evidence.reproducible, `${label} review count is inconsistent.`);
  assert(evidence.accepted <= evidence.cross_key_reviewed, `${label} acceptance count is inconsistent.`);
}

function validateReviewEvidence(evidence, label) {
  const counterKeys = [
    "valid_review_events",
    "effective_reviewer_result_pairs",
    "superseded_review_events",
    "conflicting_reviewer_result_pairs",
    "effective_cross_key_pairs",
    "effective_cross_key_pass_pairs",
    "cross_key_pass_pairs_targeting_reproducible_results",
    "result_targets_with_cross_key_review",
    "reproducible_result_targets_with_cross_key_pass_review",
    "result_targets_with_multiple_cross_key_reviewers",
    "unique_cross_key_reviewer_keys",
    "top_cross_key_reviewer_share_ppm",
    "cross_key_reviewer_hhi_ppm",
  ];
  assertExactObject(evidence, [
    "basis",
    ...counterKeys,
    "effective_cross_key_verdicts",
    "independence",
  ], [], label);
  assert(evidence.basis === "latest-valid-review-per-reviewer-key-and-result", `${label}.basis is invalid.`);
  counterKeys.forEach(key => assertCounter(evidence[key], `${label}.${key}`));
  assertExactObject(evidence.effective_cross_key_verdicts, ["pass", "changes", "reject"], [], `${label}.effective_cross_key_verdicts`);
  for (const key of ["pass", "changes", "reject"]) {
    assertCounter(evidence.effective_cross_key_verdicts[key], `${label}.effective_cross_key_verdicts.${key}`);
  }
  assert(evidence.independence === "unknown", `${label}.independence must remain unknown.`);
  assert(
    evidence.effective_reviewer_result_pairs + evidence.superseded_review_events === evidence.valid_review_events,
    `${label} effective/superseded accounting is inconsistent.`,
  );
  assert(evidence.conflicting_reviewer_result_pairs <= evidence.effective_reviewer_result_pairs, `${label} conflict count is inconsistent.`);
  assert(evidence.effective_cross_key_pairs <= evidence.effective_reviewer_result_pairs, `${label} cross-key pair count is inconsistent.`);
  assert(
    Object.values(evidence.effective_cross_key_verdicts).reduce((sum, count) => sum + count, 0)
      === evidence.effective_cross_key_pairs,
    `${label} verdict accounting is inconsistent.`,
  );
  assert(evidence.effective_cross_key_pass_pairs === evidence.effective_cross_key_verdicts.pass, `${label} PASS count is inconsistent.`);
  assert(evidence.cross_key_pass_pairs_targeting_reproducible_results <= evidence.effective_cross_key_pass_pairs, `${label} reproducible PASS count is inconsistent.`);
  assert(evidence.result_targets_with_cross_key_review <= evidence.effective_cross_key_pairs, `${label} target count is inconsistent.`);
  assert(evidence.reproducible_result_targets_with_cross_key_pass_review <= evidence.cross_key_pass_pairs_targeting_reproducible_results, `${label} reproducible target count is inconsistent.`);
  assert(evidence.result_targets_with_multiple_cross_key_reviewers <= evidence.result_targets_with_cross_key_review, `${label} multi-reviewer target count is inconsistent.`);
  assert(evidence.unique_cross_key_reviewer_keys <= evidence.effective_cross_key_pairs, `${label} reviewer-key count is inconsistent.`);
  for (const key of ["top_cross_key_reviewer_share_ppm", "cross_key_reviewer_hhi_ppm"]) {
    assert(evidence[key] <= 1_000_000, `${label}.${key} is out of bounds.`);
  }
  if (evidence.effective_cross_key_pairs === 0) {
    assert(evidence.unique_cross_key_reviewer_keys === 0, `${label} empty reviewer-key count is inconsistent.`);
    assert(evidence.top_cross_key_reviewer_share_ppm === 0, `${label} empty top share is inconsistent.`);
    assert(evidence.cross_key_reviewer_hhi_ppm === 0, `${label} empty HHI is inconsistent.`);
  } else {
    assert(evidence.unique_cross_key_reviewer_keys > 0, `${label} reviewer-key count is inconsistent.`);
    assert(evidence.top_cross_key_reviewer_share_ppm > 0, `${label} top share is inconsistent.`);
    assert(evidence.cross_key_reviewer_hhi_ppm > 0, `${label} HHI is inconsistent.`);
  }
}

function validateReportEvent(event, label) {
  assertExactObject(event, [
    "event_id", "type", "task_id", "did", "claimed_at", "observed_at", "source_ts", "parent_event_ids",
    "content_sha256", "artifact", "artifact_check", "review", "cross_key_reviewers",
    "independence", "evidence_level",
  ], [], label);
  assertHash(event.event_id, `${label}.event_id`);
  assert(EVENT_TYPES.has(event.type), `${label}.type is invalid.`);
  assert(TASK_RE.test(event.task_id ?? ""), `${label}.task_id is invalid.`);
  assert(DID_RE.test(event.did ?? ""), `${label}.did is invalid.`);
  assertCanonicalTime(event.claimed_at, `${label}.claimed_at`);
  if (event.observed_at !== null) assertCanonicalTime(event.observed_at, `${label}.observed_at`);
  if (event.source_ts !== null) assertCanonicalTime(event.source_ts, `${label}.source_ts`);
  assert(Array.isArray(event.parent_event_ids) && event.parent_event_ids.length <= 16, `${label}.parent_event_ids is invalid.`);
  assert(new Set(event.parent_event_ids).size === event.parent_event_ids.length, `${label}.parent_event_ids contains duplicates.`);
  for (const parent of event.parent_event_ids) assertHash(parent, `${label}.parent_event_ids item`);
  assertHash(event.content_sha256, `${label}.content_sha256`);
  if (event.artifact === null) assert(event.type !== "RESULT", `${label}.artifact is missing.`);
  else {
    assert(event.type === "RESULT", `${label}.artifact is only valid for RESULT.`);
    validateArtifact(event.artifact, `${label}.artifact`);
  }
  if (event.artifact_check === null) assert(event.type !== "RESULT", `${label}.artifact_check is missing.`);
  else {
    assert(event.type === "RESULT", `${label}.artifact_check is only valid for RESULT.`);
    validateArtifactCheck(event.artifact_check, `${label}.artifact_check`);
  }
  if (event.review === null) assert(event.type !== "REVIEW", `${label}.review is missing.`);
  else {
    assert(event.type === "REVIEW", `${label}.review is only valid for REVIEW.`);
    validateReview(event.review, `${label}.review`);
  }
  assert(Array.isArray(event.cross_key_reviewers) && event.cross_key_reviewers.length <= 256, `${label}.cross_key_reviewers is invalid.`);
  assert(new Set(event.cross_key_reviewers).size === event.cross_key_reviewers.length, `${label}.cross_key_reviewers contains duplicates.`);
  for (const did of event.cross_key_reviewers) assert(DID_RE.test(did), `${label}.cross_key_reviewers contains an invalid DID.`);
  assert(event.independence === "unknown", `${label}.independence must remain unknown.`);
  assert(EVIDENCE_LEVELS.has(event.evidence_level), `${label}.evidence_level is invalid.`);
}

function validateClusterList(value, label, hashLength) {
  assert(Array.isArray(value) && value.length <= 20, `${label} must contain at most 20 entries.`);
  const hashPattern = new RegExp(`^[0-9a-f]{${hashLength}}$`, "u");
  for (const entry of value) {
    assertExactObject(entry, ["cluster_sha256", "count"], [], `${label} entry`);
    assert(hashPattern.test(entry.cluster_sha256), `${label} contains an invalid cluster hash.`);
    assertCounter(entry.count, `${label} count`);
    assert(entry.count > 1, `${label} counts must represent duplicates.`);
  }
}

function validateNetworkSample(sample, label) {
  assertExactObject(sample, ["schema", "generated_at", "selection", "aggregate", "failures", "limitations"], [], label);
  assert(
    sample.schema === "swarmproof-network-sample-v1"
    || sample.schema === "swarmproof-network-sample-v2",
    `${label}.schema is invalid.`,
  );
  assertCanonicalTime(sample.generated_at, `${label}.generated_at`);
  const selectionKeys = [
    "endpoint",
    "rooms_requested",
    "rooms_returned",
    "room_entries_rejected",
    "room_entries_deduplicated",
    "room_entries_truncated",
    "room_entries_uninspected",
    "messages_per_room_requested",
    "message_entries_rejected",
    "message_entries_deduplicated",
    "message_entries_truncated",
    "message_entries_uninspected",
    "rooms_failed",
  ];
  assertExactObject(sample.selection, selectionKeys, [], `${label}.selection`);
  assert(sample.selection.endpoint === "/rooms", `${label}.selection.endpoint is invalid.`);
  for (const key of selectionKeys.filter(key => key !== "endpoint")) {
    assertCounter(sample.selection[key], `${label}.selection.${key}`);
  }
  assert(sample.selection.rooms_requested >= 1 && sample.selection.rooms_requested <= 200, `${label}.selection.rooms_requested is out of bounds.`);
  assert(sample.selection.rooms_returned <= 200, `${label}.selection.rooms_returned is out of bounds.`);
  assert(sample.selection.messages_per_room_requested >= 1 && sample.selection.messages_per_room_requested <= 200, `${label}.selection.messages_per_room_requested is out of bounds.`);
  assert(sample.selection.rooms_failed <= sample.selection.rooms_returned, `${label}.selection.rooms_failed is inconsistent.`);

  const aggregateV1Keys = [
    "messages", "did_shaped_senders", "did_shaped_message_share", "exact_unique_messages", "exact_duplicate_share",
    "exact_duplicate_clusters", "normalized_unique_messages", "normalized_duplicate_share",
    "normalized_duplicate_clusters", "minhash_similarity_threshold", "minhash_lsh_bands",
    "minhash_lsh_rows_per_band", "minhash_similarity_clusters", "minhash_similarity_message_share",
    "minhash_candidate_pairs_checked", "minhash_candidate_generation_truncated",
    "exact_messages_repeated_across_rooms", "top_exact_clusters", "top_normalized_clusters",
    "top_minhash_similarity_clusters",
  ];
  const aggregateV2Keys = [
    ...aggregateV1Keys,
    "exact_clustered_messages", "exact_clustered_message_share",
    "normalized_clustered_messages", "normalized_clustered_message_share",
    "minhash_similarity_clustered_messages", "minhash_similarity_clustered_message_share",
  ];
  const aggregateKeys = sample.schema === "swarmproof-network-sample-v2"
    ? aggregateV2Keys
    : aggregateV1Keys;
  assertExactObject(sample.aggregate, aggregateKeys, [], `${label}.aggregate`);
  for (const key of [
    "messages", "did_shaped_senders", "exact_unique_messages", "exact_duplicate_clusters",
    "normalized_unique_messages", "normalized_duplicate_clusters", "minhash_lsh_bands",
    "minhash_lsh_rows_per_band", "minhash_similarity_clusters", "minhash_candidate_pairs_checked",
    "exact_messages_repeated_across_rooms",
  ]) assertCounter(sample.aggregate[key], `${label}.aggregate.${key}`);
  assertRatio(sample.aggregate.did_shaped_message_share, `${label}.aggregate.did_shaped_message_share`);
  assertRatio(sample.aggregate.exact_duplicate_share, `${label}.aggregate.exact_duplicate_share`);
  assertRatio(sample.aggregate.normalized_duplicate_share, `${label}.aggregate.normalized_duplicate_share`);
  assertRatio(sample.aggregate.minhash_similarity_message_share, `${label}.aggregate.minhash_similarity_message_share`);
  assert(sample.aggregate.minhash_similarity_threshold === 0.75, `${label}.aggregate.minhash_similarity_threshold is invalid.`);
  assert(sample.aggregate.minhash_lsh_bands === 8, `${label}.aggregate.minhash_lsh_bands is invalid.`);
  assert(sample.aggregate.minhash_lsh_rows_per_band === 4, `${label}.aggregate.minhash_lsh_rows_per_band is invalid.`);
  assert(sample.aggregate.minhash_candidate_generation_truncated === false || sample.aggregate.minhash_candidate_generation_truncated === true, `${label}.aggregate.minhash truncation flag is invalid.`);
  assert(sample.aggregate.minhash_candidate_pairs_checked <= 250_000, `${label}.aggregate.minhash candidate count is out of bounds.`);
  assert(sample.aggregate.did_shaped_senders <= sample.aggregate.messages, `${label}.aggregate.did_shaped_senders is inconsistent.`);
  assert(sample.aggregate.exact_unique_messages <= sample.aggregate.messages, `${label}.aggregate.exact_unique_messages is inconsistent.`);
  assert(sample.aggregate.normalized_unique_messages <= sample.aggregate.messages, `${label}.aggregate.normalized_unique_messages is inconsistent.`);
  assert(sample.aggregate.normalized_unique_messages <= sample.aggregate.exact_unique_messages, `${label}.aggregate normalized uniqueness is inconsistent.`);
  assert(sample.aggregate.exact_messages_repeated_across_rooms <= sample.aggregate.exact_unique_messages, `${label}.aggregate cross-room count is inconsistent.`);
  assertDerivedRatio(
    sample.aggregate.exact_duplicate_share,
    sample.aggregate.messages - sample.aggregate.exact_unique_messages,
    sample.aggregate.messages,
    `${label}.aggregate.exact_duplicate_share`,
  );
  assertDerivedRatio(
    sample.aggregate.normalized_duplicate_share,
    sample.aggregate.messages - sample.aggregate.normalized_unique_messages,
    sample.aggregate.messages,
    `${label}.aggregate.normalized_duplicate_share`,
  );

  if (sample.schema === "swarmproof-network-sample-v2") {
    for (const key of [
      "exact_clustered_messages",
      "normalized_clustered_messages",
      "minhash_similarity_clustered_messages",
    ]) assertCounter(sample.aggregate[key], `${label}.aggregate.${key}`);
    for (const key of [
      "exact_clustered_message_share",
      "normalized_clustered_message_share",
      "minhash_similarity_clustered_message_share",
    ]) assertRatio(sample.aggregate[key], `${label}.aggregate.${key}`);

    const exactClusteredExpected = sample.aggregate.messages
      - sample.aggregate.exact_unique_messages
      + sample.aggregate.exact_duplicate_clusters;
    const normalizedClusteredExpected = sample.aggregate.messages
      - sample.aggregate.normalized_unique_messages
      + sample.aggregate.normalized_duplicate_clusters;
    assert(sample.aggregate.exact_clustered_messages === exactClusteredExpected, `${label}.aggregate exact clustered count is inconsistent.`);
    assert(sample.aggregate.normalized_clustered_messages === normalizedClusteredExpected, `${label}.aggregate normalized clustered count is inconsistent.`);
    assert(sample.aggregate.exact_clustered_messages <= sample.aggregate.normalized_clustered_messages, `${label}.aggregate exact/normalized coverage is inconsistent.`);
    assert(sample.aggregate.normalized_clustered_messages <= sample.aggregate.minhash_similarity_clustered_messages, `${label}.aggregate normalized/MinHash coverage is inconsistent.`);
    assert(sample.aggregate.minhash_similarity_clustered_messages <= sample.aggregate.messages, `${label}.aggregate MinHash clustered count is inconsistent.`);
    assert(sample.aggregate.exact_duplicate_clusters * 2 <= sample.aggregate.exact_clustered_messages, `${label}.aggregate exact cluster count is inconsistent.`);
    assert(sample.aggregate.normalized_duplicate_clusters * 2 <= sample.aggregate.normalized_clustered_messages, `${label}.aggregate normalized cluster count is inconsistent.`);
    assert(sample.aggregate.minhash_similarity_clusters * 2 <= sample.aggregate.minhash_similarity_clustered_messages, `${label}.aggregate MinHash cluster count is inconsistent.`);
    assertDerivedRatio(sample.aggregate.exact_clustered_message_share, sample.aggregate.exact_clustered_messages, sample.aggregate.messages, `${label}.aggregate.exact_clustered_message_share`);
    assertDerivedRatio(sample.aggregate.normalized_clustered_message_share, sample.aggregate.normalized_clustered_messages, sample.aggregate.messages, `${label}.aggregate.normalized_clustered_message_share`);
    assertDerivedRatio(sample.aggregate.minhash_similarity_clustered_message_share, sample.aggregate.minhash_similarity_clustered_messages, sample.aggregate.messages, `${label}.aggregate.minhash_similarity_clustered_message_share`);
    assert(sample.aggregate.minhash_similarity_message_share === sample.aggregate.minhash_similarity_clustered_message_share, `${label}.aggregate legacy MinHash share is inconsistent.`);
  }
  validateClusterList(sample.aggregate.top_exact_clusters, `${label}.aggregate.top_exact_clusters`, 64);
  validateClusterList(sample.aggregate.top_normalized_clusters, `${label}.aggregate.top_normalized_clusters`, 64);
  validateClusterList(sample.aggregate.top_minhash_similarity_clusters, `${label}.aggregate.top_minhash_similarity_clusters`, 64);

  assert(Array.isArray(sample.failures) && sample.failures.length <= 200, `${label}.failures is invalid.`);
  for (const failure of sample.failures) {
    assertExactObject(failure, ["room_sha256", "reason"], [], `${label}.failures entry`);
    assertHash(failure.room_sha256, `${label}.failures room hash`);
    assertBoundedText(failure.reason, `${label}.failures reason`, 256);
  }
  assert(sample.failures.length === sample.selection.rooms_failed, `${label}.failure count is inconsistent.`);
  assertStringArray(sample.limitations, `${label}.limitations`, 16, 512);
}

function validateSnapshotManifest(manifest, report, context) {
  assertExactObject(manifest, [
    "schema", "generated_at", "source_commit", "audit_core_sha256", "network_sample_sha256",
    "events_archive_sha256", "proposals_archive_sha256",
  ], [], "report.snapshot_manifest");
  assert(manifest.schema === "swarmproof-snapshot-manifest-v1", "report.snapshot_manifest.schema is invalid.");
  assertCanonicalTime(manifest.generated_at, "report.snapshot_manifest.generated_at");
  assert(manifest.source_commit === null || COMMIT_RE.test(manifest.source_commit), "report.snapshot_manifest.source_commit is invalid.");
  assertHash(manifest.audit_core_sha256, "report.snapshot_manifest.audit_core_sha256");
  if (manifest.network_sample_sha256 !== null) assertHash(manifest.network_sample_sha256, "report.snapshot_manifest.network_sample_sha256");
  assertHash(manifest.events_archive_sha256, "report.snapshot_manifest.events_archive_sha256");
  assertHash(manifest.proposals_archive_sha256, "report.snapshot_manifest.proposals_archive_sha256");
  assert(manifest.generated_at === report.generated_at, "report.snapshot_manifest.generated_at is inconsistent.");
  assert(manifest.audit_core_sha256 === report.audit_core_sha256, "report.snapshot_manifest.audit_core_sha256 is inconsistent.");
  const networkHash = report.network_sample === null ? null : sha256Hex(canonicalize(report.network_sample));
  assert(manifest.network_sample_sha256 === networkHash, "report.snapshot_manifest.network_sample_sha256 is inconsistent.");
  assert(manifest.events_archive_sha256 === sha256Hex(context.eventsContent), "report snapshot event archive hash is inconsistent.");
  assert(manifest.proposals_archive_sha256 === sha256Hex(context.proposalsContent), "report snapshot proposal archive hash is inconsistent.");
}

function validateReport(report, context) {
  assertExactObject(report, [
    "schema", "source_event_count", "unattributable_observation_count", "source_digest", "signing_keys",
    "evidence", "review_evidence", "events", "rejected", "semantically_ignored", "limitations", "audit_core_sha256",
    "generated_at", "event_state", "unsigned_proposals_observed", "build_room", "artifact_verification",
    "archive_policy", "snapshot_manifest", "snapshot_manifest_sha256", "network_sample",
  ], [], "report");
  assert(report.schema === "swarmproof-report-v1", "report.schema is invalid.");
  assertCounter(report.source_event_count, "report.source_event_count");
  assertCounter(report.unattributable_observation_count, "report.unattributable_observation_count");
  assertHash(report.source_digest, "report.source_digest");
  assertCounter(report.signing_keys, "report.signing_keys");
  validateEvidence(report.evidence, "report.evidence");
  validateReviewEvidence(report.review_evidence, "report.review_evidence");
  assert(Array.isArray(report.events) && report.events.length <= 1024, "report.events is invalid.");
  report.events.forEach((event, index) => validateReportEvent(event, `report.events[${index}]`));
  assert(new Set(report.events.map(event => event.event_id)).size === report.events.length, "report.events contains duplicate event IDs.");
  assert(report.evidence.attributable === report.events.length, "report.evidence.attributable is inconsistent.");
  assert(report.signing_keys === new Set(report.events.map(event => event.did)).size, "report.signing_keys is inconsistent.");

  assert(Array.isArray(report.rejected) && report.rejected.length <= context.events.length, "report.rejected is invalid.");
  for (const entry of report.rejected) {
    assertExactObject(entry, ["envelope_sha256", "reason"], [], "report.rejected entry");
    assertHash(entry.envelope_sha256, "report.rejected envelope hash");
    assertBoundedText(entry.reason, "report.rejected reason", 256);
  }
  assert(Array.isArray(report.semantically_ignored) && report.semantically_ignored.length <= report.events.length * 2, "report.semantically_ignored is invalid.");
  for (const entry of report.semantically_ignored) {
    assertExactObject(entry, ["event_id", "reason"], [], "report.semantically_ignored entry");
    assertHash(entry.event_id, "report.semantically_ignored event ID");
    assert(/^[a-z0-9-]{1,80}$/u.test(entry.reason), "report.semantically_ignored reason is invalid.");
  }
  assertStringArray(report.limitations, "report.limitations", 32, 512);
  assertHash(report.audit_core_sha256, "report.audit_core_sha256");
  const auditCore = {
    schema: report.schema,
    source_event_count: report.source_event_count,
    unattributable_observation_count: report.unattributable_observation_count,
    source_digest: report.source_digest,
    signing_keys: report.signing_keys,
    evidence: report.evidence,
    review_evidence: report.review_evidence,
    events: report.events,
    rejected: report.rejected,
    semantically_ignored: report.semantically_ignored,
    limitations: report.limitations.slice(0, 5),
  };
  assert(report.audit_core_sha256 === sha256Hex(canonicalize(auditCore)), "report.audit_core_sha256 is inconsistent.");
  assertCanonicalTime(report.generated_at, "report.generated_at");
  assert(EVENT_STATES.has(report.event_state), "report.event_state is invalid.");
  assertCounter(report.unsigned_proposals_observed, "report.unsigned_proposals_observed");

  assertExactObject(report.build_room, [
    "room", "messages_observed_in_tail", "collection_error", "response_count", "first_seq", "last_seq",
    "sequence_metadata_valid", "message_entries_truncated", "message_entries_uninspected",
    "message_entries_rejected", "message_entries_deduplicated", "continuity_complete", "continuity_reason",
  ], [], "report.build_room");
  assert(ROOM_RE.test(report.build_room.room ?? ""), "report.build_room.room is invalid.");
  assertCounter(report.build_room.messages_observed_in_tail, "report.build_room.messages_observed_in_tail");
  assert(report.build_room.messages_observed_in_tail <= 200, "report.build_room.messages_observed_in_tail is out of bounds.");
  if (report.build_room.collection_error !== null) assertBoundedText(report.build_room.collection_error, "report.build_room.collection_error", 256);
  assertCounter(report.build_room.response_count, "report.build_room.response_count");
  assert(report.build_room.response_count <= 200, "report.build_room.response_count is out of bounds.");
  assert(report.build_room.messages_observed_in_tail <= report.build_room.response_count, "report.build_room response count is inconsistent.");
  if (report.build_room.first_seq !== null) assertCounter(report.build_room.first_seq, "report.build_room.first_seq");
  assertCounter(report.build_room.last_seq, "report.build_room.last_seq");
  assert(typeof report.build_room.sequence_metadata_valid === "boolean", "report.build_room.sequence_metadata_valid is invalid.");
  assertCounter(report.build_room.message_entries_truncated, "report.build_room.message_entries_truncated");
  assertCounter(report.build_room.message_entries_uninspected, "report.build_room.message_entries_uninspected");
  assertCounter(report.build_room.message_entries_rejected, "report.build_room.message_entries_rejected");
  assertCounter(report.build_room.message_entries_deduplicated, "report.build_room.message_entries_deduplicated");
  assert(
    report.build_room.messages_observed_in_tail
      + report.build_room.message_entries_rejected
      + report.build_room.message_entries_deduplicated
      + report.build_room.message_entries_truncated
      === report.build_room.response_count,
    "report.build_room response accounting is inconsistent.",
  );
  assert(typeof report.build_room.continuity_complete === "boolean", "report.build_room.continuity_complete is invalid.");
  assert(/^[a-z0-9-]{1,80}$/u.test(report.build_room.continuity_reason ?? ""), "report.build_room.continuity_reason is invalid.");
  if (report.build_room.sequence_metadata_valid) {
    if (report.build_room.response_count === 0) {
      assert(report.build_room.first_seq === null && report.build_room.last_seq === 0, "report.build_room empty cursor is inconsistent.");
    } else {
      assert(Number.isSafeInteger(report.build_room.first_seq) && report.build_room.first_seq >= 1, "report.build_room first_seq is invalid.");
      assert(
        report.build_room.last_seq === report.build_room.first_seq + report.build_room.response_count - 1,
        "report.build_room sequence window is inconsistent.",
      );
    }
  }
  if (report.build_room.continuity_complete) {
    assert(report.build_room.sequence_metadata_valid, "report.build_room continuity lacks valid sequence metadata.");
    assert(report.build_room.message_entries_truncated === 0, "report.build_room continuity includes truncated entries.");
    assert(report.build_room.message_entries_uninspected === 0, "report.build_room continuity includes uninspected entries.");
    assert(report.build_room.message_entries_rejected === 0, "report.build_room continuity includes rejected entries.");
    assert(report.build_room.message_entries_deduplicated === 0, "report.build_room continuity includes duplicate entries.");
  }

  assertExactObject(report.artifact_verification, [
    "candidates", "attempted", "maximum_per_snapshot", "trusted_ref", "maximum_artifact_bytes",
    "eligible_result_events", "duplicate_results_ignored", "coordinator_slots_reserved",
    "participant_results_per_did_maximum", "results_per_task_maximum",
  ], [], "report.artifact_verification");
  for (const key of [
    "candidates", "attempted", "maximum_per_snapshot", "maximum_artifact_bytes",
    "eligible_result_events", "duplicate_results_ignored", "coordinator_slots_reserved",
    "participant_results_per_did_maximum", "results_per_task_maximum",
  ]) {
    assertCounter(report.artifact_verification[key], `report.artifact_verification.${key}`);
  }
  assert(report.artifact_verification.attempted <= report.artifact_verification.candidates, "report.artifact_verification.attempted is inconsistent.");
  assert(report.artifact_verification.attempted <= report.artifact_verification.maximum_per_snapshot, "report.artifact_verification.maximum is inconsistent.");
  assert(report.artifact_verification.candidates + report.artifact_verification.duplicate_results_ignored === report.artifact_verification.eligible_result_events, "report.artifact_verification duplicate accounting is inconsistent.");
  assert(report.artifact_verification.coordinator_slots_reserved === 8, "report.artifact_verification coordinator reservation is invalid.");
  assert(report.artifact_verification.participant_results_per_did_maximum === 2, "report.artifact_verification per-DID maximum is invalid.");
  assert(report.artifact_verification.results_per_task_maximum === 8, "report.artifact_verification per-task maximum is invalid.");
  assert(report.artifact_verification.trusted_ref === "HEAD", "report.artifact_verification.trusted_ref is invalid.");

  assertExactObject(report.archive_policy, [
    "event_records_maximum", "coordinator_control_records_reserved", "participant_records_maximum",
    "records_per_participant_did_and_type_maximum", "records_per_participant_did_maximum",
    "proposal_records_maximum", "selection", "participant_archive_frozen_after_event",
  ], [], "report.archive_policy");
  assert(report.archive_policy.event_records_maximum === 1024, "report.archive_policy.event_records_maximum is invalid.");
  assert(report.archive_policy.coordinator_control_records_reserved === 64, "report.archive_policy coordinator reservation is invalid.");
  assert(report.archive_policy.participant_records_maximum === 960, "report.archive_policy participant maximum is invalid.");
  assert(report.archive_policy.records_per_participant_did_and_type_maximum === 8, "report.archive_policy per-DID/type cap is invalid.");
  assert(report.archive_policy.records_per_participant_did_maximum === 32, "report.archive_policy per-DID cap is invalid.");
  assert(report.archive_policy.proposal_records_maximum === 2048, "report.archive_policy proposal cap is invalid.");
  assert(report.archive_policy.selection === "newest-round-robin-by-signing-key-and-task", "report.archive_policy selection is invalid.");
  assert(report.archive_policy.participant_archive_frozen_after_event === true, "report.archive_policy freeze policy is invalid.");

  assert(report.network_sample === null || isPlainObject(report.network_sample), "report.network_sample is invalid.");
  if (report.network_sample !== null) validateNetworkSample(report.network_sample, "report.network_sample");
  assertHash(report.snapshot_manifest_sha256, "report.snapshot_manifest_sha256");
  validateSnapshotManifest(report.snapshot_manifest, report, context);
  assert(report.snapshot_manifest_sha256 === sha256Hex(canonicalize(report.snapshot_manifest)), "report.snapshot_manifest_sha256 is inconsistent.");

  assert(report.source_event_count === context.events.length, "report.source_event_count does not match events.jsonl.");
  assert(report.unattributable_observation_count === context.proposals.length, "report unattributable count does not match proposals.jsonl.");
  assert(report.evidence.observed === context.events.length + context.proposals.length, "report.evidence.observed does not match public archives.");
  const sourceDigest = sha256Hex(context.events.map(record => sha256Hex(String(record.envelope))).sort().join("\n"));
  assert(report.source_digest === sourceDigest, "report.source_digest does not match events.jsonl.");
  assert(report.unsigned_proposals_observed === context.proposals.length, "report proposal count does not match proposals.jsonl.");
}

function validateStatus(status, report) {
  assertExactObject(status, [
    "schema", "state", "generated_at", "starts_at", "ends_at", "report_sha256", "audit_core_sha256",
    "snapshot_manifest_sha256", "source_commit", "signing_keys", "reproducible_artifacts",
    "cross_key_reviews", "accepted_results", "stale_after_seconds",
  ], [], "status");
  assert(status.schema === "swarmproof-status-v1", "status.schema is invalid.");
  assert(EVENT_STATES.has(status.state), "status.state is invalid.");
  assertCanonicalTime(status.generated_at, "status.generated_at");
  if (status.starts_at !== null) assertCanonicalTime(status.starts_at, "status.starts_at");
  if (status.ends_at !== null) assertCanonicalTime(status.ends_at, "status.ends_at");
  assert((status.starts_at === null) === (status.ends_at === null), "status event-window bounds are inconsistent.");
  if (status.starts_at !== null) {
    assert(Date.parse(status.ends_at) > Date.parse(status.starts_at), "status event window is invalid.");
    assert(Date.parse(status.ends_at) - Date.parse(status.starts_at) === 48 * 60 * 60 * 1000, "status event window must be exactly 48 hours.");
  }
  assertHash(status.report_sha256, "status.report_sha256");
  assertHash(status.audit_core_sha256, "status.audit_core_sha256");
  assertHash(status.snapshot_manifest_sha256, "status.snapshot_manifest_sha256");
  assert(status.source_commit === null || COMMIT_RE.test(status.source_commit), "status.source_commit is invalid.");
  for (const key of ["signing_keys", "reproducible_artifacts", "cross_key_reviews", "accepted_results", "stale_after_seconds"]) {
    assertCounter(status[key], `status.${key}`);
  }
  assert(status.stale_after_seconds > 0, "status.stale_after_seconds must be positive.");
  assert(status.generated_at === report.generated_at, "status.generated_at does not match report.json.");
  assert(status.state === report.event_state, "status.state does not match report.json.");
  assert(status.report_sha256 === sha256Hex(canonicalize(report)), "status.report_sha256 does not match report.json.");
  assert(status.audit_core_sha256 === report.audit_core_sha256, "status.audit_core_sha256 does not match report.json.");
  assert(status.snapshot_manifest_sha256 === report.snapshot_manifest_sha256, "status snapshot manifest hash does not match report.json.");
  assert(status.source_commit === report.snapshot_manifest.source_commit, "status.source_commit does not match the snapshot manifest.");
  assert(status.signing_keys === report.signing_keys, "status.signing_keys does not match report.json.");
  assert(status.reproducible_artifacts === report.evidence.reproducible, "status.reproducible_artifacts does not match report.json.");
  assert(status.cross_key_reviews === report.evidence.cross_key_reviewed, "status.cross_key_reviews does not match report.json.");
  assert(status.accepted_results === report.evidence.accepted, "status.accepted_results does not match report.json.");
}

function validateProposal(proposal, label) {
  assertExactObject(proposal, ["proposal_sha256", "observed_at", "source_ts", "source_room", "source_seq"], [], label);
  assertHash(proposal.proposal_sha256, `${label}.proposal_sha256`);
  assertCanonicalTime(proposal.observed_at, `${label}.observed_at`);
  if (proposal.source_ts !== null) assertCanonicalTime(proposal.source_ts, `${label}.source_ts`);
  assert(ROOM_RE.test(proposal.source_room ?? ""), `${label}.source_room is invalid.`);
  assert(proposal.source_seq === null || (Number.isSafeInteger(proposal.source_seq) && proposal.source_seq >= 0), `${label}.source_seq is invalid.`);
}

function validateNetworkSketch(record, label) {
  assertExactObject(record, [
    "room_sha256", "source_seq", "source_ts", "signing_key_sha256", "actor_sha256",
    "message_sha256", "normalized_sha256", "minhash", "character_count",
  ], [], label);
  assertHash(record.room_sha256, `${label}.room_sha256`);
  assert(record.source_seq === null || (Number.isSafeInteger(record.source_seq) && record.source_seq >= 0), `${label}.source_seq is invalid.`);
  if (record.source_ts !== null) assertUtcTime(record.source_ts, `${label}.source_ts`);
  if (record.signing_key_sha256 !== null) assertHash(record.signing_key_sha256, `${label}.signing_key_sha256`);
  if (record.actor_sha256 !== null) assertHash(record.actor_sha256, `${label}.actor_sha256`);
  assert((record.signing_key_sha256 === null) !== (record.actor_sha256 === null), `${label} actor identifiers are inconsistent.`);
  assertHash(record.message_sha256, `${label}.message_sha256`);
  assertHash(record.normalized_sha256, `${label}.normalized_sha256`);
  assert(Array.isArray(record.minhash) && record.minhash.length === 32, `${label}.minhash is invalid.`);
  for (const item of record.minhash) assert(/^[0-9a-f]{8}$/u.test(item), `${label}.minhash contains an invalid item.`);
  assertCounter(record.character_count, `${label}.character_count`);
}

async function validatePublicData(violations, dataDirectory) {
  const files = {
    events: path.join(dataDirectory, "events.jsonl"),
    proposals: path.join(dataDirectory, "proposals.jsonl"),
    report: path.join(dataDirectory, "report.json"),
    status: path.join(dataDirectory, "status.json"),
    sketches: path.join(dataDirectory, "network-sketches.jsonl"),
  };
  let events = [];
  let proposals = [];
  let report = null;
  let eventsContent = "";
  let proposalsContent = "";
  try {
    eventsContent = await readFile(files.events, "utf8");
    events = parseJsonLines(eventsContent, "events.jsonl");
    const eventIds = new Set();
    for (const record of events) {
      assertExactObject(record, ["envelope", "observed_at", "source_ts", "source_room", "source_seq"], [], "events.jsonl record");
      const verified = verifyEnvelope(record.envelope);
      assert(!eventIds.has(verified.event_id), "events.jsonl contains a duplicate event.");
      eventIds.add(verified.event_id);
      assertCanonicalTime(record.observed_at, "events.jsonl observed_at");
      if (record.source_ts !== null) assertCanonicalTime(record.source_ts, "events.jsonl source_ts");
      assert(ROOM_RE.test(record.source_room ?? ""), "events.jsonl source_room is invalid.");
      assert(record.source_seq === null || (Number.isSafeInteger(record.source_seq) && record.source_seq >= 0), "events.jsonl source_seq is invalid.");
    }
  } catch (error) {
    recordSchemaViolation(violations, files.events, "invalid-public-events-schema", error);
  }
  try {
    proposalsContent = await readFile(files.proposals, "utf8");
    proposals = parseJsonLines(proposalsContent, "proposals.jsonl");
    proposals.forEach((proposal, index) => validateProposal(proposal, `proposals.jsonl[${index}]`));
    assert(new Set(proposals.map(item => item.proposal_sha256)).size === proposals.length, "proposals.jsonl contains duplicates.");
  } catch (error) {
    recordSchemaViolation(violations, files.proposals, "invalid-public-proposals-schema", error);
  }
  try {
    report = JSON.parse(await readFile(files.report, "utf8"));
    validateReport(report, { events, proposals, eventsContent, proposalsContent });
  } catch (error) {
    recordSchemaViolation(violations, files.report, "invalid-public-report-schema", error);
  }
  try {
    const status = JSON.parse(await readFile(files.status, "utf8"));
    assert(report !== null, "report.json must validate before status.json.");
    validateStatus(status, report);
  } catch (error) {
    recordSchemaViolation(violations, files.status, "invalid-public-status-schema", error);
  }
  try {
    const sketches = parseJsonLines(await readFile(files.sketches, "utf8"), "network-sketches.jsonl");
    sketches.forEach((record, index) => validateNetworkSketch(record, `network-sketches.jsonl[${index}]`));
    if (report?.network_sample !== null) {
      assert(sketches.length === report.network_sample.aggregate.messages, "network-sketches.jsonl count does not match report.json.");
    }
  } catch (error) {
    if (error.code !== "ENOENT") {
      recordSchemaViolation(violations, files.sketches, "invalid-public-network-sketches-schema", error);
    }
  }
}

async function validateGitHistory(violations) {
  let stdout;
  try {
    ({ stdout } = await executeFile("git", ["log", "--format=%an%x00%ae%x00%cn%x00%ce%x00%ai%x00%ci%x00%B%x00%x00"], { encoding: "utf8" }));
  } catch {
    return;
  }
  if (!stdout.trim()) return;
  const records = stdout.split("\0\0");
  for (const rawRecord of records) {
    const record = rawRecord.replace(/^\r?\n/u, "");
    if (!record.trim()) continue;
    const fields = record.split("\0");
    if (fields.length !== 7) {
      violations.push({ file: ".git/history", rule: "malformed-commit-metadata" });
      continue;
    }
    const [authorName, authorEmail, committerName, committerEmail, authorDate, commitDate, body] = fields;
    if (authorName !== "SwarmProof Coordinator" || committerName !== "SwarmProof Coordinator") {
      violations.push({ file: ".git/history", rule: "non-pseudonymous-commit-name" });
    }
    if (!ALLOWED_EMAIL_RE.test(authorEmail) || !ALLOWED_EMAIL_RE.test(committerEmail)) {
      violations.push({ file: ".git/history", rule: "non-pseudonymous-commit-email" });
    }
    if (!/[+-]0000$/u.test(authorDate) || !/[+-]0000$/u.test(commitDate)) {
      violations.push({ file: ".git/history", rule: "non-utc-commit-timezone" });
    }
    if (/co-authored-by:/iu.test(body)) {
      violations.push({ file: ".git/history", rule: "co-author-trailer-forbidden" });
    }
  }
}

async function main() {
  const violations = [];
  const deniedValues = await loadLocalDenylist();
  const files = await walk(ROOT, violations);
  for (const file of files) {
    scanFilename(file, deniedValues, violations);
    await scanFile(file, violations);
  }
  await scanLocalDenylist(files, deniedValues, violations);
  await validatePublicData(violations, path.join(ROOT, "public/data"));
  if (INCLUDE_DIST) await validatePublicData(violations, path.join(ROOT, "dist/data"));
  if (process.env.SWARMPROOF_CHECK_HISTORY === "1") await validateGitHistory(violations);

  if (violations.length > 0) {
    for (const violation of violations) console.error(`privacy audit: ${violation.file}: ${violation.rule}`);
    process.exit(1);
  }
  process.stdout.write(`privacy audit passed (${files.length} files${INCLUDE_DIST ? ", including dist" : ""})\n`);
}

main().catch(error => {
  console.error(`privacy audit failed: ${error.message}`);
  process.exit(1);
});
