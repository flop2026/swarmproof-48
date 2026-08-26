#!/usr/bin/env node

import { execFile } from "node:child_process";
import { lstat, readFile, writeFile } from "node:fs/promises";
import { promisify } from "node:util";
import {
  COORDINATOR_CONTROL_RESERVATION,
  EVENT_RECORD_LIMIT,
  PARTICIPANT_RECORD_LIMIT,
  PROPOSAL_RECORD_LIMIT,
  RECORDS_PER_PARTICIPANT_DID_LIMIT,
  RECORDS_PER_PARTICIPANT_DID_TYPE_LIMIT,
} from "../lib/archive.mjs";
import { auditEvents } from "../lib/audit.mjs";
import { canonicalize } from "../lib/canonical.mjs";
import { sha256Hex } from "../lib/crypto.mjs";
import {
  ARTIFACT_CHECK_LIMIT,
  ARTIFACTS_PER_PARTICIPANT_DID_LIMIT,
  ARTIFACTS_PER_TASK_LIMIT,
  COORDINATOR_ARTIFACT_RESERVATION,
  verifyArtifactEvidence,
} from "../lib/evidence.mjs";
import { EXPERIMENT, createEnvelopeFromFiles, verifyEnvelope } from "../lib/protocol.mjs";
import {
  acquireReviewLock,
  assertReviewSnapshotTrusted,
  assertReviewSourceCommitTrusted,
  fetchPublicReviewDocuments,
  fetchReviewRoom,
  postSignedReview,
  prepareSignedReview,
  publicReviewSummary,
  readSecureReviewKey,
  stableTargetBinding,
  validateAndBindPublicReview,
} from "../lib/review.mjs";

const MEBIBYTE = 1024 * 1024;
const executeFile = promisify(execFile);
const COMMIT_RE = /^[0-9a-f]{40}$/;
const HASH_RE = /^[0-9a-f]{64}$/;
const ROOM_RE = /^[a-z0-9][a-z0-9_-]{0,47}$/;
const EVENT_STATES = new Set(["preparation", "active", "complete"]);
const EVENT_ARCHIVE_KEYS = new Set(["envelope", "observed_at", "source_ts", "source_room", "source_seq"]);
const PROPOSAL_ARCHIVE_KEYS = new Set(["proposal_sha256", "observed_at", "source_ts", "source_room", "source_seq"]);
const REPORT_KEYS = new Set([
  "schema", "source_event_count", "unattributable_observation_count", "source_digest", "signing_keys",
  "evidence", "review_evidence", "events", "rejected", "semantically_ignored", "limitations",
  "audit_core_sha256", "generated_at", "event_state", "unsigned_proposals_observed", "build_room",
  "artifact_verification", "archive_policy", "snapshot_manifest", "snapshot_manifest_sha256",
  "network_sample",
]);
const STATUS_KEYS = new Set([
  "schema", "state", "generated_at", "starts_at", "ends_at", "report_sha256", "audit_core_sha256",
  "snapshot_manifest_sha256", "source_commit", "signing_keys", "reproducible_artifacts",
  "cross_key_reviews", "accepted_results", "stale_after_seconds",
]);
const SNAPSHOT_MANIFEST_KEYS = new Set([
  "schema", "generated_at", "source_commit", "audit_core_sha256", "network_sample_sha256",
  "events_archive_sha256", "proposals_archive_sha256",
]);
const BUILD_ROOM_KEYS = new Set([
  "room", "messages_observed_in_tail", "collection_error", "response_count", "first_seq", "last_seq",
  "sequence_metadata_valid", "message_entries_truncated", "message_entries_uninspected",
  "message_entries_rejected", "message_entries_deduplicated", "continuity_complete", "continuity_reason",
]);
const ARTIFACT_VERIFICATION_KEYS = new Set([
  "candidates", "attempted", "maximum_per_snapshot", "trusted_ref", "maximum_artifact_bytes",
  "eligible_result_events", "duplicate_results_ignored", "coordinator_slots_reserved",
  "participant_results_per_did_maximum", "results_per_task_maximum",
]);
const ARCHIVE_POLICY_KEYS = new Set([
  "event_records_maximum", "coordinator_control_records_reserved", "participant_records_maximum",
  "records_per_participant_did_and_type_maximum", "records_per_participant_did_maximum",
  "proposal_records_maximum", "selection", "participant_archive_frozen_after_event",
]);
const ACTIVE_STALE_AFTER_SECONDS = 4 * 60 * 60;
const COMPLETE_STALE_AFTER_SECONDS = 90_000;
const EVENT_WINDOW_MS = 48 * 60 * 60 * 1000;
const FILE_LIMITS = {
  config: 256 * 1024,
  tasks: 256 * 1024,
  events: 16 * MEBIBYTE,
  proposals: 4 * MEBIBYTE,
  report: 16 * MEBIBYTE,
  status: 256 * 1024,
};

function usage() {
  console.error(`Usage:
  swarmproof sign --payload payload.json --key private-key.pem [--config config/event.json] [--tasks config/tasks.json]
  swarmproof verify (--envelope SP1... | --file envelope.txt) [--config config/event.json] [--tasks config/tasks.json]
  swarmproof sign --payload payload.json --key private-key.pem --structural-only
  swarmproof verify (--envelope SP1... | --file envelope.txt) --structural-only
  swarmproof replay --events events.jsonl [--proposals proposals.jsonl] [--config config/event.json] [--tasks config/tasks.json] [--out report.json]
  swarmproof verify-report [--report public/data/report.json] [--status public/data/status.json] [--events public/data/events.jsonl] [--proposals public/data/proposals.jsonl] [--config config/event.json] [--tasks config/tasks.json] [--out verification.json]
  swarmproof review --target RESULT_EVENT_ID --verdict PASS|FAIL --key reviewer.pem [--config config/event.json] [--tasks config/tasks.json] [--dry-run]
  swarmproof review --target RESULT_EVENT_ID --verdict PASS|FAIL --key reviewer.pem --post --confirm ${EXPERIMENT}`);
  console.error("\nDefault sign/verify enforce this project's repository, task manifest, and coordinator authority. --structural-only checks only protocol structure and signature; it does not establish project authorization or acceptance.");
  process.exit(2);
}

function optionsOf(arguments_) {
  const options = new Map();
  const flags = new Set();
  const booleanFlags = new Set(["structural-only", "post", "dry-run"]);
  for (let index = 0; index < arguments_.length; index += 1) {
    const token = arguments_[index];
    const flagName = token.startsWith("--") ? token.slice(2) : "";
    if (booleanFlags.has(flagName)) {
      if (flags.has(flagName)) usage();
      flags.add(flagName);
      continue;
    }
    if (!token.startsWith("--") || index + 1 >= arguments_.length || arguments_[index + 1].startsWith("--")) usage();
    const name = token.slice(2);
    if (options.has(name)) usage();
    options.set(name, arguments_[index + 1]);
    index += 1;
  }
  return { options, flags };
}

function requireOnly(options, allowed) {
  for (const name of options.keys()) {
    if (!allowed.has(name)) usage();
  }
}

function requireOnlyFlags(flags, allowed) {
  for (const name of flags) {
    if (!allowed.has(name)) usage();
  }
}

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function assertExactObject(value, keys, label) {
  assert(value && typeof value === "object" && !Array.isArray(value), `${label} must be an object.`);
  const actual = Object.keys(value);
  assert(actual.length === keys.size, `${label} has an invalid field set.`);
  for (const key of actual) assert(keys.has(key), `${label} contains an unknown field: ${key}`);
  for (const key of keys) assert(Object.hasOwn(value, key), `${label} is missing field: ${key}`);
}

function assertCanonicalTime(value, label) {
  assert(typeof value === "string", `${label} is invalid.`);
  const milliseconds = Date.parse(value);
  assert(
    Number.isFinite(milliseconds) && new Date(milliseconds).toISOString() === value,
    `${label} is not canonical UTC.`,
  );
}

function assertCounter(value, label) {
  assert(Number.isSafeInteger(value) && value >= 0, `${label} must be a non-negative safe integer.`);
}

function assertHash(value, label) {
  assert(typeof value === "string" && HASH_RE.test(value), `${label} must be a lowercase SHA-256.`);
}

function validateBuildRoom(buildRoom) {
  assertExactObject(buildRoom, BUILD_ROOM_KEYS, "Public report build_room");
  assert(ROOM_RE.test(buildRoom.room ?? ""), "Public report build_room.room is invalid.");
  for (const key of [
    "messages_observed_in_tail", "response_count", "last_seq", "message_entries_truncated",
    "message_entries_uninspected", "message_entries_rejected", "message_entries_deduplicated",
  ]) assertCounter(buildRoom[key], `Public report build_room.${key}`);
  assert(buildRoom.messages_observed_in_tail <= 200, "Public report build-room tail count is out of bounds.");
  assert(buildRoom.response_count <= 200, "Public report build-room response count is out of bounds.");
  assert(buildRoom.messages_observed_in_tail <= buildRoom.response_count, "Public report build-room tail count is inconsistent.");
  if (buildRoom.first_seq !== null) assertCounter(buildRoom.first_seq, "Public report build_room.first_seq");
  assert(
    buildRoom.collection_error === null
      || (
        typeof buildRoom.collection_error === "string"
        && buildRoom.collection_error.length > 0
        && buildRoom.collection_error.length <= 256
        && !/[\u0000-\u001f\u007f]/u.test(buildRoom.collection_error)
      ),
    "Public report build_room.collection_error is invalid.",
  );
  assert(typeof buildRoom.sequence_metadata_valid === "boolean", "Public report build-room sequence flag is invalid.");
  assert(typeof buildRoom.continuity_complete === "boolean", "Public report build-room continuity flag is invalid.");
  assert(/^[a-z0-9-]{1,80}$/u.test(buildRoom.continuity_reason ?? ""), "Public report build-room continuity reason is invalid.");
  assert(
    buildRoom.messages_observed_in_tail
      + buildRoom.message_entries_rejected
      + buildRoom.message_entries_deduplicated
      + buildRoom.message_entries_truncated
      === buildRoom.response_count,
    "Public report build-room response accounting is inconsistent.",
  );
  if (buildRoom.sequence_metadata_valid) {
    if (buildRoom.response_count === 0) {
      assert(buildRoom.first_seq === null && buildRoom.last_seq === 0, "Public report empty build-room cursor is inconsistent.");
    } else {
      assert(Number.isSafeInteger(buildRoom.first_seq) && buildRoom.first_seq >= 1, "Public report build-room first sequence is invalid.");
      assert(
        buildRoom.last_seq === buildRoom.first_seq + buildRoom.response_count - 1,
        "Public report build-room sequence window is inconsistent.",
      );
    }
  }
  if (buildRoom.continuity_complete) {
    assert(buildRoom.sequence_metadata_valid, "Public report build-room continuity lacks valid sequence metadata.");
    assert(
      buildRoom.message_entries_truncated === 0
        && buildRoom.message_entries_uninspected === 0
        && buildRoom.message_entries_rejected === 0
        && buildRoom.message_entries_deduplicated === 0,
      "Public report build-room continuity includes incomplete entries.",
    );
  }
}

function validateArtifactVerification(value) {
  assertExactObject(value, ARTIFACT_VERIFICATION_KEYS, "Public report artifact_verification");
  for (const key of [
    "candidates", "attempted", "maximum_per_snapshot", "maximum_artifact_bytes",
    "eligible_result_events", "duplicate_results_ignored", "coordinator_slots_reserved",
    "participant_results_per_did_maximum", "results_per_task_maximum",
  ]) assertCounter(value[key], `Public report artifact_verification.${key}`);
  assert(value.maximum_per_snapshot === ARTIFACT_CHECK_LIMIT, "Public report artifact-check limit is inconsistent.");
  assert(value.trusted_ref === "HEAD", "Public report artifact trusted ref is inconsistent.");
  assert(value.maximum_artifact_bytes === 4 * MEBIBYTE, "Public report artifact byte limit is inconsistent.");
  assert(value.coordinator_slots_reserved === COORDINATOR_ARTIFACT_RESERVATION, "Public report coordinator artifact reservation is inconsistent.");
  assert(value.participant_results_per_did_maximum === ARTIFACTS_PER_PARTICIPANT_DID_LIMIT, "Public report participant artifact cap is inconsistent.");
  assert(value.results_per_task_maximum === ARTIFACTS_PER_TASK_LIMIT, "Public report per-task artifact cap is inconsistent.");
  assert(value.attempted <= value.candidates && value.attempted <= value.maximum_per_snapshot, "Public report artifact attempt count is inconsistent.");
  assert(
    value.candidates + value.duplicate_results_ignored === value.eligible_result_events,
    "Public report artifact candidate accounting is inconsistent.",
  );
}

function validateArchivePolicy(value) {
  assertExactObject(value, ARCHIVE_POLICY_KEYS, "Public report archive_policy");
  assert(value.event_records_maximum === EVENT_RECORD_LIMIT, "Public report event archive limit is inconsistent.");
  assert(value.coordinator_control_records_reserved === COORDINATOR_CONTROL_RESERVATION, "Public report control reservation is inconsistent.");
  assert(value.participant_records_maximum === PARTICIPANT_RECORD_LIMIT, "Public report participant archive limit is inconsistent.");
  assert(value.records_per_participant_did_and_type_maximum === RECORDS_PER_PARTICIPANT_DID_TYPE_LIMIT, "Public report per-DID/type archive cap is inconsistent.");
  assert(value.records_per_participant_did_maximum === RECORDS_PER_PARTICIPANT_DID_LIMIT, "Public report per-DID archive cap is inconsistent.");
  assert(value.proposal_records_maximum === PROPOSAL_RECORD_LIMIT, "Public report proposal archive limit is inconsistent.");
  assert(value.selection === "newest-round-robin-by-signing-key-and-task", "Public report archive selection is inconsistent.");
  assert(value.participant_archive_frozen_after_event === true, "Public report archive freeze policy is inconsistent.");
}

function validatePublicReport(report) {
  assertExactObject(report, REPORT_KEYS, "Public report");
  assert(report.schema === "swarmproof-report-v1", "Public report schema is unsupported.");
  for (const key of [
    "source_event_count", "unattributable_observation_count", "signing_keys", "unsigned_proposals_observed",
  ]) assertCounter(report[key], `Public report ${key}`);
  for (const key of ["source_digest", "audit_core_sha256", "snapshot_manifest_sha256"]) {
    assertHash(report[key], `Public report ${key}`);
  }
  assert(report.evidence && typeof report.evidence === "object" && !Array.isArray(report.evidence), "Public report evidence is invalid.");
  assert(report.review_evidence && typeof report.review_evidence === "object" && !Array.isArray(report.review_evidence), "Public report review evidence is invalid.");
  for (const key of ["events", "rejected", "semantically_ignored", "limitations"]) {
    assert(Array.isArray(report[key]), `Public report ${key} is invalid.`);
  }
  assertCanonicalTime(report.generated_at, "Public report generated_at");
  assert(EVENT_STATES.has(report.event_state), "Public report lifecycle state is invalid.");
  validateBuildRoom(report.build_room);
  validateArtifactVerification(report.artifact_verification);
  validateArchivePolicy(report.archive_policy);
  assert(report.network_sample === null || (report.network_sample && typeof report.network_sample === "object" && !Array.isArray(report.network_sample)), "Public report network sample is invalid.");

  assertExactObject(report.snapshot_manifest, SNAPSHOT_MANIFEST_KEYS, "Snapshot manifest");
  assert(report.snapshot_manifest.schema === "swarmproof-snapshot-manifest-v1", "Snapshot manifest schema is unsupported.");
  assertCanonicalTime(report.snapshot_manifest.generated_at, "Snapshot manifest generated_at");
  assert(COMMIT_RE.test(report.snapshot_manifest.source_commit ?? ""), "Snapshot source_commit must be a full lowercase commit SHA.");
  for (const key of ["audit_core_sha256", "events_archive_sha256", "proposals_archive_sha256"]) {
    assertHash(report.snapshot_manifest[key], `Snapshot manifest ${key}`);
  }
  assert(
    report.snapshot_manifest.network_sample_sha256 === null
      || HASH_RE.test(report.snapshot_manifest.network_sample_sha256 ?? ""),
    "Snapshot manifest network sample hash is invalid.",
  );
}

function validatePublicStatus(status) {
  assertExactObject(status, STATUS_KEYS, "Public status");
  assert(status.schema === "swarmproof-status-v1", "Public status schema is unsupported.");
  assert(EVENT_STATES.has(status.state), "Public status lifecycle state is invalid.");
  for (const key of ["generated_at", "starts_at", "ends_at"]) assertCanonicalTime(status[key], `Public status ${key}`);
  for (const key of ["report_sha256", "audit_core_sha256", "snapshot_manifest_sha256"]) {
    assertHash(status[key], `Public status ${key}`);
  }
  assert(COMMIT_RE.test(status.source_commit ?? ""), "Public status source_commit is invalid.");
  for (const key of [
    "signing_keys", "reproducible_artifacts", "cross_key_reviews", "accepted_results", "stale_after_seconds",
  ]) assertCounter(status[key], `Public status ${key}`);
  assert(status.stale_after_seconds > 0, "Public status stale_after_seconds must be positive.");
}

function validateConfigBindings(config, report, status) {
  assert(config?.schema === "swarmproof-event-config-v1", "Project config schema is unsupported.");
  assert(EVENT_STATES.has(config.state), "Project config lifecycle state is invalid.");
  assert(ROOM_RE.test(config.build_room ?? ""), "Project config is missing a valid build_room.");
  assertCanonicalTime(config.starts_at, "Project config starts_at");
  assertCanonicalTime(config.ends_at, "Project config ends_at");
  assert(Date.parse(config.ends_at) - Date.parse(config.starts_at) === EVENT_WINDOW_MS, "Project config event window must be exactly 48 hours.");
  assert(status.starts_at === config.starts_at && status.ends_at === config.ends_at, "Public status event window does not match project config.");
  assert(report.build_room.room === config.build_room, "Public report build room does not match project config.");
  assert(report.event_state === config.state && status.state === config.state, "Public lifecycle state does not match project config.");
  const expectedStaleAfter = config.state === "active" ? ACTIVE_STALE_AFTER_SECONDS : COMPLETE_STALE_AFTER_SECONDS;
  assert(status.stale_after_seconds === expectedStaleAfter, "Public status stale policy does not match project config lifecycle.");
}

function validateObservation(record, config, label, sourceSequences) {
  assertCanonicalTime(record.observed_at, `${label}.observed_at`);
  if (record.source_ts !== null) assertCanonicalTime(record.source_ts, `${label}.source_ts`);
  assert(record.source_room === config.build_room, `${label}.source_room does not match the configured build room.`);
  assert(
    record.source_seq === null || (Number.isSafeInteger(record.source_seq) && record.source_seq >= 0),
    `${label}.source_seq is invalid.`,
  );
  if (record.source_seq !== null) {
    const sourceKey = `${record.source_room}\u0000${record.source_seq}`;
    assert(!sourceSequences.has(sourceKey), `${label}.source_seq duplicates another archived observation.`);
    sourceSequences.add(sourceKey);
  }
}

function validatePublicArchives(records, proposals, config, protocolOptions) {
  assert(ROOM_RE.test(config.build_room ?? ""), "Project config is missing a valid build_room.");
  const eventIds = new Set();
  const proposalHashes = new Set();
  const sourceSequences = new Set();
  records.forEach((record, index) => {
    const label = `events archive record ${index + 1}`;
    assertExactObject(record, EVENT_ARCHIVE_KEYS, label);
    validateObservation(record, config, label, sourceSequences);
    const verified = verifyEnvelope(record.envelope, protocolOptions);
    assert(!eventIds.has(verified.event_id), "Events archive contains a duplicate event.");
    eventIds.add(verified.event_id);
  });
  proposals.forEach((proposal, index) => {
    const label = `proposals archive record ${index + 1}`;
    assertExactObject(proposal, PROPOSAL_ARCHIVE_KEYS, label);
    validateObservation(proposal, config, label, sourceSequences);
    assert(HASH_RE.test(proposal.proposal_sha256), `${label}.proposal_sha256 is invalid.`);
    assert(!proposalHashes.has(proposal.proposal_sha256), "Proposals archive contains a duplicate proposal.");
    proposalHashes.add(proposal.proposal_sha256);
  });
}

async function assertTrustedSourceCommit(commit) {
  assert(COMMIT_RE.test(commit ?? ""), "Snapshot source_commit must be a full lowercase commit SHA.");
  try {
    await executeFile("git", ["merge-base", "--is-ancestor", commit, "HEAD"], {
      encoding: "utf8",
      timeout: 10_000,
    });
  } catch {
    throw new Error("Snapshot source_commit is not on the trusted HEAD history.");
  }
}

async function readBoundedText(filePath, maximumBytes, label) {
  const metadata = await lstat(filePath);
  assert(metadata.isFile(), `${label} is not a regular file.`);
  assert(metadata.size <= maximumBytes, `${label} exceeds ${maximumBytes} bytes.`);
  const content = await readFile(filePath, "utf8");
  assert(Buffer.byteLength(content, "utf8") <= maximumBytes, `${label} exceeds ${maximumBytes} bytes.`);
  return content;
}

async function loadJson(filePath, maximumBytes, label) {
  const content = await readBoundedText(filePath, maximumBytes, label);
  try {
    return { value: JSON.parse(content), content };
  } catch {
    throw new Error(`${label} is not valid JSON.`);
  }
}

async function projectProtocolOptions(options) {
  const configPath = options.get("config") ?? "config/event.json";
  const tasksPath = options.get("tasks") ?? "config/tasks.json";
  const [config, taskManifest] = await Promise.all([
    loadJson(configPath, FILE_LIMITS.config, "config").then(result => result.value),
    loadJson(tasksPath, FILE_LIMITS.tasks, "task manifest").then(result => result.value),
  ]);
  if (typeof config.repository !== "string" || typeof config.coordinator_did !== "string") {
    throw new Error("Project config is missing repository or coordinator_did.");
  }
  if (!Array.isArray(taskManifest.tasks) || taskManifest.tasks.some(task => typeof task?.id !== "string")) {
    throw new Error("Task manifest is invalid.");
  }
  return {
    allowedRepositories: new Set([config.repository]),
    allowedTasks: new Set(taskManifest.tasks.map(task => task.id)),
    coordinatorDid: config.coordinator_did,
  };
}

async function loadReviewContext(options, targetEventId, decision, now = new Date()) {
  const configPath = options.get("config") ?? "config/event.json";
  const tasksPath = options.get("tasks") ?? "config/tasks.json";
  const [config, manifest, published] = await Promise.all([
    loadJson(configPath, FILE_LIMITS.config, "config").then(result => result.value),
    loadJson(tasksPath, FILE_LIMITS.tasks, "task manifest").then(result => result.value),
    fetchPublicReviewDocuments(),
  ]);
  const context = validateAndBindPublicReview({
    config,
    manifest,
    ...published,
    targetEventId,
    decision,
    now,
  });
  await assertReviewSourceCommitTrusted(context.sourceCommit, process.cwd());
  const evidenceCommit = await assertReviewSnapshotTrusted({
    ...published,
    sourceCommit: context.sourceCommit,
    repositoryRoot: process.cwd(),
  });
  return { ...context, evidenceCommit };
}

async function loadJsonLines(filePath, maximumBytes, maximumRecords, label) {
  const content = await readBoundedText(filePath, maximumBytes, label);
  const records = content
    .split("\n")
    .filter(line => line.trim())
    .map((line, index) => {
      try {
        return JSON.parse(line);
      } catch {
        throw new Error(`Invalid JSON on ${label} line ${index + 1}.`);
      }
    });
  assert(records.length <= maximumRecords, `${label} exceeds ${maximumRecords} records.`);
  return { records, content };
}

async function replayProject(options, replayOptions = {}) {
  const eventsPath = options.get("events") ?? "public/data/events.jsonl";
  const proposalsPath = options.get("proposals") ?? "public/data/proposals.jsonl";
  const configPath = options.get("config") ?? "config/event.json";
  const tasksPath = options.get("tasks") ?? "config/tasks.json";
  const [eventArchive, proposalArchive, configDocument, taskDocument] = await Promise.all([
    loadJsonLines(eventsPath, FILE_LIMITS.events, 1024, "events archive"),
    loadJsonLines(proposalsPath, FILE_LIMITS.proposals, 2048, "proposals archive")
      .catch(error => (
        error.code === "ENOENT" && !replayOptions.strictPublicArchives
          ? { records: [], content: "" }
          : Promise.reject(error)
      )),
    loadJson(configPath, FILE_LIMITS.config, "config"),
    loadJson(tasksPath, FILE_LIMITS.tasks, "task manifest"),
  ]);
  const records = eventArchive.records;
  const proposals = proposalArchive.records;
  const config = configDocument.value;
  const taskManifest = taskDocument.value;
  assert(typeof config.repository === "string" && typeof config.coordinator_did === "string", "Project config is missing repository or coordinator_did.");
  assert(Array.isArray(taskManifest.tasks) && taskManifest.tasks.every(task => typeof task?.id === "string"), "Task manifest is invalid.");
  const allowedRepositories = new Set([config.repository]);
  const allowedTasks = new Set(taskManifest.tasks.map(task => task.id));
  const tasksById = new Map(taskManifest.tasks.map(task => [task.id, task]));
  const protocolOptions = {
    allowedRepositories,
    allowedTasks,
    coordinatorDid: config.coordinator_did,
  };
  if (replayOptions.strictPublicArchives) {
    validatePublicArchives(records, proposals, config, protocolOptions);
  }
  if (replayOptions.expectedEventsSha256 !== undefined) {
    assert(
      replayOptions.expectedEventsSha256 === sha256Hex(eventArchive.content),
      "Events archive SHA-256 does not match snapshot manifest.",
    );
  }
  if (replayOptions.expectedProposalsSha256 !== undefined) {
    assert(
      replayOptions.expectedProposalsSha256 === sha256Hex(proposalArchive.content),
      "Proposals archive SHA-256 does not match snapshot manifest.",
    );
  }
  const artifactVerification = await verifyArtifactEvidence(records, {
    repository: config.repository,
    repositoryRoot: process.cwd(),
    trustedRef: replayOptions.trustedRef ?? "HEAD",
    protocolOptions,
    tasksById,
    startsAt: config.starts_at,
    endsAt: config.ends_at,
  });
  const additionalObserved = proposals.filter(proposal => (
    proposal && /^[0-9a-f]{64}$/.test(proposal.proposal_sha256 ?? "")
  )).length;
  const result = auditEvents(records, {
    allowedRepositories: [...allowedRepositories],
    allowedTasks,
    coordinatorDid: config.coordinator_did,
    startsAt: config.starts_at,
    endsAt: config.ends_at,
    artifactChecks: artifactVerification.checks,
    additionalObserved,
  });
  return {
    result,
    records,
    proposals,
    config,
    taskManifest,
    additionalObserved,
    eventArchive,
    proposalArchive,
    artifactVerification,
  };
}

async function main() {
  const [command, ...arguments_] = process.argv.slice(2);
  if (!command) usage();
  const { options, flags } = optionsOf(arguments_);
  const structuralOnly = flags.has("structural-only");

  if (command === "sign") {
    requireOnlyFlags(flags, new Set(["structural-only"]));
    requireOnly(options, new Set(["payload", "key", "config", "tasks"]));
    if (structuralOnly && (options.has("config") || options.has("tasks"))) usage();
    const payloadPath = options.get("payload");
    const keyPath = options.get("key");
    if (!payloadPath || !keyPath) usage();
    const protocolOptions = structuralOnly ? {} : await projectProtocolOptions(options);
    const created = await createEnvelopeFromFiles(payloadPath, keyPath, protocolOptions);
    process.stdout.write(`${JSON.stringify({
      ...created,
      validation_scope: structuralOnly ? "structural-only" : "project-context",
      ...(structuralOnly ? {
        warning: "Structure and signature only; project authorization and acceptance were not checked.",
      } : {}),
    }, null, 2)}\n`);
    return;
  }

  if (command === "verify") {
    requireOnlyFlags(flags, new Set(["structural-only"]));
    requireOnly(options, new Set(["envelope", "file", "config", "tasks"]));
    if (options.has("envelope") === options.has("file")) usage();
    if (structuralOnly && (options.has("config") || options.has("tasks"))) usage();
    let envelope = options.get("envelope");
    if (!envelope && options.get("file")) envelope = (await readFile(options.get("file"), "utf8")).trim();
    if (!envelope) usage();
    const protocolOptions = structuralOnly ? {} : await projectProtocolOptions(options);
    const verified = verifyEnvelope(envelope, protocolOptions);
    process.stdout.write(`${JSON.stringify({
      ...verified,
      validation_scope: structuralOnly ? "structural-only" : "project-context",
      ...(structuralOnly ? {
        warning: "Structure and signature only; project authorization and acceptance were not checked.",
      } : {}),
    }, null, 2)}\n`);
    return;
  }

  if (command === "replay") {
    requireOnlyFlags(flags, new Set());
    if (structuralOnly) usage();
    requireOnly(options, new Set(["events", "proposals", "config", "tasks", "out"]));
    const { result } = await replayProject(options);
    const output = `${JSON.stringify(result, null, 2)}\n`;
    if (options.get("out")) await writeFile(options.get("out"), output, "utf8");
    else process.stdout.write(output);
    return;
  }

  if (command === "verify-report") {
    requireOnlyFlags(flags, new Set());
    if (structuralOnly) usage();
    requireOnly(options, new Set(["report", "status", "events", "proposals", "config", "tasks", "out"]));
    const [reportDocument, statusDocument] = await Promise.all([
      loadJson(options.get("report") ?? "public/data/report.json", FILE_LIMITS.report, "public report"),
      loadJson(options.get("status") ?? "public/data/status.json", FILE_LIMITS.status, "public status"),
    ]);
    const report = reportDocument.value;
    const status = statusDocument.value;
    validatePublicReport(report);
    validatePublicStatus(status);
    const reportSha256 = sha256Hex(canonicalize(report));
    assert(status.report_sha256 === reportSha256, "Public report SHA-256 does not match status.");
    const snapshotManifestSha256 = sha256Hex(canonicalize(report.snapshot_manifest));
    assert(report.snapshot_manifest_sha256 === snapshotManifestSha256, "Snapshot manifest SHA-256 does not match public report.");
    assert(status.snapshot_manifest_sha256 === snapshotManifestSha256, "Snapshot manifest SHA-256 does not match status.");
    assert(status.source_commit === report.snapshot_manifest.source_commit, "Source commit does not match snapshot manifest.");
    assert(status.generated_at === report.generated_at, "Report and status timestamps do not match.");
    assert(status.state === report.event_state, "Report and status lifecycle states do not match.");
    assert(status.signing_keys === report.signing_keys, "Signing-key count does not match report.");
    assert(status.reproducible_artifacts === report.evidence?.reproducible, "Reproducible count does not match report.");
    assert(status.cross_key_reviews === report.evidence?.cross_key_reviewed, "Cross-key review count does not match report.");
    assert(status.accepted_results === report.evidence?.accepted, "Accepted count does not match report.");
    const sourceCommit = report.snapshot_manifest?.source_commit;
    await assertTrustedSourceCommit(sourceCommit);
    const replayed = await replayProject(options, {
      strictPublicArchives: true,
      trustedRef: sourceCommit,
      expectedEventsSha256: report.snapshot_manifest.events_archive_sha256,
      expectedProposalsSha256: report.snapshot_manifest.proposals_archive_sha256,
    });
    validateConfigBindings(replayed.config, report, status);
    assert(replayed.additionalObserved === replayed.proposals.length, "Proposals archive contains an invalid record.");

    assert(Array.isArray(report.limitations), "Public report limitations are invalid.");
    const replayedAuditCore = replayed.result.report;
    const publicAuditCore = {
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
      limitations: report.limitations.slice(0, replayedAuditCore.limitations.length),
    };
    assert(
      canonicalize(publicAuditCore) === canonicalize(replayedAuditCore),
      "Public report audit-core fields do not match the replayed archives.",
    );

    assert(report.audit_core_sha256 === replayed.result.report_sha256, "Replayed audit core does not match public report.");
    assert(status.audit_core_sha256 === replayed.result.report_sha256, "Replayed audit core does not match status.");
    assert(report.snapshot_manifest.audit_core_sha256 === replayed.result.report_sha256, "Snapshot manifest audit core SHA-256 is inconsistent.");
    assert(report.snapshot_manifest.events_archive_sha256 === sha256Hex(replayed.eventArchive.content), "Events archive SHA-256 does not match snapshot manifest.");
    assert(report.snapshot_manifest.proposals_archive_sha256 === sha256Hex(replayed.proposalArchive.content), "Proposals archive SHA-256 does not match snapshot manifest.");
    const networkSampleSha256 = report.network_sample === null
      ? null
      : sha256Hex(canonicalize(report.network_sample));
    assert(report.snapshot_manifest.network_sample_sha256 === networkSampleSha256, "Network sample SHA-256 does not match snapshot manifest.");
    assert(report.snapshot_manifest.generated_at === report.generated_at, "Snapshot manifest and report timestamps do not match.");
    assert(report.source_event_count === replayed.records.length, "Public report event count does not match events archive.");
    assert(report.unsigned_proposals_observed === replayed.proposals.length, "Public report proposal count does not match proposals archive.");
    assert(report.artifact_verification.candidates === replayed.artifactVerification.candidates, "Public report artifact candidate count does not match replay.");
    assert(report.artifact_verification.attempted === replayed.artifactVerification.attempted, "Public report artifact attempt count does not match replay.");
    assert(report.artifact_verification.maximum_per_snapshot === replayed.artifactVerification.maximum, "Public report artifact-check maximum does not match replay.");
    assert(report.artifact_verification.eligible_result_events === replayed.artifactVerification.eligible_result_events, "Public report eligible-result count does not match replay.");
    assert(report.artifact_verification.duplicate_results_ignored === replayed.artifactVerification.duplicate_results, "Public report duplicate-result count does not match replay.");

    const verification = {
      schema: "swarmproof-report-verification-v1",
      validation_scope: "project-context",
      report_sha256: reportSha256,
      audit_core_sha256: replayed.result.report_sha256,
      snapshot_manifest_sha256: snapshotManifestSha256,
      source_commit: status.source_commit,
      records: {
        events: replayed.records.length,
        proposals: replayed.proposals.length,
        artifact_candidates: replayed.artifactVerification.candidates,
        artifact_checks_attempted: replayed.artifactVerification.attempted,
      },
      checks: {
        report_status_binding: "pass",
        audit_core_replay: "pass",
        archive_manifest_binding: "pass",
        evidence_status_binding: "pass",
      },
      limitations: [
        "A successful verification proves deterministic consistency of the supplied local files, not author identity, novelty, independence, or reward eligibility.",
      ],
    };
    const output = `${JSON.stringify(verification, null, 2)}\n`;
    if (options.get("out")) await writeFile(options.get("out"), output, "utf8");
    else process.stdout.write(output);
    return;
  }

  if (command === "review") {
    requireOnlyFlags(flags, new Set(["post", "dry-run"]));
    requireOnly(options, new Set(["target", "verdict", "key", "config", "tasks", "confirm"]));
    assert(!flags.has("post") || !flags.has("dry-run"), "--post and --dry-run cannot be combined.");
    const shouldPost = flags.has("post");
    const confirmation = options.get("confirm");
    if (shouldPost) assert(confirmation === EXPERIMENT, `Posting requires --confirm ${EXPERIMENT}.`);
    else assert(confirmation === undefined, "--confirm is only accepted with --post.");
    const targetEventId = options.get("target");
    const decision = options.get("verdict");
    const keyPath = options.get("key");
    if (!targetEventId || !decision || !keyPath) usage();

    const privateKeyPem = await readSecureReviewKey(keyPath);
    const preflightContext = await loadReviewContext(options, targetEventId, decision);
    const preflightRoom = await fetchReviewRoom({ room: preflightContext.config.build_room });
    const preflightPrepared = prepareSignedReview({
      context: preflightContext,
      roomData: preflightRoom,
      privateKeyPem,
    });
    if (!shouldPost) {
      process.stdout.write(`${JSON.stringify(publicReviewSummary({
        context: preflightContext,
        prepared: preflightPrepared,
        action: preflightPrepared.duplicate ? "already_reviewed" : "would_post",
        dryRun: true,
      }), null, 2)}\n`);
      return;
    }

    const releaseLock = await acquireReviewLock(process.env.SWARMPROOF_REVIEW_LOCK_FILE);
    try {
      const context = await loadReviewContext(options, targetEventId, decision);
      assert(
        stableTargetBinding(context) === stableTargetBinding(preflightContext),
        "Target binding changed after review preflight; rerun against the new public snapshot.",
      );
      const roomData = await fetchReviewRoom({ room: context.config.build_room });
      const prepared = prepareSignedReview({ context, roomData, privateKeyPem });
      if (prepared.duplicate) {
        process.stdout.write(`${JSON.stringify(publicReviewSummary({
          context,
          prepared,
          action: "already_reviewed",
          dryRun: false,
        }), null, 2)}\n`);
        return;
      }
      await postSignedReview({ context, prepared, privateKeyPem });
      process.stdout.write(`${JSON.stringify(publicReviewSummary({
        context,
        prepared,
        action: "posted",
        dryRun: false,
      }), null, 2)}\n`);
    } finally {
      await releaseLock();
    }
    return;
  }

  usage();
}

main().catch(error => {
  console.error(`swarmproof: ${error.message}`);
  process.exit(1);
});
