#!/usr/bin/env node

import { execFile } from "node:child_process";
import { readFile, rename, writeFile } from "node:fs/promises";
import { pathToFileURL } from "node:url";
import { promisify } from "node:util";
import {
  COORDINATOR_CONTROL_RESERVATION,
  EVENT_RECORD_LIMIT,
  mergeProposals,
  mergeProtocolRecords,
  PARTICIPANT_RECORD_LIMIT,
  PROPOSAL_RECORD_LIMIT,
  RECORDS_PER_PARTICIPANT_DID_LIMIT,
  RECORDS_PER_PARTICIPANT_DID_TYPE_LIMIT,
} from "../lib/archive.mjs";
import { auditEvents } from "../lib/audit.mjs";
import { canonicalize } from "../lib/canonical.mjs";
import {
  collectNetworkSnapshot,
  deriveMessageRecord,
  readRoom,
} from "../lib/collector.mjs";
import { sha256Hex } from "../lib/crypto.mjs";
import { acquireRepositoryLock } from "../lib/repository-lock.mjs";
import {
  ARTIFACTS_PER_PARTICIPANT_DID_LIMIT,
  ARTIFACTS_PER_TASK_LIMIT,
  COORDINATOR_ARTIFACT_RESERVATION,
  verifyArtifactEvidence,
} from "../lib/evidence.mjs";

const executeFile = promisify(execFile);
const CONFIG_FILE = process.env.SWARMPROOF_CONFIG_FILE ?? "config/event.json";
const TRANSACTION_FILE = process.env.SWARMPROOF_FINALIZE_TRANSACTION_FILE
  ?? `${CONFIG_FILE}.finalization-transaction.json`;
const REPOSITORY_LOCK_FILE = process.env.SWARMPROOF_SNAPSHOT_LOCK_FILE
  ?? `${CONFIG_FILE}.snapshot-finalize.lock`;
export const ACTIVE_STALE_AFTER_SECONDS = 4 * 60 * 60;
export const ACTIVE_REFRESH_INTERVAL_SECONDS = 3 * 60 * 60;

async function readJson(path) {
  return JSON.parse(await readFile(path, "utf8"));
}

async function readJsonLines(path, maximumBytes, maximumLines) {
  try {
    const content = await readFile(path, "utf8");
    if (Buffer.byteLength(content, "utf8") > maximumBytes) {
      throw new Error(`${path} exceeds its archive byte limit.`);
    }
    const lines = content.split("\n").filter(Boolean);
    if (lines.length > maximumLines) throw new Error(`${path} exceeds its archive record limit.`);
    return lines.map(JSON.parse);
  } catch (error) {
    if (error.code === "ENOENT") return [];
    throw error;
  }
}

async function writeAtomic(path, content) {
  const temporary = `${path}.tmp-${process.pid}`;
  await writeFile(temporary, content, { encoding: "utf8", mode: 0o644 });
  await rename(temporary, path);
}

async function currentCommit() {
  try {
    const { stdout } = await executeFile("git", ["rev-parse", "HEAD"], { encoding: "utf8" });
    return stdout.trim();
  } catch {
    return null;
  }
}

function parsedNow() {
  const now = process.env.SWARMPROOF_NOW === undefined
    ? new Date()
    : new Date(process.env.SWARMPROOF_NOW);
  if (!Number.isFinite(now.getTime())) throw new Error("Snapshot time is invalid.");
  return now;
}

export function sourceAtOrBeforeEnd(sourceTs, endsAt) {
  if (typeof sourceTs !== "string" || typeof endsAt !== "string") return false;
  const sourceMs = Date.parse(sourceTs);
  const endMs = Date.parse(endsAt);
  return Number.isFinite(sourceMs) && Number.isFinite(endMs) && sourceMs <= endMs;
}

export function snapshotSemanticState(report) {
  return {
    event_state: report?.event_state ?? null,
    audit_core_sha256: report?.audit_core_sha256 ?? null,
    source_event_count: report?.source_event_count ?? null,
    source_digest: report?.source_digest ?? null,
    evidence: report?.evidence ?? null,
    unsigned_proposals_observed: report?.unsigned_proposals_observed ?? null,
    collection_failed: report?.build_room?.collection_error !== null,
    build_room_cursor: {
      last_seq: report?.build_room?.last_seq ?? null,
      sequence_metadata_valid: report?.build_room?.sequence_metadata_valid ?? false,
      continuity_complete: report?.build_room?.continuity_complete ?? false,
      continuity_reason: report?.build_room?.continuity_reason ?? null,
      message_entries_truncated: report?.build_room?.message_entries_truncated ?? null,
      message_entries_uninspected: report?.build_room?.message_entries_uninspected ?? null,
      message_entries_rejected: report?.build_room?.message_entries_rejected ?? null,
      message_entries_deduplicated: report?.build_room?.message_entries_deduplicated ?? null,
    },
    events_archive_sha256: report?.snapshot_manifest?.events_archive_sha256 ?? null,
    proposals_archive_sha256: report?.snapshot_manifest?.proposals_archive_sha256 ?? null,
    network_sample_sha256: report?.snapshot_manifest?.network_sample_sha256 ?? null,
  };
}

export function deriveBuildRoomContinuity(previous, current) {
  const truncated = current?.message_entries_truncated ?? 0;
  const uninspected = current?.message_entries_uninspected ?? 0;
  const rejected = current?.message_entries_rejected ?? 0;
  const deduplicated = current?.message_entries_deduplicated ?? 0;
  if (
    current?.sequence_metadata_valid !== true
    || !Number.isSafeInteger(current.response_count)
    || current.response_count < 0
    || current.response_count > 200
    || !Number.isSafeInteger(truncated)
    || truncated !== 0
    || !Number.isSafeInteger(uninspected)
    || uninspected !== 0
    || !Number.isSafeInteger(rejected)
    || rejected !== 0
    || !Number.isSafeInteger(deduplicated)
    || deduplicated !== 0
  ) {
    return { complete: false, reason: "invalid-or-truncated-sequence-metadata" };
  }
  if (previous?.continuity_complete === false) {
    return { complete: false, reason: previous.continuity_reason ?? "previous-sequence-gap" };
  }

  const currentFirst = current.first_seq;
  const currentLast = current.last_seq;
  if (current.response_count === 0) {
    if (currentFirst !== null || currentLast !== 0) {
      return { complete: false, reason: "invalid-empty-sequence-window" };
    }
  } else if (
    !Number.isSafeInteger(currentFirst)
    || currentFirst < 1
    || !Number.isSafeInteger(currentLast)
    || currentLast < currentFirst
  ) {
    return { complete: false, reason: "invalid-sequence-window" };
  }

  const previousLast = previous?.last_seq;
  if (!Number.isSafeInteger(previousLast) || previousLast < 0) {
    return current.response_count === 0 || currentFirst === 1
      ? { complete: true, reason: "complete-from-room-origin" }
      : { complete: false, reason: "missing-contiguous-baseline" };
  }
  if (currentLast < previousLast) {
    return { complete: false, reason: "sequence-regressed" };
  }
  if (current.response_count === 0) {
    return previousLast === 0
      ? { complete: true, reason: "complete-empty-room" }
      : { complete: false, reason: "sequence-regressed" };
  }
  return currentFirst <= previousLast + 1
    ? { complete: true, reason: "overlap-or-contiguous" }
    : { complete: false, reason: "sequence-gap" };
}

export function shouldWriteSnapshot({
  previousReport,
  nextReport,
  now,
  force = false,
  refreshIntervalSeconds = ACTIVE_REFRESH_INTERVAL_SECONDS,
}) {
  if (force || !previousReport) return true;
  if (canonicalize(snapshotSemanticState(previousReport)) !== canonicalize(snapshotSemanticState(nextReport))) {
    return true;
  }
  const previousGeneratedAt = Date.parse(previousReport.generated_at);
  const nowMs = now instanceof Date ? now.getTime() : Number.NaN;
  if (!Number.isFinite(previousGeneratedAt) || !Number.isFinite(nowMs)) return true;
  return nowMs - previousGeneratedAt >= refreshIntervalSeconds * 1000;
}

function publicNetworkRecord(record) {
  return {
    room_sha256: record.room_sha256,
    source_seq: record.source_seq,
    source_ts: record.source_ts,
    signing_key_sha256: record.signed_did ? sha256Hex(record.signed_did) : null,
    actor_sha256: record.actor_sha256,
    message_sha256: record.message_sha256,
    normalized_sha256: record.normalized_sha256,
    minhash: record.minhash,
    character_count: record.character_count,
  };
}

async function snapshotMain() {
  const [config, taskManifest] = await Promise.all([
    readJson("config/event.json"),
    readJson("config/tasks.json"),
  ]);
  const allowedRepositories = new Set([config.repository]);
  const allowedTasks = new Set(taskManifest.tasks.map(task => task.id));
  const tasksById = new Map(taskManifest.tasks.map(task => [task.id, task]));
  const protocolOptions = {
    allowedRepositories,
    allowedTasks,
    coordinatorDid: config.coordinator_did,
  };
  const now = parsedNow();
  const generatedAt = now.toISOString();
  const endsAtMs = Date.parse(config.ends_at);
  const finalDrain = config.state === "active"
    && Number.isFinite(endsAtMs)
    && now.getTime() >= endsAtMs;
  const previousReport = await readJson("public/data/report.json").catch(() => null);
  const [unboundedExistingEvents, unboundedExistingProposals, roomData] = await Promise.all([
    readJsonLines("public/data/events.jsonl", 8 * 1024 * 1024, 1024),
    readJsonLines("public/data/proposals.jsonl", 4 * 1024 * 1024, 2048),
    config.state === "active"
      ? readRoom(config.build_room, 200, {
        protocolOptions,
        attempts: 4,
      }).catch(error => ({ messages: [], collection_error: error.message }))
      : Promise.resolve({
        messages: [],
        messages_observed_in_tail: previousReport?.build_room?.messages_observed_in_tail ?? 0,
        collection_error: previousReport?.build_room?.collection_error ?? null,
        response_count: previousReport?.build_room?.response_count ?? 0,
        first_seq: previousReport?.build_room?.first_seq ?? null,
        last_seq: previousReport?.build_room?.last_seq ?? 0,
        sequence_metadata_valid: previousReport?.build_room?.sequence_metadata_valid ?? false,
        message_entries_truncated: previousReport?.build_room?.message_entries_truncated ?? 0,
        message_entries_uninspected: previousReport?.build_room?.message_entries_uninspected ?? 0,
        message_entries_rejected: previousReport?.build_room?.message_entries_rejected ?? 0,
        message_entries_deduplicated: previousReport?.build_room?.message_entries_deduplicated ?? 0,
      }),
  ]);

  if (finalDrain && roomData.collection_error) {
    throw new Error(`Final build-room drain failed: ${roomData.collection_error}`);
  }
  const existingEvents = finalDrain
    ? unboundedExistingEvents.filter(record => sourceAtOrBeforeEnd(record.source_ts, config.ends_at))
    : unboundedExistingEvents;
  const existingProposals = finalDrain
    ? unboundedExistingProposals.filter(record => sourceAtOrBeforeEnd(record.source_ts, config.ends_at))
    : unboundedExistingProposals;

  const incomingEvents = [];
  const incomingProposals = [];
  for (const message of roomData.messages) {
    try {
      const derived = deriveMessageRecord(config.build_room, message, { protocolOptions });
      if (finalDrain && !sourceAtOrBeforeEnd(derived.source_ts, config.ends_at)) continue;
      if (derived.protocol_envelope) {
        incomingEvents.push({
          envelope: derived.protocol_envelope,
          observed_at: generatedAt,
          source_ts: derived.source_ts,
          source_room: config.build_room,
          source_seq: derived.source_seq,
        });
      } else if (typeof message?.text === "string" && message.text.startsWith("PROPOSE v1")) {
        incomingProposals.push({
          proposal_sha256: derived.message_sha256,
          observed_at: generatedAt,
          source_ts: derived.source_ts,
          source_room: config.build_room,
          source_seq: derived.source_seq,
        });
      }
    } catch {
      // One malformed untrusted message must not abort the bounded snapshot.
    }
  }

  const acceptIncoming = config.state === "active";
  const mergedEvents = mergeProtocolRecords(
    existingEvents,
    acceptIncoming ? incomingEvents : [],
    {
      protocolOptions,
      sourceRoom: config.build_room,
      coordinatorDid: config.coordinator_did,
    },
  );
  const events = finalDrain
    ? mergedEvents.filter(record => sourceAtOrBeforeEnd(record.source_ts, config.ends_at))
    : mergedEvents;
  const mergedProposals = mergeProposals(
    existingProposals,
    acceptIncoming ? incomingProposals : [],
    config.build_room,
  );
  const proposals = finalDrain
    ? mergedProposals.filter(record => sourceAtOrBeforeEnd(record.source_ts, config.ends_at))
    : mergedProposals;
  const artifactVerification = await verifyArtifactEvidence(events, {
    repository: config.repository,
    protocolOptions,
    tasksById,
    startsAt: config.starts_at,
    endsAt: config.ends_at,
  });
  const audited = auditEvents(events, {
    allowedRepositories: [...allowedRepositories],
    allowedTasks,
    coordinatorDid: config.coordinator_did,
    startsAt: config.starts_at,
    endsAt: config.ends_at,
    artifactChecks: artifactVerification.checks,
    additionalObserved: proposals.length,
  });

  let networkSample = null;
  let networkRecords = null;
  if (process.env.SWARMPROOF_NETWORK === "1") {
    const sampled = await collectNetworkSnapshot({
      roomLimit: Number(process.env.SWARMPROOF_ROOM_LIMIT ?? config.sample.rooms),
      messageLimit: Number(process.env.SWARMPROOF_MESSAGE_LIMIT ?? config.sample.messages_per_room),
      paceMs: Number(process.env.SWARMPROOF_PACE_MS ?? 300),
      protocolOptions,
    });
    networkSample = {
      schema: sampled.schema,
      generated_at: sampled.generated_at,
      selection: sampled.selection,
      aggregate: sampled.aggregate,
      failures: sampled.failures,
      limitations: sampled.limitations,
    };
    if (process.env.SWARMPROOF_RETAIN_SKETCHES === "1") {
      networkRecords = sampled.records.map(publicNetworkRecord);
    }
  } else {
    networkSample = previousReport?.network_sample ?? null;
  }

  const sourceCommit = await currentCommit();
  const cursorRoomData = roomData.collection_error
    ? {
      ...roomData,
      messages_observed_in_tail: previousReport?.build_room?.messages_observed_in_tail ?? 0,
      response_count: previousReport?.build_room?.response_count ?? 0,
      first_seq: previousReport?.build_room?.first_seq ?? null,
      last_seq: previousReport?.build_room?.last_seq ?? 0,
      sequence_metadata_valid: previousReport?.build_room?.sequence_metadata_valid ?? false,
      message_entries_truncated: previousReport?.build_room?.message_entries_truncated ?? 0,
      message_entries_uninspected: previousReport?.build_room?.message_entries_uninspected ?? 0,
      message_entries_rejected: previousReport?.build_room?.message_entries_rejected ?? 0,
      message_entries_deduplicated: previousReport?.build_room?.message_entries_deduplicated ?? 0,
    }
    : roomData;
  const buildRoomContinuity = config.state === "active"
    ? (roomData.collection_error
      ? {
        complete: previousReport?.build_room?.continuity_complete ?? false,
        reason: previousReport?.build_room?.continuity_reason ?? "collection-failed-before-baseline",
      }
      : deriveBuildRoomContinuity(previousReport?.build_room, cursorRoomData))
    : {
      complete: previousReport?.build_room?.continuity_complete ?? false,
      reason: previousReport?.build_room?.continuity_reason ?? "frozen-without-continuity-proof",
    };
  const eventsArchive = events.map(record => JSON.stringify(record)).join("\n") + (events.length ? "\n" : "");
  const proposalsArchive = proposals.map(record => JSON.stringify(record)).join("\n") + (proposals.length ? "\n" : "");
  const snapshotManifest = {
    schema: "swarmproof-snapshot-manifest-v1",
    generated_at: generatedAt,
    source_commit: sourceCommit,
    audit_core_sha256: audited.report_sha256,
    network_sample_sha256: networkSample ? sha256Hex(canonicalize(networkSample)) : null,
    events_archive_sha256: sha256Hex(eventsArchive),
    proposals_archive_sha256: sha256Hex(proposalsArchive),
  };
  const snapshotManifestSha256 = sha256Hex(canonicalize(snapshotManifest));
  const report = {
    ...audited.report,
    audit_core_sha256: audited.report_sha256,
    generated_at: generatedAt,
    event_state: config.state,
    unsigned_proposals_observed: proposals.length,
    build_room: {
      room: config.build_room,
      messages_observed_in_tail: config.state === "active"
        ? (roomData.collection_error ? cursorRoomData.messages_observed_in_tail : roomData.messages.length)
        : cursorRoomData.messages_observed_in_tail,
      collection_error: roomData.collection_error ?? null,
      response_count: cursorRoomData.response_count ?? 0,
      first_seq: cursorRoomData.first_seq ?? null,
      last_seq: cursorRoomData.last_seq ?? 0,
      sequence_metadata_valid: cursorRoomData.sequence_metadata_valid === true,
      message_entries_truncated: cursorRoomData.message_entries_truncated ?? 0,
      message_entries_uninspected: cursorRoomData.message_entries_uninspected ?? 0,
      message_entries_rejected: cursorRoomData.message_entries_rejected ?? 0,
      message_entries_deduplicated: cursorRoomData.message_entries_deduplicated ?? 0,
      continuity_complete: buildRoomContinuity.complete,
      continuity_reason: buildRoomContinuity.reason,
    },
    artifact_verification: {
      candidates: artifactVerification.candidates,
      attempted: artifactVerification.attempted,
      maximum_per_snapshot: artifactVerification.maximum,
      trusted_ref: "HEAD",
      maximum_artifact_bytes: 4 * 1024 * 1024,
      eligible_result_events: artifactVerification.eligible_result_events,
      duplicate_results_ignored: artifactVerification.duplicate_results,
      coordinator_slots_reserved: COORDINATOR_ARTIFACT_RESERVATION,
      participant_results_per_did_maximum: ARTIFACTS_PER_PARTICIPANT_DID_LIMIT,
      results_per_task_maximum: ARTIFACTS_PER_TASK_LIMIT,
    },
    archive_policy: {
      event_records_maximum: EVENT_RECORD_LIMIT,
      coordinator_control_records_reserved: COORDINATOR_CONTROL_RESERVATION,
      participant_records_maximum: PARTICIPANT_RECORD_LIMIT,
      records_per_participant_did_and_type_maximum: RECORDS_PER_PARTICIPANT_DID_TYPE_LIMIT,
      records_per_participant_did_maximum: RECORDS_PER_PARTICIPANT_DID_LIMIT,
      proposal_records_maximum: PROPOSAL_RECORD_LIMIT,
      selection: "newest-round-robin-by-signing-key-and-task",
      participant_archive_frozen_after_event: true,
    },
    snapshot_manifest: snapshotManifest,
    snapshot_manifest_sha256: snapshotManifestSha256,
    network_sample: networkSample,
    limitations: [
      ...audited.report.limitations,
      "Network measurements are bounded samples, not population estimates.",
      "Arbitrary Technocore message text is processed transiently and not archived.",
      "Hashes of short public text can be vulnerable to guessing.",
      "Duplicate RESULT bytes in the same repository are attributable but only the earliest eligible event, across every path, commit, and task, can be replayed or counted as reproducible.",
      "Artifact checks reserve eight coordinator slots, then select participants fairly by DID and task with per-DID and per-task caps; free DIDs still make complete Sybil resistance impossible.",
      "The event archive reserves coordinator control capacity and follows recent activity with bounded round-robin key/task selection; dependencies outside the retained archive cannot earn DAG evidence.",
      "Published network aggregates cannot be independently recomputed because per-message sketches are discarded by the public workflow.",
      "DID-shaped sender counts describe server-reported sender values; this collector does not independently verify the outer transport signature.",
      "The build room exposes a newest-200 tail without pagination, so more than 200 posts between polls can create an observation gap.",
      "TASK, CLAIM, RESULT, and REVIEW DAG evidence requires both signed claimed_at and the retained Technocore source timestamp inside the event window; polling time alone cannot admit pre-start posts.",
      "Technocore source timestamps and sequence numbers are server-reported transport metadata and are not covered by the inner SP1 signature.",
      "Fixed replay checks run from an exact trusted-main archive in a secretless bounded process; operating-system network isolation is not asserted.",
    ],
  };
  const reportSha256 = sha256Hex(canonicalize(report));
  const status = {
    schema: "swarmproof-status-v1",
    state: config.state,
    generated_at: generatedAt,
    starts_at: config.starts_at,
    ends_at: config.ends_at,
    report_sha256: reportSha256,
    audit_core_sha256: audited.report_sha256,
    snapshot_manifest_sha256: snapshotManifestSha256,
    source_commit: sourceCommit,
    signing_keys: report.signing_keys,
    reproducible_artifacts: report.evidence.reproducible,
    cross_key_reviews: report.evidence.cross_key_reviewed,
    accepted_results: report.evidence.accepted,
    stale_after_seconds: config.state === "active" ? ACTIVE_STALE_AFTER_SECONDS : 90_000,
  };

  const forceWrite = finalDrain || process.env.SWARMPROOF_NETWORK === "1" || config.state !== "active";
  if (!shouldWriteSnapshot({ previousReport, nextReport: report, now, force: forceWrite })) {
    process.stdout.write(`${JSON.stringify({
      action: "skipped",
      reason: "no_semantic_change",
      generated_at: previousReport.generated_at,
      report_sha256: sha256Hex(canonicalize(previousReport)),
    })}\n`);
    return;
  }

  await Promise.all([
    writeAtomic("public/data/events.jsonl", eventsArchive),
    writeAtomic("public/data/proposals.jsonl", proposalsArchive),
    writeAtomic("public/data/report.json", `${JSON.stringify(report, null, 2)}\n`),
    writeAtomic("public/data/status.json", `${JSON.stringify(status, null, 2)}\n`),
  ]);

  if (networkRecords) {
    await writeAtomic(
      "public/data/network-sketches.jsonl",
      networkRecords.map(record => JSON.stringify(record)).join("\n") + (networkRecords.length ? "\n" : ""),
    );
  }

  process.stdout.write(`${JSON.stringify({
    action: finalDrain ? "final_drain" : "written",
    generated_at: generatedAt,
    report_sha256: reportSha256,
    audit_core_sha256: audited.report_sha256,
    snapshot_manifest_sha256: snapshotManifestSha256,
    events: events.length,
    proposals: proposals.length,
    network_messages: networkSample?.aggregate?.messages ?? null,
  })}\n`);
}

async function assertNoPendingFinalization() {
  try {
    await readFile(TRANSACTION_FILE, "utf8");
  } catch (error) {
    if (error.code === "ENOENT") return;
    throw error;
  }
  throw new Error("A pending finalization transaction must be recovered before another snapshot.");
}

async function main() {
  const release = await acquireRepositoryLock(REPOSITORY_LOCK_FILE, "snapshot/finalizer process");
  try {
    await assertNoPendingFinalization();
    return await snapshotMain();
  } finally {
    await release();
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch(error => {
    console.error(`snapshot failed: ${error.message}`);
    process.exit(1);
  });
}
