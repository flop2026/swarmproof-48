#!/usr/bin/env node

import { execFile } from "node:child_process";
import { readFile, rename, writeFile } from "node:fs/promises";
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
import {
  ARTIFACTS_PER_PARTICIPANT_DID_LIMIT,
  ARTIFACTS_PER_TASK_LIMIT,
  COORDINATOR_ARTIFACT_RESERVATION,
  verifyArtifactEvidence,
} from "../lib/evidence.mjs";

const executeFile = promisify(execFile);

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

async function main() {
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
  const generatedAt = new Date().toISOString();
  const [existingEvents, existingProposals, roomData] = await Promise.all([
    readJsonLines("public/data/events.jsonl", 8 * 1024 * 1024, 1024),
    readJsonLines("public/data/proposals.jsonl", 4 * 1024 * 1024, 2048),
    readRoom(config.build_room, 200, {
      protocolOptions,
      attempts: 4,
    }).catch(error => ({ messages: [], collection_error: error.message })),
  ]);

  const incomingEvents = [];
  const incomingProposals = [];
  for (const message of roomData.messages) {
    try {
      const derived = deriveMessageRecord(config.build_room, message, { protocolOptions });
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
  const events = mergeProtocolRecords(
    existingEvents,
    acceptIncoming ? incomingEvents : [],
    {
      protocolOptions,
      sourceRoom: config.build_room,
      coordinatorDid: config.coordinator_did,
    },
  );
  const proposals = mergeProposals(
    existingProposals,
    acceptIncoming ? incomingProposals : [],
    config.build_room,
  );
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
    const previous = await readJson("public/data/report.json").catch(() => null);
    networkSample = previous?.network_sample ?? null;
  }

  const sourceCommit = await currentCommit();
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
      messages_observed_in_tail: roomData.messages.length,
      collection_error: roomData.collection_error ?? null,
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
      "Duplicate RESULT artifact tuples are attributable but only the earliest eligible event, across every task, can be replayed or counted as reproducible.",
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
    stale_after_seconds: config.state === "active" ? 2_700 : 90_000,
  };

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
    generated_at: generatedAt,
    report_sha256: reportSha256,
    audit_core_sha256: audited.report_sha256,
    snapshot_manifest_sha256: snapshotManifestSha256,
    events: events.length,
    proposals: proposals.length,
    network_messages: networkSample?.aggregate?.messages ?? null,
  })}\n`);
}

main().catch(error => {
  console.error(`snapshot failed: ${error.message}`);
  process.exit(1);
});
