import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { generateKeyPairSync } from "node:crypto";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import test from "node:test";
import { auditEvents } from "../lib/audit.mjs";
import { canonicalize } from "../lib/canonical.mjs";
import { sha256Hex } from "../lib/crypto.mjs";
import { createEnvelope } from "../lib/protocol.mjs";

const executeFile = promisify(execFile);
const PROJECT_ROOT = fileURLToPath(new URL("..", import.meta.url));
const CLI = path.join(PROJECT_ROOT, "bin", "swarmproof.mjs");

async function run(arguments_) {
  return executeFile(process.execPath, [CLI, ...arguments_], {
    cwd: PROJECT_ROOT,
    encoding: "utf8",
  });
}

async function currentCommit() {
  return (await executeFile("git", ["rev-parse", "HEAD"], {
    cwd: PROJECT_ROOT,
    encoding: "utf8",
  })).stdout.trim();
}

test("CLI defaults to project authorization and labels structural-only output", async () => {
  const directory = await mkdtemp(path.join(tmpdir(), "swarmproof-cli-context-"));
  try {
    const { privateKey } = generateKeyPairSync("ed25519");
    const keyPath = path.join(directory, "test-key.pem");
    const payloadPath = path.join(directory, "task.json");
    await Promise.all([
      writeFile(keyPath, privateKey.export({ format: "pem", type: "pkcs8" }), { mode: 0o600 }),
      writeFile(payloadPath, JSON.stringify({
        schema: "swarmproof-event-v1",
        type: "TASK",
        task_id: "protocol",
        claimed_at: "2026-08-26T00:00:00.000Z",
        nonce: "1",
        parent_event_ids: [],
        content_sha256: "a".repeat(64),
      })),
    ]);

    await assert.rejects(
      run(["sign", "--payload", payloadPath, "--key", keyPath]),
      error => error.code === 1 && /configured coordinator DID/u.test(error.stderr),
    );

    const signed = JSON.parse((await run([
      "sign", "--payload", payloadPath, "--key", keyPath, "--structural-only",
    ])).stdout);
    assert.equal(signed.validation_scope, "structural-only");
    assert.match(signed.warning, /authorization and acceptance were not checked/u);

    await assert.rejects(
      run(["verify", "--envelope", signed.envelope]),
      error => error.code === 1 && /configured coordinator DID/u.test(error.stderr),
    );

    const verified = JSON.parse((await run([
      "verify", "--envelope", signed.envelope, "--structural-only",
    ])).stdout);
    assert.equal(verified.signature_valid, true);
    assert.equal(verified.validation_scope, "structural-only");
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("CLI verifies and replays a public report plus its bound archives in one command", async () => {
  const directory = await mkdtemp(path.join(tmpdir(), "swarmproof-cli-report-"));
  try {
    const { privateKey } = generateKeyPairSync("ed25519");
    const repository = "flop2026/swarmproof-48";
    const taskSeed = {
      schema: "swarmproof-event-v1",
      type: "TASK",
      task_id: "protocol",
      claimed_at: "2026-08-26T00:00:00.000Z",
      nonce: "1",
      parent_event_ids: [],
      content_sha256: "a".repeat(64),
    };
    const coordinatorDid = createEnvelope(taskSeed, privateKey).payload.did;
    const task = createEnvelope(taskSeed, privateKey, {
      coordinatorDid,
      allowedRepositories: new Set([repository]),
      allowedTasks: new Set(["protocol"]),
    });
    const record = {
      envelope: task.envelope,
      observed_at: "2026-08-26T00:00:01.000Z",
      source_ts: "2026-08-26T00:00:00.500Z",
      source_room: "cli-report-fixture",
      source_seq: 1,
    };
    const config = {
      schema: "swarmproof-event-config-v1",
      repository,
      coordinator_did: coordinatorDid,
      build_room: "cli-report-fixture",
      state: "active",
      starts_at: "2026-08-26T00:00:00.000Z",
      ends_at: "2026-08-28T00:00:00.000Z",
    };
    const taskManifest = {
      tasks: [{ id: "protocol", replay_check: ["node", "--test"] }],
    };
    const audited = auditEvents([record], {
      allowedRepositories: [repository],
      allowedTasks: new Set(["protocol"]),
      coordinatorDid,
      startsAt: config.starts_at,
      endsAt: config.ends_at,
    });
    const eventsContent = `${JSON.stringify(record)}\n`;
    const proposalsContent = "";
    const generatedAt = "2026-08-26T00:01:00.000Z";
    const sourceCommit = await currentCommit();
    const snapshotManifest = {
      schema: "swarmproof-snapshot-manifest-v1",
      generated_at: generatedAt,
      audit_core_sha256: audited.report_sha256,
      network_sample_sha256: null,
      events_archive_sha256: sha256Hex(eventsContent),
      proposals_archive_sha256: sha256Hex(proposalsContent),
      source_commit: sourceCommit,
    };
    const report = {
      ...audited.report,
      audit_core_sha256: audited.report_sha256,
      generated_at: generatedAt,
      event_state: "active",
      unsigned_proposals_observed: 0,
      build_room: {
        room: config.build_room,
        messages_observed_in_tail: 1,
        collection_error: null,
        response_count: 1,
        first_seq: 1,
        last_seq: 1,
        sequence_metadata_valid: true,
        message_entries_truncated: 0,
        message_entries_uninspected: 0,
        message_entries_rejected: 0,
        message_entries_deduplicated: 0,
        continuity_complete: true,
        continuity_reason: "complete-from-room-origin",
      },
      artifact_verification: {
        candidates: 0,
        attempted: 0,
        maximum_per_snapshot: 64,
        trusted_ref: "HEAD",
        maximum_artifact_bytes: 4 * 1024 * 1024,
        eligible_result_events: 0,
        duplicate_results_ignored: 0,
        coordinator_slots_reserved: 8,
        participant_results_per_did_maximum: 2,
        results_per_task_maximum: 8,
      },
      archive_policy: {
        event_records_maximum: 1024,
        coordinator_control_records_reserved: 64,
        participant_records_maximum: 960,
        records_per_participant_did_and_type_maximum: 8,
        records_per_participant_did_maximum: 32,
        proposal_records_maximum: 2048,
        selection: "newest-round-robin-by-signing-key-and-task",
        participant_archive_frozen_after_event: true,
      },
      network_sample: null,
      snapshot_manifest: snapshotManifest,
      snapshot_manifest_sha256: sha256Hex(canonicalize(snapshotManifest)),
    };
    const status = {
      schema: "swarmproof-status-v1",
      state: "active",
      generated_at: generatedAt,
      starts_at: config.starts_at,
      ends_at: config.ends_at,
      report_sha256: sha256Hex(canonicalize(report)),
      audit_core_sha256: audited.report_sha256,
      snapshot_manifest_sha256: report.snapshot_manifest_sha256,
      source_commit: sourceCommit,
      signing_keys: report.signing_keys,
      reproducible_artifacts: report.evidence.reproducible,
      cross_key_reviews: report.evidence.cross_key_reviewed,
      accepted_results: report.evidence.accepted,
      stale_after_seconds: 4 * 60 * 60,
    };
    const paths = Object.fromEntries(
      ["config", "tasks", "events", "proposals", "report", "status"]
        .map(name => [name, path.join(directory, `${name}.${["events", "proposals"].includes(name) ? "jsonl" : "json"}`)]),
    );
    await Promise.all([
      writeFile(paths.config, JSON.stringify(config)),
      writeFile(paths.tasks, JSON.stringify(taskManifest)),
      writeFile(paths.events, eventsContent),
      writeFile(paths.proposals, proposalsContent),
      writeFile(paths.report, JSON.stringify(report)),
      writeFile(paths.status, JSON.stringify(status)),
    ]);
    const arguments_ = [
      "verify-report",
      "--config", paths.config,
      "--tasks", paths.tasks,
      "--events", paths.events,
      "--proposals", paths.proposals,
      "--report", paths.report,
      "--status", paths.status,
    ];
    const verification = JSON.parse((await run(arguments_)).stdout);
    assert.equal(verification.schema, "swarmproof-report-verification-v1");
    assert.equal(verification.checks.audit_core_replay, "pass");
    assert.equal(verification.checks.archive_manifest_binding, "pass");
    assert.equal(verification.records.events, 1);

    const expectBindingFailure = async (documents, pattern) => {
      const nextReport = documents.report ?? report;
      const nextStatus = documents.status ?? status;
      const nextConfig = documents.config ?? config;
      try {
        await Promise.all([
          writeFile(paths.config, JSON.stringify(nextConfig)),
          writeFile(paths.report, JSON.stringify(nextReport)),
          writeFile(paths.status, JSON.stringify(nextStatus)),
        ]);
        await assert.rejects(
          run(arguments_),
          error => error.code === 1 && pattern.test(error.stderr),
        );
      } finally {
        await Promise.all([
          writeFile(paths.config, JSON.stringify(config)),
          writeFile(paths.report, JSON.stringify(report)),
          writeFile(paths.status, JSON.stringify(status)),
        ]);
      }
    };

    await expectBindingFailure({
      status: { ...status, unbound_claim: "world-number-one" },
    }, /Public status has an invalid field set/u);

    await expectBindingFailure({
      status: {
        ...status,
        starts_at: "2026-08-27T00:00:00.000Z",
        ends_at: "2026-08-29T00:00:00.000Z",
      },
    }, /event window does not match project config/u);

    const wrongRoomReport = {
      ...report,
      build_room: { ...report.build_room, room: "other-room" },
    };
    await expectBindingFailure({
      report: wrongRoomReport,
      status: { ...status, report_sha256: sha256Hex(canonicalize(wrongRoomReport)) },
    }, /build room does not match project config/u);

    await expectBindingFailure({
      config: { ...config, state: "complete" },
    }, /lifecycle state does not match project config/u);

    const inflatedArtifactReport = {
      ...report,
      artifact_verification: {
        ...report.artifact_verification,
        candidates: 1,
        eligible_result_events: 1,
      },
    };
    await expectBindingFailure({
      report: inflatedArtifactReport,
      status: { ...status, report_sha256: sha256Hex(canonicalize(inflatedArtifactReport)) },
    }, /artifact candidate count does not match replay/u);

    const expectArchiveFailure = async ({ events = eventsContent, proposals = proposalsContent }, pattern) => {
      await Promise.all([
        writeFile(paths.events, events),
        writeFile(paths.proposals, proposals),
      ]);
      await assert.rejects(
        run(arguments_),
        error => error.code === 1 && pattern.test(error.stderr),
      );
      await Promise.all([
        writeFile(paths.events, eventsContent),
        writeFile(paths.proposals, proposalsContent),
      ]);
    };

    const untrustedSourceManifest = {
      ...report.snapshot_manifest,
      source_commit: "0".repeat(40),
    };
    const untrustedSourceReport = {
      ...report,
      snapshot_manifest: untrustedSourceManifest,
      snapshot_manifest_sha256: sha256Hex(canonicalize(untrustedSourceManifest)),
    };
    const untrustedSourceStatus = {
      ...status,
      report_sha256: sha256Hex(canonicalize(untrustedSourceReport)),
      snapshot_manifest_sha256: untrustedSourceReport.snapshot_manifest_sha256,
      source_commit: untrustedSourceManifest.source_commit,
    };
    await Promise.all([
      writeFile(paths.report, JSON.stringify(untrustedSourceReport)),
      writeFile(paths.status, JSON.stringify(untrustedSourceStatus)),
    ]);
    await assert.rejects(
      run(arguments_),
      error => error.code === 1 && /source_commit is not on the trusted HEAD history/u.test(error.stderr),
    );
    await Promise.all([
      writeFile(paths.report, JSON.stringify(report)),
      writeFile(paths.status, JSON.stringify(status)),
    ]);

    await expectArchiveFailure({
      events: `${JSON.stringify({ ...record, unexpected: true })}\n`,
    }, /invalid field set/u);
    await expectArchiveFailure({
      events: `${JSON.stringify({ ...record, source_room: "other-room" })}\n`,
    }, /does not match the configured build room/u);
    await expectArchiveFailure({
      events: `${JSON.stringify({ ...record, observed_at: "2026-08-26T00:00:01Z" })}\n`,
    }, /is not canonical UTC/u);
    await expectArchiveFailure({
      events: `${JSON.stringify(record)}\n${JSON.stringify({ ...record, source_seq: null })}\n`,
    }, /duplicate event/u);
    const proposal = {
      proposal_sha256: "f".repeat(64),
      observed_at: "2026-08-26T00:00:02.000Z",
      source_ts: "2026-08-26T00:00:01.500Z",
      source_room: config.build_room,
      source_seq: 2,
    };
    await expectArchiveFailure({
      proposals: `${JSON.stringify(proposal)}\n${JSON.stringify({ ...proposal, source_seq: 3 })}\n`,
    }, /duplicate proposal/u);

    const inflatedReport = {
      ...report,
      evidence: {
        ...report.evidence,
        observed: report.evidence.observed + 100,
      },
    };
    const reboundStatus = {
      ...status,
      report_sha256: sha256Hex(canonicalize(inflatedReport)),
    };
    await Promise.all([
      writeFile(paths.report, JSON.stringify(inflatedReport)),
      writeFile(paths.status, JSON.stringify(reboundStatus)),
    ]);
    await assert.rejects(
      run(arguments_),
      error => error.code === 1 && /audit-core fields do not match/u.test(error.stderr),
    );

    await Promise.all([
      writeFile(paths.report, JSON.stringify(report)),
      writeFile(paths.status, JSON.stringify(status)),
    ]);
    await writeFile(paths.events, `${eventsContent}\n`);
    await assert.rejects(
      run(arguments_),
      error => error.code === 1 && /Events archive SHA-256 does not match snapshot manifest/u.test(error.stderr),
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
