import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createHash, generateKeyPairSync } from "node:crypto";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { hostname, tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
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
} from "../lib/evidence.mjs";
import { createEnvelope } from "../lib/protocol.mjs";
import { acquireRepositoryLock } from "../lib/repository-lock.mjs";
import { validateFinalDrain } from "../scripts/finalize.mjs";
import {
  ACTIVE_REFRESH_INTERVAL_SECONDS,
  ACTIVE_STALE_AFTER_SECONDS,
  deriveBuildRoomContinuity,
  shouldWriteSnapshot,
  sourceAtOrBeforeEnd,
} from "../scripts/snapshot.mjs";

const executeFile = promisify(execFile);
const PROJECT_ROOT = fileURLToPath(new URL("../", import.meta.url));
const FINALIZER = path.join(PROJECT_ROOT, "scripts/finalize.mjs");
const SNAPSHOT = path.join(PROJECT_ROOT, "scripts/snapshot.mjs");

async function waitFor(predicate, message, attempts = 100) {
  for (let attempt = 0; attempt < attempts; attempt += 1) {
    if (await predicate()) return;
    await new Promise(resolve => setTimeout(resolve, 20));
  }
  throw new Error(message);
}

function finalizationTransactionId(transaction) {
  return sha256Hex(canonicalize({
    schema: transaction.schema,
    owner_token: transaction.owner_token,
    events_archive_sha256: transaction.events_archive_sha256,
    proposals_archive_sha256: transaction.proposals_archive_sha256,
    targets: Object.fromEntries(
      ["config", "report", "status"].map(name => [name, transaction.targets[name].sha256]),
    ),
  }));
}

async function currentCommit() {
  return (await executeFile("git", ["rev-parse", "HEAD"], {
    cwd: PROJECT_ROOT,
    encoding: "utf8",
  })).stdout.trim();
}

async function drainFixture(options = {}) {
  const { privateKey: fixedSigner } = generateKeyPairSync("ed25519");
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
  const coordinatorDid = createEnvelope(taskSeed, fixedSigner).payload.did;
  const config = {
    schema: "swarmproof-event-config-v1",
    repository,
    coordinator_did: coordinatorDid,
    state: "active",
    starts_at: "2026-08-26T00:00:00.000Z",
    ends_at: "2026-08-28T00:00:00.000Z",
    build_room: "swarmproof-test",
    sample: { rooms: 200, messages_per_room: 200 },
  };
  const task = createEnvelope(taskSeed, fixedSigner, {
    coordinatorDid,
    allowedRepositories: new Set([repository]),
    allowedTasks: new Set(["protocol"]),
  });
  const event = {
    envelope: options.invalidEnvelope ? "SP1.test" : task.envelope,
    observed_at: "2026-08-28T00:01:00.000Z",
    source_ts: config.ends_at,
    source_room: config.build_room,
    source_seq: 10,
  };
  const eventsContent = `${JSON.stringify(event)}\n`;
  const proposalsContent = "";
  const audited = auditEvents([event], {
    allowedRepositories: [repository],
    allowedTasks: new Set(["protocol"]),
    coordinatorDid,
    startsAt: config.starts_at,
    endsAt: config.ends_at,
  });
  const generatedAt = "2026-08-28T00:01:00.000Z";
  const networkSample = {
    generated_at: "2026-08-28T00:01:30.000Z",
    selection: {
      rooms_requested: 200,
      rooms_returned: 200,
      messages_per_room_requested: 200,
      rooms_failed: 0,
    },
    aggregate: { messages: 1_000 },
    failures: [],
  };
  const snapshotManifest = {
    schema: "swarmproof-snapshot-manifest-v1",
    generated_at: generatedAt,
    source_commit: await currentCommit(),
    audit_core_sha256: audited.report_sha256,
    events_archive_sha256: sha256Hex(eventsContent),
    proposals_archive_sha256: sha256Hex(proposalsContent),
    network_sample_sha256: sha256Hex(canonicalize(networkSample)),
  };
  const report = {
    ...audited.report,
    audit_core_sha256: audited.report_sha256,
    unsigned_proposals_observed: 0,
    generated_at: generatedAt,
    event_state: "active",
    build_room: {
      room: config.build_room,
      messages_observed_in_tail: 17,
      collection_error: null,
      response_count: 17,
      first_seq: 1,
      last_seq: 17,
      sequence_metadata_valid: true,
      message_entries_truncated: 0,
      message_entries_uninspected: 0,
      message_entries_rejected: 0,
      message_entries_deduplicated: 0,
      continuity_complete: true,
      continuity_reason: "overlap-or-contiguous",
    },
    artifact_verification: {
      candidates: 0,
      attempted: 0,
      maximum_per_snapshot: ARTIFACT_CHECK_LIMIT,
      trusted_ref: "HEAD",
      maximum_artifact_bytes: 4 * 1024 * 1024,
      eligible_result_events: 0,
      duplicate_results_ignored: 0,
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
    network_sample: networkSample,
    snapshot_manifest: snapshotManifest,
    snapshot_manifest_sha256: sha256Hex(canonicalize(snapshotManifest)),
  };
  const status = {
    schema: "swarmproof-status-v1",
    state: "active",
    generated_at: report.generated_at,
    starts_at: config.starts_at,
    ends_at: config.ends_at,
    audit_core_sha256: audited.report_sha256,
    snapshot_manifest_sha256: report.snapshot_manifest_sha256,
    report_sha256: sha256Hex(canonicalize(report)),
    source_commit: snapshotManifest.source_commit,
    signing_keys: report.signing_keys,
    reproducible_artifacts: report.evidence.reproducible,
    cross_key_reviews: report.evidence.cross_key_reviewed,
    accepted_results: report.evidence.accepted,
    stale_after_seconds: 14_400,
  };
  return {
    config,
    tasks: { tasks: [{ id: "protocol" }] },
    report,
    status,
    eventsContent,
    proposalsContent,
    now: new Date("2026-08-28T00:02:00.000Z"),
  };
}

async function writeFinalizerFixture(root, fixture) {
  const paths = {
    config: path.join(root, "event.json"),
    tasks: path.join(root, "tasks.json"),
    report: path.join(root, "report.json"),
    status: path.join(root, "status.json"),
    events: path.join(root, "events.jsonl"),
    proposals: path.join(root, "proposals.jsonl"),
    transaction: path.join(root, "transaction.json"),
    lock: path.join(root, "snapshot-finalize.lock"),
  };
  await Promise.all([
    writeFile(paths.config, `${JSON.stringify(fixture.config, null, 2)}\n`, "utf8"),
    writeFile(paths.tasks, `${JSON.stringify(fixture.tasks, null, 2)}\n`, "utf8"),
    writeFile(paths.report, `${JSON.stringify(fixture.report, null, 2)}\n`, "utf8"),
    writeFile(paths.status, `${JSON.stringify(fixture.status, null, 2)}\n`, "utf8"),
    writeFile(paths.events, fixture.eventsContent, "utf8"),
    writeFile(paths.proposals, fixture.proposalsContent, "utf8"),
  ]);
  return paths;
}

function finalizerEnvironment(paths, fixture, overrides = {}) {
  return {
    ...process.env,
    SWARMPROOF_CONFIG_FILE: paths.config,
    SWARMPROOF_TASKS_FILE: paths.tasks,
    SWARMPROOF_REPORT_FILE: paths.report,
    SWARMPROOF_STATUS_FILE: paths.status,
    SWARMPROOF_EVENTS_FILE: paths.events,
    SWARMPROOF_PROPOSALS_FILE: paths.proposals,
    SWARMPROOF_FINALIZE_TRANSACTION_FILE: paths.transaction,
    SWARMPROOF_SNAPSHOT_LOCK_FILE: paths.lock,
    SWARMPROOF_NOW: fixture.now.toISOString(),
    ...overrides,
  };
}

function semanticReport(generatedAt = "2026-08-26T01:00:00.000Z") {
  return {
    generated_at: generatedAt,
    event_state: "active",
    audit_core_sha256: "a".repeat(64),
    source_event_count: 3,
    source_digest: "b".repeat(64),
    evidence: { observed: 3, attributable: 3, reproducible: 1, cross_key_reviewed: 0, accepted: 0 },
    unsigned_proposals_observed: 0,
    build_room: { collection_error: null, messages_observed_in_tail: 10 },
    snapshot_manifest: {
      source_commit: "c".repeat(40),
      events_archive_sha256: "d".repeat(64),
      proposals_archive_sha256: "e".repeat(64),
      network_sample_sha256: "f".repeat(64),
    },
  };
}

test("active freshness tolerates schedule delay while refreshing before the bound", () => {
  assert.equal(ACTIVE_REFRESH_INTERVAL_SECONDS, 3 * 60 * 60);
  assert.equal(ACTIVE_STALE_AFTER_SECONDS, 4 * 60 * 60);
  assert.ok(ACTIVE_REFRESH_INTERVAL_SECONDS < ACTIVE_STALE_AFTER_SECONDS);
});

test("final-drain boundary admits only trustworthy source timestamps at or before ends_at", () => {
  const end = "2026-08-28T00:00:00.000Z";
  assert.equal(sourceAtOrBeforeEnd("2026-08-27T23:59:59.999Z", end), true);
  assert.equal(sourceAtOrBeforeEnd(end, end), true);
  assert.equal(sourceAtOrBeforeEnd("2026-08-28T00:00:00.001Z", end), false);
  assert.equal(sourceAtOrBeforeEnd(null, end), false);
  assert.equal(sourceAtOrBeforeEnd("not-a-time", end), false);
});

test("build-room continuity is sticky and rejects a cursor gap or truncated tail", () => {
  const previous = {
    last_seq: 100,
    continuity_complete: true,
    continuity_reason: "overlap-or-contiguous",
  };
  const current = {
    response_count: 11,
    first_seq: 100,
    last_seq: 110,
    sequence_metadata_valid: true,
    message_entries_truncated: 0,
    message_entries_uninspected: 0,
    message_entries_rejected: 0,
    message_entries_deduplicated: 0,
  };
  assert.deepEqual(deriveBuildRoomContinuity(previous, current), {
    complete: true,
    reason: "overlap-or-contiguous",
  });
  assert.deepEqual(deriveBuildRoomContinuity(previous, { ...current, first_seq: 102, last_seq: 112 }), {
    complete: false,
    reason: "sequence-gap",
  });
  assert.deepEqual(deriveBuildRoomContinuity(previous, { ...current, message_entries_truncated: 1 }), {
    complete: false,
    reason: "invalid-or-truncated-sequence-metadata",
  });
  assert.deepEqual(deriveBuildRoomContinuity(previous, { ...current, message_entries_rejected: 1 }), {
    complete: false,
    reason: "invalid-or-truncated-sequence-metadata",
  });
  assert.deepEqual(deriveBuildRoomContinuity({
    ...previous,
    continuity_complete: false,
    continuity_reason: "sequence-gap",
  }, current), {
    complete: false,
    reason: "sequence-gap",
  });
});

test("15-minute polls suppress timestamp-only commits but preserve changes and keepalives", () => {
  const previousReport = semanticReport();
  const nextReport = structuredClone(previousReport);
  nextReport.generated_at = "2026-08-26T01:15:00.000Z";
  nextReport.snapshot_manifest.source_commit = "9".repeat(40);
  nextReport.build_room.messages_observed_in_tail = 11;
  assert.equal(shouldWriteSnapshot({
    previousReport,
    nextReport,
    now: new Date(nextReport.generated_at),
  }), false);

  assert.equal(shouldWriteSnapshot({
    previousReport,
    nextReport,
    now: new Date("2026-08-26T04:00:00.000Z"),
  }), true);

  nextReport.source_event_count += 1;
  assert.equal(shouldWriteSnapshot({
    previousReport,
    nextReport,
    now: new Date("2026-08-26T01:15:00.000Z"),
  }), true);
  assert.equal(shouldWriteSnapshot({
    previousReport,
    nextReport: previousReport,
    now: new Date("2026-08-26T01:15:00.000Z"),
    force: true,
  }), true);
});

test("finalization accepts a successful post-boundary drain and rejects late or failed evidence", async () => {
  const valid = await drainFixture();
  assert.deepEqual(validateFinalDrain(valid), {
    events: 1,
    proposals: 0,
    generated_at: valid.report.generated_at,
  });

  const afterEnd = structuredClone(valid);
  const afterEndEvent = JSON.parse(afterEnd.eventsContent);
  afterEndEvent.source_ts = "2026-08-28T00:00:00.001Z";
  afterEnd.eventsContent = `${JSON.stringify(afterEndEvent)}\n`;
  assert.throws(() => validateFinalDrain(afterEnd), /after the event boundary/u);

  const failed = structuredClone(valid);
  failed.report.build_room.collection_error = "temporary failure";
  assert.throws(() => validateFinalDrain(failed), /did not succeed/u);

  const gapped = structuredClone(valid);
  gapped.report.build_room.continuity_complete = false;
  gapped.report.build_room.continuity_reason = "sequence-gap";
  assert.throws(() => validateFinalDrain(gapped), /history is not contiguous/u);

  const partialSample = structuredClone(valid);
  partialSample.report.network_sample.selection.rooms_failed = 1;
  partialSample.report.network_sample.failures.push({ room_sha256: "a".repeat(64), reason: "read failed" });
  assert.throws(() => validateFinalDrain(partialSample), /network sample is incomplete/u);

  const oldSample = structuredClone(valid);
  oldSample.report.network_sample.generated_at = "2026-08-27T23:59:59.999Z";
  assert.throws(() => validateFinalDrain(oldSample), /network sample was captured before/u);

  const early = structuredClone(valid);
  early.report.generated_at = "2026-08-27T23:59:59.999Z";
  early.status.generated_at = early.report.generated_at;
  assert.throws(() => validateFinalDrain(early), /before the event ended/u);
});

test("finalizer check reports a required drain without mutating active config", async t => {
  const root = await mkdtemp(path.join(tmpdir(), "swarmproof-finalizer-check-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const configPath = path.join(root, "event.json");
  const config = {
    schema: "swarmproof-event-config-v1",
    state: "active",
    starts_at: "2026-08-26T00:00:00.000Z",
    ends_at: "2026-08-28T00:00:00.000Z",
  };
  const original = `${JSON.stringify(config, null, 2)}\n`;
  await writeFile(configPath, original, "utf8");
  const result = await executeFile(process.execPath, [FINALIZER, "--check"], {
    encoding: "utf8",
    env: {
      ...process.env,
      SWARMPROOF_CONFIG_FILE: configPath,
      SWARMPROOF_NOW: config.ends_at,
    },
  });
  assert.match(result.stdout, /"action":"final_drain_required"/u);
  assert.equal(await readFile(configPath, "utf8"), original);
});

test("finalizer freezes only the exact validated drain files", async t => {
  const root = await mkdtemp(path.join(tmpdir(), "swarmproof-finalizer-freeze-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const fixture = await drainFixture();
  const paths = await writeFinalizerFixture(root, fixture);
  const result = await executeFile(process.execPath, [FINALIZER], {
    encoding: "utf8",
    env: finalizerEnvironment(paths, fixture),
    cwd: PROJECT_ROOT,
  });
  assert.match(result.stdout, /"action":"finalized"/u);
  const [config, report, status] = await Promise.all([
    readFile(paths.config, "utf8").then(JSON.parse),
    readFile(paths.report, "utf8").then(JSON.parse),
    readFile(paths.status, "utf8").then(JSON.parse),
  ]);
  assert.equal(config.state, "complete");
  assert.equal(report.event_state, "complete");
  assert.equal(status.state, "complete");
  assert.equal(report.generated_at, fixture.report.generated_at);
  assert.deepEqual(report.network_sample, fixture.report.network_sample);
  assert.deepEqual(report.snapshot_manifest, fixture.report.snapshot_manifest);
  assert.equal(status.report_sha256, sha256Hex(canonicalize(report)));
  assert.equal(status.stale_after_seconds, 90_000);
  await assert.rejects(readFile(paths.transaction, "utf8"), error => error.code === "ENOENT");
});

test("finalizer rejects an invalid but self-consistent public envelope before transition", async t => {
  const root = await mkdtemp(path.join(tmpdir(), "swarmproof-finalizer-envelope-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const fixture = await drainFixture({ invalidEnvelope: true });
  assert.doesNotThrow(() => validateFinalDrain(fixture));
  const paths = await writeFinalizerFixture(root, fixture);
  const originals = await Promise.all([
    readFile(paths.config, "utf8"),
    readFile(paths.report, "utf8"),
    readFile(paths.status, "utf8"),
  ]);

  await assert.rejects(
    executeFile(process.execPath, [FINALIZER], {
      encoding: "utf8",
      env: finalizerEnvironment(paths, fixture),
      cwd: PROJECT_ROOT,
    }),
    error => (
      error.code === 1
      && /Full public snapshot verification failed/u.test(error.stderr)
      && /Envelope prefix is invalid/u.test(error.stderr)
    ),
  );

  assert.deepEqual(await Promise.all([
    readFile(paths.config, "utf8"),
    readFile(paths.report, "utf8"),
    readFile(paths.status, "utf8"),
  ]), originals);
  await assert.rejects(readFile(paths.transaction, "utf8"), error => error.code === "ENOENT");
});

test("finalizer recovers a partially applied transaction without replacing the final drain", async t => {
  const root = await mkdtemp(path.join(tmpdir(), "swarmproof-finalizer-recovery-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const fixture = await drainFixture();
  const paths = await writeFinalizerFixture(root, fixture);

  await assert.rejects(
    executeFile(process.execPath, [FINALIZER], {
      encoding: "utf8",
      env: finalizerEnvironment(paths, fixture, {
        NODE_ENV: "test",
        SWARMPROOF_TEST_INTERRUPT_AFTER_TARGET: "report",
      }),
      cwd: PROJECT_ROOT,
    }),
    error => error.code === 1 && /Simulated interruption after report/u.test(error.stderr),
  );
  assert.equal(JSON.parse(await readFile(paths.config, "utf8")).state, "active");
  assert.equal(JSON.parse(await readFile(paths.report, "utf8")).event_state, "complete");
  assert.equal(JSON.parse(await readFile(paths.status, "utf8")).state, "active");
  assert.equal(JSON.parse(await readFile(paths.transaction, "utf8")).schema, "swarmproof-finalization-transaction-v2");

  const recovered = await executeFile(process.execPath, [FINALIZER], {
    encoding: "utf8",
    env: finalizerEnvironment(paths, fixture, {
      NODE_ENV: "production",
      SWARMPROOF_TEST_INTERRUPT_AFTER_TARGET: "",
    }),
    cwd: PROJECT_ROOT,
  });
  assert.match(recovered.stdout, /"reason":"recovered_interrupted_transaction"/u);
  const [config, report, status] = await Promise.all([
    readFile(paths.config, "utf8").then(JSON.parse),
    readFile(paths.report, "utf8").then(JSON.parse),
    readFile(paths.status, "utf8").then(JSON.parse),
  ]);
  assert.equal(config.state, "complete");
  assert.equal(report.event_state, "complete");
  assert.equal(status.state, "complete");
  assert.equal(report.generated_at, fixture.report.generated_at);
  assert.deepEqual(report.network_sample, fixture.report.network_sample);
  assert.deepEqual(report.snapshot_manifest, fixture.report.snapshot_manifest);
  assert.equal(status.report_sha256, sha256Hex(canonicalize(report)));
  await assert.rejects(readFile(paths.transaction, "utf8"), error => error.code === "ENOENT");
});

test("snapshot and finalizer share one exclusive repository lock", async t => {
  const root = await mkdtemp(path.join(tmpdir(), "swarmproof-finalizer-lock-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const fixture = await drainFixture();
  const paths = await writeFinalizerFixture(root, fixture);
  const holder = executeFile(process.execPath, [FINALIZER], {
    encoding: "utf8",
    env: finalizerEnvironment(paths, fixture, {
      NODE_ENV: "test",
      SWARMPROOF_TEST_PAUSE_AFTER_TARGET: "report",
      SWARMPROOF_TEST_PAUSE_MS: "2000",
    }),
    cwd: PROJECT_ROOT,
  });
  await waitFor(async () => {
    try {
      return JSON.parse(await readFile(paths.report, "utf8")).event_state === "complete";
    } catch {
      return false;
    }
  }, "Finalizer did not reach its locked apply phase.");

  await assert.rejects(
    executeFile(process.execPath, [SNAPSHOT], {
      encoding: "utf8",
      env: finalizerEnvironment(paths, fixture),
      cwd: PROJECT_ROOT,
    }),
    error => error.code === 1 && /owns the repository lock/u.test(error.stderr),
  );
  const completed = await holder;
  assert.match(completed.stdout, /"action":"finalized"/u);
  await assert.rejects(readFile(paths.lock, "utf8"), error => error.code === "ENOENT");
});

test("finalizer detects archive mutation before config is completed", async t => {
  const root = await mkdtemp(path.join(tmpdir(), "swarmproof-finalizer-archive-cas-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const fixture = await drainFixture();
  const paths = await writeFinalizerFixture(root, fixture);
  const finalizing = executeFile(process.execPath, [FINALIZER], {
    encoding: "utf8",
    env: finalizerEnvironment(paths, fixture, {
      NODE_ENV: "test",
      SWARMPROOF_TEST_PAUSE_AFTER_TARGET: "report",
      SWARMPROOF_TEST_PAUSE_MS: "2000",
    }),
    cwd: PROJECT_ROOT,
  });
  await waitFor(async () => {
    try {
      return JSON.parse(await readFile(paths.report, "utf8")).event_state === "complete";
    } catch {
      return false;
    }
  }, "Finalizer did not reach its archive-CAS test point.");
  await writeFile(paths.events, `${fixture.eventsContent}\n`, "utf8");

  await assert.rejects(
    finalizing,
    error => error.code === 1 && /Event archive changed before applying status/u.test(error.stderr),
  );
  assert.equal(JSON.parse(await readFile(paths.config, "utf8")).state, "active");
  assert.equal(JSON.parse(await readFile(paths.status, "utf8")).state, "active");
  assert.equal(JSON.parse(await readFile(paths.transaction, "utf8")).schema, "swarmproof-finalization-transaction-v2");
});

test("finalizer checks journal ownership before every remaining target", async t => {
  const root = await mkdtemp(path.join(tmpdir(), "swarmproof-finalizer-journal-cas-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const fixture = await drainFixture();
  const paths = await writeFinalizerFixture(root, fixture);
  const finalizing = executeFile(process.execPath, [FINALIZER], {
    encoding: "utf8",
    env: finalizerEnvironment(paths, fixture, {
      NODE_ENV: "test",
      SWARMPROOF_TEST_PAUSE_AFTER_TARGET: "report",
      SWARMPROOF_TEST_PAUSE_MS: "2000",
    }),
    cwd: PROJECT_ROOT,
  });
  await waitFor(async () => {
    try {
      return JSON.parse(await readFile(paths.report, "utf8")).event_state === "complete";
    } catch {
      return false;
    }
  }, "Finalizer did not reach its journal-CAS test point.");
  const replacement = JSON.parse(await readFile(paths.transaction, "utf8"));
  replacement.owner_token = "b".repeat(64);
  replacement.transaction_id = finalizationTransactionId(replacement);
  await writeFile(paths.transaction, `${JSON.stringify(replacement, null, 2)}\n`, "utf8");

  await assert.rejects(
    finalizing,
    error => error.code === 1 && /transaction ownership changed before applying status/u.test(error.stderr),
  );
  assert.equal(JSON.parse(await readFile(paths.config, "utf8")).state, "active");
  assert.equal(JSON.parse(await readFile(paths.status, "utf8")).state, "active");
  assert.equal(JSON.parse(await readFile(paths.transaction, "utf8")).owner_token, "b".repeat(64));
});

test("pending finalization journal blocks a new snapshot even without a lock holder", async t => {
  const root = await mkdtemp(path.join(tmpdir(), "swarmproof-finalizer-journal-block-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const transaction = path.join(root, "transaction.json");
  const lock = path.join(root, "snapshot-finalize.lock");
  await writeFile(transaction, "pending\n", "utf8");
  await assert.rejects(
    executeFile(process.execPath, [SNAPSHOT], {
      encoding: "utf8",
      env: {
        ...process.env,
        SWARMPROOF_CONFIG_FILE: path.join(root, "event.json"),
        SWARMPROOF_FINALIZE_TRANSACTION_FILE: transaction,
        SWARMPROOF_SNAPSHOT_LOCK_FILE: lock,
      },
      cwd: PROJECT_ROOT,
    }),
    error => error.code === 1 && /must be recovered before another snapshot/u.test(error.stderr),
  );
  await assert.rejects(readFile(lock, "utf8"), error => error.code === "ENOENT");
});

test("repository lock refuses active and stale foreign owners without deleting either", async t => {
  const root = await mkdtemp(path.join(tmpdir(), "swarmproof-repository-lock-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const lock = path.join(root, "repository.lock");
  const release = await acquireRepositoryLock(lock, "test process");
  const activeContent = await readFile(lock, "utf8");
  await assert.rejects(
    acquireRepositoryLock(lock, "test process"),
    /held by an active local process.*refusing to remove it/u,
  );
  assert.equal(await readFile(lock, "utf8"), activeContent);
  await release();

  const staleContent = `${JSON.stringify({
    schema: "swarmproof-repository-lock-v1",
    owner_token: "a".repeat(64),
    pid: 2_147_483_647,
    host_sha256: createHash("sha256").update(hostname(), "utf8").digest("hex"),
    created_at: "2026-08-26T00:00:00.000Z",
  })}\n`;
  await writeFile(lock, staleContent, { encoding: "utf8", mode: 0o600 });
  await assert.rejects(
    acquireRepositoryLock(lock, "test process"),
    /stale from a terminated local process.*refusing to remove it/u,
  );
  assert.equal(await readFile(lock, "utf8"), staleContent);
});

test("repository lock release is ownership-checked", async t => {
  const root = await mkdtemp(path.join(tmpdir(), "swarmproof-repository-lock-owner-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const lock = path.join(root, "repository.lock");
  const release = await acquireRepositoryLock(lock, "test process");
  const metadata = JSON.parse(await readFile(lock, "utf8"));
  metadata.owner_token = "f".repeat(64);
  await writeFile(lock, `${JSON.stringify(metadata)}\n`, "utf8");
  await assert.rejects(release(), /owner changed before release/u);
  assert.equal(JSON.parse(await readFile(lock, "utf8")).owner_token, "f".repeat(64));
});
