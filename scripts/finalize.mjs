#!/usr/bin/env node

import { execFile } from "node:child_process";
import { randomBytes } from "node:crypto";
import { link, mkdtemp, readFile, rename, rm, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { promisify } from "node:util";
import { canonicalize } from "../lib/canonical.mjs";
import { sha256Hex } from "../lib/crypto.mjs";
import { transitionEventLifecycle } from "../lib/lifecycle.mjs";
import { acquireRepositoryLock } from "../lib/repository-lock.mjs";

const executeFile = promisify(execFile);
const CONFIG_FILE = process.env.SWARMPROOF_CONFIG_FILE ?? "config/event.json";
const TASKS_FILE = process.env.SWARMPROOF_TASKS_FILE ?? "config/tasks.json";
const REPORT_FILE = process.env.SWARMPROOF_REPORT_FILE ?? "public/data/report.json";
const STATUS_FILE = process.env.SWARMPROOF_STATUS_FILE ?? "public/data/status.json";
const EVENTS_FILE = process.env.SWARMPROOF_EVENTS_FILE ?? "public/data/events.jsonl";
const PROPOSALS_FILE = process.env.SWARMPROOF_PROPOSALS_FILE ?? "public/data/proposals.jsonl";
const TRANSACTION_FILE = process.env.SWARMPROOF_FINALIZE_TRANSACTION_FILE
  ?? `${CONFIG_FILE}.finalization-transaction.json`;
const REPOSITORY_LOCK_FILE = process.env.SWARMPROOF_SNAPSHOT_LOCK_FILE
  ?? `${CONFIG_FILE}.snapshot-finalize.lock`;
const VERIFY_CLI = fileURLToPath(new URL("../bin/swarmproof.mjs", import.meta.url));
const FUTURE_GRACE_MS = 5 * 60 * 1000;
const COMPLETE_STALE_AFTER_SECONDS = 90_000;
const TRANSACTION_SCHEMA = "swarmproof-finalization-transaction-v2";
const TARGET_NAMES = ["config", "report", "status"];
const APPLY_ORDER = ["report", "status", "config"];
const TARGET_LIMITS = {
  config: 256 * 1024,
  report: 16 * 1024 * 1024,
  status: 256 * 1024,
};

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function assertExactKeys(value, keys, label) {
  assert(value && typeof value === "object" && !Array.isArray(value), `${label} is invalid.`);
  const actual = Object.keys(value);
  assert(actual.length === keys.length, `${label} has an invalid field set.`);
  for (const key of keys) assert(Object.hasOwn(value, key), `${label} is missing ${key}.`);
  for (const key of actual) assert(keys.includes(key), `${label} contains an unknown field: ${key}`);
}

function canonicalTime(value, label) {
  assert(typeof value === "string", `${label} is invalid.`);
  const milliseconds = Date.parse(value);
  assert(Number.isFinite(milliseconds) && new Date(milliseconds).toISOString() === value, `${label} is invalid.`);
  return milliseconds;
}

function parseArchive(content, label) {
  assert(Buffer.byteLength(content, "utf8") <= 8 * 1024 * 1024, `${label} is oversized.`);
  return content.split("\n").filter(Boolean).map((line, index) => {
    try {
      return JSON.parse(line);
    } catch {
      throw new Error(`${label} line ${index + 1} is invalid.`);
    }
  });
}

async function writeAtomic(filePath, content, mode = 0o644) {
  const temporary = `${filePath}.tmp-${process.pid}`;
  await writeFile(temporary, content, { encoding: "utf8", mode });
  await rename(temporary, filePath);
}

function parseJson(content, label) {
  try {
    return JSON.parse(content);
  } catch {
    throw new Error(`${label} is not valid JSON.`);
  }
}

function transactionDigestInput(transaction) {
  return {
    schema: transaction.schema,
    owner_token: transaction.owner_token,
    events_archive_sha256: transaction.events_archive_sha256,
    proposals_archive_sha256: transaction.proposals_archive_sha256,
    targets: Object.fromEntries(TARGET_NAMES.map(name => [name, transaction.targets[name].sha256])),
  };
}

function validateTransaction(transaction) {
  assertExactKeys(transaction, [
    "schema",
    "transaction_id",
    "owner_token",
    "events_archive_sha256",
    "proposals_archive_sha256",
    "targets",
  ], "finalization transaction");
  assert(transaction.schema === TRANSACTION_SCHEMA, "Finalization transaction schema is invalid.");
  assert(/^[0-9a-f]{64}$/u.test(transaction.owner_token), "Finalization transaction owner token is invalid.");
  assert(/^[0-9a-f]{64}$/u.test(transaction.events_archive_sha256), "Finalization event archive hash is invalid.");
  assert(/^[0-9a-f]{64}$/u.test(transaction.proposals_archive_sha256), "Finalization proposal archive hash is invalid.");
  assertExactKeys(transaction.targets, TARGET_NAMES, "finalization transaction targets");
  for (const name of TARGET_NAMES) {
    const target = transaction.targets[name];
    assertExactKeys(target, ["sha256", "content"], `finalization ${name} target`);
    assert(typeof target.content === "string", `Finalization ${name} target content is invalid.`);
    assert(
      Buffer.byteLength(target.content, "utf8") <= TARGET_LIMITS[name],
      `Finalization ${name} target is oversized.`,
    );
    assert(/^[0-9a-f]{64}$/u.test(target.sha256), `Finalization ${name} target hash is invalid.`);
    assert(sha256Hex(target.content) === target.sha256, `Finalization ${name} target hash does not match its content.`);
  }
  assert(
    transaction.transaction_id === sha256Hex(canonicalize(transactionDigestInput(transaction))),
    "Finalization transaction ID is inconsistent.",
  );
  const config = parseJson(transaction.targets.config.content, "Finalization config target");
  const report = parseJson(transaction.targets.report.content, "Finalization report target");
  const status = parseJson(transaction.targets.status.content, "Finalization status target");
  assert(config.state === "complete", "Finalization config target is not complete.");
  assert(report.event_state === "complete", "Finalization report target is not complete.");
  assert(status.state === "complete", "Finalization status target is not complete.");
  assert(status.report_sha256 === sha256Hex(canonicalize(report)), "Finalization report and status are inconsistent.");
  return { config, report, status };
}

function createTransaction({ config, report, status, eventsContent, proposalsContent }) {
  const completeConfig = { ...config, state: "complete" };
  const completeReport = { ...report, event_state: "complete" };
  const completeStatus = {
    ...status,
    state: "complete",
    report_sha256: sha256Hex(canonicalize(completeReport)),
    stale_after_seconds: COMPLETE_STALE_AFTER_SECONDS,
  };
  const contents = {
    config: `${JSON.stringify(completeConfig, null, 2)}\n`,
    report: `${JSON.stringify(completeReport, null, 2)}\n`,
    status: `${JSON.stringify(completeStatus, null, 2)}\n`,
  };
  const transaction = {
    schema: TRANSACTION_SCHEMA,
    transaction_id: null,
    owner_token: randomBytes(32).toString("hex"),
    events_archive_sha256: sha256Hex(eventsContent),
    proposals_archive_sha256: sha256Hex(proposalsContent),
    targets: Object.fromEntries(TARGET_NAMES.map(name => [name, {
      sha256: sha256Hex(contents[name]),
      content: contents[name],
    }])),
  };
  transaction.transaction_id = sha256Hex(canonicalize(transactionDigestInput(transaction)));
  validateTransaction(transaction);
  return transaction;
}

async function readTransaction() {
  try {
    const content = await readFile(TRANSACTION_FILE, "utf8");
    assert(Buffer.byteLength(content, "utf8") <= 36 * 1024 * 1024, "Finalization transaction is oversized.");
    const transaction = parseJson(content, "Finalization transaction");
    validateTransaction(transaction);
    return transaction;
  } catch (error) {
    if (error.code === "ENOENT") return null;
    throw error;
  }
}

async function assertTransactionOwnership(transaction, phase) {
  const current = await readTransaction();
  assert(current !== null, `Finalization transaction disappeared ${phase}.`);
  assert(
    current.owner_token === transaction.owner_token
      && current.transaction_id === transaction.transaction_id,
    `Finalization transaction ownership changed ${phase}.`,
  );
  return current;
}

async function assertArchiveOwnership(transaction, phase) {
  const [eventsContent, proposalsContent] = await Promise.all([
    readFile(EVENTS_FILE, "utf8"),
    readFile(PROPOSALS_FILE, "utf8"),
  ]);
  assert(
    sha256Hex(eventsContent) === transaction.events_archive_sha256,
    `Event archive changed ${phase}.`,
  );
  assert(
    sha256Hex(proposalsContent) === transaction.proposals_archive_sha256,
    `Proposal archive changed ${phase}.`,
  );
  return { eventsContent, proposalsContent };
}

async function writeTransactionExclusive(transaction) {
  validateTransaction(transaction);
  const temporary = `${TRANSACTION_FILE}.tmp-${process.pid}-${transaction.owner_token}`;
  await writeFile(temporary, `${JSON.stringify(transaction, null, 2)}\n`, {
    encoding: "utf8",
    mode: 0o600,
    flag: "wx",
  });
  try {
    await link(temporary, TRANSACTION_FILE);
  } catch (error) {
    if (error.code === "EEXIST") {
      throw new Error("A finalization transaction journal already exists; refusing to replace it.");
    }
    throw error;
  } finally {
    await rm(temporary, { force: true });
  }
  await assertTransactionOwnership(transaction, "immediately after journal creation");
}

async function verifyFullPublicSnapshot(transaction, now) {
  const { config, report, status } = validateTransaction(transaction);
  const { eventsContent, proposalsContent } = await assertArchiveOwnership(transaction, "during finalization verification");

  const activeReport = { ...report, event_state: "active" };
  const activeStatus = {
    ...status,
    state: "active",
    report_sha256: sha256Hex(canonicalize(activeReport)),
  };
  validateFinalDrain({
    config: { ...config, state: "active" },
    report: activeReport,
    status: activeStatus,
    eventsContent,
    proposalsContent,
    now,
  });

  const directory = await mkdtemp(path.join(path.dirname(TRANSACTION_FILE), ".finalization-verify-"));
  const verificationPaths = {
    config: path.join(directory, "event.json"),
    report: path.join(directory, "report.json"),
    status: path.join(directory, "status.json"),
  };
  try {
    await Promise.all([
      writeFile(verificationPaths.config, transaction.targets.config.content, { encoding: "utf8", mode: 0o600 }),
      writeFile(verificationPaths.report, transaction.targets.report.content, { encoding: "utf8", mode: 0o600 }),
      writeFile(verificationPaths.status, transaction.targets.status.content, { encoding: "utf8", mode: 0o600 }),
    ]);
    try {
      await executeFile(process.execPath, [
        VERIFY_CLI,
        "verify-report",
        "--config", verificationPaths.config,
        "--tasks", TASKS_FILE,
        "--events", EVENTS_FILE,
        "--proposals", PROPOSALS_FILE,
        "--report", verificationPaths.report,
        "--status", verificationPaths.status,
      ], {
        cwd: process.cwd(),
        encoding: "utf8",
        maxBuffer: 2 * 1024 * 1024,
        timeout: 14 * 60 * 1000,
      });
    } catch (error) {
      const detail = typeof error.stderr === "string" && error.stderr.trim()
        ? error.stderr.trim()
        : error.message;
      throw new Error(`Full public snapshot verification failed: ${detail}`);
    }
    await assertArchiveOwnership(transaction, "during full public snapshot verification");
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}

async function applyTransaction(transaction) {
  validateTransaction(transaction);
  const targetPaths = {
    config: CONFIG_FILE,
    report: REPORT_FILE,
    status: STATUS_FILE,
  };
  const interruptAfter = process.env.NODE_ENV === "test"
    ? process.env.SWARMPROOF_TEST_INTERRUPT_AFTER_TARGET
    : undefined;
  for (const name of APPLY_ORDER) {
    await assertTransactionOwnership(transaction, `before applying ${name}`);
    await assertArchiveOwnership(transaction, `before applying ${name}`);
    const target = transaction.targets[name];
    let current = null;
    try {
      current = await readFile(targetPaths[name], "utf8");
    } catch (error) {
      if (error.code !== "ENOENT") throw error;
    }
    if (current === null || sha256Hex(current) !== target.sha256) {
      await writeAtomic(targetPaths[name], target.content);
    }
    assert(
      sha256Hex(await readFile(targetPaths[name], "utf8")) === target.sha256,
      `Finalization ${name} target was not applied exactly.`,
    );
    const pauseAfter = process.env.NODE_ENV === "test"
      ? process.env.SWARMPROOF_TEST_PAUSE_AFTER_TARGET
      : undefined;
    if (pauseAfter === name) {
      const pauseMs = Number(process.env.SWARMPROOF_TEST_PAUSE_MS ?? 2_000);
      assert(Number.isSafeInteger(pauseMs) && pauseMs > 0 && pauseMs <= 10_000, "Test pause is invalid.");
      await new Promise(resolve => setTimeout(resolve, pauseMs));
    }
    if (interruptAfter === name) throw new Error(`Simulated interruption after ${name}.`);
  }
  await assertTransactionOwnership(transaction, "before journal removal");
  await assertArchiveOwnership(transaction, "before journal removal");
  await rm(TRANSACTION_FILE);
}

export function validateFinalDrain({ config, report, status, eventsContent, proposalsContent, now }) {
  assert(config?.state === "active", "Only an active event can be finalized.");
  const endsAt = canonicalTime(config.ends_at, "config.ends_at");
  const nowMs = now instanceof Date ? now.getTime() : Number.NaN;
  assert(Number.isFinite(nowMs) && nowMs >= endsAt, "The event window has not ended.");
  assert(report?.schema === "swarmproof-report-v1", "Final-drain report schema is invalid.");
  assert(status?.schema === "swarmproof-status-v1", "Final-drain status schema is invalid.");
  assert(report.event_state === "active" && status.state === "active", "Final drain must be captured before the archive is frozen.");
  assert(status.starts_at === config.starts_at && status.ends_at === config.ends_at, "Final-drain event window is inconsistent.");
  const generatedAt = canonicalTime(report.generated_at, "report.generated_at");
  assert(status.generated_at === report.generated_at, "Final-drain report and status timestamps differ.");
  assert(generatedAt >= endsAt, "Final drain was captured before the event ended.");
  assert(generatedAt <= nowMs + FUTURE_GRACE_MS, "Final drain timestamp is in the future.");
  assert(report.build_room?.room === config.build_room, "Final drain used the wrong build room.");
  assert(report.build_room.collection_error === null, "Final build-room drain did not succeed.");
  assert(report.build_room.sequence_metadata_valid === true, "Final build-room sequence metadata is invalid.");
  assert(report.build_room.continuity_complete === true, "Final build-room history is not contiguous.");
  assert(report.build_room.message_entries_truncated === 0, "Final build-room response was truncated.");
  assert(report.build_room.message_entries_uninspected === 0, "Final build-room response was not fully inspected.");
  assert(report.build_room.message_entries_rejected === 0, "Final build-room response contained rejected entries.");
  assert(report.build_room.message_entries_deduplicated === 0, "Final build-room response contained duplicate entries.");
  assert(
    Number.isSafeInteger(report.build_room.response_count)
      && report.build_room.response_count >= 0
      && report.build_room.response_count <= 200,
    "Final build-room response count is invalid.",
  );
  assert(
    Number.isSafeInteger(report.build_room.last_seq) && report.build_room.last_seq >= 0,
    "Final build-room cursor is invalid.",
  );
  assert(
    Number.isSafeInteger(report.build_room.messages_observed_in_tail)
      && report.build_room.messages_observed_in_tail >= 0
      && report.build_room.messages_observed_in_tail <= 200,
    "Final build-room tail count is invalid.",
  );
  const sample = report.network_sample;
  assert(sample && typeof sample === "object", "Final network sample is missing.");
  const sampleGeneratedAt = canonicalTime(sample.generated_at, "network_sample.generated_at");
  assert(sampleGeneratedAt >= endsAt, "Final network sample was captured before the event ended.");
  assert(sampleGeneratedAt <= nowMs + FUTURE_GRACE_MS, "Final network sample timestamp is in the future.");
  assert(
    sample.selection?.rooms_requested === config.sample?.rooms
      && sample.selection?.rooms_returned === config.sample?.rooms
      && sample.selection?.messages_per_room_requested === config.sample?.messages_per_room
      && sample.selection?.rooms_failed === 0
      && Array.isArray(sample.failures)
      && sample.failures.length === 0
      && sample.aggregate?.messages > 0,
    "Final network sample is incomplete.",
  );

  const events = parseArchive(eventsContent, "events archive");
  const proposals = parseArchive(proposalsContent, "proposals archive");
  for (const [label, records] of [["event", events], ["proposal", proposals]]) {
    for (const record of records) {
      const sourceTs = canonicalTime(record.source_ts, `${label}.source_ts`);
      assert(sourceTs <= endsAt, `${label} was observed after the event boundary.`);
      assert(record.source_room === config.build_room, `${label} came from the wrong build room.`);
    }
  }

  assert(report.source_event_count === events.length, "Final report does not cover the frozen event archive.");
  assert(report.unsigned_proposals_observed === proposals.length, "Final report does not cover the frozen proposal archive.");
  assert(report.snapshot_manifest?.generated_at === report.generated_at, "Final-drain manifest timestamp is inconsistent.");
  assert(
    report.snapshot_manifest?.network_sample_sha256 === sha256Hex(canonicalize(sample)),
    "Final network sample hash is inconsistent.",
  );
  assert(
    report.snapshot_manifest?.events_archive_sha256 === sha256Hex(eventsContent),
    "Final-drain event archive hash is inconsistent.",
  );
  assert(
    report.snapshot_manifest?.proposals_archive_sha256 === sha256Hex(proposalsContent),
    "Final-drain proposal archive hash is inconsistent.",
  );
  assert(
    report.snapshot_manifest_sha256 === sha256Hex(canonicalize(report.snapshot_manifest)),
    "Final-drain manifest hash is inconsistent.",
  );
  assert(status.snapshot_manifest_sha256 === report.snapshot_manifest_sha256, "Final-drain status manifest hash is inconsistent.");
  assert(status.report_sha256 === sha256Hex(canonicalize(report)), "Final-drain status report hash is inconsistent.");
  return { events: events.length, proposals: proposals.length, generated_at: report.generated_at };
}

async function finalizerMain() {
  const argumentsList = process.argv.slice(2);
  assert(argumentsList.every(argument => ["--check", "--recover"].includes(argument)), "Unknown finalizer argument.");
  assert(new Set(argumentsList).size === argumentsList.length, "Duplicate finalizer argument.");
  assert(argumentsList.length <= 1, "Finalizer modes are mutually exclusive.");
  const checkOnly = argumentsList.includes("--check");
  const recoverOnly = argumentsList.includes("--recover");
  const now = process.env.SWARMPROOF_NOW === undefined
    ? new Date()
    : new Date(process.env.SWARMPROOF_NOW);
  assert(Number.isFinite(now.getTime()), "Current time is invalid.");

  const pending = await readTransaction();
  if (pending) {
    if (checkOnly) {
      process.stdout.write(`${JSON.stringify({ action: "finalization_recovery_required" })}\n`);
      return;
    }
    await verifyFullPublicSnapshot(pending, now);
    await applyTransaction(pending);
    process.stdout.write(`${JSON.stringify({
      action: "finalized",
      reason: "recovered_interrupted_transaction",
      transaction_id: pending.transaction_id,
    })}\n`);
    return;
  }
  if (recoverOnly) {
    process.stdout.write(`${JSON.stringify({ action: "skip", reason: "no_pending_transaction" })}\n`);
    return;
  }

  const config = JSON.parse(await readFile(CONFIG_FILE, "utf8"));
  const result = transitionEventLifecycle(config, now);
  if (checkOnly && result.action === "finalized") {
    process.stdout.write(`${JSON.stringify({ action: "final_drain_required", reason: result.reason })}\n`);
    return;
  }
  if (result.action === "finalized") {
    const [report, status, eventsContent, proposalsContent] = await Promise.all([
      readFile(REPORT_FILE, "utf8").then(JSON.parse),
      readFile(STATUS_FILE, "utf8").then(JSON.parse),
      readFile(EVENTS_FILE, "utf8"),
      readFile(PROPOSALS_FILE, "utf8"),
    ]);
    const drained = validateFinalDrain({ config, report, status, eventsContent, proposalsContent, now });
    const transaction = createTransaction({ config, report, status, eventsContent, proposalsContent });
    await verifyFullPublicSnapshot(transaction, now);
    await assertArchiveOwnership(transaction, "before journal creation");
    await writeTransactionExclusive(transaction);
    await applyTransaction(transaction);
    process.stdout.write(`${JSON.stringify({
      action: result.action,
      reason: result.reason,
      drained,
      transaction_id: transaction.transaction_id,
    })}\n`);
    return;
  }
  process.stdout.write(`${JSON.stringify({ action: result.action, reason: result.reason })}\n`);
}

async function main() {
  const release = await acquireRepositoryLock(REPOSITORY_LOCK_FILE, "snapshot/finalizer process");
  try {
    return await finalizerMain();
  } finally {
    await release();
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch(error => {
    console.error(`event finalizer failed: ${error.message}`);
    process.exit(1);
  });
}
