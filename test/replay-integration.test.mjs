import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { auditEvents } from "../lib/audit.mjs";
import { verifyArtifactEvidence } from "../lib/evidence.mjs";

async function json(path) {
  return JSON.parse(await readFile(path, "utf8"));
}

async function jsonLines(path) {
  return (await readFile(path, "utf8"))
    .split("\n")
    .filter(Boolean)
    .map(JSON.parse);
}

test("offline replay reproduces the published audit-core hash", async () => {
  const [config, taskManifest, records, proposals, report, status] = await Promise.all([
    json("config/event.json"),
    json("config/tasks.json"),
    jsonLines("public/data/events.jsonl"),
    jsonLines("public/data/proposals.jsonl"),
    json("public/data/report.json"),
    json("public/data/status.json"),
  ]);
  const allowedRepositories = new Set([config.repository]);
  const allowedTasks = new Set(taskManifest.tasks.map(task => task.id));
  const protocolOptions = {
    allowedRepositories,
    allowedTasks,
    coordinatorDid: config.coordinator_did,
  };
  const artifacts = await verifyArtifactEvidence(records, {
    repository: config.repository,
    repositoryRoot: process.cwd(),
    trustedRef: "HEAD",
    protocolOptions,
    tasksById: new Map(taskManifest.tasks.map(task => [task.id, task])),
    startsAt: config.starts_at,
    endsAt: config.ends_at,
  });
  const replayed = auditEvents(records, {
    allowedRepositories: [...allowedRepositories],
    allowedTasks,
    coordinatorDid: config.coordinator_did,
    startsAt: config.starts_at,
    endsAt: config.ends_at,
    artifactChecks: artifacts.checks,
    additionalObserved: proposals.length,
  });
  assert.equal(replayed.report_sha256, report.audit_core_sha256);
  assert.equal(replayed.report_sha256, status.audit_core_sha256);
});
