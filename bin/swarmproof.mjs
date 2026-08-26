#!/usr/bin/env node

import { readFile, writeFile } from "node:fs/promises";
import { auditEvents } from "../lib/audit.mjs";
import { verifyArtifactEvidence } from "../lib/evidence.mjs";
import { createEnvelopeFromFiles, verifyEnvelope } from "../lib/protocol.mjs";

function usage() {
  console.error(`Usage:
  swarmproof sign --payload payload.json --key private-key.pem [--config config/event.json] [--tasks config/tasks.json]
  swarmproof verify (--envelope SP1... | --file envelope.txt) [--config config/event.json] [--tasks config/tasks.json]
  swarmproof sign --payload payload.json --key private-key.pem --structural-only
  swarmproof verify (--envelope SP1... | --file envelope.txt) --structural-only
  swarmproof replay --events events.jsonl [--proposals proposals.jsonl] [--config config/event.json] [--tasks config/tasks.json] [--out report.json]`);
  console.error("\nDefault sign/verify enforce this project's repository, task manifest, and coordinator authority. --structural-only checks only protocol structure and signature; it does not establish project authorization or acceptance.");
  process.exit(2);
}

function optionsOf(arguments_) {
  const options = new Map();
  const flags = new Set();
  for (let index = 0; index < arguments_.length; index += 1) {
    const token = arguments_[index];
    if (token === "--structural-only") {
      if (flags.has("structural-only")) usage();
      flags.add("structural-only");
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

async function projectProtocolOptions(options) {
  const configPath = options.get("config") ?? "config/event.json";
  const tasksPath = options.get("tasks") ?? "config/tasks.json";
  const [config, taskManifest] = await Promise.all([
    readFile(configPath, "utf8").then(JSON.parse),
    readFile(tasksPath, "utf8").then(JSON.parse),
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

async function loadJsonLines(path) {
  const content = await readFile(path, "utf8");
  return content
    .split("\n")
    .filter(line => line.trim())
    .map((line, index) => {
      try {
        return JSON.parse(line);
      } catch {
        throw new Error(`Invalid JSON on events line ${index + 1}.`);
      }
    });
}

async function main() {
  const [command, ...arguments_] = process.argv.slice(2);
  if (!command) usage();
  const { options, flags } = optionsOf(arguments_);
  const structuralOnly = flags.has("structural-only");

  if (command === "sign") {
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
    if (structuralOnly) usage();
    requireOnly(options, new Set(["events", "proposals", "config", "tasks", "out"]));
    const eventsPath = options.get("events") ?? "public/data/events.jsonl";
    const proposalsPath = options.get("proposals") ?? "public/data/proposals.jsonl";
    const configPath = options.get("config") ?? "config/event.json";
    const tasksPath = options.get("tasks") ?? "config/tasks.json";
    const [records, proposals, config, taskManifest] = await Promise.all([
      loadJsonLines(eventsPath),
      loadJsonLines(proposalsPath).catch(error => error.code === "ENOENT" ? [] : Promise.reject(error)),
      readFile(configPath, "utf8").then(JSON.parse),
      readFile(tasksPath, "utf8").then(JSON.parse),
    ]);
    const allowedRepositories = new Set([config.repository]);
    const allowedTasks = new Set(taskManifest.tasks.map(task => task.id));
    const tasksById = new Map(taskManifest.tasks.map(task => [task.id, task]));
    const protocolOptions = {
      allowedRepositories,
      allowedTasks,
      coordinatorDid: config.coordinator_did,
    };
    const artifactVerification = await verifyArtifactEvidence(records, {
      repository: config.repository,
      repositoryRoot: process.cwd(),
      trustedRef: "HEAD",
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
    const output = `${JSON.stringify(result, null, 2)}\n`;
    if (options.get("out")) await writeFile(options.get("out"), output, "utf8");
    else process.stdout.write(output);
    return;
  }

  usage();
}

main().catch(error => {
  console.error(`swarmproof: ${error.message}`);
  process.exit(1);
});
