#!/usr/bin/env node

import { execFile } from "node:child_process";
import { createPrivateKey, randomUUID } from "node:crypto";
import { constants } from "node:fs";
import { lstat, mkdtemp, open, readFile, rename, rm, unlink, writeFile } from "node:fs/promises";
import { basename, dirname, join, resolve } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import {
  CONTRIBUTION_INDEX_CONTROLLER,
  CONTRIBUTION_INDEX_MAX_BYTES,
  contributionsFromSwarmproofReport,
  createContributionIndex,
  deriveContributionFacets,
  verifyContributionIndexControlClaim,
  verifyContributionIndexPublications,
  verifyContributionIndexReplacement,
} from "../lib/contribution-index.mjs";
import {
  CONTROL_CLAIM_MAX_BYTES,
  verifyControlClaim,
  verifyControlClaimPublications,
} from "../lib/control-claim.mjs";

const executeFile = promisify(execFile);
const PROJECT_ROOT = fileURLToPath(new URL("..", import.meta.url));
const PRIVATE_KEY_MAX_BYTES = 16 * 1024;
const INPUT_MAX_BYTES = 256 * 1024;
const DEFAULT_CONTROL_CLAIM = join(
  PROJECT_ROOT,
  "public",
  ".well-known",
  "swarmproof-control-claim-v1.json",
);
const DEFAULT_INDEX = join(
  PROJECT_ROOT,
  "public",
  ".well-known",
  "swarmproof-contribution-index-v1.json",
);

function fail(message) {
  throw new Error(message);
}

function usage() {
  console.error(`Usage:
  contribution-index prepare --out unsigned-input.json [--replace]
  contribution-index create --input unsigned-input.json --key private-key.pem [--control-claim claim.json] [--out index.json] [--replace]
  contribution-index verify [--file index.json] [--control-claim claim.json] [--project] [--publications]

prepare first runs the full local SwarmProof report verifier, then emits unsigned subject-based
input for every non-duplicate REPRODUCIBLE-or-higher RESULT. create derives the configured DID from an owner-only
Ed25519 key and never prints the key, proof, or signed document. verify always checks the strict
signature and the exact control-claim hash. --project additionally replays the public snapshot
before deriving per-subject facets. --publications fetches only implementation-pinned, bounded,
redirect-free GitHub and Pages endpoints; it never follows an index-supplied URL.`);
  process.exit(2);
}

function parseArguments(arguments_) {
  const options = new Map();
  const flags = new Set();
  const booleanFlags = new Set(["replace", "project", "publications"]);
  for (let index = 0; index < arguments_.length; index += 1) {
    const token = arguments_[index];
    const name = token.startsWith("--") ? token.slice(2) : "";
    if (booleanFlags.has(name)) {
      if (flags.has(name)) usage();
      flags.add(name);
      continue;
    }
    if (!token.startsWith("--") || index + 1 >= arguments_.length || arguments_[index + 1].startsWith("--")) {
      usage();
    }
    if (options.has(name)) usage();
    options.set(name, arguments_[index + 1]);
    index += 1;
  }
  return { options, flags };
}

function requireOnly(options, allowed) {
  for (const name of options.keys()) if (!allowed.has(name)) usage();
}

function requireOnlyFlags(flags, allowed) {
  for (const name of flags) if (!allowed.has(name)) usage();
}

async function readRegularFileNoFollow(filePath, maximumBytes, label, options = {}) {
  const noFollow = constants.O_NOFOLLOW ?? 0;
  const handle = await open(filePath, constants.O_RDONLY | noFollow);
  try {
    const metadata = await handle.stat();
    if (!metadata.isFile()) fail(`${label} is not a regular file.`);
    if (metadata.size > maximumBytes) fail(`${label} exceeds ${maximumBytes} bytes.`);
    if (options.ownerOnly) {
      if ((metadata.mode & 0o077) !== 0) fail(`${label} must have owner-only permissions.`);
      if (typeof process.getuid === "function" && metadata.uid !== process.getuid()) {
        fail(`${label} must be owned by the current user.`);
      }
    }
    const bytes = await handle.readFile();
    if (bytes.length > maximumBytes) fail(`${label} exceeds ${maximumBytes} bytes.`);
    return { bytes, metadata };
  } finally {
    await handle.close();
  }
}

async function pathMetadata(filePath) {
  try {
    return await lstat(filePath);
  } catch (error) {
    if (error.code === "ENOENT") return null;
    throw error;
  }
}

async function assertSafeOutputTarget(outputPath, options = {}) {
  if (options.keyPath && resolve(outputPath) === resolve(options.keyPath)) {
    fail("Output path must differ from the private key path.");
  }
  const metadata = await pathMetadata(outputPath);
  if (!metadata) return null;
  if (!metadata.isFile() || metadata.isSymbolicLink()) fail("Existing output must be a regular non-symlink file.");
  if (options.keyMetadata && metadata.dev === options.keyMetadata.dev && metadata.ino === options.keyMetadata.ino) {
    fail("Output must not be the private key file or one of its hard links.");
  }
  if (!options.replace) fail("Output already exists; pass --replace for an explicit valid replacement.");
  return metadata;
}

async function writeAtomic(filePath, content) {
  const temporaryPath = join(dirname(filePath), `.${basename(filePath)}.${process.pid}.${randomUUID()}.tmp`);
  try {
    await writeFile(temporaryPath, content, { encoding: "utf8", flag: "wx", mode: 0o644 });
    await rename(temporaryPath, filePath);
  } finally {
    await unlink(temporaryPath).catch(error => {
      if (error.code !== "ENOENT") throw error;
    });
  }
}

function parseJson(bytes, label) {
  try {
    return JSON.parse(bytes.toString("utf8"));
  } catch {
    throw new Error(`${label} is not valid JSON.`);
  }
}

function validateUnsignedInput(input) {
  if (!input || typeof input !== "object" || Array.isArray(input)) fail("Unsigned input must be an object.");
  const expected = new Set(["sequence", "previous_index_sha256", "contributions"]);
  const keys = Object.keys(input);
  if (keys.length !== expected.size || keys.some(key => !expected.has(key))) {
    fail("Unsigned input has an invalid field set.");
  }
  if (typeof input.sequence !== "string" || !/^[1-9][0-9]{0,18}$/u.test(input.sequence)) {
    fail("Unsigned input sequence is invalid.");
  }
  if (input.previous_index_sha256 !== null && !/^[0-9a-f]{64}$/u.test(input.previous_index_sha256 ?? "")) {
    fail("Unsigned input previous_index_sha256 is invalid.");
  }
  if (!Array.isArray(input.contributions)) fail("Unsigned input contributions must be an array.");
  return input;
}

async function verifyProjectReportWithArguments(arguments_) {
  const result = await executeFile(process.execPath, [
    join(PROJECT_ROOT, "bin", "swarmproof.mjs"),
    "verify-report",
    ...arguments_,
  ], {
    cwd: PROJECT_ROOT,
    encoding: "utf8",
    maxBuffer: 4 * 1024 * 1024,
    env: {
      PATH: process.env.PATH,
      HOME: process.env.HOME,
      LANG: "C.UTF-8",
      LC_ALL: "C.UTF-8",
      TZ: "UTC",
    },
  });
  const verification = JSON.parse(result.stdout);
  if (verification?.checks?.audit_core_replay !== "pass") fail("Project report replay did not pass.");
  return verification;
}

const PROJECT_SNAPSHOT_PATHS = Object.freeze({
  report: "public/data/report.json",
  status: "public/data/status.json",
  events: "public/data/events.jsonl",
  proposals: "public/data/proposals.jsonl",
  config: "config/event.json",
  tasks: "config/tasks.json",
});

async function gitOutput(arguments_, options = {}) {
  const result = await executeFile("git", arguments_, {
    cwd: PROJECT_ROOT,
    encoding: "utf8",
    maxBuffer: options.maxBuffer ?? 20 * 1024 * 1024,
    env: {
      PATH: process.env.PATH,
      HOME: process.env.HOME,
      LANG: "C.UTF-8",
      LC_ALL: "C.UTF-8",
      TZ: "UTC",
    },
  });
  return result.stdout;
}

async function assertTrustedPublicationCommit(commit) {
  if (!/^[0-9a-f]{40}$/u.test(commit ?? "")) fail("Snapshot publication commit is invalid.");
  const resolved = (await gitOutput(["rev-parse", `${commit}^{commit}`])).trim();
  if (resolved !== commit) fail("Snapshot publication commit does not resolve exactly.");
  try {
    await gitOutput(["merge-base", "--is-ancestor", commit, "HEAD"]);
  } catch {
    fail("Snapshot publication commit is not an ancestor of trusted HEAD.");
  }
}

async function filesAtPublicationCommit(commit) {
  await assertTrustedPublicationCommit(commit);
  const entries = await Promise.all(Object.entries(PROJECT_SNAPSHOT_PATHS).map(async ([key, path]) => [
    key,
    await gitOutput(["show", `${commit}:${path}`]),
  ]));
  return Object.fromEntries(entries);
}

async function verifyProjectReportAtCommit(commit) {
  const files = await filesAtPublicationCommit(commit);
  const directory = await mkdtemp(join(tmpdir(), "swarmproof-contribution-snapshot-"));
  try {
    const paths = {};
    for (const [key, content] of Object.entries(files)) {
      const path = join(directory, basename(PROJECT_SNAPSHOT_PATHS[key]));
      await writeFile(path, content, { encoding: "utf8", flag: "wx", mode: 0o600 });
      paths[key] = path;
    }
    const verification = await verifyProjectReportWithArguments([
      "--report", paths.report,
      "--status", paths.status,
      "--events", paths.events,
      "--proposals", paths.proposals,
      "--config", paths.config,
      "--tasks", paths.tasks,
    ]);
    return {
      verification,
      project: {
        report: JSON.parse(files.report),
        status: JSON.parse(files.status),
        events: files.events,
        config: JSON.parse(files.config),
        tasks: JSON.parse(files.tasks),
        publicationCommit: commit,
        reportVerification: verification,
      },
    };
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}

async function currentPublicationCommit() {
  const paths = Object.values(PROJECT_SNAPSHOT_PATHS).filter(path => path.startsWith("public/data/"));
  const commit = (await gitOutput(["log", "-1", "--format=%H", "--", ...paths])).trim();
  await assertTrustedPublicationCommit(commit);
  const committed = await filesAtPublicationCommit(commit);
  for (const [key, path] of Object.entries(PROJECT_SNAPSHOT_PATHS)) {
    if (!path.startsWith("public/data/")) continue;
    const current = await readFile(join(PROJECT_ROOT, path), "utf8");
    if (current !== committed[key]) fail("Current public snapshot files do not share one immutable publication commit.");
  }
  return commit;
}

function snapshotPublicationCommitFromIndex(document) {
  const commits = new Set();
  for (const contribution of document.payload.contributions) {
    for (const evidence of contribution.evidence) {
      if (["swarmproof-result-snapshot", "cross-key-review"].includes(evidence.kind)) {
        commits.add(evidence.publication_commit);
      }
    }
  }
  if (commits.size !== 1) fail("Project verification requires exactly one immutable SwarmProof publication commit.");
  return [...commits][0];
}

function safeVerificationOutput(verified, scope, extra = {}) {
  const payload = verified.document.payload;
  return {
    schema: "swarmproof-contribution-index-verification-v1",
    validation_scope: scope,
    controller: payload.controller,
    index_sha256: verified.index_sha256,
    sequence: payload.sequence,
    issued_at: payload.issued_at,
    previous_index_sha256: payload.previous_index_sha256,
    control_claim_sha256: payload.control_claim_sha256,
    signature_valid: verified.signature_valid,
    unique_contributions: payload.contributions.length,
    ...extra,
    limitations: [
      "The DID signature is the controller's assertion over this index; it does not prove human identity, authorship, novelty, operator independence, endorsement, or reward eligibility.",
      "Evidence kinds retain separate scopes and are not summed into a single verification score.",
      "Official-task entries may record submitted work only; v1 forbids self-claimed official acceptance and reward status.",
    ],
  };
}

async function prepareCommand(options, flags) {
  requireOnly(options, new Set(["out"]));
  requireOnlyFlags(flags, new Set(["replace"]));
  const outputPath = options.get("out");
  if (!outputPath) usage();
  await assertSafeOutputTarget(outputPath, { replace: flags.has("replace") });
  const publicationCommit = await currentPublicationCommit();
  const historical = await verifyProjectReportAtCommit(publicationCommit);
  const normalized = contributionsFromSwarmproofReport(
    historical.project.report,
    historical.project.status,
    publicationCommit,
  );
  const contributions = normalized.map(({ subject, evidence }) => ({ subject, evidence }));
  const input = {
    sequence: "1",
    previous_index_sha256: null,
    contributions,
  };
  await writeAtomic(outputPath, `${JSON.stringify(input, null, 2)}\n`);
  process.stdout.write(`${JSON.stringify({
    schema: "swarmproof-contribution-index-input-created-v1",
    output: basename(outputPath),
    publication_commit: publicationCommit,
    unique_contributions: contributions.length,
    next_step: "Inspect the unsigned input, then run contribution-index create with the owner-only DID key.",
  }, null, 2)}\n`);
}

async function createCommand(options, flags) {
  requireOnly(options, new Set(["input", "key", "control-claim", "out"]));
  requireOnlyFlags(flags, new Set(["replace"]));
  const inputPath = options.get("input");
  const keyPath = options.get("key");
  const controlClaimPath = options.get("control-claim") ?? DEFAULT_CONTROL_CLAIM;
  const outputPath = options.get("out") ?? DEFAULT_INDEX;
  if (!inputPath || !keyPath) usage();
  const [inputFile, keyFile, controlClaimFile] = await Promise.all([
    readRegularFileNoFollow(inputPath, INPUT_MAX_BYTES, "Unsigned input file"),
    readRegularFileNoFollow(keyPath, PRIVATE_KEY_MAX_BYTES, "Private key file", { ownerOnly: true }),
    readRegularFileNoFollow(controlClaimPath, CONTROL_CLAIM_MAX_BYTES, "Control-claim file"),
  ]);
  const input = validateUnsignedInput(parseJson(inputFile.bytes, "Unsigned input file"));
  const controlClaimText = controlClaimFile.bytes.toString("utf8");
  const controlClaim = verifyControlClaim(controlClaimText);
  let signer;
  try {
    signer = createPrivateKey(keyFile.bytes);
  } finally {
    keyFile.bytes.fill(0);
  }
  if (signer.asymmetricKeyType !== "ed25519") fail("Private key must be Ed25519.");
  const existingMetadata = await assertSafeOutputTarget(outputPath, {
    keyPath,
    keyMetadata: keyFile.metadata,
    replace: flags.has("replace"),
  });
  if (existingMetadata) {
    const previousFile = await readRegularFileNoFollow(outputPath, CONTRIBUTION_INDEX_MAX_BYTES, "Existing contribution-index file");
    const previousText = previousFile.bytes.toString("utf8");
    verifyContributionIndexReplacement(previousText, {
      sequence: input.sequence,
      previous_index_sha256: input.previous_index_sha256,
    });
  }
  const created = createContributionIndex(input.contributions, signer, {
    sequence: input.sequence,
    previousIndexSha256: input.previous_index_sha256,
    controlClaimSha256: controlClaim.claim_sha256,
  });
  await writeAtomic(outputPath, created.serialized);
  process.stdout.write(`${JSON.stringify({
    schema: "swarmproof-contribution-index-created-v1",
    controller: CONTRIBUTION_INDEX_CONTROLLER,
    index_sha256: created.index_sha256,
    sequence: created.document.payload.sequence,
    issued_at: created.document.payload.issued_at,
    unique_contributions: created.document.payload.contributions.length,
    next_step: "Publish the exact canonical file at both configured well-known endpoints, then run verify --project --publications.",
  }, null, 2)}\n`);
}

async function verifyCommand(options, flags) {
  requireOnly(options, new Set(["file", "control-claim"]));
  requireOnlyFlags(flags, new Set(["project", "publications"]));
  const indexPath = options.get("file") ?? DEFAULT_INDEX;
  const controlClaimPath = options.get("control-claim") ?? DEFAULT_CONTROL_CLAIM;
  const [indexFile, controlClaimFile] = await Promise.all([
    readRegularFileNoFollow(indexPath, CONTRIBUTION_INDEX_MAX_BYTES, "Contribution-index file"),
    readRegularFileNoFollow(controlClaimPath, CONTROL_CLAIM_MAX_BYTES, "Control-claim file"),
  ]);
  const indexText = indexFile.bytes.toString("utf8");
  const controlClaimText = controlClaimFile.bytes.toString("utf8");
  let verified = verifyContributionIndexControlClaim(indexText, controlClaimText);
  let publications = "not-checked";
  let controlClaimPublications = "not-checked";
  if (flags.has("publications")) {
    const [indexCopies, claimCopies] = await Promise.all([
      verifyContributionIndexPublications(indexText),
      verifyControlClaimPublications(controlClaimText),
    ]);
    verified = indexCopies;
    publications = indexCopies.publications;
    controlClaimPublications = claimCopies.publications;
  }
  let project = "not-checked";
  if (flags.has("project")) {
    const publicationCommit = snapshotPublicationCommitFromIndex(verified.document);
    const historical = await verifyProjectReportAtCommit(publicationCommit);
    project = {
      publication_commit: publicationCommit,
      replay: historical.verification,
      facets: deriveContributionFacets(verified, historical.project),
    };
  }
  const scope = flags.has("publications")
    ? (flags.has("project") ? "fixed-publications-and-replayed-project" : "fixed-publications")
    : (flags.has("project") ? "signed-index-and-replayed-project" : "signed-index-and-control-claim");
  process.stdout.write(`${JSON.stringify(safeVerificationOutput(verified, scope, {
    publications,
    control_claim_publications: controlClaimPublications,
    project,
  }), null, 2)}\n`);
}

async function main() {
  const [command, ...arguments_] = process.argv.slice(2);
  if (!command) usage();
  const { options, flags } = parseArguments(arguments_);
  if (command === "prepare") return prepareCommand(options, flags);
  if (command === "create") return createCommand(options, flags);
  if (command === "verify") return verifyCommand(options, flags);
  usage();
}

main().catch(error => {
  console.error(`contribution-index: ${error.message}`);
  process.exit(1);
});
