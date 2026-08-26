#!/usr/bin/env node

import { execFile } from "node:child_process";
import { randomUUID } from "node:crypto";
import { constants } from "node:fs";
import { lstat, mkdtemp, open, readFile, rename, rm, unlink, writeFile } from "node:fs/promises";
import { basename, dirname, join, resolve } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import {
  CONTRIBUTION_INDEX_CONTROLLER,
  CONTRIBUTION_INDEX_MAX_BYTES,
  CONTRIBUTION_INDEX_MAX_HISTORY,
  contributionsFromSwarmproofReport,
  createContributionIndex,
  deriveContributionFacets,
  normalizeContributions,
  verifyContributionIndex,
  verifyContributionIndexControlClaim,
  verifyContributionIndexHistory,
  verifyContributionIndexPublications,
  verifyContributionIndexReplacement,
} from "../lib/contribution-index.mjs";
import {
  CONTROL_CLAIM_MAX_BYTES,
  verifyControlClaim,
  verifyControlClaimPublications,
} from "../lib/control-claim.mjs";
import { parsePrivateKeyAndZeroInput } from "../lib/crypto.mjs";

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
  contribution-index prepare --out unsigned-input.json [--previous prior-index.json] [--replace]
  contribution-index create --input unsigned-input.json --key private-key.pem [--control-claim claim.json] [--out index.json] [--previous prior-index.json] [--replace]
  contribution-index verify [--file index.json] [--control-claim claim.json] [--previous index-v1.json ...] [--project] [--publications]

prepare first runs the full local SwarmProof report verifier, then emits unsigned subject-based
input for every non-duplicate REPRODUCIBLE-or-higher RESULT. Give prepare --previous to derive the
next exact sequence and predecessor hash without editing them manually. create derives the configured DID from an owner-only
Ed25519 key and never prints the key, proof, or signed document. Every sequence after 1 requires
--previous naming its canonical signed immediate predecessor. --replace requires an existing output
whose bytes match --previous; omit --replace to stage a successor at a new path. verify always checks
the current strict signature and exact control-claim hash. Repeated --previous values, supplied in
oldest-to-newest order starting at sequence 1, additionally verify the complete signed history chain.
Without them a root has no applicable history and later-sequence history is explicitly not checked.
--project additionally replays the public snapshot
before deriving per-subject facets. --publications fetches only implementation-pinned, bounded,
redirect-free GitHub and Pages endpoints; it never follows an index-supplied URL.`);
  process.exit(2);
}

function parseArguments(arguments_) {
  const options = new Map();
  const flags = new Set();
  const booleanFlags = new Set(["replace", "project", "publications"]);
  const repeatableOptions = new Set(["previous"]);
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
    const value = arguments_[index + 1];
    if (options.has(name)) {
      if (!repeatableOptions.has(name)) usage();
      options.get(name).push(value);
    } else {
      options.set(name, repeatableOptions.has(name) ? [value] : value);
    }
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

async function readPrivateKeyNoFollow(filePath) {
  const noFollow = constants.O_NOFOLLOW ?? 0;
  const handle = await open(filePath, constants.O_RDONLY | noFollow);
  let bytes = null;
  try {
    const metadata = await handle.stat();
    if (!metadata.isFile()) fail("Private key file is not a regular file.");
    if (metadata.size > PRIVATE_KEY_MAX_BYTES) {
      fail(`Private key file exceeds ${PRIVATE_KEY_MAX_BYTES} bytes.`);
    }
    if ((metadata.mode & 0o077) !== 0) fail("Private key file must have owner-only permissions.");
    if (typeof process.getuid === "function" && metadata.uid !== process.getuid()) {
      fail("Private key file must be owned by the current user.");
    }
    bytes = await handle.readFile();
    if (bytes.length > PRIVATE_KEY_MAX_BYTES) {
      fail(`Private key file exceeds ${PRIVATE_KEY_MAX_BYTES} bytes.`);
    }
    return {
      metadata,
      signer: parsePrivateKeyAndZeroInput(bytes),
    };
  } finally {
    if (bytes) bytes.fill(0);
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

function sameFileMetadata(left, right) {
  return left !== null
    && right !== null
    && left.dev === right.dev
    && left.ino === right.ino;
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
  if (input.sequence === "1" && input.previous_index_sha256 !== null) {
    fail("Unsigned input sequence 1 cannot name a previous index.");
  }
  if (input.sequence !== "1" && input.previous_index_sha256 === null) {
    fail("Unsigned input sequence after 1 requires a previous index hash.");
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
  const limitations = [
    "The DID signature is the controller's assertion over this index; it does not prove human identity, authorship, novelty, operator independence, endorsement, or reward eligibility.",
    "Evidence kinds retain separate scopes and are not summed into a single verification score.",
    "Official-task entries may record submitted work only; v1 forbids self-claimed official acceptance and reward status.",
  ];
  if (extra.history_chain?.status === "pass") {
    limitations.push(
      "History verification checks canonical bytes, signatures, the configured controller, exact sequence increments, and SHA-256 links; it does not revalidate historical control claims or evidence sources.",
    );
  } else if (extra.history_chain?.status === "not-applicable-root-sequence") {
    limitations.push(
      "Sequence 1 is the signed root and has no predecessor link or earlier index history.",
    );
  } else {
    limitations.push(
      "Only the current index was verified; any previous_index_sha256 link and earlier index history remain unchecked until a complete oldest-to-newest --previous chain is supplied.",
    );
  }
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
    limitations,
  };
}

function safeHistoryOutput(history, current) {
  if (!history) {
    if (current.document.payload.sequence === "1") {
      return {
        status: "not-applicable-root-sequence",
        supplied_previous_indexes: 0,
        index_count: 1,
        current_sequence: "1",
        current_index_sha256: current.index_sha256,
      };
    }
    return {
      status: "not-checked",
      supplied_previous_indexes: 0,
      current_sequence: current.document.payload.sequence,
    };
  }
  return {
    status: "pass",
    validation_scope: "complete-signed-index-chain",
    supplied_previous_indexes: history.index_count - 1,
    index_count: history.index_count,
    first_sequence: history.first_sequence,
    current_sequence: history.current_sequence,
    first_index_sha256: history.first_index_sha256,
    current_index_sha256: history.current_index_sha256,
    historical_control_claims: "not-checked",
    historical_evidence_sources: "not-checked",
  };
}

async function prepareCommand(options, flags) {
  requireOnly(options, new Set(["out", "previous"]));
  requireOnlyFlags(flags, new Set(["replace"]));
  const outputPath = options.get("out");
  const previousPaths = options.get("previous") ?? [];
  if (!outputPath) usage();
  if (previousPaths.length > 1) fail("prepare accepts at most one --previous index.");
  let sequence = "1";
  let previousIndexSha256 = null;
  let previousMetadata = null;
  if (previousPaths.length === 1) {
    if (resolve(outputPath) === resolve(previousPaths[0])) {
      fail("Unsigned output path must differ from --previous.");
    }
    const previousFile = await readRegularFileNoFollow(
      previousPaths[0],
      CONTRIBUTION_INDEX_MAX_BYTES,
      "Previous contribution-index file",
    );
    const previous = verifyContributionIndex(previousFile.bytes.toString("utf8"));
    sequence = (BigInt(previous.document.payload.sequence) + 1n).toString();
    if (!/^[1-9][0-9]{0,18}$/u.test(sequence)) {
      fail("Contribution-index sequence limit is exhausted.");
    }
    previousIndexSha256 = previous.index_sha256;
    previousMetadata = previousFile.metadata;
  }
  const outputMetadata = await assertSafeOutputTarget(outputPath, {
    replace: flags.has("replace"),
  });
  if (flags.has("replace") && !outputMetadata) {
    fail("--replace requires an existing output file.");
  }
  if (sameFileMetadata(outputMetadata, previousMetadata)) {
    fail("Unsigned output must not overwrite --previous or one of its hard links.");
  }
  const publicationCommit = await currentPublicationCommit();
  const historical = await verifyProjectReportAtCommit(publicationCommit);
  const normalized = contributionsFromSwarmproofReport(
    historical.project.report,
    historical.project.status,
    publicationCommit,
  );
  const contributions = normalized.map(({ subject, evidence }) => ({ subject, evidence }));
  const input = {
    sequence,
    previous_index_sha256: previousIndexSha256,
    contributions,
  };
  await writeAtomic(outputPath, `${JSON.stringify(input, null, 2)}\n`);
  process.stdout.write(`${JSON.stringify({
    schema: "swarmproof-contribution-index-input-created-v1",
    output: basename(outputPath),
    publication_commit: publicationCommit,
    predecessor_link: previousIndexSha256 === null ? "root-sequence" : "verified",
    unique_contributions: contributions.length,
    next_step: "Inspect the unsigned input, then run contribution-index create with the owner-only DID key.",
  }, null, 2)}\n`);
}

async function createCommand(options, flags) {
  requireOnly(options, new Set(["input", "key", "control-claim", "out", "previous"]));
  requireOnlyFlags(flags, new Set(["replace"]));
  const inputPath = options.get("input");
  const keyPath = options.get("key");
  const controlClaimPath = options.get("control-claim") ?? DEFAULT_CONTROL_CLAIM;
  const outputPath = options.get("out") ?? DEFAULT_INDEX;
  const previousPaths = options.get("previous") ?? [];
  if (!inputPath || !keyPath) usage();
  if (previousPaths.length > 1) fail("create accepts exactly one --previous index.");

  const [inputFile, controlClaimFile] = await Promise.all([
    readRegularFileNoFollow(inputPath, INPUT_MAX_BYTES, "Unsigned input file"),
    readRegularFileNoFollow(controlClaimPath, CONTROL_CLAIM_MAX_BYTES, "Control-claim file"),
  ]);
  const input = validateUnsignedInput(parseJson(inputFile.bytes, "Unsigned input file"));
  const normalizedContributions = normalizeContributions(input.contributions)
    .map(({ subject, evidence }) => ({ subject, evidence }));
  const controlClaimText = controlClaimFile.bytes.toString("utf8");
  const controlClaim = verifyControlClaim(controlClaimText);

  let previous = null;
  let previousText = null;
  if (input.sequence === "1") {
    if (previousPaths.length !== 0) fail("Sequence 1 must not use --previous.");
  } else {
    if (previousPaths.length !== 1) {
      fail("Every contribution-index sequence after 1 requires exactly one --previous index.");
    }
    const previousFile = await readRegularFileNoFollow(
      previousPaths[0],
      CONTRIBUTION_INDEX_MAX_BYTES,
      "Previous contribution-index file",
    );
    previousText = previousFile.bytes.toString("utf8");
    previous = verifyContributionIndexReplacement(previousText, {
      sequence: input.sequence,
      previous_index_sha256: input.previous_index_sha256,
    });
  }

  const existingMetadata = await assertSafeOutputTarget(outputPath, {
    keyPath,
    replace: flags.has("replace"),
  });
  if (flags.has("replace") && !existingMetadata) {
    fail("--replace requires an existing output file.");
  }
  if (existingMetadata) {
    if (!previous) fail("Replacing an existing index requires a successor sequence and --previous.");
    const existingFile = await readRegularFileNoFollow(
      outputPath,
      CONTRIBUTION_INDEX_MAX_BYTES,
      "Existing contribution-index file",
    );
    if (existingFile.bytes.toString("utf8") !== previousText) {
      fail("Existing output bytes must exactly match --previous before replacement.");
    }
  }

  const keyFile = await readPrivateKeyNoFollow(keyPath);
  const signer = keyFile.signer;
  if (signer.asymmetricKeyType !== "ed25519") fail("Private key must be Ed25519.");

  const currentMetadata = await assertSafeOutputTarget(outputPath, {
    keyPath,
    keyMetadata: keyFile.metadata,
    replace: flags.has("replace"),
  });
  if (
    (existingMetadata === null) !== (currentMetadata === null)
    || (existingMetadata !== null && !sameFileMetadata(existingMetadata, currentMetadata))
  ) {
    fail("Output target changed during contribution-index validation.");
  }
  if (currentMetadata) {
    const currentFile = await readRegularFileNoFollow(
      outputPath,
      CONTRIBUTION_INDEX_MAX_BYTES,
      "Existing contribution-index file",
    );
    if (currentFile.bytes.toString("utf8") !== previousText) {
      fail("Existing output changed after --previous validation.");
    }
  }

  const created = createContributionIndex(normalizedContributions, signer, {
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
    predecessor_link: previous ? "verified" : "root-sequence",
    next_step: "Publish the exact canonical file at both configured well-known endpoints, then run verify --project --publications.",
  }, null, 2)}\n`);
}

async function verifyCommand(options, flags) {
  requireOnly(options, new Set(["file", "control-claim", "previous"]));
  requireOnlyFlags(flags, new Set(["project", "publications"]));
  const indexPath = options.get("file") ?? DEFAULT_INDEX;
  const controlClaimPath = options.get("control-claim") ?? DEFAULT_CONTROL_CLAIM;
  const previousPaths = options.get("previous") ?? [];
  if (previousPaths.length >= CONTRIBUTION_INDEX_MAX_HISTORY) {
    fail(`At most ${CONTRIBUTION_INDEX_MAX_HISTORY - 1} --previous indexes may be supplied.`);
  }
  const [indexFile, controlClaimFile] = await Promise.all([
    readRegularFileNoFollow(indexPath, CONTRIBUTION_INDEX_MAX_BYTES, "Contribution-index file"),
    readRegularFileNoFollow(controlClaimPath, CONTROL_CLAIM_MAX_BYTES, "Control-claim file"),
  ]);
  const indexText = indexFile.bytes.toString("utf8");
  const controlClaimText = controlClaimFile.bytes.toString("utf8");
  let verified = verifyContributionIndexControlClaim(indexText, controlClaimText);
  let history = null;
  if (previousPaths.length > 0) {
    const previousTexts = [];
    for (let index = 0; index < previousPaths.length; index += 1) {
      const file = await readRegularFileNoFollow(
        previousPaths[index],
        CONTRIBUTION_INDEX_MAX_BYTES,
        `Previous contribution-index file ${index + 1}`,
      );
      previousTexts.push(file.bytes.toString("utf8"));
    }
    history = verifyContributionIndexHistory(previousTexts, indexText);
    if (history.current.index_sha256 !== verified.index_sha256) {
      fail("Verified history current index differs from --file.");
    }
  }
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
      facets: deriveContributionFacets(verified.serialized, historical.project),
    };
  }
  const currentScope = flags.has("publications")
    ? (flags.has("project") ? "fixed-publications-and-replayed-project" : "fixed-publications")
    : (flags.has("project") ? "signed-index-and-replayed-project" : "signed-index-and-control-claim");
  const scope = history ? `${currentScope}-and-complete-signed-history-chain` : currentScope;
  process.stdout.write(`${JSON.stringify(safeVerificationOutput(verified, scope, {
    history_chain: safeHistoryOutput(history, verified),
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
