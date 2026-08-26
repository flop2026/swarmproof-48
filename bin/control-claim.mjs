#!/usr/bin/env node

import { createPrivateKey, randomUUID } from "node:crypto";
import { basename, dirname, join, resolve } from "node:path";
import { constants } from "node:fs";
import { lstat, open, rename, unlink, writeFile } from "node:fs/promises";
import {
  CONTROL_CLAIM_CONTROLLER,
  CONTROL_CLAIM_MAX_BYTES,
  CONTROL_CLAIM_MAX_VALIDITY_MS,
  createControlClaim,
  parseControlClaim,
  verifyControlClaim,
  verifyControlClaimPublications,
} from "../lib/control-claim.mjs";

const PRIVATE_KEY_MAX_BYTES = 16 * 1024;
const DEFAULT_VALID_DAYS = CONTROL_CLAIM_MAX_VALIDITY_MS / (24 * 60 * 60 * 1000);

function fail(message) {
  throw new Error(message);
}

function usage() {
  console.error(`Usage:
  control-claim create --key private-key.pem --out claim.json [--valid-days 1..366] [--replace]
  control-claim verify --file claim.json [--publications]

create derives the DID from an owner-only Ed25519 key file and never prints the key, PEM, or signature.
verify checks the project-specific schema, canonical bytes, validity window, and domain-separated signature.
--publications additionally requires exact copies at the fixed GitHub and Pages well-known endpoints.`);
  process.exit(2);
}

function parseArguments(arguments_) {
  const options = new Map();
  const flags = new Set();
  for (let index = 0; index < arguments_.length; index += 1) {
    const token = arguments_[index];
    if (token === "--publications") {
      if (flags.has("publications")) usage();
      flags.add("publications");
      continue;
    }
    if (token === "--replace") {
      if (flags.has("replace")) usage();
      flags.add("replace");
      continue;
    }
    if (!token.startsWith("--") || index + 1 >= arguments_.length || arguments_[index + 1].startsWith("--")) {
      usage();
    }
    const name = token.slice(2);
    if (options.has(name)) usage();
    options.set(name, arguments_[index + 1]);
    index += 1;
  }
  return { options, flags };
}

function requireOnly(options, allowed) {
  for (const option of options.keys()) {
    if (!allowed.has(option)) usage();
  }
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

async function assertSafeOutputTarget(keyPath, keyMetadata, outputPath, replaceExisting) {
  if (resolve(keyPath) === resolve(outputPath)) fail("Output path must differ from the private key path.");
  let metadata;
  try {
    metadata = await lstat(outputPath);
  } catch (error) {
    if (error.code === "ENOENT") return;
    throw error;
  }
  if (!metadata.isFile() || metadata.isSymbolicLink()) fail("Existing output must be a regular non-symlink file.");
  if (metadata.dev === keyMetadata.dev && metadata.ino === keyMetadata.ino) {
    fail("Output must not be the private key file or one of its hard links.");
  }
  if (!replaceExisting) fail("Output already exists; pass --replace only when rotating a valid prior claim.");

  const existing = await readRegularFileNoFollow(outputPath, CONTROL_CLAIM_MAX_BYTES, "Existing control-claim file");
  const existingText = existing.bytes.toString("utf8");
  const parsed = parseControlClaim(existingText);
  // Verify the existing signature at issuance so an expired but otherwise authentic claim can be
  // safely rotated. --replace may not be used as a generic arbitrary-file overwrite primitive.
  verifyControlClaim(existingText, { at: parsed.payload.issued_at });
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

function verificationOutput(verified, scope) {
  return {
    schema: "swarmproof-control-claim-verification-v1",
    validation_scope: scope,
    controller: verified.document.payload.controller,
    claim_sha256: verified.claim_sha256,
    issued_at: verified.document.payload.issued_at,
    expires_at: verified.document.payload.expires_at,
    valid_at: verified.valid_at,
    signature_valid: verified.signature_valid,
    publications: verified.publications ?? "not-checked",
    limitations: scope === "fixed-publications"
      ? [
        "The result binds this DID key to bytes served from the configured project resources at verification time; it does not identify a person, prove independent operation, or establish reward eligibility.",
        "The GitHub and Pages copies share a deployment chain and are not independent witnesses.",
      ]
      : [
        "A valid signature is the DID controller's self-assertion only. Resource control requires the separate fixed-publication check.",
        "The claim does not identify a person, prove independent operation, or establish reward eligibility.",
      ],
  };
}

async function main() {
  const [command, ...arguments_] = process.argv.slice(2);
  if (!command) usage();
  const { options, flags } = parseArguments(arguments_);

  if (command === "create") {
    requireOnly(options, new Set(["key", "out", "valid-days"]));
    if ([...flags].some(flag => flag !== "replace")) usage();
    const keyPath = options.get("key");
    const outputPath = options.get("out");
    if (!keyPath || !outputPath) usage();
    const validDaysText = options.get("valid-days") ?? String(DEFAULT_VALID_DAYS);
    if (!/^\d{1,3}$/u.test(validDaysText)) fail("valid-days must be an integer from 1 through 366.");
    const validDays = Number(validDaysText);
    if (!Number.isSafeInteger(validDays) || validDays < 1 || validDays > DEFAULT_VALID_DAYS) {
      fail("valid-days must be an integer from 1 through 366.");
    }

    const keyFile = await readRegularFileNoFollow(keyPath, PRIVATE_KEY_MAX_BYTES, "Private key file", {
      ownerOnly: true,
    });
    let signer;
    try {
      signer = createPrivateKey(keyFile.bytes);
    } finally {
      keyFile.bytes.fill(0);
    }
    if (signer.asymmetricKeyType !== "ed25519") fail("Private key must be Ed25519.");
    await assertSafeOutputTarget(keyPath, keyFile.metadata, outputPath, flags.has("replace"));

    const issuedAt = Date.now();
    const created = createControlClaim(signer, {
      issuedAt,
      expiresAt: issuedAt + validDays * 24 * 60 * 60 * 1000,
    });
    await writeAtomic(outputPath, created.serialized);
    process.stdout.write(`${JSON.stringify({
      schema: "swarmproof-control-claim-created-v1",
      controller: CONTROL_CLAIM_CONTROLLER,
      claim_sha256: created.claim_sha256,
      issued_at: created.document.payload.issued_at,
      expires_at: created.document.payload.expires_at,
      next_step: "Publish the exact canonical file at both configured well-known endpoints, then run verify --publications.",
    }, null, 2)}\n`);
    return;
  }

  if (command === "verify") {
    requireOnly(options, new Set(["file"]));
    if ([...flags].some(flag => flag !== "publications")) usage();
    const filePath = options.get("file");
    if (!filePath) usage();
    const claimFile = await readRegularFileNoFollow(filePath, CONTROL_CLAIM_MAX_BYTES, "Control-claim file");
    const claimText = claimFile.bytes.toString("utf8");
    const verified = flags.has("publications")
      ? await verifyControlClaimPublications(claimText)
      : verifyControlClaim(claimText);
    process.stdout.write(`${JSON.stringify(verificationOutput(
      verified,
      flags.has("publications") ? "fixed-publications" : "signed-document-only",
    ), null, 2)}\n`);
    return;
  }

  usage();
}

main().catch(error => {
  console.error(`control-claim: ${error.message}`);
  process.exit(1);
});
