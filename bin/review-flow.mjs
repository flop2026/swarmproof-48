#!/usr/bin/env node

import { constants as fsConstants } from "node:fs";
import { open, writeFile } from "node:fs/promises";
import {
  acquireReviewLock,
  assertReviewSnapshotTrusted,
  assertReviewSourceCommitTrusted,
  fetchPublicReviewDocuments,
  fetchReviewRoom,
  validateAndBindPublicReview,
} from "../lib/review.mjs";
import {
  REVIEW_DOCUMENT_MAX_BYTES,
  canonicalReviewDocument,
  createPromotionMaterial,
  createReviewSigningRequest,
  createReviewTargetPacket,
  createReviewTransport,
  parseCanonicalReviewDocument,
  postReviewTransport,
  readBackReviewTransport,
  readSecureReviewKeyObject,
  reviewDocumentSha256,
  validateReviewSigningRequest,
  validateReviewTargetPacket,
  validateReviewTransport,
} from "../lib/review-flow.mjs";
import { EXPERIMENT } from "../lib/protocol.mjs";

const FILE_LIMITS = Object.freeze({ config: 256 * 1024, tasks: 256 * 1024 });

function usage() {
  console.error(`Usage:
  review inspect --target RESULT_EVENT_ID --verdict PASS|FAIL --out target.json [--config config/event.json] [--tasks config/tasks.json]
  review payload --packet target.json --reviewer-did did:key:... --claimed-at ISO_UTC --nonce SAFE_DECIMAL --out request.json
  review sign --packet target.json --request request.json --key reviewer.pem --out transport.json
  review post --packet target.json --request request.json --transport transport.json --confirm ${EXPERIMENT} [--config config/event.json] [--tasks config/tasks.json]
  review readback --packet target.json --request request.json --transport transport.json [--config config/event.json] [--tasks config/tasks.json]
  review promote --target RESULT_EVENT_ID --review REVIEW_EVENT_ID --claimed-at ISO_UTC --nonce SAFE_DECIMAL --out promote-payload.json [--config config/event.json] [--tasks config/tasks.json]

inspect, payload, sign, and promote never write to Technocore. post is the only writing command and never reads a private key.`);
  process.exit(2);
}

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function optionsOf(arguments_) {
  const options = new Map();
  for (let index = 0; index < arguments_.length; index += 1) {
    const token = arguments_[index];
    if (!token.startsWith("--") || index + 1 >= arguments_.length || arguments_[index + 1].startsWith("--")) usage();
    const name = token.slice(2);
    if (options.has(name)) usage();
    options.set(name, arguments_[index + 1]);
    index += 1;
  }
  return options;
}

function requireOnly(options, allowed) {
  for (const name of options.keys()) if (!allowed.has(name)) usage();
}

async function readBoundedRegular(path, maximumBytes, label, { ownerOnly = false } = {}) {
  let handle;
  try {
    handle = await open(path, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
  } catch {
    throw new Error(`${label} could not be opened as a non-symlink file.`);
  }
  try {
    const metadata = await handle.stat();
    assert(metadata.isFile(), `${label} must be a regular file.`);
    assert(metadata.size > 0 && metadata.size <= maximumBytes, `${label} size is invalid.`);
    if (ownerOnly) {
      assert((metadata.mode & 0o077) === 0, `${label} permissions must deny group and other access.`);
      if (typeof process.getuid === "function") {
        assert(metadata.uid === process.getuid(), `${label} must be owned by the current user.`);
      }
    }
    const bytes = await handle.readFile();
    try {
      assert(bytes.length > 0 && bytes.length <= maximumBytes, `${label} size changed during its safe read.`);
      return bytes.toString("utf8");
    } finally {
      if (ownerOnly) bytes.fill(0);
    }
  } finally {
    await handle.close();
  }
}

async function readJson(path, maximumBytes, label) {
  const content = await readBoundedRegular(path, maximumBytes, label);
  try {
    return JSON.parse(content);
  } catch {
    throw new Error(`${label} is not valid JSON.`);
  }
}

async function readCanonical(path, validator, label, options) {
  const content = await readBoundedRegular(path, REVIEW_DOCUMENT_MAX_BYTES, label, options);
  return parseCanonicalReviewDocument(content, validator, label);
}

async function writeCanonical(path, value, mode, label) {
  assert(typeof path === "string" && path.length > 0, `${label} output path is required.`);
  const bytes = canonicalReviewDocument(value);
  await writeFile(path, bytes, { encoding: "utf8", flag: "wx", mode });
  return { bytes: Buffer.byteLength(bytes, "utf8"), sha256: reviewDocumentSha256(value) };
}

async function loadReviewContext(options, targetEventId, decision, { allowComplete = false } = {}) {
  const configPath = options.get("config") ?? "config/event.json";
  const tasksPath = options.get("tasks") ?? "config/tasks.json";
  const [config, manifest, published] = await Promise.all([
    readJson(configPath, FILE_LIMITS.config, "Project config"),
    readJson(tasksPath, FILE_LIMITS.tasks, "Task manifest"),
    fetchPublicReviewDocuments(),
  ]);
  const context = validateAndBindPublicReview({
    config,
    manifest,
    ...published,
    targetEventId,
    decision,
    now: new Date(),
    allowComplete,
  });
  await assertReviewSourceCommitTrusted(context.sourceCommit, process.cwd());
  const evidenceCommit = await assertReviewSnapshotTrusted({
    ...published,
    sourceCommit: context.sourceCommit,
    repositoryRoot: process.cwd(),
  });
  return { ...context, evidenceCommit };
}

function safeTargetSummary(packet) {
  return {
    event_id: packet.target.event_id,
    author_did: packet.target.payload.did,
    task_id: packet.target.payload.task_id,
    task_event_id: packet.target.task_event_id,
    content_sha256: packet.target.payload.content_sha256,
    artifact: packet.target.payload.artifact,
    acceptance: packet.target.acceptance,
    artifact_check_status: packet.target.artifact_check_status,
    evidence_level: packet.target.evidence_level,
  };
}

async function main() {
  const [command, ...arguments_] = process.argv.slice(2);
  if (!command) usage();
  const options = optionsOf(arguments_);

  if (command === "inspect") {
    requireOnly(options, new Set(["target", "verdict", "out", "config", "tasks"]));
    const target = options.get("target");
    const verdict = options.get("verdict");
    const out = options.get("out");
    if (!target || !verdict || !out) usage();
    const context = await loadReviewContext(options, target, verdict);
    const packet = createReviewTargetPacket(context);
    const written = await writeCanonical(out, packet, 0o644, "Review target packet");
    process.stdout.write(`${JSON.stringify({
      schema: "swarmproof-review-flow-summary-v1",
      action: "inspected",
      wrote_network: false,
      packet_sha256: written.sha256,
      packet_bytes: written.bytes,
      decision: packet.decision,
      signed_verdict: packet.protocol_verdict,
      target: safeTargetSummary(packet),
      snapshot: packet.snapshot,
      limitations: packet.limitations,
    }, null, 2)}\n`);
    return;
  }

  if (command === "payload") {
    requireOnly(options, new Set(["packet", "reviewer-did", "claimed-at", "nonce", "out"]));
    const packetPath = options.get("packet");
    const reviewerDid = options.get("reviewer-did");
    const claimedAt = options.get("claimed-at");
    const nonce = options.get("nonce");
    const out = options.get("out");
    if (!packetPath || !reviewerDid || !claimedAt || !nonce || !out) usage();
    const packet = await readCanonical(packetPath, validateReviewTargetPacket, "Review target packet");
    const request = createReviewSigningRequest({ packet, reviewerDid, claimedAt, nonce });
    const written = await writeCanonical(out, request, 0o644, "Review signing request");
    process.stdout.write(`${JSON.stringify({
      schema: "swarmproof-review-flow-summary-v1",
      action: "payload-prepared",
      wrote_network: false,
      packet_sha256: request.target_packet_sha256,
      signing_request_sha256: written.sha256,
      signing_request_bytes: written.bytes,
      reviewer_did: request.reviewer_did,
      claimed_at: request.payload.claimed_at,
      nonce: request.payload.nonce,
      target_event_id: request.payload.review.target_event_id,
      verdict: request.payload.review.verdict,
      operator_independence: "unknown",
    }, null, 2)}\n`);
    return;
  }

  if (command === "sign") {
    requireOnly(options, new Set(["packet", "request", "key", "out"]));
    const packetPath = options.get("packet");
    const requestPath = options.get("request");
    const keyPath = options.get("key");
    const out = options.get("out");
    if (!packetPath || !requestPath || !keyPath || !out) usage();
    const packet = await readCanonical(packetPath, validateReviewTargetPacket, "Review target packet");
    const request = await readCanonical(
      requestPath,
      value => validateReviewSigningRequest(value, packet),
      "Review signing request",
    );
    const privateKey = await readSecureReviewKeyObject(keyPath);
    const transport = createReviewTransport({ packet, request, privateKey });
    const written = await writeCanonical(out, transport, 0o600, "Review transport");
    process.stdout.write(`${JSON.stringify({
      schema: "swarmproof-review-flow-summary-v1",
      action: "transport-signed",
      wrote_network: false,
      reviewer_did: transport.did,
      event_id: transport.event_id,
      target_event_id: request.payload.review.target_event_id,
      verdict: request.payload.review.verdict,
      packet_sha256: transport.target_packet_sha256,
      signing_request_sha256: transport.signing_request_sha256,
      transport_sha256: written.sha256,
      transport_bytes: written.bytes,
      sensitive_fields_printed: false,
      operator_independence: "unknown",
    }, null, 2)}\n`);
    return;
  }

  if (command === "post" || command === "readback") {
    requireOnly(options, new Set(["packet", "request", "transport", "confirm", "config", "tasks"]));
    if (command === "post") {
      assert(options.get("confirm") === EXPERIMENT, `Posting requires --confirm ${EXPERIMENT}.`);
    } else {
      assert(!options.has("confirm"), "--confirm is only accepted by post.");
    }
    const packetPath = options.get("packet");
    const requestPath = options.get("request");
    const transportPath = options.get("transport");
    if (!packetPath || !requestPath || !transportPath) usage();
    const packet = await readCanonical(packetPath, validateReviewTargetPacket, "Review target packet");
    const request = await readCanonical(
      requestPath,
      value => validateReviewSigningRequest(value, packet),
      "Review signing request",
    );
    const transport = await readCanonical(
      transportPath,
      value => validateReviewTransport(value, packet, request),
      "Review transport",
      { ownerOnly: true },
    );
    const context = await loadReviewContext(
      options,
      packet.target.event_id,
      packet.decision,
      { allowComplete: command === "readback" },
    );
    let result;
    if (command === "readback") {
      result = await readBackReviewTransport({ context, packet, request, transport });
    } else {
      const releaseLock = await acquireReviewLock(process.env.SWARMPROOF_REVIEW_LOCK_FILE);
      try {
        result = await postReviewTransport({ context, packet, request, transport });
      } finally {
        await releaseLock();
      }
    }
    process.stdout.write(`${JSON.stringify({
      schema: "swarmproof-review-flow-summary-v1",
      action: command,
      wrote_network: result.wroteNetwork,
      status: result.status,
      event_id: transport.event_id,
      reviewer_did: transport.did,
      target_event_id: packet.target.event_id,
      verdict: packet.protocol_verdict,
      observed_source_seq: result.observed?.source_seq ?? null,
      observed_source_ts: result.observed?.source_ts ?? null,
      observation_source: result.observationSource,
      effective: result.effective,
      effective_event_id: result.effectiveReview?.event_id ?? null,
      effective_verdict: result.effectiveReview?.payload.review.verdict ?? null,
      operator_independence: "unknown",
    }, null, 2)}\n`);
    return;
  }

  if (command === "promote") {
    requireOnly(options, new Set(["target", "review", "claimed-at", "nonce", "out", "config", "tasks"]));
    const target = options.get("target");
    const review = options.get("review");
    const claimedAt = options.get("claimed-at");
    const nonce = options.get("nonce");
    const out = options.get("out");
    if (!target || !review || !claimedAt || !nonce || !out) usage();
    const context = await loadReviewContext(options, target, "PASS");
    const roomData = await fetchReviewRoom({ room: context.config.build_room });
    const prepared = createPromotionMaterial({ context, roomData, reviewEventId: review, claimedAt, nonce });
    const written = await writeCanonical(out, prepared.material, 0o644, "Promotion material");
    process.stdout.write(`${JSON.stringify({
      schema: "swarmproof-review-flow-summary-v1",
      action: "promotion-material-prepared",
      wrote_network: false,
      promotion_material_sha256: written.sha256,
      promotion_material_bytes: written.bytes,
      target_event_id: context.target.event_id,
      qualifying_review_event_id: prepared.qualifyingReview.event_id,
      qualifying_reviewer_did: prepared.qualifyingReview.payload.did,
      qualifying_verdict: prepared.qualifyingReview.payload.review.verdict,
      distinct_from_result_author: prepared.qualifyingReview.payload.did !== context.target.payload.did,
      distinct_from_project_controller: prepared.qualifyingReview.payload.did !== context.config.coordinator_did,
      operator_independence: "unknown",
      requires_separate_controller_signature_and_transport: true,
    }, null, 2)}\n`);
    return;
  }

  usage();
}

main().catch(error => {
  console.error(`review: ${error.message}`);
  process.exit(1);
});
