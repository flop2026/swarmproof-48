import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { generateKeyPairSync } from "node:crypto";
import { chmod, lstat, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import test from "node:test";
import { didFromPrivateKey } from "../lib/crypto.mjs";
import {
  prepareSignedReview,
  validateAndBindPublicReview,
} from "../lib/review.mjs";
import {
  canonicalReviewDocument,
  createPromotionMaterial,
  createReviewSigningRequest,
  createReviewTargetPacket,
  createReviewTransport,
  parseCanonicalReviewDocument,
  postReviewTransport,
  reviewDocumentSha256,
  validateReviewSigningRequest,
  validateReviewTargetPacket,
  validateReviewTransport,
} from "../lib/review-flow.mjs";

const executeFile = promisify(execFile);
const PROJECT_ROOT = fileURLToPath(new URL("..", import.meta.url));
const CLI = path.join(PROJECT_ROOT, "bin", "review-flow.mjs");

function privateKey() {
  return generateKeyPairSync("ed25519").privateKey;
}

async function fixture(decision = "PASS") {
  const [config, manifest, report, status, eventsContent] = await Promise.all([
    readFile(path.join(PROJECT_ROOT, "config/event.json"), "utf8").then(JSON.parse),
    readFile(path.join(PROJECT_ROOT, "config/tasks.json"), "utf8").then(JSON.parse),
    readFile(path.join(PROJECT_ROOT, "public/data/report.json"), "utf8").then(JSON.parse),
    readFile(path.join(PROJECT_ROOT, "public/data/status.json"), "utf8").then(JSON.parse),
    readFile(path.join(PROJECT_ROOT, "public/data/events.jsonl"), "utf8"),
  ]);
  const target = report.events.find(event => event.type === "RESULT" && event.artifact_check?.status === "pass");
  assert(target);
  const context = validateAndBindPublicReview({
    config,
    manifest,
    report,
    status,
    eventsContent,
    targetEventId: target.event_id,
    decision,
    now: new Date(Date.parse(report.generated_at) + 60_000),
  });
  return { ...context, evidenceCommit: "a".repeat(40) };
}

function emptyRoom() {
  return { room: "swarmproof-48-e463", count: 0, first_seq: null, last_seq: 0, messages: [] };
}

function roomWithEvents(events, { firstSeq = 20, extra = [] } = {}) {
  const messages = [
    ...events.map((event, index) => ({
      seq: firstSeq + index,
      ts: event.payload.claimed_at,
      from: event.payload.did,
      nonce: Number(event.payload.nonce),
      text: event.envelope,
    })),
    ...extra,
  ];
  return {
    room: "swarmproof-48-e463",
    count: messages.length,
    first_seq: messages.length === 0 ? null : firstSeq,
    last_seq: messages.length === 0 ? 0 : firstSeq + messages.length - 1,
    messages,
  };
}

function reviewInputs(context, key = privateKey()) {
  const packet = createReviewTargetPacket(context);
  const reviewerDid = didFromPrivateKey(key);
  const claimedAt = new Date(Math.max(
    Date.parse(context.report.generated_at),
    Date.parse(packet.target.source_ts),
  ) + 1_000).toISOString();
  const request = createReviewSigningRequest({
    packet,
    reviewerDid,
    claimedAt,
    nonce: String(Date.parse(claimedAt)),
  });
  const transport = createReviewTransport({ packet, request, privateKey: key });
  return { packet, request, transport, key };
}

function createdFromInputs(inputs) {
  return {
    envelope: inputs.transport.envelope,
    event_id: inputs.transport.event_id,
    payload: inputs.request.payload,
  };
}

test("target packets are deterministic, replay-bound, and preserve explicit non-claims", async () => {
  const context = await fixture();
  const first = createReviewTargetPacket(context);
  const second = createReviewTargetPacket(context);
  assert.deepEqual(first, second);
  assert.equal(first.limitations.operator_independence, "unknown");
  assert.equal(first.limitations.reward_eligibility, "not-evaluated");
  assert.equal(parseCanonicalReviewDocument(
    canonicalReviewDocument(first),
    validateReviewTargetPacket,
  ).target_binding, first.target_binding);

  const changedContent = structuredClone(first);
  changedContent.target.payload.content_sha256 = "0".repeat(64);
  assert.throws(() => validateReviewTargetPacket(changedContent), /content_sha256|content binding|binding does not replay/u);
  const overclaim = structuredClone(first);
  overclaim.limitations.operator_independence = "independent";
  assert.throws(() => validateReviewTargetPacket(overclaim), /must not claim operator independence/u);
  const changedAcceptance = structuredClone(first);
  changedAcceptance.target.acceptance = ["accept without inspecting the artifact"];
  assert.throws(() => validateReviewTargetPacket(changedAcceptance), /signed task manifest entry/u);
  const changedTaskManifest = structuredClone(first);
  changedTaskManifest.target.task_manifest_entry.acceptance[0] = "different criterion";
  changedTaskManifest.target.acceptance[0] = "different criterion";
  assert.throws(() => validateReviewTargetPacket(changedTaskManifest), /coordinator-signed TASK digest/u);
  const changedEnvelope = structuredClone(first);
  changedEnvelope.target.envelope = `${changedEnvelope.target.envelope.slice(0, -1)}${changedEnvelope.target.envelope.endsWith("A") ? "B" : "A"}`;
  assert.throws(() => validateReviewTargetPacket(changedEnvelope), /signature|event ID/u);
  const unknown = { ...first, endorsement: true };
  assert.throws(() => validateReviewTargetPacket(unknown), /invalid field set/u);
  const nonCanonical = `${JSON.stringify(first, null, 2)}\n`;
  assert.throws(
    () => parseCanonicalReviewDocument(nonCanonical, validateReviewTargetPacket),
    /not canonical JSON/u,
  );
});

test("offline signing requests require an explicit distinct reviewer and deterministic time/nonce", async () => {
  const context = await fixture();
  const key = privateKey();
  const packet = createReviewTargetPacket(context);
  const claimedAt = new Date(Date.parse(context.report.generated_at) + 1_000).toISOString();
  const input = {
    packet,
    reviewerDid: didFromPrivateKey(key),
    claimedAt,
    nonce: String(Date.parse(claimedAt)),
  };
  assert.deepEqual(createReviewSigningRequest(input), createReviewSigningRequest(input));
  assert.throws(
    () => createReviewSigningRequest({ ...input, reviewerDid: packet.target.payload.did }),
    /differ from the RESULT author/u,
  );
  assert.throws(
    () => createReviewSigningRequest({ ...input, reviewerDid: packet.project.coordinator_did }),
    /differ from the (?:project controller|RESULT author)/u,
  );
  assert.throws(
    () => createReviewSigningRequest({ ...input, claimedAt: "2026-08-26T00:00:00.000Z" }),
    /predates|outside the event/u,
  );
  assert.throws(
    () => createReviewSigningRequest({ ...input, nonce: String(BigInt(Number.MAX_SAFE_INTEGER) + 1n) }),
    /safe positive decimal|string|safe transport range/u,
  );
  const request = createReviewSigningRequest(input);
  const wrongPacketHash = { ...request, target_packet_sha256: "f".repeat(64) };
  assert.throws(
    () => validateReviewSigningRequest(wrongPacketHash, packet),
    /different packet bytes/u,
  );
  const changedVerdict = structuredClone(request);
  changedVerdict.payload.review.verdict = "REJECT";
  assert.throws(
    () => validateReviewSigningRequest(changedVerdict, packet),
    /does not match the target packet/u,
  );
});

test("offline transport signing is deterministic and every binding fails closed", async () => {
  const context = await fixture();
  const inputs = reviewInputs(context);
  const repeated = createReviewTransport({
    packet: inputs.packet,
    request: inputs.request,
    privateKey: inputs.key,
  });
  assert.deepEqual(inputs.transport, repeated);
  assert.equal(validateReviewTransport(inputs.transport, inputs.packet, inputs.request), inputs.transport);

  const flipLast = value => `${value.slice(0, -1)}${value.endsWith("A") ? "B" : "A"}`;
  for (const mutate of [
    value => { value.target_packet_sha256 = "0".repeat(64); },
    value => { value.signing_request_sha256 = "0".repeat(64); },
    value => { value.room = "lobby"; },
    value => { value.event_id = "0".repeat(64); },
    value => { value.transport_signature = flipLast(value.transport_signature); },
    value => { value.envelope = flipLast(value.envelope); },
  ]) {
    const tampered = structuredClone(inputs.transport);
    mutate(tampered);
    assert.throws(() => validateReviewTransport(tampered, inputs.packet, inputs.request));
  }
});

test("posting consumes a pre-signed transport without a key and requires verified read-back", async () => {
  const context = await fixture();
  const inputs = reviewInputs(context);
  const staleObservationPacket = structuredClone(inputs.packet);
  staleObservationPacket.target.source_seq += 1;
  validateReviewTargetPacket(staleObservationPacket);
  const misleadingRequest = createReviewSigningRequest({
    packet: staleObservationPacket,
    reviewerDid: inputs.transport.did,
    claimedAt: inputs.request.payload.claimed_at,
    nonce: inputs.request.payload.nonce,
  });
  const misleadingTransport = createReviewTransport({
    packet: staleObservationPacket,
    request: misleadingRequest,
    privateKey: inputs.key,
  });
  let misleadingFetches = 0;
  await assert.rejects(postReviewTransport({
    context,
    packet: staleObservationPacket,
    request: misleadingRequest,
    transport: misleadingTransport,
    fetchImpl: async () => {
      misleadingFetches += 1;
      return new Response(JSON.stringify(emptyRoom()), { status: 200 });
    },
    technocoreOrigin: "https://fixture.invalid/",
  }), /inspection material changed/u);
  assert.equal(misleadingFetches, 0);

  let posted = false;
  let postedBody = null;
  const fetchImpl = async (_url, options) => {
    if (options.method === "POST") {
      posted = true;
      postedBody = JSON.parse(options.body);
      return new Response("{}", { status: 200 });
    }
    return new Response(JSON.stringify(posted
      ? roomWithEvents([createdFromInputs(inputs)])
      : emptyRoom()), { status: 200 });
  };
  const result = await postReviewTransport({
    context,
    packet: inputs.packet,
    request: inputs.request,
    transport: inputs.transport,
    fetchImpl,
    technocoreOrigin: "https://fixture.invalid/",
  });
  assert.equal(result.status, "posted-and-observed");
  assert.equal(result.observed.event_id, inputs.transport.event_id);
  assert.equal(postedBody.did, inputs.transport.did);
  assert.equal(postedBody.text, inputs.transport.envelope);
  assert.equal(postedBody.sig, inputs.transport.transport_signature);

  let writes = 0;
  const staleRoom = roomWithEvents([], {
    extra: [{
      seq: 20,
      ts: inputs.request.payload.claimed_at,
      from: inputs.transport.did,
      nonce: Number(inputs.transport.nonce),
      text: "ordinary",
    }],
  });
  const staleFetch = async (_url, options) => {
    if (options.method === "POST") writes += 1;
    return new Response(JSON.stringify(staleRoom), { status: 200 });
  };
  await assert.rejects(postReviewTransport({
    context,
    packet: inputs.packet,
    request: inputs.request,
    transport: inputs.transport,
    fetchImpl: staleFetch,
    technocoreOrigin: "https://fixture.invalid/",
  }), /nonce is no longer greater/u);
  assert.equal(writes, 0);

  const rejectContext = await fixture("FAIL");
  const rejectPacket = createReviewTargetPacket(rejectContext);
  const rejectClaimedAt = new Date(Date.parse(inputs.request.payload.claimed_at) + 1_000).toISOString();
  const rejectRequest = createReviewSigningRequest({
    packet: rejectPacket,
    reviewerDid: inputs.transport.did,
    claimedAt: rejectClaimedAt,
    nonce: String(Date.parse(rejectClaimedAt)),
  });
  const rejectTransport = createReviewTransport({
    packet: rejectPacket,
    request: rejectRequest,
    privateKey: inputs.key,
  });
  let rejectionPosted = false;
  const correctionFetch = async (_url, options) => {
    if (options.method === "POST") {
      rejectionPosted = true;
      return new Response("{}", { status: 200 });
    }
    return new Response(JSON.stringify(roomWithEvents([
      createdFromInputs(inputs),
      ...(rejectionPosted ? [createdFromInputs({ request: rejectRequest, transport: rejectTransport })] : []),
    ])), { status: 200 });
  };
  const correction = await postReviewTransport({
    context: rejectContext,
    packet: rejectPacket,
    request: rejectRequest,
    transport: rejectTransport,
    fetchImpl: correctionFetch,
    technocoreOrigin: "https://fixture.invalid/",
  });
  assert.equal(correction.status, "posted-and-observed");
  assert.equal(correction.observed.payload.review.verdict, "REJECT");
});

test("promotion material requires an observed, effective PASS from a distinct DID", async () => {
  const context = await fixture("PASS");
  const reviewerKey = privateKey();
  const pass = prepareSignedReview({
    context,
    roomData: emptyRoom(),
    privateKeyPem: reviewerKey,
    now: new Date(context.report.generated_at),
  });
  const claimedAt = new Date(Date.parse(pass.created.payload.claimed_at) + 2_000).toISOString();
  const nonce = String(Date.parse(claimedAt));
  const prepared = createPromotionMaterial({
    context,
    roomData: roomWithEvents([pass.created]),
    reviewEventId: pass.created.event_id,
    claimedAt,
    nonce,
  });
  assert.equal(prepared.material.type, "PROMOTE");
  assert.deepEqual(prepared.material.parent_event_ids, [context.target.event_id]);
  assert.equal(prepared.qualifyingReview.payload.did, pass.reviewerDid);
  assert.notEqual(pass.reviewerDid, context.config.coordinator_did);

  assert.throws(() => createPromotionMaterial({
    context,
    roomData: emptyRoom(),
    reviewEventId: pass.created.event_id,
    claimedAt,
    nonce,
  }), /not a valid observed/u);

  const rejectContext = await fixture("FAIL");
  const rejection = prepareSignedReview({
    context: rejectContext,
    roomData: roomWithEvents([pass.created]),
    privateKeyPem: reviewerKey,
    now: new Date(Date.parse(pass.created.payload.claimed_at) + 1_000),
  });
  assert.throws(() => createPromotionMaterial({
    context,
    roomData: roomWithEvents([pass.created, rejection.created]),
    reviewEventId: pass.created.event_id,
    claimedAt: new Date(Date.parse(rejection.created.payload.claimed_at) + 1_000).toISOString(),
    nonce: String(Date.parse(rejection.created.payload.claimed_at) + 1_000),
  }), /superseded/u);
  assert.throws(() => createPromotionMaterial({
    context,
    roomData: roomWithEvents([pass.created]),
    reviewEventId: pass.created.event_id,
    claimedAt: pass.created.payload.claimed_at,
    nonce: "1",
  }), /controller nonce/u);
});

test("CLI signs only after validating non-secret inputs and never prints signed material", async () => {
  const directory = await mkdtemp(path.join(tmpdir(), "swarmproof-review-flow-"));
  try {
    const context = await fixture();
    const inputs = reviewInputs(context);
    const packetPath = path.join(directory, "target.json");
    const requestPath = path.join(directory, "request.json");
    const keyPath = path.join(directory, "reviewer.pem");
    const transportPath = path.join(directory, "transport.json");
    await Promise.all([
      writeFile(packetPath, canonicalReviewDocument(inputs.packet), { mode: 0o644 }),
      writeFile(requestPath, canonicalReviewDocument(inputs.request), { mode: 0o644 }),
      writeFile(keyPath, inputs.key.export({ format: "pem", type: "pkcs8" }), { mode: 0o600 }),
    ]);
    const signed = await executeFile(process.execPath, [
      CLI,
      "sign",
      "--packet", packetPath,
      "--request", requestPath,
      "--key", keyPath,
      "--out", transportPath,
    ], { cwd: PROJECT_ROOT, encoding: "utf8" });
    const summary = JSON.parse(signed.stdout);
    const serializedSummary = JSON.stringify(summary);
    assert.equal(summary.action, "transport-signed");
    assert.equal(summary.sensitive_fields_printed, false);
    assert(!serializedSummary.includes(inputs.transport.envelope));
    assert(!serializedSummary.includes(inputs.transport.transport_signature));
    assert(!/envelope|transport_signature|private[_-]?key|\bproof\b/iu.test(serializedSummary));
    assert.equal((await lstat(transportPath)).mode & 0o077, 0);
    const writtenTransport = parseCanonicalReviewDocument(
      await readFile(transportPath, "utf8"),
      value => validateReviewTransport(value, inputs.packet, inputs.request),
      "Review transport",
    );
    assert.equal(reviewDocumentSha256(writtenTransport), summary.transport_sha256);

    const invalid = { ...inputs.request, target_packet_sha256: "0".repeat(64) };
    const invalidPath = path.join(directory, "invalid-request.json");
    await writeFile(invalidPath, canonicalReviewDocument(invalid));
    await assert.rejects(executeFile(process.execPath, [
      CLI,
      "sign",
      "--packet", packetPath,
      "--request", invalidPath,
      "--key", path.join(directory, "missing.pem"),
      "--out", path.join(directory, "must-not-exist.json"),
    ], { cwd: PROJECT_ROOT, encoding: "utf8" }), error => (
      error.code === 1 && /different packet bytes/u.test(error.stderr) && !/could not be opened/u.test(error.stderr)
    ));

    await assert.rejects(executeFile(process.execPath, [
      CLI,
      "post",
      "--packet", path.join(directory, "missing-packet.json"),
      "--request", path.join(directory, "missing-request.json"),
      "--transport", path.join(directory, "missing-transport.json"),
    ], { cwd: PROJECT_ROOT, encoding: "utf8" }), error => (
      error.code === 1 && /Posting requires --confirm/u.test(error.stderr)
    ));
  } finally {
    await chmod(directory, 0o700).catch(() => {});
    await rm(directory, { recursive: true, force: true });
  }
});
