import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { generateKeyPairSync } from "node:crypto";
import { chmod, mkdtemp, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import test from "node:test";
import { verifyUtf8 } from "../lib/crypto.mjs";
import { createEnvelope } from "../lib/protocol.mjs";
import {
  assertReviewSnapshotTrusted,
  assertReviewSourceCommitTrusted,
  fetchPublicReviewDocuments,
  fetchReviewRoom,
  findValidObservedReview,
  normalizeReviewDecision,
  postSignedReview,
  prepareSignedReview,
  publicReviewSummary,
  readSecureReviewKey,
  stableTargetBinding,
  validateAndBindPublicReview,
} from "../lib/review.mjs";

const executeFile = promisify(execFile);
const PROJECT_ROOT = fileURLToPath(new URL("..", import.meta.url));
const CLI = path.join(PROJECT_ROOT, "bin", "swarmproof.mjs");

function privatePem() {
  const { privateKey } = generateKeyPairSync("ed25519");
  return privateKey.export({ format: "pem", type: "pkcs8" });
}

async function fixture() {
  const [config, manifest, report, status, eventsContent] = await Promise.all([
    readFile(path.join(PROJECT_ROOT, "config/event.json"), "utf8").then(JSON.parse),
    readFile(path.join(PROJECT_ROOT, "config/tasks.json"), "utf8").then(JSON.parse),
    readFile(path.join(PROJECT_ROOT, "public/data/report.json"), "utf8").then(JSON.parse),
    readFile(path.join(PROJECT_ROOT, "public/data/status.json"), "utf8").then(JSON.parse),
    readFile(path.join(PROJECT_ROOT, "public/data/events.jsonl"), "utf8"),
  ]);
  const target = report.events.find(event => (
    event.type === "RESULT" && event.artifact_check?.status === "pass"
  ));
  assert(target, "Checked-in review fixture must contain a reproducible RESULT.");
  return {
    config,
    manifest,
    report,
    status,
    eventsContent,
    targetEventId: target.event_id,
    now: new Date(Date.parse(report.generated_at) + 60_000),
  };
}

function emptyRoom() {
  return {
    room: "swarmproof-48-e463",
    count: 0,
    first_seq: null,
    last_seq: 0,
    messages: [],
  };
}

function roomWithEvent(created) {
  return roomWithEvents([created]);
}

function roomWithEvents(events, { firstSeq = 20, sourceTimes = [] } = {}) {
  return {
    room: "swarmproof-48-e463",
    count: events.length,
    first_seq: events.length === 0 ? null : firstSeq,
    last_seq: events.length === 0 ? 0 : firstSeq + events.length - 1,
    messages: events.map((created, index) => ({
      seq: firstSeq + index,
      ts: sourceTimes[index] ?? created.payload.claimed_at,
      from: created.payload.did,
      nonce: Number(created.payload.nonce),
      text: created.envelope,
    })),
  };
}

function contextProtocolOptions(context) {
  return {
    allowedRepositories: new Set([context.config.repository]),
    allowedTasks: new Set(context.manifest.tasks.map(task => task.id)),
    coordinatorDid: context.config.coordinator_did,
  };
}

async function boundContext(decision = "PASS") {
  const input = await fixture();
  return validateAndBindPublicReview({ ...input, decision });
}

test("normalizes the ergonomic FAIL decision to the v1 REJECT verdict", () => {
  assert.deepEqual(normalizeReviewDecision("pass"), { decision: "PASS", protocolVerdict: "PASS" });
  assert.deepEqual(normalizeReviewDecision("fail"), { decision: "FAIL", protocolVerdict: "REJECT" });
  assert.throws(() => normalizeReviewDecision("CHANGES"), /PASS or FAIL/u);
});

test("binds a public RESULT to its exact TASK ancestry and content hash", async () => {
  const context = await boundContext();
  assert.equal(context.target.payload.type, "RESULT");
  assert.equal(context.task.payload.type, "TASK");
  assert.equal(context.task.payload.task_id, context.target.payload.task_id);
  assert.equal(context.task.payload.did, context.config.coordinator_did);
  assert.equal(context.target.payload.content_sha256, context.target.payload.artifact.sha256);
  assert.match(stableTargetBinding(context), /^[0-9a-f]{64}$/u);
});

test("fails closed on report/status, archive, target-type, and source-commit tampering", async () => {
  const input = await fixture();
  await assert.rejects(
    Promise.resolve().then(() => validateAndBindPublicReview({
      ...input,
      decision: "PASS",
      status: { ...input.status, report_sha256: "0".repeat(64) },
    })),
    /report SHA-256/u,
  );
  await assert.rejects(
    Promise.resolve().then(() => validateAndBindPublicReview({
      ...input,
      decision: "PASS",
      eventsContent: `${input.eventsContent} `,
    })),
    /archive SHA-256/u,
  );
  const taskId = input.report.events.find(event => event.type === "TASK").event_id;
  await assert.rejects(
    Promise.resolve().then(() => validateAndBindPublicReview({
      ...input,
      targetEventId: taskId,
      decision: "PASS",
    })),
    /not a RESULT/u,
  );
  await assert.rejects(
    assertReviewSourceCommitTrusted("f".repeat(40), PROJECT_ROOT),
    /trusted HEAD history/u,
  );
  const changedManifest = structuredClone(input.manifest);
  changedManifest.tasks.find(task => task.id === input.report.events.find(event => event.event_id === input.targetEventId).task_id)
    .acceptance[0] = "unbound acceptance criterion";
  await assert.rejects(
    Promise.resolve().then(() => validateAndBindPublicReview({
      ...input,
      manifest: changedManifest,
      decision: "PASS",
    })),
    /does not bind the checked-in task manifest/u,
  );
});

test("requires the exact public snapshot bytes to coexist on trusted HEAD history", async () => {
  const input = await fixture();
  const reportText = await readFile(path.join(PROJECT_ROOT, "public/data/report.json"), "utf8");
  const statusText = await readFile(path.join(PROJECT_ROOT, "public/data/status.json"), "utf8");
  const evidenceCommit = await assertReviewSnapshotTrusted({
    reportText,
    statusText,
    eventsContent: input.eventsContent,
    sourceCommit: input.status.source_commit,
    repositoryRoot: PROJECT_ROOT,
  });
  assert.match(evidenceCommit, /^[0-9a-f]{40}$/u);
  await assert.rejects(
    assertReviewSnapshotTrusted({
      reportText: `${reportText} `,
      statusText,
      eventsContent: input.eventsContent,
      sourceCommit: input.status.source_commit,
      repositoryRoot: PROJECT_ROOT,
    }),
    /do not exist together/u,
  );
});

test("prepares a cross-key REVIEW without exposing signed material in its summary", async () => {
  const context = await boundContext();
  const key = privatePem();
  const prepared = prepareSignedReview({ context, roomData: emptyRoom(), privateKeyPem: key, now: context.now ?? new Date(context.report.generated_at) });
  assert(prepared.created);
  assert.equal(prepared.created.payload.type, "REVIEW");
  assert.deepEqual(prepared.created.payload.parent_event_ids, [context.target.event_id]);
  assert.equal(prepared.created.payload.content_sha256, context.target.payload.content_sha256);
  assert.equal(prepared.created.payload.review.verdict, "PASS");
  const summary = publicReviewSummary({ context, prepared, action: "would_post", dryRun: true });
  const serialized = JSON.stringify(summary);
  assert.equal(summary.target.task_event_id, context.task.event_id);
  assert.equal(summary.target.content_sha256, context.target.payload.content_sha256);
  assert.equal(summary.dry_run, true);
  assert(!serialized.includes(prepared.created.envelope));
  assert(!/envelope|signature|private[_-]?key|\bsig\b/iu.test(serialized));
});

test("refuses a self-review and suppresses an identical observed review", async () => {
  const context = await boundContext();
  const key = privatePem();
  const first = prepareSignedReview({ context, roomData: emptyRoom(), privateKeyPem: key, now: new Date(context.report.generated_at) });
  const selfContext = structuredClone(context);
  selfContext.target.payload.did = first.reviewerDid;
  assert.throws(
    () => prepareSignedReview({ context: selfContext, roomData: emptyRoom(), privateKeyPem: key, now: new Date(context.report.generated_at) }),
    /different from the RESULT author/u,
  );
  const duplicate = prepareSignedReview({
    context,
    roomData: roomWithEvent(first.created),
    privateKeyPem: key,
    now: new Date(Date.parse(context.report.generated_at) + 1_000),
  });
  assert.equal(duplicate.created, null);
  assert.equal(duplicate.duplicate.event_id, first.created.event_id);
});

test("does not suppress against a structurally valid REVIEW with the wrong content hash", async () => {
  const context = await boundContext();
  const key = privatePem();
  const now = new Date(context.report.generated_at);
  const valid = prepareSignedReview({ context, roomData: emptyRoom(), privateKeyPem: key, now });
  const invalid = createEnvelope({
    ...valid.created.payload,
    content_sha256: "0".repeat(64),
  }, key, contextProtocolOptions(context));
  const prepared = prepareSignedReview({
    context,
    roomData: roomWithEvent(invalid),
    privateKeyPem: key,
    now: new Date(now.getTime() + 1_000),
  });
  assert(prepared.created);
  assert.equal(prepared.duplicate, null);
  assert.notEqual(prepared.created.event_id, invalid.event_id);
});

test("a newer valid REJECT supersedes an older PASS for duplicate suppression", async () => {
  const passContext = await boundContext("PASS");
  const rejectContext = await boundContext("FAIL");
  const key = privatePem();
  const firstTime = new Date(passContext.report.generated_at);
  const pass = prepareSignedReview({
    context: passContext,
    roomData: emptyRoom(),
    privateKeyPem: key,
    now: firstTime,
  });
  const reject = prepareSignedReview({
    context: rejectContext,
    roomData: roomWithEvent(pass.created),
    privateKeyPem: key,
    now: new Date(firstTime.getTime() + 1_000),
  });
  assert(reject.created);
  assert.equal(reject.created.payload.review.verdict, "REJECT");
  const requestedPass = prepareSignedReview({
    context: passContext,
    roomData: roomWithEvents([pass.created, reject.created]),
    privateKeyPem: key,
    now: new Date(firstTime.getTime() + 2_000),
  });
  assert(requestedPass.created);
  assert.equal(requestedPass.duplicate, null);
  assert.equal(requestedPass.created.payload.review.verdict, "PASS");
});

test("read-back rejects a REVIEW outside the event window or before its target", async () => {
  const context = await boundContext();
  const key = privatePem();
  const prepared = prepareSignedReview({
    context,
    roomData: emptyRoom(),
    privateKeyPem: key,
    now: new Date(context.report.generated_at),
  });
  const wrongContent = createEnvelope({
    ...prepared.created.payload,
    content_sha256: "0".repeat(64),
  }, key, contextProtocolOptions(context));
  assert.equal(findValidObservedReview({
    context,
    roomData: roomWithEvent(wrongContent),
    eventId: wrongContent.event_id,
    observedAt: new Date(context.report.generated_at),
  }), null);
  const afterWindow = new Date(Date.parse(context.config.ends_at) + 1_000).toISOString();
  assert.equal(findValidObservedReview({
    context,
    roomData: roomWithEvents([prepared.created], { sourceTimes: [afterWindow] }),
    eventId: prepared.created.event_id,
    observedAt: afterWindow,
  }), null);
  assert.equal(findValidObservedReview({
    context,
    roomData: roomWithEvents([prepared.created], {
      sourceTimes: [new Date(Date.parse(context.target.source_ts) - 1_000).toISOString()],
    }),
    eventId: prepared.created.event_id,
    observedAt: new Date(context.report.generated_at),
  }), null);
});

test("chooses a bounded monotonic transport-safe nonce", async () => {
  const context = await boundContext("FAIL");
  const key = privatePem();
  const seed = prepareSignedReview({ context, roomData: emptyRoom(), privateKeyPem: key, now: new Date(context.report.generated_at) });
  const priorNonce = Number(seed.created.payload.nonce) + 50;
  const room = {
    room: "swarmproof-48-e463",
    count: 1,
    first_seq: 20,
    last_seq: 20,
    messages: [{ seq: 20, from: seed.reviewerDid, nonce: priorNonce, text: "ordinary", ts: context.report.generated_at }],
  };
  const next = prepareSignedReview({ context, roomData: room, privateKeyPem: key, now: new Date(context.report.generated_at) });
  assert.equal(Number(next.created.payload.nonce), priorNonce + 1);
  assert(Number(next.created.payload.nonce) <= Number.MAX_SAFE_INTEGER);
  assert.equal(next.created.payload.review.verdict, "REJECT");
});

test("reads only owner-only regular PEM files and refuses symlinks", async () => {
  const directory = await mkdtemp(path.join(tmpdir(), "swarmproof-review-key-"));
  try {
    const keyPath = path.join(directory, "reviewer.pem");
    const linkPath = path.join(directory, "reviewer-link.pem");
    const pem = privatePem();
    await writeFile(keyPath, pem, { mode: 0o600 });
    assert.equal(await readSecureReviewKey(keyPath), pem);
    await chmod(keyPath, 0o644);
    await assert.rejects(readSecureReviewKey(keyPath), /deny group and other access/u);
    await chmod(keyPath, 0o600);
    await symlink(keyPath, linkPath);
    await assert.rejects(readSecureReviewKey(linkPath), /opened safely/u);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("fetches only the three fixed public documents with bounded GET requests", async () => {
  const input = await fixture();
  const calls = [];
  const bodies = new Map([
    ["/data/report.json", JSON.stringify(input.report)],
    ["/data/status.json", JSON.stringify(input.status)],
    ["/data/events.jsonl", input.eventsContent],
  ]);
  const fetchImpl = async (url, options) => {
    const parsed = new URL(url);
    calls.push({ parsed, options });
    return new Response(bodies.get(parsed.pathname), { status: 200 });
  };
  const fetched = await fetchPublicReviewDocuments({
    fetchImpl,
    publicOrigin: "https://fixture.invalid/",
    cacheBust: 123,
  });
  assert.equal(fetched.status.report_sha256, input.status.report_sha256);
  assert.deepEqual(calls.map(call => call.parsed.pathname).sort(), [
    "/data/events.jsonl",
    "/data/report.json",
    "/data/status.json",
  ]);
  for (const call of calls) {
    assert.equal(call.options.method, "GET");
    assert.equal(call.options.redirect, "error");
    assert.equal(call.parsed.origin, "https://fixture.invalid");
    assert.equal(call.parsed.searchParams.get("n"), "123");
  }
  await assert.rejects(
    fetchPublicReviewDocuments({ fetchImpl, publicOrigin: "http://fixture.invalid/" }),
    /Public origin is invalid/u,
  );
});

test("validates exact live-room sequence metadata", async () => {
  const response = emptyRoom();
  const fetchImpl = async () => new Response(JSON.stringify(response), { status: 200 });
  assert.deepEqual(await fetchReviewRoom({
    fetchImpl,
    technocoreOrigin: "https://fixture.invalid/",
    cacheBust: 123,
  }), response);
  const invalidFetch = async () => new Response(JSON.stringify({ ...response, count: 1 }), { status: 200 });
  await assert.rejects(
    fetchReviewRoom({ fetchImpl: invalidFetch, technocoreOrigin: "https://fixture.invalid/" }),
    /response count is invalid/u,
  );
});

test("POST signs the fixed room transport tuple and requires read-back", async () => {
  const context = await boundContext();
  const key = privatePem();
  const prepared = prepareSignedReview({ context, roomData: emptyRoom(), privateKeyPem: key, now: new Date(context.report.generated_at) });
  let postedBody;
  const fetchImpl = async (url, options) => {
    if (options.method === "POST") {
      postedBody = JSON.parse(options.body);
      return new Response("{}", { status: 200 });
    }
    return new Response(JSON.stringify(roomWithEvent(prepared.created)), { status: 200 });
  };
  const observed = await postSignedReview({
    context,
    prepared,
    privateKeyPem: key,
    fetchImpl,
    technocoreOrigin: "https://fixture.invalid/",
  });
  assert.equal(observed.event_id, prepared.created.event_id);
  assert.equal(postedBody.did, prepared.reviewerDid);
  assert.equal(postedBody.nonce, prepared.created.payload.nonce);
  assert.equal(postedBody.text, prepared.created.envelope);
  assert(verifyUtf8(
    prepared.reviewerDid,
    `${context.config.build_room}|${postedBody.nonce}|${postedBody.text}`,
    Buffer.from(postedBody.sig, "base64url"),
  ));
});

test("review CLI requires an explicit post confirmation before any network access", async () => {
  const run = arguments_ => executeFile(process.execPath, [CLI, ...arguments_], {
    cwd: PROJECT_ROOT,
    encoding: "utf8",
  });
  await assert.rejects(
    run(["review", "--target", "a".repeat(64), "--verdict", "PASS", "--key", "/missing", "--post"]),
    error => error.code === 1 && /Posting requires --confirm/u.test(error.stderr),
  );
  await assert.rejects(
    run(["review", "--target", "a".repeat(64), "--verdict", "PASS", "--key", "/missing", "--confirm", "swarmproof-48-e463"]),
    error => error.code === 1 && /only accepted with --post/u.test(error.stderr),
  );
  await assert.rejects(
    run(["review", "--target", "a".repeat(64), "--verdict", "PASS", "--key", "/missing", "--post", "--dry-run", "--confirm", "swarmproof-48-e463"]),
    error => error.code === 1 && /cannot be combined/u.test(error.stderr),
  );
});
