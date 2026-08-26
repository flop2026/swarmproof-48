import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import {
  deploymentReadbackMatches,
  LOCAL_FALLBACK_POLICY,
  localFallbackEndpoints,
  statusesMatchExactly,
  validateActionsSnapshotGate,
  validateFallbackConfig,
  validatePublicFallbackStatus,
  validateSnapshotPaths,
  validateSshOrigin,
} from "../lib/local-snapshot-fallback.mjs";
import { runLocalSnapshotFallback } from "../scripts/local-snapshot-fallback.mjs";

const executeFile = promisify(execFile);

const RUNNER = fileURLToPath(new URL("../scripts/local-snapshot-fallback.mjs", import.meta.url));
const RUNBOOK = fileURLToPath(new URL("../LOCAL-SNAPSHOT-FALLBACK.md", import.meta.url));
const PLIST = fileURLToPath(new URL(
  "../ops/org.swarmproof.local-snapshot-fallback.plist.example",
  import.meta.url,
));

function statusFixture(overrides = {}) {
  return {
    schema: "swarmproof-status-v1",
    state: "active",
    generated_at: "2026-08-26T08:45:00.000Z",
    starts_at: "2026-08-26T00:00:00.000Z",
    ends_at: "2026-08-28T00:00:00.000Z",
    report_sha256: "a".repeat(64),
    audit_core_sha256: "b".repeat(64),
    snapshot_manifest_sha256: "c".repeat(64),
    source_commit: "d".repeat(40),
    signing_keys: 3,
    reproducible_artifacts: 2,
    cross_key_reviews: 1,
    accepted_results: 1,
    stale_after_seconds: 4 * 60 * 60,
    ...overrides,
  };
}

function actionRun(overrides = {}) {
  return {
    id: 123,
    head_branch: "main",
    head_sha: "e".repeat(40),
    event: "schedule",
    status: "completed",
    conclusion: "failure",
    created_at: "2026-08-26T11:00:00.000Z",
    updated_at: "2026-08-26T11:30:00.000Z",
    ...overrides,
  };
}

function responseFor(url, value, options = {}) {
  const response = new Response(JSON.stringify(value), {
    status: options.status ?? 200,
    headers: {
      "content-type": "application/json",
      ...options.headers,
    },
  });
  Object.defineProperty(response, "url", { value: String(url) });
  return response;
}

async function temporaryMainRepository(t) {
  const root = await mkdtemp(path.join(tmpdir(), "swarmproof-fallback-test-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  await executeFile("/usr/bin/git", ["init", "-b", "main"], { cwd: root });
  await Promise.all([
    writeFile(path.join(root, ".nvmrc"), `${process.versions.node}\n`, "utf8"),
    writeFile(path.join(root, "seed.txt"), "fixture\n", "utf8"),
  ]);
  await executeFile("/usr/bin/git", ["add", ".nvmrc", "seed.txt"], { cwd: root });
  await executeFile("/usr/bin/git", [
    "-c", "user.name=SwarmProof Coordinator",
    "-c", "user.email=321255904+flop2026@users.noreply.github.com",
    "commit", "-m", "test fixture",
  ], { cwd: root });
  return root;
}

test("fallback starts at 3h15 and retains 45 minutes before active staleness", () => {
  assert.equal(LOCAL_FALLBACK_POLICY.minimumStatusAgeSeconds, 3 * 60 * 60 + 15 * 60);
  const status = statusFixture();
  const early = validatePublicFallbackStatus(status, new Date("2026-08-26T11:59:59.999Z"));
  assert.equal(early.eligible, false);
  assert.equal(early.finalizationDue, false);

  const eligible = validatePublicFallbackStatus(status, new Date("2026-08-26T12:00:00.000Z"));
  assert.equal(eligible.eligible, true);
  assert.equal(eligible.secondsUntilStale, 45 * 60);
});

test("elapsed event boundary prioritizes final drain without waiting for the age gate", () => {
  const status = statusFixture({
    generated_at: "2026-08-27T23:55:00.000Z",
    ends_at: "2026-08-28T00:00:00.000Z",
  });
  const result = validatePublicFallbackStatus(status, new Date("2026-08-28T00:00:00.000Z"));
  assert.equal(result.ageSeconds, 5 * 60);
  assert.equal(result.finalizationDue, true);
  assert.equal(result.eligible, true);
});

test("public gate rejects schema drift, future timestamps, and changed active freshness", () => {
  const now = new Date("2026-08-26T12:00:00.000Z");
  assert.throws(
    () => validatePublicFallbackStatus(statusFixture({ extra: true }), now),
    /field set/u,
  );
  assert.throws(
    () => validatePublicFallbackStatus(statusFixture({ generated_at: "2026-08-26T12:05:00.001Z" }), now),
    /future/u,
  );
  assert.throws(
    () => validatePublicFallbackStatus(statusFixture({ stale_after_seconds: 14_401 }), now),
    /freshness policy/u,
  );
  assert.throws(
    () => validatePublicFallbackStatus(statusFixture({ generated_at: "2026-08-26T08:45:00Z" }), now),
    /generation time is invalid/u,
  );
});

test("local config must describe the exact active public event", () => {
  const status = statusFixture();
  const config = {
    repository: "flop2026/swarmproof-48",
    state: "active",
    starts_at: status.starts_at,
    ends_at: status.ends_at,
  };
  assert.doesNotThrow(() => validateFallbackConfig(config, status));
  assert.throws(() => validateFallbackConfig({ ...config, repository: "other/project" }, status), /allowlisted/u);
  assert.throws(() => validateFallbackConfig({ ...config, ends_at: "2026-08-29T00:00:00.000Z" }, status), /end times/u);
});

test("Actions gate requires every returned run complete and latest run quiet for 30 minutes", () => {
  const now = new Date("2026-08-26T12:00:00.000Z");
  const accepted = validateActionsSnapshotGate({ workflow_runs: [actionRun()] }, { now });
  assert.equal(accepted.quietSeconds, 30 * 60);

  assert.throws(
    () => validateActionsSnapshotGate({
      workflow_runs: [actionRun({ updated_at: "2026-08-26T11:30:00.001Z" })],
    }, { now }),
    /quiet long enough/u,
  );
  assert.throws(
    () => validateActionsSnapshotGate({
      workflow_runs: [actionRun(), actionRun({ id: 124, status: "queued", conclusion: null })],
    }, { now }),
    /may still publish/u,
  );
});

test("Actions gate accepts GitHub API UTC seconds and canonical UTC milliseconds", () => {
  const apiFixture = {
    workflow_runs: [{
      id: 173849201,
      head_branch: "main",
      head_sha: "e".repeat(40),
      event: "schedule",
      status: "completed",
      conclusion: "failure",
      created_at: "2026-08-26T14:00:00Z",
      updated_at: "2026-08-26T14:29:20Z",
    }],
  };
  const result = validateActionsSnapshotGate(apiFixture, {
    now: new Date("2026-08-26T15:00:00.000Z"),
  });
  assert.equal(result.quietSeconds, 30 * 60 + 40);
  assert.equal(result.observation.updated_at, "2026-08-26T14:29:20Z");

  assert.doesNotThrow(() => validateActionsSnapshotGate({
    workflow_runs: [actionRun()],
  }, { now: new Date("2026-08-26T12:00:00.000Z") }));
  for (const updated_at of [
    "2026-08-26T14:29:20.0Z",
    "2026-08-26T14:29:20.0000Z",
    "2026-08-26T21:29:20+07:00",
  ]) {
    assert.throws(() => validateActionsSnapshotGate({
      workflow_runs: [actionRun({ updated_at })],
    }, { now: new Date("2026-08-26T15:00:00.000Z") }), /updated_at is invalid/u);
  }
});

test("pre-push Actions observation must be byte-semantically unchanged", () => {
  const firstNow = new Date("2026-08-26T12:00:00.000Z");
  const first = validateActionsSnapshotGate({ workflow_runs: [actionRun()] }, { now: firstNow });
  assert.doesNotThrow(() => validateActionsSnapshotGate(
    { workflow_runs: [actionRun()] },
    { now: new Date("2026-08-26T12:10:00.000Z"), previous: first.observation },
  ));
  assert.throws(
    () => validateActionsSnapshotGate(
      { workflow_runs: [actionRun({ id: 125, updated_at: "2026-08-26T11:40:00.000Z" })] },
      { now: new Date("2026-08-26T12:10:00.000Z"), previous: first.observation },
    ),
    /progressed/u,
  );
});

test("network gates use only fixed Cloudflare and GitHub API endpoints", () => {
  const endpoints = localFallbackEndpoints(LOCAL_FALLBACK_POLICY, 123);
  assert.equal(endpoints.status, "https://swarmproof-48-e463.pages.dev/data/status.json?n=123");
  assert.equal(
    endpoints.actions,
    "https://api.github.com/repos/flop2026/swarmproof-48/actions/workflows/snapshot.yml/runs?branch=main&per_page=5",
  );
});

test("only the exact SSH origin is accepted", () => {
  const githubIdentity = ["git", "github.com"].join("@");
  assert.equal(
    validateSshOrigin(`${githubIdentity}:flop2026/swarmproof-48.git`),
    "flop2026/swarmproof-48",
  );
  assert.equal(
    validateSshOrigin(`ssh://${githubIdentity}/flop2026/swarmproof-48.git`),
    "flop2026/swarmproof-48",
  );
  for (const url of [
    "https://github.com/flop2026/swarmproof-48.git",
    `ssh://${["other", "github.com"].join("@")}/flop2026/swarmproof-48.git`,
    `ssh://${["git", "github.example"].join("@")}/flop2026/swarmproof-48.git`,
    `${githubIdentity}:flop2026/other.git`,
  ]) assert.throws(() => validateSshOrigin(url));
});

test("snapshot mutation allowlist is exact", () => {
  assert.deepEqual(validateSnapshotPaths([
    "public/data/status.json",
    "config/event.json",
    "public/data/report.json",
  ]), ["config/event.json", "public/data/report.json", "public/data/status.json"]);
  assert.throws(() => validateSnapshotPaths(["package.json"]), /outside/u);
  assert.throws(() => validateSnapshotPaths(["public/data/../index.html"]), /outside/u);
  assert.throws(() => validateSnapshotPaths(["public/data/status.json", "public/data/status.json"]), /duplicate/u);
});

test("status races and exact deployment read-back are fail closed", () => {
  const initial = statusFixture();
  assert.equal(statusesMatchExactly(initial, structuredClone(initial)), true);
  assert.equal(statusesMatchExactly(initial, { ...initial, generated_at: "2026-08-26T08:46:00.000Z" }), false);
  assert.equal(deploymentReadbackMatches(initial, structuredClone(initial)), true);
  assert.equal(deploymentReadbackMatches(initial, { ...initial, report_sha256: "f".repeat(64) }), false);

  const complete = statusFixture({ state: "complete", stale_after_seconds: 90_000 });
  assert.equal(deploymentReadbackMatches(complete, structuredClone(complete)), true);
});

test("runner encodes commit-before-validation, double gates, one push, and one unknown-outcome lookup", async () => {
  const source = await readFile(RUNNER, "utf8");
  const snapshot = source.indexOf("async function snapshotAndCommit");
  const commit = source.indexOf('"commit",', snapshot);
  const validation = source.indexOf("const validationSteps", commit);
  const publicRecheck = source.indexOf("publicBeforePush", validation);
  const actionsRecheck = source.indexOf("actions.observation", publicRecheck);
  const remoteRecheck = source.indexOf("verifyRemoteTipUnchanged", actionsRecheck);
  const push = source.indexOf("pushCandidateOnce", remoteRecheck);
  const readback = source.indexOf("verifyCloudflareReadback", push);
  assert.ok(snapshot >= 0 && snapshot < commit);
  assert.ok(commit < validation && validation < publicRecheck);
  assert.ok(publicRecheck < actionsRecheck && actionsRecheck < remoteRecheck);
  assert.ok(remoteRecheck < push && push < readback);

  assert.equal((source.match(/\[\s*"push",/gu) ?? []).length, 1);
  assert.equal((source.match(/"ls-remote"/gu) ?? []).length, 1);
  assert.doesNotMatch(source, /force-with-lease|force push|--force/u);
  assert.match(source, /SWARMPROOF_CHECK_HISTORY: "1"/u);
  assert.match(source, /core\.hooksPath=\/dev\/null/u);
  assert.match(source, /commit\.gpgSign=false/u);
  assert.match(source, /321255904\+flop2026@users\.noreply\.github\.com/u);
  assert.match(source, /SWARMPROOF_NETWORK: finalDrain \? "1" : "0"/u);
  assert.match(source, /-F\/dev\/null/u);
  assert.match(source, /-oIdentityFile=none/u);
  assert.doesNotMatch(source, /\.\.\.process\.env/u);
});

test("runbook and LaunchAgent remain an unloaded, placeholder-only proposal", async () => {
  const [runbook, plist] = await Promise.all([readFile(RUNBOOK, "utf8"), readFile(PLIST, "utf8")]);
  assert.match(runbook, /best-effort/u);
  assert.match(runbook, /3 hours 15 minutes/u);
  assert.match(runbook, /30 minutes/u);
  assert.match(runbook, /not installed or loaded/u);
  assert.match(plist, /__NODE_BINARY__/u);
  assert.match(plist, /__REPOSITORY_ROOT__/u);
  assert.match(plist, /__STATE_DIRECTORY__/u);
  assert.match(plist, /<integer>600<\/integer>/u);
  assert.doesNotMatch(plist, /SWARMPROOF_NETWORK/u);
  assert.doesNotMatch(plist, /\/tmp\//u);
  assert.doesNotMatch(plist, /SSH_AUTH_SOCK|BEGIN .*PRIVATE KEY/u);
});

test("fresh status is a read-only no-op before Actions, SSH, or snapshot work", async t => {
  const root = await temporaryMainRepository(t);
  const now = new Date("2026-08-26T12:00:00.000Z");
  const fresh = statusFixture({ generated_at: "2026-08-26T11:55:00.000Z" });
  let fetches = 0;
  const result = await runLocalSnapshotFallback({
    cwd: root,
    now,
    fetchImpl: async url => {
      fetches += 1;
      return responseFor(url, fresh);
    },
  });
  assert.deepEqual(result, {
    action: "skipped",
    reason: "public_status_fresh",
    status_age_seconds: 5 * 60,
  });
  assert.equal(fetches, 1);
  assert.equal((await executeFile("/usr/bin/git", ["status", "--porcelain"], { cwd: root })).stdout, "");
});

test("dirty checkout refuses before making any network request", async t => {
  const root = await temporaryMainRepository(t);
  await writeFile(path.join(root, "untracked.txt"), "do not touch\n", "utf8");
  let fetches = 0;
  await assert.rejects(
    runLocalSnapshotFallback({
      cwd: root,
      fetchImpl: async () => {
        fetches += 1;
        throw new Error("must not fetch");
      },
    }),
    error => error?.code === "dirty_worktree",
  );
  assert.equal(fetches, 0);
  assert.equal(await readFile(path.join(root, "untracked.txt"), "utf8"), "do not touch\n");
});

test("a malformed eligible gate creates owner-only persistent backoff", async t => {
  const root = await temporaryMainRepository(t);
  const now = new Date();
  const generatedAt = new Date(now.getTime() - 4 * 60 * 60 * 1000).toISOString();
  const invalid = statusFixture({ generated_at: generatedAt, extra: true });
  let fetches = 0;
  await assert.rejects(
    runLocalSnapshotFallback({
      cwd: root,
      now,
      fetchImpl: async url => {
        fetches += 1;
        return responseFor(url, invalid);
      },
    }),
    error => error?.code === "public_status_invalid",
  );
  assert.equal(fetches, 1);

  const skipped = await runLocalSnapshotFallback({
    cwd: root,
    now,
    fetchImpl: async () => {
      throw new Error("backoff must precede fetch");
    },
  });
  assert.deepEqual(skipped, { action: "skipped", reason: "persistent_backoff" });
  const statePath = path.join(root, ".git", "swarmproof-local-snapshot-fallback.backoff.json");
  const state = JSON.parse(await readFile(statePath, "utf8"));
  assert.equal(state.schema, "swarmproof-local-fallback-backoff-v1");
  assert.equal(state.failure_code, "public_status_invalid");
  assert.equal(state.attempts, 1);
  assert.equal((await stat(statePath)).mode & 0o777, 0o600);
});
