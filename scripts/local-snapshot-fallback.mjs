#!/usr/bin/env node

import { spawn } from "node:child_process";
import { lstat, open, readFile, realpath, rename, rm } from "node:fs/promises";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { acquireRepositoryLock } from "../lib/repository-lock.mjs";
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

const GIT = "/usr/bin/git";
const SSH_COMMAND = [
  "/usr/bin/ssh",
  "-F/dev/null",
  "-oBatchMode=yes",
  "-oConnectTimeout=10",
  "-oConnectionAttempts=1",
  "-oServerAliveInterval=5",
  "-oServerAliveCountMax=1",
  "-oStrictHostKeyChecking=yes",
  "-oCanonicalizeHostname=no",
  "-oProxyCommand=none",
  "-oHostname=github.com",
  "-oHostKeyAlias=github.com",
  "-oUser=git",
  "-oIdentityFile=none",
  "-oAddKeysToAgent=no",
  "-oPasswordAuthentication=no",
  "-oKbdInteractiveAuthentication=no",
  "-oPreferredAuthentications=publickey",
  "-p22",
].join(" ");
const MAXIMUM_COMMAND_OUTPUT_BYTES = 2 * 1024 * 1024;
const BACKOFF_SCHEMA = "swarmproof-local-fallback-backoff-v1";
const BACKOFF_FILE = "swarmproof-local-snapshot-fallback.backoff.json";
const LOCK_FILE = "swarmproof-local-snapshot-fallback.lock";
const COMMIT_RE = /^[0-9a-f]{40}$/u;
const FAILURE_CODE_RE = /^[a-z0-9_]{1,64}$/u;
const SAFE_HOME_RE = /^\/(?!$)[^\u0000-\u001f\u007f]{1,1023}$/u;

class FallbackFailure extends Error {
  constructor(code, options = {}) {
    super(code);
    this.name = "FallbackFailure";
    this.code = code;
    this.backoffSeconds = options.backoffSeconds ?? 30 * 60;
  }
}

class CommandFailure extends Error {
  constructor(label, result) {
    super(label);
    this.name = "CommandFailure";
    this.label = label;
    this.result = result;
  }
}

function fail(code, options) {
  throw new FallbackFailure(code, options);
}

function parseNulList(value) {
  if (value === "") return [];
  const values = value.split("\0");
  if (values.at(-1) === "") values.pop();
  return values;
}

function parseLastJsonLine(value, code) {
  const lines = value.split("\n").map(line => line.trim()).filter(Boolean);
  if (lines.length === 0) fail(code);
  try {
    const parsed = JSON.parse(lines.at(-1));
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) fail(code);
    return parsed;
  } catch {
    fail(code);
  }
}

function appendBounded(chunks, chunk, state, child) {
  state.bytes += chunk.byteLength;
  if (state.bytes > MAXIMUM_COMMAND_OUTPUT_BYTES) {
    state.overflow = true;
    terminateProcessGroup(child, "SIGTERM");
    if (!state.killScheduled) {
      state.killScheduled = true;
      setTimeout(() => terminateProcessGroup(child, "SIGKILL"), 2_000);
    }
    return;
  }
  chunks.push(Buffer.from(chunk));
}

function terminateProcessGroup(child, signal) {
  if (child.pid === undefined) return;
  try {
    if (process.platform === "win32") child.kill(signal);
    else process.kill(-child.pid, signal);
  } catch {
    // The bounded child already exited.
  }
}

async function executeBounded(file, args, options = {}) {
  const timeoutMs = options.timeoutMs ?? 60_000;
  return await new Promise((resolve, reject) => {
    const child = spawn(file, args, {
      cwd: options.cwd,
      env: options.env,
      detached: process.platform !== "win32",
      shell: false,
      stdio: ["ignore", "pipe", "pipe"],
    });
    const stdout = [];
    const stderr = [];
    const state = { bytes: 0, overflow: false, timedOut: false, killScheduled: false };
    let killTimer;
    const timeout = setTimeout(() => {
      state.timedOut = true;
      terminateProcessGroup(child, "SIGTERM");
      killTimer = setTimeout(() => terminateProcessGroup(child, "SIGKILL"), 2_000);
    }, timeoutMs);
    child.stdout.on("data", chunk => appendBounded(stdout, chunk, state, child));
    child.stderr.on("data", chunk => appendBounded(stderr, chunk, state, child));
    child.once("error", error => {
      clearTimeout(timeout);
      if (killTimer) clearTimeout(killTimer);
      reject(error);
    });
    child.once("close", (code, signal) => {
      clearTimeout(timeout);
      if (killTimer) clearTimeout(killTimer);
      resolve({
        code,
        signal,
        timedOut: state.timedOut,
        overflow: state.overflow,
        stdout: Buffer.concat(stdout).toString("utf8"),
        stderr: Buffer.concat(stderr).toString("utf8"),
      });
    });
  });
}

function childEnvironment(extra = {}, options = {}) {
  const environment = {
    PATH: "/usr/bin:/bin",
    TZ: "UTC",
    LANG: "C",
    LC_ALL: "C",
    GIT_CONFIG_NOSYSTEM: "1",
    GIT_CONFIG_GLOBAL: "/dev/null",
    GIT_TERMINAL_PROMPT: "0",
    GCM_INTERACTIVE: "never",
    ...extra,
  };
  if (typeof process.env.TMPDIR === "string" && SAFE_HOME_RE.test(process.env.TMPDIR)) {
    environment.TMPDIR = process.env.TMPDIR;
  }
  if (options.ssh) {
    if (typeof process.env.HOME !== "string" || !SAFE_HOME_RE.test(process.env.HOME)) {
      fail("ssh_home_unavailable");
    }
    if (
      typeof process.env.SSH_AUTH_SOCK !== "string"
      || !SAFE_HOME_RE.test(process.env.SSH_AUTH_SOCK)
    ) fail("ssh_agent_unavailable", { backoffSeconds: 10 * 60 });
    environment.HOME = process.env.HOME;
    environment.SSH_AUTH_SOCK = process.env.SSH_AUTH_SOCK;
    environment.GIT_SSH_COMMAND = SSH_COMMAND;
  }
  return environment;
}

async function runCommand(file, args, options = {}) {
  const result = await executeBounded(file, args, options).catch(() => {
    throw new CommandFailure(options.label ?? "command", {
      code: null,
      timedOut: false,
      overflow: false,
      stdout: "",
      stderr: "",
    });
  });
  if (result.code !== 0 || result.timedOut || result.overflow) {
    throw new CommandFailure(options.label ?? "command", result);
  }
  return result.stdout;
}

async function git(args, options = {}) {
  return await runCommand(GIT, ["-c", "core.hooksPath=/dev/null", ...args], {
    ...options,
    env: options.env ?? childEnvironment({}, { ssh: options.ssh === true }),
    label: options.label ?? "git",
  });
}

async function gitResult(args, options = {}) {
  return await executeBounded(GIT, ["-c", "core.hooksPath=/dev/null", ...args], {
    ...options,
    env: options.env ?? childEnvironment({}, { ssh: options.ssh === true }),
  });
}

async function readBoundedResponse(response, maximumBytes) {
  const declared = response.headers.get("content-length");
  if (declared !== null && (!/^\d+$/u.test(declared) || Number(declared) > maximumBytes)) {
    fail("network_response_oversized", { backoffSeconds: 10 * 60 });
  }
  if (response.body === null) fail("network_response_missing", { backoffSeconds: 10 * 60 });
  const reader = response.body.getReader();
  const chunks = [];
  let bytes = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      bytes += value.byteLength;
      if (bytes > maximumBytes) fail("network_response_oversized", { backoffSeconds: 10 * 60 });
      chunks.push(Buffer.from(value));
    }
  } catch (error) {
    await reader.cancel().catch(() => {});
    throw error;
  }
  return Buffer.concat(chunks, bytes).toString("utf8");
}

async function fetchJsonExact(url, options = {}) {
  const expected = new URL(url);
  const allowedOrigin = options.allowedOrigin;
  if (expected.origin !== allowedOrigin) fail("network_origin_forbidden");
  let response;
  try {
    response = await (options.fetchImpl ?? fetch)(expected, {
      redirect: "error",
      cache: "no-store",
      headers: {
        accept: "application/json",
        "cache-control": "no-cache",
        "user-agent": "swarmproof-local-snapshot-fallback/1",
      },
      signal: AbortSignal.timeout(options.timeoutMs ?? LOCAL_FALLBACK_POLICY.requestTimeoutMs),
    });
  } catch {
    fail("network_gate_unavailable", { backoffSeconds: 10 * 60 });
  }
  if (response.url !== expected.href) fail("network_redirect_refused", { backoffSeconds: 10 * 60 });
  if (!response.ok) {
    if (response.status === 429) {
      const retryAfter = response.headers.get("retry-after");
      let retrySeconds = Number(retryAfter);
      if (!Number.isFinite(retrySeconds) && retryAfter !== null) {
        retrySeconds = (Date.parse(retryAfter) - Date.now()) / 1000;
      }
      const boundedRetry = Number.isFinite(retrySeconds)
        ? Math.min(Math.max(Math.ceil(retrySeconds), 10 * 60), 60 * 60)
        : 30 * 60;
      fail("network_rate_limited", { backoffSeconds: boundedRetry });
    }
    fail("network_gate_unavailable", { backoffSeconds: 10 * 60 });
  }
  const contentType = response.headers.get("content-type")?.split(";", 1)[0].trim().toLowerCase();
  if (contentType !== "application/json") fail("network_media_type_invalid", { backoffSeconds: 10 * 60 });
  const body = await readBoundedResponse(response, options.maximumBytes);
  try {
    return JSON.parse(body);
  } catch {
    fail("network_json_invalid", { backoffSeconds: 10 * 60 });
  }
}

function backoffRecord(code, now, seconds) {
  return {
    schema: BACKOFF_SCHEMA,
    failure_code: code,
    attempts: 1,
    not_before: new Date(now.getTime() + seconds * 1000).toISOString(),
  };
}

async function readBackoff(file, now) {
  let metadata;
  try {
    metadata = await lstat(file);
  } catch (error) {
    if (error.code === "ENOENT") return null;
    fail("backoff_state_unreadable");
  }
  if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.size > 4 * 1024) {
    fail("backoff_state_unsafe");
  }
  let state;
  try {
    state = JSON.parse(await readFile(file, "utf8"));
  } catch {
    fail("backoff_state_invalid");
  }
  if (
    !state || typeof state !== "object" || Array.isArray(state)
    || Object.keys(state).length !== 4
    || state.schema !== BACKOFF_SCHEMA
    || !FAILURE_CODE_RE.test(state.failure_code ?? "")
    || !Number.isSafeInteger(state.attempts)
    || state.attempts < 1
    || state.attempts > 32
  ) fail("backoff_state_invalid");
  const notBefore = Date.parse(state.not_before);
  if (!Number.isFinite(notBefore) || new Date(notBefore).toISOString() !== state.not_before) {
    fail("backoff_state_invalid");
  }
  return { ...state, active: now.getTime() < notBefore };
}

async function writeBackoff(file, code, now, seconds, previous = null) {
  const attempts = previous?.failure_code === code ? Math.min(previous.attempts + 1, 32) : 1;
  const delaySeconds = Math.min(seconds * (2 ** Math.min(attempts - 1, 5)), 6 * 60 * 60);
  const record = {
    ...backoffRecord(code, now, delaySeconds),
    attempts,
  };
  const temporary = `${file}.tmp-${process.pid}`;
  const handle = await open(temporary, "wx", 0o600);
  try {
    await handle.writeFile(`${JSON.stringify(record)}\n`, "utf8");
    await handle.sync();
  } finally {
    await handle.close();
  }
  await rename(temporary, file);
}

async function clearBackoff(file) {
  await rm(file, { force: true });
}

async function assertCleanRepository(cwd, code = "dirty_worktree") {
  const status = await git(["status", "--porcelain=v1", "-z", "--untracked-files=all"], {
    cwd,
    timeoutMs: 30_000,
    label: "status",
  }).catch(() => fail("git_status_failed"));
  if (status !== "") fail(code);
}

async function changedSnapshotPaths(cwd) {
  const [tracked, untracked] = await Promise.all([
    git(["diff", "--name-only", "-z", "HEAD"], { cwd, timeoutMs: 30_000, label: "diff" }),
    git(["ls-files", "--others", "--exclude-standard", "-z"], {
      cwd,
      timeoutMs: 30_000,
      label: "untracked",
    }),
  ]).catch(() => fail("snapshot_diff_failed"));
  try {
    return validateSnapshotPaths([...new Set([...parseNulList(tracked), ...parseNulList(untracked)])]);
  } catch {
    fail("snapshot_diff_outside_allowlist");
  }
}

async function fetchPublicStatus(now, fetchImpl, sequence) {
  const endpoints = localFallbackEndpoints(LOCAL_FALLBACK_POLICY, now.getTime() + sequence);
  return await fetchJsonExact(endpoints.status, {
    allowedOrigin: LOCAL_FALLBACK_POLICY.publicOrigin,
    maximumBytes: LOCAL_FALLBACK_POLICY.publicStatusMaximumBytes,
    fetchImpl,
  });
}

async function fetchActionsGate(now, fetchImpl, previous) {
  const endpoints = localFallbackEndpoints(LOCAL_FALLBACK_POLICY, now.getTime());
  const payload = await fetchJsonExact(endpoints.actions, {
    allowedOrigin: LOCAL_FALLBACK_POLICY.githubApiOrigin,
    maximumBytes: LOCAL_FALLBACK_POLICY.actionsMaximumBytes,
    fetchImpl,
  });
  try {
    return validateActionsSnapshotGate(payload, {
      now,
      previous,
      policy: LOCAL_FALLBACK_POLICY,
    });
  } catch {
    fail("actions_snapshot_not_quiet", { backoffSeconds: 10 * 60 });
  }
}

async function verifyOrigins(cwd) {
  let fetchUrls;
  let pushUrls;
  try {
    [fetchUrls, pushUrls] = await Promise.all([
      git(["remote", "get-url", "--all", "origin"], { cwd, timeoutMs: 30_000 }),
      git(["remote", "get-url", "--push", "--all", "origin"], { cwd, timeoutMs: 30_000 }),
    ]);
  } catch {
    fail("origin_url_unreadable");
  }
  const fetchList = fetchUrls.trim().split("\n").filter(Boolean);
  const pushList = pushUrls.trim().split("\n").filter(Boolean);
  if (fetchList.length !== 1 || pushList.length !== 1 || fetchList[0] !== pushList[0]) {
    fail("origin_url_ambiguous");
  }
  try {
    validateSshOrigin(fetchList[0]);
  } catch {
    fail("origin_url_forbidden");
  }
}

async function assertSshAgentSocket() {
  childEnvironment({}, { ssh: true });
  let metadata;
  try {
    metadata = await lstat(process.env.SSH_AUTH_SOCK);
  } catch {
    fail("ssh_agent_unavailable", { backoffSeconds: 10 * 60 });
  }
  if (!metadata.isSocket() || metadata.isSymbolicLink()) {
    fail("ssh_agent_socket_unsafe", { backoffSeconds: 10 * 60 });
  }
}

async function fetchAndFastForward(cwd) {
  const sshEnv = childEnvironment({}, { ssh: true });
  await git([
    "fetch",
    "--no-tags",
    "origin",
    "refs/heads/main:refs/remotes/origin/main",
  ], {
    cwd,
    env: sshEnv,
    timeoutMs: 60_000,
    label: "fetch",
  }).catch(() => fail("origin_fetch_failed", { backoffSeconds: 10 * 60 }));

  const head = (await git(["rev-parse", "HEAD"], { cwd, timeoutMs: 30_000 })).trim();
  const remote = (await git(["rev-parse", "refs/remotes/origin/main"], {
    cwd,
    timeoutMs: 30_000,
  })).trim();
  if (!COMMIT_RE.test(head) || !COMMIT_RE.test(remote)) fail("git_commit_invalid");
  const ancestry = await gitResult(["merge-base", "--is-ancestor", head, remote], {
    cwd,
    timeoutMs: 30_000,
  });
  if (ancestry.code !== 0) fail("local_main_not_fast_forward");
  if (head !== remote) {
    await git(["merge", "--ff-only", "--no-edit", remote], {
      cwd,
      timeoutMs: 60_000,
      label: "fast-forward",
    }).catch(() => fail("local_main_fast_forward_failed"));
  }
  await assertCleanRepository(cwd, "worktree_dirty_after_fast_forward");
  const updated = (await git(["rev-parse", "HEAD"], { cwd, timeoutMs: 30_000 })).trim();
  if (updated !== remote) fail("origin_tip_mismatch");
  return remote;
}

async function runNode(cwd, args, options = {}) {
  return await runCommand(process.execPath, args, {
    cwd,
    env: options.env ?? childEnvironment(),
    timeoutMs: options.timeoutMs ?? LOCAL_FALLBACK_POLICY.commandTimeoutMs,
    label: options.label ?? "node",
  });
}

async function snapshotAndCommit(cwd, baseCommit, now) {
  let lifecycle;
  try {
    const output = await runNode(cwd, ["scripts/finalize.mjs", "--check"], {
      timeoutMs: 60_000,
      label: "finalizer-check",
    });
    lifecycle = parseLastJsonLine(output, "lifecycle_check_invalid");
  } catch (error) {
    if (error instanceof FallbackFailure) throw error;
    fail("lifecycle_check_failed");
  }
  if (lifecycle.action === "finalization_recovery_required") fail("finalization_recovery_required");
  const finalDrain = lifecycle.action === "final_drain_required";

  const snapshotEnv = childEnvironment({
    SWARMPROOF_NETWORK: finalDrain ? "1" : "0",
    SWARMPROOF_RETAIN_SKETCHES: "0",
    SWARMPROOF_PACE_MS: "300",
  });
  let snapshot;
  try {
    const output = await runNode(cwd, ["scripts/snapshot.mjs"], {
      env: snapshotEnv,
      label: "snapshot",
    });
    snapshot = parseLastJsonLine(output, "snapshot_output_invalid");
  } catch (error) {
    if (error instanceof FallbackFailure) throw error;
    fail("snapshot_generation_failed", { backoffSeconds: 30 * 60 });
  }
  if (finalDrain && snapshot.action !== "final_drain") fail("final_drain_not_generated");
  if (!finalDrain && !["written", "skipped"].includes(snapshot.action)) fail("snapshot_action_invalid");
  if (finalDrain) {
    await runNode(cwd, ["scripts/finalize.mjs"], { label: "finalizer" })
      .catch(() => fail("finalization_failed", { backoffSeconds: 30 * 60 }));
  }

  const paths = await changedSnapshotPaths(cwd);
  if (paths.length === 0) fail("eligible_snapshot_made_no_change", { backoffSeconds: 10 * 60 });
  await git(["add", "--", "config/event.json", "public/data"], {
    cwd,
    timeoutMs: 30_000,
    label: "stage",
  }).catch(() => fail("snapshot_stage_failed"));
  const staged = validateSnapshotPaths(parseNulList(await git([
    "diff", "--cached", "--name-only", "-z",
  ], { cwd, timeoutMs: 30_000 })));
  if (staged.length === 0 || staged.join("\0") !== paths.join("\0")) fail("snapshot_stage_mismatch");

  const commitEnvironment = childEnvironment({
    GIT_AUTHOR_NAME: "SwarmProof Coordinator",
    GIT_AUTHOR_EMAIL: "321255904+flop2026@users.noreply.github.com",
    GIT_COMMITTER_NAME: "SwarmProof Coordinator",
    GIT_COMMITTER_EMAIL: "321255904+flop2026@users.noreply.github.com",
  });
  await git([
    "-c", "commit.gpgSign=false",
    "-c", "user.useConfigOnly=true",
    "commit",
    "--no-gpg-sign",
    "--no-verify",
    "-m",
    finalDrain ? "event: freeze final evidence snapshot" : "data: emergency local evidence snapshot",
  ], {
    cwd,
    env: commitEnvironment,
    timeoutMs: 60_000,
    label: "commit",
  }).catch(() => fail("snapshot_commit_failed"));
  const candidate = (await git(["rev-parse", "HEAD"], { cwd, timeoutMs: 30_000 })).trim();
  const parent = (await git(["rev-parse", "HEAD^"], { cwd, timeoutMs: 30_000 })).trim();
  if (!COMMIT_RE.test(candidate) || parent !== baseCommit) fail("snapshot_commit_parent_invalid");

  const validationEnv = childEnvironment({ SWARMPROOF_CHECK_HISTORY: "1" });
  const validationSteps = [
    ["node_modules/typescript/bin/tsc", "--noEmit"],
    ["scripts/generate-conformance-vectors.mjs", "--check"],
    ["--test"],
    ["scripts/privacy-audit.mjs"],
  ];
  for (const args of validationSteps) {
    await runNode(cwd, args, {
      env: validationEnv,
      timeoutMs: LOCAL_FALLBACK_POLICY.validationTimeoutMs,
      label: "validation",
    }).catch(() => fail("snapshot_validation_failed", { backoffSeconds: 60 * 60 }));
  }
  if (finalDrain) {
    await runNode(cwd, ["bin/swarmproof.mjs", "verify-report"], {
      env: validationEnv,
      timeoutMs: LOCAL_FALLBACK_POLICY.validationTimeoutMs,
      label: "verify-report",
    }).catch(() => fail("final_report_verification_failed", { backoffSeconds: 60 * 60 }));
  }
  const unchanged = (await git(["rev-parse", "HEAD"], { cwd, timeoutMs: 30_000 })).trim();
  if (unchanged !== candidate) fail("snapshot_commit_changed_during_validation");
  await assertCleanRepository(cwd, "validation_changed_worktree");
  return { candidate, finalDrain, paths };
}

async function readRepositoryJson(cwd, file) {
  try {
    return JSON.parse(await readFile(path.join(cwd, file), "utf8"));
  } catch {
    fail("repository_json_invalid");
  }
}

async function verifyRemoteTipUnchanged(cwd, baseCommit, publicStatus) {
  const sshEnv = childEnvironment({}, { ssh: true });
  await git([
    "fetch",
    "--no-tags",
    "origin",
    "refs/heads/main:refs/remotes/origin/main",
  ], {
    cwd,
    env: sshEnv,
    timeoutMs: 60_000,
    label: "prepush-fetch",
  }).catch(() => fail("prepush_origin_fetch_failed", { backoffSeconds: 10 * 60 }));
  const tip = (await git(["rev-parse", "refs/remotes/origin/main"], {
    cwd,
    timeoutMs: 30_000,
  })).trim();
  if (tip !== baseCommit) fail("origin_main_progressed", { backoffSeconds: 10 * 60 });
  let originStatus;
  try {
    originStatus = JSON.parse(await git([
      "show", "refs/remotes/origin/main:public/data/status.json",
    ], { cwd, timeoutMs: 30_000 }));
  } catch {
    fail("origin_status_invalid");
  }
  if (!statusesMatchExactly(publicStatus, originStatus)) fail("origin_status_differs_from_public");
}

async function resolvePushOnce(cwd, candidate) {
  let output;
  try {
    output = await git(["ls-remote", "--heads", "origin", "refs/heads/main"], {
      cwd,
      ssh: true,
      timeoutMs: 60_000,
      label: "push-readback",
    });
  } catch {
    return false;
  }
  const match = /^([0-9a-f]{40})\trefs\/heads\/main\n?$/u.exec(output);
  return match?.[1] === candidate;
}

async function pushCandidateOnce(cwd, candidate) {
  let result = null;
  try {
    result = await gitResult([
      "push",
      "--porcelain",
      "origin",
      `${candidate}:refs/heads/main`,
    ], {
      cwd,
      env: childEnvironment({}, { ssh: true }),
      timeoutMs: 60_000,
    });
  } catch {
    // A spawn/transport failure can still have an unknown remote outcome.
  }
  if (result?.code === 0 && !result.timedOut && !result.overflow) return "pushed";
  if (await resolvePushOnce(cwd, candidate)) return "confirmed_after_unknown_push";
  fail("push_not_confirmed", { backoffSeconds: 60 * 60 });
}

async function verifyCloudflareReadback(cwd, expected, fetchImpl) {
  const deadline = Date.now() + LOCAL_FALLBACK_POLICY.deploymentTimeoutMs;
  let sequence = 100;
  while (Date.now() < deadline) {
    try {
      const observed = await fetchPublicStatus(new Date(), fetchImpl, sequence);
      if (deploymentReadbackMatches(expected, observed)) return;
    } catch (error) {
      if (error instanceof FallbackFailure && error.code === "network_rate_limited") throw error;
      // A bounded retry may observe the exact deployment later.
    }
    sequence += 1;
    await new Promise(resolve => setTimeout(resolve, 10_000));
  }
  fail("cloudflare_readback_timeout", { backoffSeconds: 60 * 60 });
}

export async function runLocalSnapshotFallback(options = {}) {
  const now = options.now ?? new Date();
  if (!(now instanceof Date) || !Number.isFinite(now.getTime())) fail("clock_invalid");
  const cwd = await realpath(options.cwd ?? process.cwd()).catch(() => fail("repository_root_unreadable"));
  let pinnedNode;
  try {
    pinnedNode = (await readFile(path.join(cwd, ".nvmrc"), "utf8")).trim();
  } catch {
    fail("node_version_pin_unreadable");
  }
  if (!/^\d+\.\d+\.\d+$/u.test(pinnedNode) || process.versions.node !== pinnedNode) {
    fail("node_version_not_pinned");
  }
  const topLevel = (await git(["rev-parse", "--show-toplevel"], {
    cwd,
    timeoutMs: 30_000,
  }).catch(() => fail("not_a_git_repository"))).trim();
  const resolvedTopLevel = await realpath(topLevel).catch(() => fail("repository_root_unreadable"));
  if (resolvedTopLevel !== cwd) fail("working_directory_not_repository_root");
  const commonDirectoryRaw = (await git([
    "rev-parse", "--path-format=absolute", "--git-common-dir",
  ], { cwd, timeoutMs: 30_000 }).catch(() => fail("git_common_directory_unreadable"))).trim();
  const commonDirectory = path.resolve(cwd, commonDirectoryRaw);
  const release = await acquireRepositoryLock(path.join(commonDirectory, LOCK_FILE), "local fallback process")
    .catch(() => fail("fallback_lock_unavailable", { backoffSeconds: 10 * 60 }));
  const backoffFile = path.join(commonDirectory, BACKOFF_FILE);
  let mutationEligible = false;
  let previousBackoff = null;
  try {
    const branch = (await git(["symbolic-ref", "--quiet", "--short", "HEAD"], {
      cwd,
      timeoutMs: 30_000,
    }).catch(() => fail("detached_or_unreadable_branch"))).trim();
    if (branch !== LOCAL_FALLBACK_POLICY.branch) fail("dedicated_main_checkout_required");
    await assertCleanRepository(cwd);
    previousBackoff = await readBackoff(backoffFile, now);
    if (previousBackoff?.active) return { action: "skipped", reason: "persistent_backoff" };

    const publicStatus = await fetchPublicStatus(now, options.fetchImpl, 0);
    let freshness;
    try {
      freshness = validatePublicFallbackStatus(publicStatus, now);
    } catch {
      fail("public_status_invalid", { backoffSeconds: 10 * 60 });
    }
    if (!freshness.eligible) {
      await clearBackoff(backoffFile);
      return {
        action: "skipped",
        reason: "public_status_fresh",
        status_age_seconds: Math.floor(freshness.ageSeconds),
      };
    }
    mutationEligible = true;
    const actions = await fetchActionsGate(now, options.fetchImpl);
    await assertSshAgentSocket();
    await verifyOrigins(cwd);
    const baseCommit = await fetchAndFastForward(cwd);
    const [config, originStatus] = await Promise.all([
      readRepositoryJson(cwd, "config/event.json"),
      readRepositoryJson(cwd, "public/data/status.json"),
    ]);
    try {
      validateFallbackConfig(config, publicStatus);
    } catch {
      fail("local_config_differs_from_public");
    }
    if (!statusesMatchExactly(publicStatus, originStatus)) fail("origin_status_differs_from_public");

    const created = await snapshotAndCommit(cwd, baseCommit, now);
    const prepushNow = new Date();
    const publicBeforePush = await fetchPublicStatus(prepushNow, options.fetchImpl, 1);
    if (!statusesMatchExactly(publicStatus, publicBeforePush)) {
      fail("public_status_progressed", { backoffSeconds: 10 * 60 });
    }
    await fetchActionsGate(prepushNow, options.fetchImpl, actions.observation);
    await verifyRemoteTipUnchanged(cwd, baseCommit, publicStatus);
    const head = (await git(["rev-parse", "HEAD"], { cwd, timeoutMs: 30_000 })).trim();
    if (head !== created.candidate) fail("candidate_commit_changed");
    const pushOutcome = await pushCandidateOnce(cwd, created.candidate);
    const expected = await readRepositoryJson(cwd, "public/data/status.json");
    await verifyCloudflareReadback(cwd, expected, options.fetchImpl);
    await clearBackoff(backoffFile);
    return {
      action: "published",
      mode: created.finalDrain ? "final_drain" : "active_keepalive",
      commit: created.candidate,
      push_outcome: pushOutcome,
      changed_paths: created.paths.length,
    };
  } catch (error) {
    const failure = error instanceof FallbackFailure
      ? error
      : new FallbackFailure("internal_failure", { backoffSeconds: 30 * 60 });
    if (mutationEligible || failure.code !== "dirty_worktree") {
      await writeBackoff(
        backoffFile,
        failure.code,
        new Date(),
        failure.backoffSeconds,
        previousBackoff,
      ).catch(() => {});
    }
    throw failure;
  } finally {
    await release();
  }
}

async function main() {
  try {
    const result = await runLocalSnapshotFallback();
    process.stdout.write(`${JSON.stringify(result)}\n`);
  } catch (error) {
    const code = error instanceof FallbackFailure ? error.code : "internal_failure";
    process.stderr.write(`${JSON.stringify({ action: "refused", reason: code })}\n`);
    process.exitCode = 1;
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  await main();
}
