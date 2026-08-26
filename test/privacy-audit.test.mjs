import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { cp, mkdir, mkdtemp, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { canonicalize } from "../lib/canonical.mjs";

const executeFile = promisify(execFile);
const PROJECT_ROOT = fileURLToPath(new URL("../", import.meta.url));
const AUDIT_SCRIPT = path.join(PROJECT_ROOT, "scripts/privacy-audit.mjs");

function sha256Hex(value) {
  return createHash("sha256").update(value).digest("hex");
}

async function fixture() {
  const root = await mkdtemp(path.join(tmpdir(), "swarmproof-privacy-audit-"));
  await mkdir(path.join(root, "public"), { recursive: true });
  await cp(path.join(PROJECT_ROOT, "public/data"), path.join(root, "public/data"), { recursive: true });
  await writeFile(path.join(root, "safe.txt"), "bounded public fixture\n", "utf8");
  return root;
}

async function audit(root, includeDist = false, checkHistory = false) {
  return executeFile(process.execPath, [AUDIT_SCRIPT], {
    cwd: root,
    encoding: "utf8",
    env: {
      ...process.env,
      SWARMPROOF_AUDIT_DIST: includeDist ? "1" : "0",
      SWARMPROOF_CHECK_HISTORY: checkHistory ? "1" : "0",
    },
  });
}

async function updateReport(root, mutate) {
  const reportPath = path.join(root, "public/data/report.json");
  const statusPath = path.join(root, "public/data/status.json");
  const report = JSON.parse(await readFile(reportPath, "utf8"));
  const status = JSON.parse(await readFile(statusPath, "utf8"));
  mutate(report);
  report.snapshot_manifest.network_sample_sha256 = report.network_sample === null
    ? null
    : sha256Hex(canonicalize(report.network_sample));
  report.snapshot_manifest_sha256 = sha256Hex(canonicalize(report.snapshot_manifest));
  status.snapshot_manifest_sha256 = report.snapshot_manifest_sha256;
  status.report_sha256 = sha256Hex(canonicalize(report));
  await writeFile(reportPath, `${JSON.stringify(report, null, 2)}\n`, "utf8");
  await writeFile(statusPath, `${JSON.stringify(status, null, 2)}\n`, "utf8");
}

function promoteNetworkSampleToV2(sample) {
  const aggregate = sample.aggregate;
  sample.schema = "swarmproof-network-sample-v2";
  aggregate.exact_clustered_messages = aggregate.messages
    - aggregate.exact_unique_messages
    + aggregate.exact_duplicate_clusters;
  aggregate.exact_clustered_message_share = aggregate.messages === 0
    ? null
    : aggregate.exact_clustered_messages / aggregate.messages;
  aggregate.normalized_clustered_messages = aggregate.messages
    - aggregate.normalized_unique_messages
    + aggregate.normalized_duplicate_clusters;
  aggregate.normalized_clustered_message_share = aggregate.messages === 0
    ? null
    : aggregate.normalized_clustered_messages / aggregate.messages;
  aggregate.minhash_similarity_clustered_messages = aggregate.messages === 0
    ? 0
    : Math.round(aggregate.minhash_similarity_message_share * aggregate.messages);
  aggregate.minhash_similarity_clustered_message_share = aggregate.messages === 0
    ? null
    : aggregate.minhash_similarity_clustered_messages / aggregate.messages;
  aggregate.minhash_similarity_message_share = aggregate.minhash_similarity_clustered_message_share;
}

test("privacy audit accepts the current exact public-data schemas", async t => {
  const root = await fixture();
  t.after(() => rm(root, { recursive: true, force: true }));
  const result = await audit(root);
  assert.match(result.stdout, /privacy audit passed/u);
});

test("privacy audit accepts the complete v2 network-sample shape", async t => {
  const root = await fixture();
  t.after(() => rm(root, { recursive: true, force: true }));
  await updateReport(root, report => promoteNetworkSampleToV2(report.network_sample));
  const result = await audit(root);
  assert.match(result.stdout, /privacy audit passed/u);
});

test("privacy audit rejects mixed or incomplete network-sample schema shapes", async t => {
  const mixedRoot = await fixture();
  const incompleteRoot = await fixture();
  t.after(() => Promise.all([
    rm(mixedRoot, { recursive: true, force: true }),
    rm(incompleteRoot, { recursive: true, force: true }),
  ]));

  await updateReport(mixedRoot, report => {
    report.network_sample.aggregate.exact_clustered_messages = 1;
  });
  await assert.rejects(
    () => audit(mixedRoot),
    error => error.code === 1 && /invalid-public-report-schema/u.test(error.stderr),
  );

  await updateReport(incompleteRoot, report => {
    promoteNetworkSampleToV2(report.network_sample);
    delete report.network_sample.aggregate.normalized_clustered_message_share;
  });
  await assert.rejects(
    () => audit(incompleteRoot),
    error => error.code === 1 && /invalid-public-report-schema/u.test(error.stderr),
  );
});

test("privacy audit ignores the root git worktree pointer", async t => {
  const root = await fixture();
  t.after(() => rm(root, { recursive: true, force: true }));
  await writeFile(path.join(root, ".git"), "gitdir: /var/tmp/repository/.git/worktrees/fixture\n", "utf8");
  const result = await audit(root);
  assert.match(result.stdout, /privacy audit passed/u);
});

test("privacy audit rejects every repository symlink", async t => {
  const root = await fixture();
  t.after(() => rm(root, { recursive: true, force: true }));
  await symlink("safe.txt", path.join(root, "linked-safe.txt"));
  await assert.rejects(
    () => audit(root),
    error => error.code === 1 && /symbolic-link-forbidden/u.test(error.stderr),
  );
});

test("privacy audit scans filenames without opening them", async t => {
  const root = await fixture();
  t.after(() => rm(root, { recursive: true, force: true }));
  await writeFile(path.join(root, ".env.production"), "placeholder=true\n", "utf8");
  await assert.rejects(
    () => audit(root),
    error => error.code === 1 && /sensitive-filename/u.test(error.stderr),
  );
});

test("privacy audit rejects unknown status fields", async t => {
  const root = await fixture();
  t.after(() => rm(root, { recursive: true, force: true }));
  const statusPath = path.join(root, "public/data/status.json");
  const status = JSON.parse(await readFile(statusPath, "utf8"));
  status.unexpected = true;
  await writeFile(statusPath, `${JSON.stringify(status, null, 2)}\n`, "utf8");
  await assert.rejects(
    () => audit(root),
    error => error.code === 1 && /invalid-public-status-schema/u.test(error.stderr),
  );
});

test("dist scanning is opt-in and catches generated credential markers", async t => {
  const root = await fixture();
  t.after(() => rm(root, { recursive: true, force: true }));
  await mkdir(path.join(root, "dist/assets"), { recursive: true });
  const marker = ["gh", "p_", "A".repeat(24)].join("");
  await writeFile(path.join(root, "dist/assets/generated.js"), `export default ${JSON.stringify(marker)};\n`, "utf8");
  await audit(root, false);
  await assert.rejects(
    () => audit(root, true),
    error => error.code === 1 && /github-token/u.test(error.stderr),
  );
});

test("history audit parses multiple UTC pseudonymous commits without record drift", async t => {
  const root = await fixture();
  t.after(() => rm(root, { recursive: true, force: true }));
  await executeFile("git", ["init"], { cwd: root });
  await executeFile("git", ["config", "user.name", "SwarmProof Coordinator"], { cwd: root });
  await executeFile("git", ["config", "user.email", "321255904+flop2026@users.noreply.github.com"], { cwd: root });
  const commitEnv = {
    ...process.env,
    GIT_AUTHOR_DATE: "2026-08-26T00:00:00Z",
    GIT_COMMITTER_DATE: "2026-08-26T00:00:00Z",
  };
  await executeFile("git", ["add", "."], { cwd: root });
  await executeFile("git", ["commit", "-m", "fixture: first UTC commit"], { cwd: root, env: commitEnv });
  await writeFile(path.join(root, "second.txt"), "second bounded fixture\n", "utf8");
  await executeFile("git", ["add", "second.txt"], { cwd: root });
  await executeFile("git", ["commit", "-m", "fixture: second UTC commit"], { cwd: root, env: commitEnv });
  const result = await audit(root, false, true);
  assert.match(result.stdout, /privacy audit passed/u);
});
