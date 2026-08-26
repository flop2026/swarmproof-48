import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { generateKeyPairSync } from "node:crypto";
import { chmod, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import test from "node:test";

const executeFile = promisify(execFile);
const PROJECT_ROOT = fileURLToPath(new URL("..", import.meta.url));
const CLI = path.join(PROJECT_ROOT, "bin", "contribution-index.mjs");
const PUBLICATION_COMMIT = "24e6dfe6549cc791a64ed2d6e7d7364784b23959";

async function run(arguments_) {
  return executeFile(process.execPath, [CLI, ...arguments_], {
    cwd: PROJECT_ROOT,
    encoding: "utf8",
    maxBuffer: 8 * 1024 * 1024,
  });
}

test("prepare replays the snapshot and emits eight unsigned deduplicated subjects", async () => {
  const directory = await mkdtemp(path.join(tmpdir(), "swarmproof-contribution-prepare-"));
  try {
    const outputPath = path.join(directory, "input.json");
    const result = await run(["prepare", "--out", outputPath]);
    const summary = JSON.parse(result.stdout);
    const input = JSON.parse(await readFile(outputPath, "utf8"));
    assert.equal(summary.unique_contributions, 8);
    assert.equal(summary.publication_commit, PUBLICATION_COMMIT);
    assert.equal(input.sequence, "1");
    assert.equal(input.previous_index_sha256, null);
    assert.equal(input.contributions.length, 8);
    assert.equal(new Set(input.contributions.map(item => item.subject.content_sha256)).size, 8);
    assert.ok(input.contributions.every(item => (
      item.evidence.length === 1
      && item.evidence[0].kind === "swarmproof-result-snapshot"
      && item.evidence[0].publication_commit === PUBLICATION_COMMIT
    )));
    assert.ok(!result.stdout.includes('"proof"'));
    assert.ok(!result.stdout.includes("PRIVATE KEY"));

    await assert.rejects(
      run(["prepare", "--out", outputPath]),
      error => error.code === 1 && /Output already exists/u.test(error.stderr),
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("create rejects weak key permissions and a different DID without leaking key bytes", async () => {
  const directory = await mkdtemp(path.join(tmpdir(), "swarmproof-contribution-create-"));
  try {
    const { privateKey } = generateKeyPairSync("ed25519");
    const pem = privateKey.export({ format: "pem", type: "pkcs8" }).toString();
    const keyPath = path.join(directory, "test-key.pem");
    const inputPath = path.join(directory, "input.json");
    const outputPath = path.join(directory, "index.json");
    await writeFile(keyPath, pem, { mode: 0o644 });
    await writeFile(inputPath, `${JSON.stringify({
      sequence: "1",
      previous_index_sha256: null,
      contributions: [{
        subject: {
          type: "git-content",
          repository: "flop2026/swarmproof-48",
          content_sha256: "a".repeat(64),
        },
        evidence: [{
          kind: "swarmproof-result-snapshot",
          result_event_id: "b".repeat(64),
          publication_commit: PUBLICATION_COMMIT,
          report_sha256: "c".repeat(64),
          snapshot_manifest_sha256: "d".repeat(64),
        }],
      }],
    }, null, 2)}\n`);

    await assert.rejects(
      run(["create", "--input", inputPath, "--key", keyPath, "--out", outputPath]),
      error => (
        error.code === 1
        && /owner-only permissions/u.test(error.stderr)
        && !error.stderr.includes(pem)
        && error.stdout === ""
      ),
    );

    await chmod(keyPath, 0o600);
    await assert.rejects(
      run(["create", "--input", inputPath, "--key", keyPath, "--out", outputPath]),
      error => (
        error.code === 1
        && /does not match the configured contribution-index DID/u.test(error.stderr)
        && !error.stderr.includes(pem)
        && error.stdout === ""
      ),
    );
    await assert.rejects(
      run(["create", "--input", inputPath, "--key", keyPath, "--out", keyPath]),
      error => error.code === 1 && /Output path must differ/u.test(error.stderr) && !error.stderr.includes(pem),
    );
    assert.equal(await readFile(keyPath, "utf8"), pem);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("CLI rejects duplicate options and unknown mutation flags", async () => {
  await assert.rejects(
    run(["verify", "--file", "one", "--file", "two"]),
    error => error.code === 2,
  );
  await assert.rejects(
    run(["verify", "--replace"]),
    error => error.code === 2,
  );
});
