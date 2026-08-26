import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { generateKeyPairSync } from "node:crypto";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import test from "node:test";

const executeFile = promisify(execFile);
const PROJECT_ROOT = fileURLToPath(new URL("..", import.meta.url));
const CLI = path.join(PROJECT_ROOT, "bin", "swarmproof.mjs");

async function run(arguments_) {
  return executeFile(process.execPath, [CLI, ...arguments_], {
    cwd: PROJECT_ROOT,
    encoding: "utf8",
  });
}

test("CLI defaults to project authorization and labels structural-only output", async () => {
  const directory = await mkdtemp(path.join(tmpdir(), "swarmproof-cli-context-"));
  try {
    const { privateKey } = generateKeyPairSync("ed25519");
    const keyPath = path.join(directory, "test-key.pem");
    const payloadPath = path.join(directory, "task.json");
    await Promise.all([
      writeFile(keyPath, privateKey.export({ format: "pem", type: "pkcs8" }), { mode: 0o600 }),
      writeFile(payloadPath, JSON.stringify({
        schema: "swarmproof-event-v1",
        type: "TASK",
        task_id: "protocol",
        claimed_at: "2026-08-26T00:00:00.000Z",
        nonce: "1",
        parent_event_ids: [],
        content_sha256: "a".repeat(64),
      })),
    ]);

    await assert.rejects(
      run(["sign", "--payload", payloadPath, "--key", keyPath]),
      error => error.code === 1 && /configured coordinator DID/u.test(error.stderr),
    );

    const signed = JSON.parse((await run([
      "sign", "--payload", payloadPath, "--key", keyPath, "--structural-only",
    ])).stdout);
    assert.equal(signed.validation_scope, "structural-only");
    assert.match(signed.warning, /authorization and acceptance were not checked/u);

    await assert.rejects(
      run(["verify", "--envelope", signed.envelope]),
      error => error.code === 1 && /configured coordinator DID/u.test(error.stderr),
    );

    const verified = JSON.parse((await run([
      "verify", "--envelope", signed.envelope, "--structural-only",
    ])).stdout);
    assert.equal(verified.signature_valid, true);
    assert.equal(verified.validation_scope, "structural-only");
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
