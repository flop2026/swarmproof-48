import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { generateKeyPairSync } from "node:crypto";
import { chmod, mkdtemp, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import test from "node:test";

const executeFile = promisify(execFile);
const PROJECT_ROOT = fileURLToPath(new URL("..", import.meta.url));
const CLI = path.join(PROJECT_ROOT, "bin", "control-claim.mjs");
const PUBLIC_CLAIM = path.join(
  PROJECT_ROOT,
  "public",
  ".well-known",
  "swarmproof-control-claim-v1.json",
);

async function run(arguments_) {
  return executeFile(process.execPath, [CLI, ...arguments_], {
    cwd: PROJECT_ROOT,
    encoding: "utf8",
  });
}

test("control-claim CLI verifies the checked-in claim without echoing its proof", async () => {
  const claim = JSON.parse(await readFile(PUBLIC_CLAIM, "utf8"));
  const result = await run([
    "verify",
    "--file", PUBLIC_CLAIM,
  ]);
  const output = JSON.parse(result.stdout);
  assert.equal(output.schema, "swarmproof-control-claim-verification-v1");
  assert.equal(output.validation_scope, "signed-document-only");
  assert.equal(output.controller, claim.payload.controller);
  assert.equal(output.signature_valid, true);
  assert.equal(output.publications, "not-checked");
  assert.ok(!result.stdout.includes(claim.proof.value));
  assert.ok(!result.stdout.includes("private-key"));
  assert.equal(result.stderr, "");
});

test("control-claim CLI rejects weak key permissions and a wrong DID without leaking PEM", async () => {
  const directory = await mkdtemp(path.join(tmpdir(), "swarmproof-control-cli-"));
  try {
    const { privateKey } = generateKeyPairSync("ed25519");
    const pem = privateKey.export({ format: "pem", type: "pkcs8" }).toString();
    const keyPath = path.join(directory, "test-key.pem");
    const outputPath = path.join(directory, "claim.json");
    const pemMarker = ["BEGIN", "PRIVATE", "KEY"].join(" ");
    await writeFile(keyPath, pem, { mode: 0o644 });

    await assert.rejects(
      run(["create", "--key", keyPath, "--out", outputPath]),
      error => (
        error.code === 1
        && /owner-only permissions/u.test(error.stderr)
        && !error.stderr.includes(pem)
        && !error.stderr.includes(pemMarker)
        && error.stdout === ""
      ),
    );

    await chmod(keyPath, 0o600);
    await assert.rejects(
      run(["create", "--key", keyPath, "--out", outputPath]),
      error => (
        error.code === 1
        && /does not match the configured project DID/u.test(error.stderr)
        && !error.stderr.includes(pem)
        && !error.stderr.includes(pemMarker)
        && error.stdout === ""
      ),
    );

    const linkPath = path.join(directory, "key-link.pem");
    await symlink(keyPath, linkPath);
    await assert.rejects(
      run(["create", "--key", linkPath, "--out", outputPath]),
      error => error.code === 1 && !error.stderr.includes(pem) && error.stdout === "",
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("control-claim CLI refuses to overwrite a claim unless rotation is explicit", async () => {
  const directory = await mkdtemp(path.join(tmpdir(), "swarmproof-control-overwrite-"));
  try {
    const { privateKey } = generateKeyPairSync("ed25519");
    const keyPath = path.join(directory, "wrong-key.pem");
    const pem = privateKey.export({ format: "pem", type: "pkcs8" }).toString();
    await writeFile(keyPath, pem, { mode: 0o600 });
    await assert.rejects(
      run(["create", "--key", keyPath, "--out", keyPath]),
      error => error.code === 1 && /Output path must differ/u.test(error.stderr),
    );
    assert.equal(await readFile(keyPath, "utf8"), pem);

    const unrelatedPath = path.join(directory, "unrelated.json");
    await writeFile(unrelatedPath, "do-not-replace\n");
    await assert.rejects(
      run(["create", "--key", keyPath, "--out", unrelatedPath]),
      error => error.code === 1 && /Output already exists/u.test(error.stderr),
    );
    await assert.rejects(
      run(["create", "--key", keyPath, "--out", unrelatedPath, "--replace"]),
      error => error.code === 1 && /not valid JSON/u.test(error.stderr),
    );
    assert.equal(await readFile(unrelatedPath, "utf8"), "do-not-replace\n");
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
