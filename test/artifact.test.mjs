import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { promisify } from "node:util";
import { replayTrustedCheck, verifyLocalArtifact } from "../lib/artifact.mjs";
import { sha256Hex } from "../lib/crypto.mjs";

const executeFile = promisify(execFile);
const REPOSITORY = "flop2026/swarmproof-48";

async function fixtureRepository() {
  const directory = await mkdtemp(path.join(tmpdir(), "swarmproof-artifact-"));
  await executeFile("git", ["init", "-b", "main"], { cwd: directory });
  await executeFile("git", ["config", "user.name", "SwarmProof Fixture"], { cwd: directory });
  await executeFile("git", ["config", "user.email", "flop2026@users.noreply.github.com"], { cwd: directory });
  const content = Buffer.from("deterministic artifact\n", "utf8");
  await writeFile(path.join(directory, "result.txt"), content);
  await executeFile("git", ["add", "result.txt"], { cwd: directory });
  await executeFile("git", ["commit", "-m", "fixture"], {
    cwd: directory,
    env: { ...process.env, TZ: "UTC" },
  });
  const { stdout } = await executeFile("git", ["rev-parse", "HEAD"], { cwd: directory, encoding: "utf8" });
  return { directory, commit: stdout.trim(), content };
}

test("verifies only immutable, reachable, hash-matching artifacts", async () => {
  const fixture = await fixtureRepository();
  const artifact = {
    repository: REPOSITORY,
    commit: fixture.commit,
    path: "result.txt",
    sha256: sha256Hex(fixture.content),
  };
  const result = await verifyLocalArtifact(artifact, {
    repositoryRoot: fixture.directory,
    allowedRepository: REPOSITORY,
  });
  assert.equal(result.status, "pass");

  const mismatch = await verifyLocalArtifact({ ...artifact, sha256: "0".repeat(64) }, {
    repositoryRoot: fixture.directory,
    allowedRepository: REPOSITORY,
  });
  assert.equal(mismatch.reason, "artifact-hash-mismatch");
});

test("rejects repository changes and path traversal before running git", async () => {
  await assert.rejects(
    () => verifyLocalArtifact({
      repository: "outside/repository",
      commit: "a".repeat(40),
      path: "result.txt",
      sha256: "b".repeat(64),
    }, { allowedRepository: REPOSITORY }),
    /not allowlisted/u,
  );
  await assert.rejects(
    () => verifyLocalArtifact({
      repository: REPOSITORY,
      commit: "a".repeat(40),
      path: "../secret",
      sha256: "b".repeat(64),
    }, { allowedRepository: REPOSITORY }),
    /path is invalid/u,
  );
});

test("replays only the fixed test command from an exact trusted commit", async () => {
  const fixture = await fixtureRepository();
  const replay = await replayTrustedCheck(fixture.commit, ["node", "--test"], {
    repositoryRoot: fixture.directory,
    trustedRef: "main",
  });
  assert.equal(replay.status, "pass");
  assert.equal(replay.commit, fixture.commit);
  await assert.rejects(
    () => replayTrustedCheck(fixture.commit, ["node", "script.mjs"], {
      repositoryRoot: fixture.directory,
      trustedRef: "main",
    }),
    /fixed allowlisted check/u,
  );
});
