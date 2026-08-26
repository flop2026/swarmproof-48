import { execFile } from "node:child_process";
import { mkdir, mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import { sha256Hex } from "./crypto.mjs";

const executeFile = promisify(execFile);
const COMMIT_RE = /^[0-9a-f]{40}$/;
const PATH_RE = /^(?!\/)(?!.*(?:^|\/)\.\.(?:\/|$))[A-Za-z0-9._/-]{1,240}$/;

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

export async function verifyLocalArtifact(artifact, options = {}) {
  assert(artifact && typeof artifact === "object", "artifact is required.");
  assert(artifact.repository === options.allowedRepository, "artifact repository is not allowlisted.");
  assert(COMMIT_RE.test(artifact.commit ?? ""), "artifact commit must be a full lowercase SHA.");
  assert(PATH_RE.test(artifact.path ?? ""), "artifact path is invalid.");
  assert(/^[0-9a-f]{64}$/.test(artifact.sha256 ?? ""), "artifact hash is invalid.");
  const repositoryRoot = options.repositoryRoot ?? process.cwd();

  try {
    await executeFile("git", ["merge-base", "--is-ancestor", artifact.commit, options.trustedRef ?? "main"], {
      cwd: repositoryRoot,
      encoding: "utf8",
      timeout: options.timeoutMs ?? 10_000,
    });
  } catch {
    return { status: "fail", reason: "commit-not-on-trusted-ref" };
  }

  let stdout;
  try {
    ({ stdout } = await executeFile("git", ["show", `${artifact.commit}:${artifact.path}`], {
      cwd: repositoryRoot,
      encoding: "buffer",
      maxBuffer: options.maximumBytes ?? 4 * 1024 * 1024,
      timeout: options.timeoutMs ?? 10_000,
    }));
  } catch {
    return { status: "fail", reason: "artifact-missing-or-oversized" };
  }

  const actualSha256 = sha256Hex(stdout);
  if (actualSha256 !== artifact.sha256) {
    return { status: "fail", reason: "artifact-hash-mismatch", actual_sha256: actualSha256 };
  }
  return { status: "pass", sha256: actualSha256, bytes: stdout.byteLength };
}

export async function replayTrustedCheck(commit, command, options = {}) {
  assert(COMMIT_RE.test(commit ?? ""), "replay commit must be a full lowercase SHA.");
  assert(
    Array.isArray(command)
      && command.length === 2
      && command[0] === "node"
      && command[1] === "--test",
    "replay command is not the fixed allowlisted check.",
  );
  const repositoryRoot = options.repositoryRoot ?? process.cwd();
  try {
    await executeFile("git", ["merge-base", "--is-ancestor", commit, options.trustedRef ?? "HEAD"], {
      cwd: repositoryRoot,
      encoding: "utf8",
      timeout: options.timeoutMs ?? 10_000,
    });
  } catch {
    return { status: "fail", reason: "replay-commit-not-on-trusted-ref" };
  }

  const temporaryRoot = await mkdtemp(path.join(tmpdir(), "swarmproof-replay-"));
  const archivePath = path.join(temporaryRoot, "source.tar");
  const sourcePath = path.join(temporaryRoot, "source");
  try {
    await mkdir(sourcePath, { mode: 0o700 });
    await executeFile("git", ["archive", "--format=tar", `--output=${archivePath}`, commit], {
      cwd: repositoryRoot,
      encoding: "utf8",
      timeout: options.timeoutMs ?? 30_000,
    });
    await executeFile("tar", ["-xf", archivePath, "-C", sourcePath], {
      encoding: "utf8",
      timeout: options.timeoutMs ?? 30_000,
    });
    await executeFile(process.execPath, ["--test"], {
      cwd: sourcePath,
      encoding: "utf8",
      timeout: options.replayTimeoutMs ?? 120_000,
      maxBuffer: options.maximumOutputBytes ?? 2 * 1024 * 1024,
      env: {
        PATH: `${path.dirname(process.execPath)}:/usr/bin:/bin`,
        TZ: "UTC",
        CI: "1",
        SWARMPROOF_OFFLINE_REPLAY: "1",
      },
    });
    return {
      status: "pass",
      check: "node --test",
      commit,
      isolation: "fresh-git-archive-secretless-process",
    };
  } catch {
    return { status: "fail", reason: "trusted-replay-failed", commit };
  } finally {
    await rm(temporaryRoot, { recursive: true, force: true });
  }
}
