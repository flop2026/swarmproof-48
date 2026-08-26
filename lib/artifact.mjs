import { execFile } from "node:child_process";
import { mkdir, mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import { sha256Hex } from "./crypto.mjs";

const executeFile = promisify(execFile);
const COMMIT_RE = /^[0-9a-f]{40}$/;
const HASH_RE = /^[0-9a-f]{64}$/;
const PATH_RE = /^[A-Za-z0-9._/-]{1,240}$/;
const ARTIFACT_KEYS = new Set(["repository", "commit", "path", "sha256"]);
const REGULAR_FILE_MODES = new Set(["100644", "100755"]);

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function isSafeArtifactPath(value) {
  if (!PATH_RE.test(value ?? "") || value.startsWith("/") || value.endsWith("/")) return false;
  return value.split("/").every(segment => (
    segment.length > 0
    && segment !== "."
    && segment !== ".."
    && segment.toLowerCase() !== ".git"
  ));
}

async function resolveRegularBlob(artifact, repositoryRoot, options) {
  let stdout;
  try {
    ({ stdout } = await executeFile(
      "git",
      ["ls-tree", "-z", "--full-tree", artifact.commit, "--", artifact.path],
      {
        cwd: repositoryRoot,
        encoding: "buffer",
        maxBuffer: 4096,
        timeout: options.timeoutMs ?? 10_000,
      },
    ));
  } catch {
    return { status: "fail", reason: "artifact-tree-lookup-failed" };
  }

  const entry = stdout.toString("utf8");
  if (!entry) return { status: "fail", reason: "artifact-missing" };
  const match = /^(\d{6}) ([a-z]+) ([0-9a-f]{40})\t([^\0]+)\0$/u.exec(entry);
  if (!match || match[4] !== artifact.path) {
    return { status: "fail", reason: "artifact-tree-entry-invalid" };
  }
  const [, mode, type, objectId] = match;
  if (type !== "blob" || !REGULAR_FILE_MODES.has(mode)) {
    return { status: "fail", reason: "artifact-not-regular-file" };
  }
  return { status: "pass", objectId };
}

export async function verifyLocalArtifact(artifact, options = {}) {
  assert(artifact && typeof artifact === "object" && !Array.isArray(artifact), "artifact is required.");
  for (const key of Object.keys(artifact)) assert(ARTIFACT_KEYS.has(key), `artifact contains unknown field: ${key}`);
  for (const key of ARTIFACT_KEYS) assert(Object.hasOwn(artifact, key), `artifact is missing field: ${key}`);
  assert(artifact.repository === options.allowedRepository, "artifact repository is not allowlisted.");
  assert(COMMIT_RE.test(artifact.commit ?? ""), "artifact commit must be a full lowercase SHA.");
  assert(isSafeArtifactPath(artifact.path), "artifact path is invalid.");
  assert(HASH_RE.test(artifact.sha256 ?? ""), "artifact hash is invalid.");
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

  const resolved = await resolveRegularBlob(artifact, repositoryRoot, options);
  if (resolved.status !== "pass") return resolved;

  const maximumBytes = options.maximumBytes ?? 4 * 1024 * 1024;
  try {
    const { stdout: sizeOutput } = await executeFile("git", ["cat-file", "-s", resolved.objectId], {
      cwd: repositoryRoot,
      encoding: "utf8",
      maxBuffer: 128,
      timeout: options.timeoutMs ?? 10_000,
    });
    const size = Number(sizeOutput.trim());
    if (!Number.isSafeInteger(size) || size < 0) {
      return { status: "fail", reason: "artifact-size-invalid" };
    }
    if (size > maximumBytes) return { status: "fail", reason: "artifact-oversized" };
  } catch {
    return { status: "fail", reason: "artifact-size-unavailable" };
  }

  let stdout;
  try {
    ({ stdout } = await executeFile("git", ["cat-file", "blob", resolved.objectId], {
      cwd: repositoryRoot,
      encoding: "buffer",
      maxBuffer: maximumBytes,
      timeout: options.timeoutMs ?? 10_000,
    }));
  } catch {
    return { status: "fail", reason: "artifact-read-failed" };
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
    const replayGitEnvironment = {
      PATH: `${path.dirname(process.execPath)}:/usr/bin:/bin`,
      TZ: "UTC",
      GIT_CONFIG_NOSYSTEM: "1",
      GIT_CONFIG_GLOBAL: "/dev/null",
      GIT_AUTHOR_NAME: "SwarmProof Coordinator",
      GIT_AUTHOR_EMAIL: "flop2026@users.noreply.github.com",
      GIT_COMMITTER_NAME: "SwarmProof Coordinator",
      GIT_COMMITTER_EMAIL: "flop2026@users.noreply.github.com",
      GIT_AUTHOR_DATE: "2000-01-01T00:00:00Z",
      GIT_COMMITTER_DATE: "2000-01-01T00:00:00Z",
    };
    await executeFile("git", ["init", "--quiet", "--initial-branch=replay"], {
      cwd: sourcePath,
      encoding: "utf8",
      timeout: options.timeoutMs ?? 30_000,
      env: replayGitEnvironment,
    });
    await executeFile("git", ["add", "--force", "--all"], {
      cwd: sourcePath,
      encoding: "utf8",
      timeout: options.timeoutMs ?? 30_000,
      env: replayGitEnvironment,
    });
    await executeFile("git", ["commit", "--quiet", "--no-gpg-sign", "-m", "replay: isolated source snapshot"], {
      cwd: sourcePath,
      encoding: "utf8",
      timeout: options.timeoutMs ?? 30_000,
      env: replayGitEnvironment,
    });
    const [{ stdout: trustedTreeRaw }, { stdout: replayTreeRaw }] = await Promise.all([
      executeFile("git", ["rev-parse", `${commit}^{tree}`], {
        cwd: repositoryRoot,
        encoding: "utf8",
        timeout: options.timeoutMs ?? 30_000,
      }),
      executeFile("git", ["rev-parse", "HEAD^{tree}"], {
        cwd: sourcePath,
        encoding: "utf8",
        timeout: options.timeoutMs ?? 30_000,
        env: replayGitEnvironment,
      }),
    ]);
    assert(
      trustedTreeRaw.trim() === replayTreeRaw.trim(),
      "Synthetic replay Git tree does not match the archived trusted commit.",
    );
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
        GIT_CONFIG_NOSYSTEM: "1",
        GIT_CONFIG_GLOBAL: "/dev/null",
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
