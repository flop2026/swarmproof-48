import { createHash, randomBytes } from "node:crypto";
import { lstat, mkdir, open, readFile, rm } from "node:fs/promises";
import { hostname } from "node:os";
import path from "node:path";

const LOCK_SCHEMA = "swarmproof-repository-lock-v1";
const OWNER_RE = /^[0-9a-f]{64}$/u;
const LOCK_LIMIT = 4 * 1024;
const HOST_SHA256 = createHash("sha256").update(hostname(), "utf8").digest("hex");

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function parseMetadata(content) {
  assert(Buffer.byteLength(content, "utf8") <= LOCK_LIMIT, "Repository lock metadata is oversized.");
  let metadata;
  try {
    metadata = JSON.parse(content);
  } catch {
    throw new Error("Repository lock metadata is invalid JSON.");
  }
  assert(
    metadata && typeof metadata === "object" && !Array.isArray(metadata),
    "Repository lock metadata is invalid.",
  );
  const expected = ["schema", "owner_token", "pid", "host_sha256", "created_at"];
  const keys = Object.keys(metadata);
  assert(
    keys.length === expected.length
      && keys.every(key => expected.includes(key))
      && expected.every(key => Object.hasOwn(metadata, key)),
    "Repository lock metadata has an invalid field set.",
  );
  assert(metadata.schema === LOCK_SCHEMA, "Repository lock schema is invalid.");
  assert(OWNER_RE.test(metadata.owner_token), "Repository lock owner token is invalid.");
  assert(Number.isSafeInteger(metadata.pid) && metadata.pid > 0, "Repository lock PID is invalid.");
  assert(OWNER_RE.test(metadata.host_sha256), "Repository lock host hash is invalid.");
  const createdAt = Date.parse(metadata.created_at);
  assert(
    Number.isFinite(createdAt) && new Date(createdAt).toISOString() === metadata.created_at,
    "Repository lock creation time is invalid.",
  );
  return metadata;
}

function processState(metadata) {
  if (metadata.host_sha256 !== HOST_SHA256) return "held on another host or from an unverifiable prior run";
  try {
    process.kill(metadata.pid, 0);
    return "held by an active local process";
  } catch (error) {
    if (error.code === "EPERM") return "held by an active local process";
    if (error.code === "ESRCH") return "stale from a terminated local process";
    return "owned by a local process whose state cannot be verified";
  }
}

async function describeExistingLock(lockPath) {
  try {
    const metadata = await lstat(lockPath);
    if (!metadata.isFile() || metadata.isSymbolicLink()) {
      return "an unsafe non-regular lock entry exists";
    }
    const owner = parseMetadata(await readFile(lockPath, "utf8"));
    return `${processState(owner)} (pid ${owner.pid}, owner ${owner.owner_token.slice(0, 12)})`;
  } catch (error) {
    if (error.code === "ENOENT") return "the competing lock changed while it was inspected";
    return `an existing lock cannot be verified (${error.message})`;
  }
}

/**
 * Acquire a repository-scoped lock without ever reclaiming another owner's file.
 * A stale owner is reported, not deleted automatically: PID reuse and lock-path
 * replacement must never let a waiter remove an active holder.
 */
export async function acquireRepositoryLock(lockPath, label = "repository mutation") {
  assert(typeof lockPath === "string" && lockPath.length > 0, "Repository lock path is invalid.");
  const resolved = path.resolve(lockPath);
  const directory = path.dirname(resolved);
  assert(directory !== path.parse(directory).root, "Repository lock path is unsafe.");
  await mkdir(directory, { recursive: true, mode: 0o700 });
  const directoryMetadata = await lstat(directory);
  assert(
    directoryMetadata.isDirectory() && !directoryMetadata.isSymbolicLink(),
    "Repository lock directory must be a regular directory.",
  );

  const owner = {
    schema: LOCK_SCHEMA,
    owner_token: randomBytes(32).toString("hex"),
    pid: process.pid,
    host_sha256: HOST_SHA256,
    created_at: new Date().toISOString(),
  };
  let handle;
  try {
    handle = await open(resolved, "wx", 0o600);
  } catch (error) {
    if (error.code !== "EEXIST") throw error;
    const detail = await describeExistingLock(resolved);
    throw new Error(`Another ${label} owns the repository lock: ${detail}; refusing to remove it.`);
  }

  try {
    await handle.writeFile(`${JSON.stringify(owner)}\n`, "utf8");
    await handle.sync();
  } catch (error) {
    await handle.close().catch(() => {});
    // Do not unlink after a failed initialization: without a validated owner
    // token, removing the path could delete a replacement created by another
    // process. A malformed/stale entry is safer than violating exclusivity.
    throw error;
  }
  const heldMetadata = await handle.stat();
  let released = false;

  return async () => {
    if (released) return;
    try {
      const pathMetadata = await lstat(resolved).catch(error => {
        if (error.code === "ENOENT") throw new Error("Owned repository lock disappeared before release.");
        throw error;
      });
      assert(
        pathMetadata.isFile()
          && !pathMetadata.isSymbolicLink()
          && pathMetadata.dev === heldMetadata.dev
          && pathMetadata.ino === heldMetadata.ino,
        "Repository lock path changed ownership before release; refusing to remove it.",
      );
      const current = parseMetadata(await readFile(resolved, "utf8"));
      assert(
        current.owner_token === owner.owner_token
          && current.pid === owner.pid
          && current.host_sha256 === owner.host_sha256,
        "Repository lock owner changed before release; refusing to remove it.",
      );
      const finalMetadata = await lstat(resolved);
      assert(
        finalMetadata.dev === heldMetadata.dev && finalMetadata.ino === heldMetadata.ino,
        "Repository lock was replaced before release; refusing to remove it.",
      );
      await rm(resolved);
    } finally {
      released = true;
      await handle.close();
    }
  };
}
