import { canonicalize } from "./canonical.mjs";
import { deploymentStatusMatches } from "./deployment.mjs";

const COMMIT_RE = /^[0-9a-f]{40}$/u;
const HASH_RE = /^[0-9a-f]{64}$/u;
const SSH_SCP_RE = /^git@github\.com:([A-Za-z0-9_.-]{1,39}\/[A-Za-z0-9_.-]{1,100})(?:\.git)?$/u;
const ACTIVE_STALE_AFTER_SECONDS = 4 * 60 * 60;

export const LOCAL_FALLBACK_POLICY = Object.freeze({
  repository: "flop2026/swarmproof-48",
  branch: "main",
  publicOrigin: "https://swarmproof-48-e463.pages.dev",
  githubApiOrigin: "https://api.github.com",
  workflowFile: "snapshot.yml",
  minimumStatusAgeSeconds: 3 * 60 * 60 + 15 * 60,
  actionsQuietSeconds: 30 * 60,
  maximumFutureSkewSeconds: 5 * 60,
  requestTimeoutMs: 20_000,
  publicStatusMaximumBytes: 65_536,
  actionsMaximumBytes: 512 * 1024,
  commandTimeoutMs: 15 * 60 * 1000,
  validationTimeoutMs: 15 * 60 * 1000,
  deploymentTimeoutMs: 12 * 60 * 1000,
});

const STATUS_KEYS = Object.freeze([
  "schema",
  "state",
  "generated_at",
  "starts_at",
  "ends_at",
  "report_sha256",
  "audit_core_sha256",
  "snapshot_manifest_sha256",
  "source_commit",
  "signing_keys",
  "reproducible_artifacts",
  "cross_key_reviews",
  "accepted_results",
  "stale_after_seconds",
]);

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function isPlainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function assertExactKeys(value, keys, label) {
  assert(isPlainObject(value), `${label} is invalid.`);
  const actual = Object.keys(value);
  assert(actual.length === keys.length, `${label} has an invalid field set.`);
  for (const key of keys) assert(Object.hasOwn(value, key), `${label} is missing ${key}.`);
  for (const key of actual) assert(keys.includes(key), `${label} contains an unknown field.`);
}

function canonicalTime(value, label) {
  assert(typeof value === "string", `${label} is invalid.`);
  const milliseconds = Date.parse(value);
  assert(
    Number.isFinite(milliseconds) && new Date(milliseconds).toISOString() === value,
    `${label} is invalid.`,
  );
  return milliseconds;
}

function githubUtcTime(value, label) {
  assert(
    typeof value === "string"
      && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/u.test(value),
    `${label} is invalid.`,
  );
  const milliseconds = Date.parse(value);
  assert(Number.isFinite(milliseconds), `${label} is invalid.`);
  const canonicalMilliseconds = new Date(milliseconds).toISOString();
  const canonical = value.includes(".")
    ? canonicalMilliseconds
    : canonicalMilliseconds.replace(/\.000Z$/u, "Z");
  assert(canonical === value, `${label} is invalid.`);
  return milliseconds;
}

function safeCounter(value, label) {
  assert(Number.isSafeInteger(value) && value >= 0, `${label} is invalid.`);
}

export function localFallbackEndpoints(policy = LOCAL_FALLBACK_POLICY, nonce = Date.now()) {
  assert(/^\d+$/u.test(String(nonce)), "Fallback request nonce is invalid.");
  const repositoryPath = policy.repository.split("/").map(encodeURIComponent).join("/");
  return {
    status: `${policy.publicOrigin}/data/status.json?n=${nonce}`,
    actions: `${policy.githubApiOrigin}/repos/${repositoryPath}/actions/workflows/${encodeURIComponent(policy.workflowFile)}/runs?branch=${encodeURIComponent(policy.branch)}&per_page=5`,
  };
}

export function validatePublicFallbackStatus(status, now = new Date(), policy = LOCAL_FALLBACK_POLICY) {
  assertExactKeys(status, STATUS_KEYS, "Published status");
  assert(status.schema === "swarmproof-status-v1", "Published status schema is invalid.");
  assert(status.state === "active", "Published status is not active.");
  const generatedAt = canonicalTime(status.generated_at, "Published status generation time");
  const startsAt = canonicalTime(status.starts_at, "Published status start time");
  const endsAt = canonicalTime(status.ends_at, "Published status end time");
  assert(startsAt < endsAt, "Published status event window is invalid.");
  assert(generatedAt >= startsAt, "Published active status predates the event window.");
  assert(HASH_RE.test(status.report_sha256 ?? ""), "Published report hash is invalid.");
  assert(HASH_RE.test(status.audit_core_sha256 ?? ""), "Published audit-core hash is invalid.");
  assert(
    HASH_RE.test(status.snapshot_manifest_sha256 ?? ""),
    "Published snapshot-manifest hash is invalid.",
  );
  assert(COMMIT_RE.test(status.source_commit ?? ""), "Published source commit is invalid.");
  for (const key of [
    "signing_keys",
    "reproducible_artifacts",
    "cross_key_reviews",
    "accepted_results",
  ]) safeCounter(status[key], `Published status ${key}`);
  assert(
    status.stale_after_seconds === ACTIVE_STALE_AFTER_SECONDS,
    "Published active freshness policy changed.",
  );

  const nowMs = now instanceof Date ? now.getTime() : Number.NaN;
  assert(Number.isFinite(nowMs), "Fallback clock is invalid.");
  assert(
    Number.isSafeInteger(policy.minimumStatusAgeSeconds)
      && policy.minimumStatusAgeSeconds >= 3 * 60 * 60
      && policy.minimumStatusAgeSeconds < ACTIVE_STALE_AFTER_SECONDS,
    "Fallback status-age policy is invalid.",
  );
  assert(
    generatedAt <= nowMs + policy.maximumFutureSkewSeconds * 1000,
    "Published status is from the future.",
  );
  const ageSeconds = (nowMs - generatedAt) / 1000;
  return {
    ageSeconds,
    finalizationDue: nowMs >= endsAt,
    eligible: ageSeconds >= policy.minimumStatusAgeSeconds || nowMs >= endsAt,
    secondsUntilStale: ACTIVE_STALE_AFTER_SECONDS - ageSeconds,
  };
}

export function validateFallbackConfig(config, status, policy = LOCAL_FALLBACK_POLICY) {
  assert(isPlainObject(config), "Fallback config is invalid.");
  assert(config.repository === policy.repository, "Fallback repository is not allowlisted.");
  assert(config.state === "active", "Local event config is not active.");
  assert(config.starts_at === status.starts_at, "Local and published start times differ.");
  assert(config.ends_at === status.ends_at, "Local and published end times differ.");
}

function actionsRunTime(run, key) {
  return githubUtcTime(run[key], `Actions run ${key}`);
}

export function validateActionsSnapshotGate(payload, options = {}) {
  const policy = options.policy ?? LOCAL_FALLBACK_POLICY;
  const now = options.now ?? new Date();
  assert(isPlainObject(payload), "Actions response is invalid.");
  assert(Array.isArray(payload.workflow_runs), "Actions workflow-runs response is invalid.");
  assert(
    payload.workflow_runs.length >= 1 && payload.workflow_runs.length <= 5,
    "Actions workflow-runs response has an invalid size.",
  );
  for (const candidate of payload.workflow_runs) {
    assert(isPlainObject(candidate), "Actions snapshot run is invalid.");
    assert(
      ["requested", "waiting", "pending", "queued", "in_progress", "completed"].includes(candidate.status),
      "Actions snapshot run status is invalid.",
    );
    assert(candidate.status === "completed", "An Actions snapshot run may still publish.");
  }
  const run = payload.workflow_runs[0];
  assert(isPlainObject(run), "Latest Actions snapshot run is invalid.");
  assert(Number.isSafeInteger(run.id) && run.id > 0, "Latest Actions snapshot run ID is invalid.");
  assert(run.head_branch === policy.branch, "Latest Actions snapshot run is on the wrong branch.");
  assert(COMMIT_RE.test(run.head_sha ?? ""), "Latest Actions snapshot head commit is invalid.");
  assert(
    ["schedule", "workflow_dispatch"].includes(run.event),
    "Latest Actions snapshot trigger is invalid.",
  );
  const createdAt = actionsRunTime(run, "created_at");
  const updatedAt = actionsRunTime(run, "updated_at");
  assert(updatedAt >= createdAt, "Latest Actions snapshot timestamps are inconsistent.");
  for (const candidate of payload.workflow_runs.slice(1)) {
    assert(
      actionsRunTime(candidate, "created_at") <= createdAt,
      "Actions snapshot runs are not newest-first.",
    );
  }
  assert(run.status === "completed", "Latest Actions snapshot may still publish.");
  assert(typeof run.conclusion === "string" && run.conclusion.length > 0, "Latest Actions conclusion is missing.");
  const nowMs = now instanceof Date ? now.getTime() : Number.NaN;
  assert(Number.isFinite(nowMs), "Fallback clock is invalid.");
  assert(
    Number.isSafeInteger(policy.actionsQuietSeconds) && policy.actionsQuietSeconds >= 15 * 60,
    "Actions quiet-period policy is invalid.",
  );
  assert(
    updatedAt <= nowMs + policy.maximumFutureSkewSeconds * 1000,
    "Latest Actions snapshot update is from the future.",
  );
  const quietSeconds = (nowMs - updatedAt) / 1000;
  assert(quietSeconds >= policy.actionsQuietSeconds, "Latest Actions snapshot is not quiet long enough.");
  const observation = {
    id: run.id,
    head_sha: run.head_sha,
    status: run.status,
    conclusion: run.conclusion,
    created_at: run.created_at,
    updated_at: run.updated_at,
  };
  if (options.previous !== undefined) {
    assert(
      canonicalize(observation) === canonicalize(options.previous),
      "Latest Actions snapshot progressed during fallback validation.",
    );
  }
  return { observation, quietSeconds };
}

export function statusesMatchExactly(expected, observed) {
  try {
    validatePublicFallbackStatus(expected, new Date(expected.generated_at), {
      ...LOCAL_FALLBACK_POLICY,
      minimumStatusAgeSeconds: 3 * 60 * 60,
    });
    validatePublicFallbackStatus(observed, new Date(observed.generated_at), {
      ...LOCAL_FALLBACK_POLICY,
      minimumStatusAgeSeconds: 3 * 60 * 60,
    });
  } catch {
    return false;
  }
  return canonicalize(expected) === canonicalize(observed);
}

export function deploymentReadbackMatches(expected, observed) {
  return deploymentStatusMatches(expected, observed)
    && canonicalize(expected) === canonicalize(observed);
}

export function validateSshOrigin(url, policy = LOCAL_FALLBACK_POLICY) {
  assert(typeof url === "string" && url.length <= 256, "Origin URL is invalid.");
  let repository = null;
  const scp = SSH_SCP_RE.exec(url);
  if (scp) {
    repository = scp[1].replace(/\.git$/u, "");
  } else {
    let parsed;
    try {
      parsed = new URL(url);
    } catch {
      throw new Error("Origin URL is not an SSH URL.");
    }
    assert(parsed.protocol === "ssh:", "Origin URL is not SSH.");
    assert(parsed.username === "git" && parsed.password === "", "Origin SSH identity is invalid.");
    assert(parsed.hostname === "github.com" && parsed.port === "", "Origin SSH host is invalid.");
    assert(parsed.search === "" && parsed.hash === "", "Origin SSH URL is invalid.");
    repository = parsed.pathname.replace(/^\//u, "").replace(/\.git$/u, "").replace(/\/$/u, "");
  }
  assert(repository === policy.repository, "Origin SSH repository is not allowlisted.");
  return repository;
}

export function validateSnapshotPaths(paths) {
  assert(Array.isArray(paths), "Snapshot path list is invalid.");
  const unique = new Set();
  for (const candidate of paths) {
    assert(typeof candidate === "string" && candidate.length > 0, "Snapshot path is invalid.");
    assert(!unique.has(candidate), "Snapshot path list contains a duplicate.");
    unique.add(candidate);
    assert(
      candidate === "config/event.json"
        || (/^public\/data\/[A-Za-z0-9._/-]{1,200}$/u.test(candidate)
          && candidate.split("/").every(segment => segment !== "" && segment !== "." && segment !== "..")),
      "Snapshot changed a path outside the publication allowlist.",
    );
  }
  return [...unique].sort();
}
