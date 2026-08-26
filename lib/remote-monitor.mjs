import { reconcilePublishedState } from "./lifecycle.mjs";
import { assessCheckpointChain, checkpointAgeSeconds } from "./checkpoint.mjs";
import { sha256Hex } from "./crypto.mjs";
import { verifyEnvelope } from "./protocol.mjs";

const HASH_RE = /^[0-9a-f]{64}$/u;
const COMMIT_RE = /^[0-9a-f]{40}$/u;
const DID_RE = /^did:key:z6Mk[1-9A-HJ-NP-Za-km-z]+$/u;
const CANONICAL_TIME_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u;
const PROFILE_ALIAS_RE = /^[a-z0-9][a-z0-9_-]{0,63}$/u;
const STATUS_KEYS = new Set([
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

export const REMOTE_MONITOR_POLICY = Object.freeze({
  publicOrigin: "https://swarmproof-48-e463.pages.dev",
  technocoreOrigin: "https://technocore.chat",
  repository: "flop2026/swarmproof-48",
  coordinatorDid: "did:key:z6MkqNyQTuVH8ZqJc5HZ2M9FGDDWBmVupBrX96G3EA3J5gSw",
  officialRoom: "d-swarmproof-48-e463",
  profileAlias: "swarmproof-e463",
  launchEventId: "7c9cb51d2c52670c0d2ef5c485ca0bbf9684742c40b79ee2c4c756a475dd11fd",
  maximumAgeSeconds: 26 * 60 * 60,
  maximumFutureSkewSeconds: 5 * 60,
});

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function isPlainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function canonicalMilliseconds(value, label) {
  assert(typeof value === "string" && CANONICAL_TIME_RE.test(value), `${label} is not canonical UTC.`);
  const milliseconds = Date.parse(value);
  assert(Number.isFinite(milliseconds) && new Date(milliseconds).toISOString() === value, `${label} is invalid.`);
  return milliseconds;
}

function currentMilliseconds(now) {
  const milliseconds = now instanceof Date ? now.getTime() : Number.NaN;
  assert(Number.isFinite(milliseconds), "Current time is invalid.");
  return milliseconds;
}

function boundedAgeSeconds(value, label, now, policy) {
  const nowMs = currentMilliseconds(now);
  const valueMs = canonicalMilliseconds(value, label);
  const ageSeconds = (nowMs - valueMs) / 1000;
  assert(ageSeconds >= -policy.maximumFutureSkewSeconds, `${label} is too far in the future.`);
  assert(ageSeconds <= policy.maximumAgeSeconds, `${label} is older than 26 hours.`);
  return Math.max(0, ageSeconds);
}

function validatePolicy(policy) {
  assert(isPlainObject(policy), "Remote-monitor policy is invalid.");
  assert(new URL(policy.publicOrigin).origin === policy.publicOrigin, "Public origin policy is invalid.");
  assert(new URL(policy.technocoreOrigin).origin === policy.technocoreOrigin, "Technocore origin policy is invalid.");
  assert(/^[A-Za-z0-9_.-]{1,39}\/[A-Za-z0-9_.-]{1,100}$/u.test(policy.repository ?? ""), "Repository policy is invalid.");
  assert(DID_RE.test(policy.coordinatorDid ?? ""), "Coordinator DID policy is invalid.");
  assert(/^d-[a-z0-9][a-z0-9_-]{0,45}$/u.test(policy.officialRoom ?? ""), "Official-room policy is invalid.");
  assert(PROFILE_ALIAS_RE.test(policy.profileAlias ?? ""), "Profile alias policy is invalid.");
  assert(HASH_RE.test(policy.launchEventId ?? ""), "Launch-event policy is invalid.");
  assert(policy.maximumAgeSeconds === 26 * 60 * 60, "Remote-monitor age policy must be 26 hours.");
  assert(policy.maximumFutureSkewSeconds === 5 * 60, "Remote-monitor clock-skew policy is invalid.");
}

export function profilePathForDid(did) {
  assert(DID_RE.test(did ?? ""), "Profile DID is invalid.");
  const fingerprint = sha256Hex(did).slice(0, 16);
  return `/kv/did-${fingerprint.slice(0, 2)}/${fingerprint.slice(2)}`;
}

export function remoteMonitorEndpoints(config, nonce, policy = REMOTE_MONITOR_POLICY) {
  validatePolicy(policy);
  validateMonitorConfig(config, policy);
  assert(/^[0-9]{1,19}$/u.test(nonce ?? ""), "Monitor request nonce is invalid.");
  return Object.freeze({
    status: `${policy.publicOrigin}/data/status.json?n=${nonce}`,
    profile: `${policy.technocoreOrigin}${profilePathForDid(policy.coordinatorDid)}`,
    owner: `${policy.technocoreOrigin}/kv/room-owners/${encodeURIComponent(policy.officialRoom)}`,
    room: `${policy.technocoreOrigin}/r/${encodeURIComponent(policy.officialRoom)}?format=json&limit=200&n=${nonce}`,
  });
}

export function validateMonitorConfig(config, policy = REMOTE_MONITOR_POLICY) {
  validatePolicy(policy);
  assert(isPlainObject(config), "Event config is invalid.");
  assert(config.repository === policy.repository, "Event repository does not match the monitor policy.");
  assert(config.coordinator_did === policy.coordinatorDid, "Event DID does not match the monitor policy.");
  assert(config.official_room === policy.officialRoom, "Official room does not match the monitor policy.");
  assert(new Set(["active", "complete"]).has(config.state), "Remote monitoring requires an active or complete event.");
  const startsAt = canonicalMilliseconds(config.starts_at, "config.starts_at");
  const endsAt = canonicalMilliseconds(config.ends_at, "config.ends_at");
  assert(endsAt - startsAt === 48 * 60 * 60 * 1000, "Event window must be exactly 48 hours.");
  return config;
}

export function validatePublicStatus(config, status, now = new Date(), policy = REMOTE_MONITOR_POLICY) {
  validateMonitorConfig(config, policy);
  assert(isPlainObject(status), "Published status is invalid.");
  assert(Object.keys(status).length === STATUS_KEYS.size, "Published status fields are invalid.");
  for (const key of Object.keys(status)) assert(STATUS_KEYS.has(key), `Published status contains an unknown field: ${key}`);
  assert(status.schema === "swarmproof-status-v1", "Published status schema is invalid.");
  assert(new Set(["active", "complete"]).has(status.state), "Published status state is invalid.");
  const effectiveConfig = reconcilePublishedState(config, status);
  assert(status.starts_at === effectiveConfig.starts_at && status.ends_at === effectiveConfig.ends_at, "Published status window is invalid.");
  assert(COMMIT_RE.test(status.source_commit ?? ""), "Published status source commit is invalid.");
  for (const key of ["report_sha256", "audit_core_sha256", "snapshot_manifest_sha256"]) {
    assert(HASH_RE.test(status[key] ?? ""), `Published status ${key} is invalid.`);
  }
  for (const key of ["signing_keys", "reproducible_artifacts", "cross_key_reviews", "accepted_results", "stale_after_seconds"]) {
    assert(Number.isSafeInteger(status[key]) && status[key] >= 0, `Published status ${key} is invalid.`);
  }
  assert(status.stale_after_seconds > 0, "Published status staleness bound is invalid.");

  const nowMs = currentMilliseconds(now);
  const generatedAt = canonicalMilliseconds(status.generated_at, "Published status generated_at");
  const ageSeconds = (nowMs - generatedAt) / 1000;
  assert(ageSeconds >= -policy.maximumFutureSkewSeconds, "Published status is too far in the future.");
  assert(
    ageSeconds <= Math.min(status.stale_after_seconds, policy.maximumAgeSeconds),
    "Published status is stale.",
  );
  return { effectiveConfig, ageSeconds: Math.max(0, ageSeconds) };
}

export function expectedProfileStatic(config, policy = REMOTE_MONITOR_POLICY) {
  validateMonitorConfig(config, policy);
  return [
    policy.coordinatorDid,
    `alias:${policy.profileAlias}`,
    "role:evidence_coordinator",
    "project:swarmproof-48",
    "capabilities:signed_protocol,replayable_audit,privacy_preserving_aggregation",
    "contribution:copyprint_coverage_ladder",
    `official_room:${policy.officialRoom}`,
    `status:${config.state}`,
    `repository:https://github.com/${policy.repository}`,
    `site:${policy.publicOrigin}`,
  ].join(" ");
}

function profileRecordFromBody(body, did) {
  assert(typeof body === "string", "DID profile response is invalid.");
  const candidates = body
    .split(/\r?\n/u)
    .map(line => line.trim())
    .filter(line => line.startsWith(`${did} `));
  assert(candidates.length === 1, "DID profile identity is missing or ambiguous.");
  return candidates[0];
}

export function validateDidProfile(config, body, now = new Date(), policy = REMOTE_MONITOR_POLICY) {
  const profile = profileRecordFromBody(body, policy.coordinatorDid);
  const marker = " updated_at:";
  const markerIndex = profile.lastIndexOf(marker);
  assert(markerIndex > 0, "DID profile maintenance time is missing.");
  assert(profile.slice(0, markerIndex) === expectedProfileStatic(config, policy), "DID profile identity or state does not match.");
  const updatedAt = profile.slice(markerIndex + marker.length);
  const ageSeconds = boundedAgeSeconds(updatedAt, "DID profile updated_at", now, policy);
  return { updatedAt, ageSeconds };
}

export function validateOfficialRoomOwner(body, policy = REMOTE_MONITOR_POLICY) {
  validatePolicy(policy);
  assert(typeof body === "string", "Official-room owner response is invalid.");
  const dids = body
    .split(/\r?\n/u)
    .map(line => line.trim())
    .filter(line => DID_RE.test(line));
  assert(dids.length === 1, "Official-room owner is missing or ambiguous.");
  assert(dids[0] === policy.coordinatorDid, "Official room is not owned by the coordinator DID.");
  return { ownerDid: dids[0] };
}

export function verifiedCheckpointsFromRoom(room, config, policy = REMOTE_MONITOR_POLICY) {
  validateMonitorConfig(config, policy);
  assert(isPlainObject(room) && room.room === policy.officialRoom, "Official-room response identity is invalid.");
  assert(Array.isArray(room.messages) && room.messages.length <= 200, "Official-room response is invalid or oversized.");
  const checkpoints = [];
  const seenEventIds = new Set();
  for (const message of room.messages) {
    if (!isPlainObject(message) || message.from !== policy.coordinatorDid || typeof message.text !== "string") continue;
    try {
      const verified = verifyEnvelope(message.text, {
        allowedRepositories: new Set([policy.repository]),
        allowedTasks: new Set(["event-start", "daily-checkpoint"]),
        coordinatorDid: policy.coordinatorDid,
      });
      if (
        verified.payload.type !== "CHECKPOINT"
        || verified.payload.did !== policy.coordinatorDid
        || String(message.nonce ?? "") !== verified.payload.nonce
        || seenEventIds.has(verified.event_id)
      ) continue;
      seenEventIds.add(verified.event_id);
      checkpoints.push({
        event_id: verified.event_id,
        report_sha256: verified.payload.content_sha256,
        nonce: verified.payload.nonce,
        posted_at: verified.payload.claimed_at,
        task_id: verified.payload.task_id,
        parent_event_ids: verified.payload.parent_event_ids,
      });
    } catch {
      // Official-room content is untrusted; malformed or unauthorized messages are not evidence.
    }
  }
  checkpoints.sort((left, right) => {
    const leftNonce = BigInt(left.nonce);
    const rightNonce = BigInt(right.nonce);
    return leftNonce < rightNonce ? -1 : leftNonce > rightNonce ? 1 : 0;
  });
  assert(new Set(checkpoints.map(checkpoint => checkpoint.nonce)).size === checkpoints.length, "Verified checkpoint nonces are not unique.");
  return checkpoints;
}

export function validateCheckpointChain(room, config, now = new Date(), policy = REMOTE_MONITOR_POLICY) {
  const checkpoints = verifiedCheckpointsFromRoom(room, config, policy);
  const chain = assessCheckpointChain(checkpoints);
  assert(chain.eligible, "Verified checkpoint chain has no launch event.");
  assert(checkpoints[0].event_id === policy.launchEventId, "Verified checkpoint chain does not contain the pinned launch event.");
  const latest = checkpoints.at(-1);
  const ageSeconds = checkpointAgeSeconds(latest, now);
  assert(ageSeconds <= policy.maximumAgeSeconds, "Latest verified signed checkpoint is older than 26 hours.");
  return { checkpointCount: checkpoints.length, latest, ageSeconds: Math.max(0, ageSeconds) };
}

export function validateRemoteMonitor({
  config,
  status,
  profileBody,
  ownerBody,
  room,
  now = new Date(),
  policy = REMOTE_MONITOR_POLICY,
}) {
  const statusResult = validatePublicStatus(config, status, now, policy);
  const profileResult = validateDidProfile(statusResult.effectiveConfig, profileBody, now, policy);
  validateOfficialRoomOwner(ownerBody, policy);
  const checkpointResult = validateCheckpointChain(room, statusResult.effectiveConfig, now, policy);
  return {
    statusAgeSeconds: statusResult.ageSeconds,
    profileAgeSeconds: profileResult.ageSeconds,
    checkpointAgeSeconds: checkpointResult.ageSeconds,
    latestCheckpointEventId: checkpointResult.latest.event_id,
    checkpointCount: checkpointResult.checkpointCount,
    state: statusResult.effectiveConfig.state,
  };
}
