import { canonicalize } from "./canonical.mjs";
import { sha256Hex } from "./crypto.mjs";
import { createEnvelope } from "./protocol.mjs";

const HASH_RE = /^[0-9a-f]{64}$/;
const COMMIT_RE = /^[0-9a-f]{40}$/;
const DID_RE = /^did:key:z6Mk[1-9A-HJ-NP-Za-km-z]+$/;
const ROOM_RE = /^d-[a-z0-9][a-z0-9_-]{0,45}$/;
const REPOSITORY_RE = /^[A-Za-z0-9_.-]{1,39}\/[A-Za-z0-9_.-]{1,100}$/;
const NETWORK_SAMPLE_SCHEMAS = new Set([
  "swarmproof-network-sample-v1",
  "swarmproof-network-sample-v2",
]);

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function parsedTime(value, label) {
  const milliseconds = Date.parse(value);
  assert(typeof value === "string" && Number.isFinite(milliseconds), `${label} is invalid.`);
  return milliseconds;
}

function sameCounter(left, right, label) {
  assert(Number.isSafeInteger(left) && left >= 0, `${label} is invalid in status.`);
  assert(left === right, `${label} does not match the report.`);
}

export function meaningfulCheckpointState(config, report) {
  const networkSample = report.network_sample;
  return {
    schema: "swarmproof-checkpoint-state-v1",
    event_state: report.event_state,
    starts_at: config.starts_at,
    ends_at: config.ends_at,
    source_event_count: report.source_event_count,
    source_digest: report.source_digest,
    signing_keys: report.signing_keys,
    evidence: report.evidence,
    events_sha256: sha256Hex(canonicalize(report.events)),
    rejected_sha256: sha256Hex(canonicalize(report.rejected)),
    unsigned_proposals_observed: report.unsigned_proposals_observed,
    build_room: {
      messages_observed_in_tail: report.build_room.messages_observed_in_tail,
      collection_failed: report.build_room.collection_error !== null,
    },
    network_sample: {
      schema: networkSample.schema,
      selection: networkSample.selection,
      aggregate: networkSample.aggregate,
      failures_sha256: sha256Hex(canonicalize(networkSample.failures)),
    },
  };
}

export function meaningfulCheckpointSha(config, report) {
  return sha256Hex(canonicalize(meaningfulCheckpointState(config, report)));
}

export function assessCheckpointChain(checkpoints) {
  assert(Array.isArray(checkpoints), "Remote checkpoint chain is invalid.");
  if (checkpoints.length === 0) return { eligible: false, reason: "awaiting_event_start" };
  const starts = checkpoints.filter(checkpoint => (
    checkpoint?.task_id === "event-start"
      && Array.isArray(checkpoint.parent_event_ids)
      && checkpoint.parent_event_ids.length === 0
  ));
  assert(starts.length === 1, "Remote checkpoint chain must contain exactly one event-start.");
  assert(checkpoints[0].event_id === starts[0].event_id, "event-start must be the first checkpoint by nonce.");
  for (let index = 1; index < checkpoints.length; index += 1) {
    const checkpoint = checkpoints[index];
    assert(checkpoint.task_id === "daily-checkpoint", "Only daily checkpoints may follow event-start.");
    assert(
      Array.isArray(checkpoint.parent_event_ids) && checkpoint.parent_event_ids.length === 1,
      "Daily checkpoint parent binding is invalid.",
    );
    assert(checkpoint.parent_event_ids[0] === checkpoints[index - 1].event_id, "Remote checkpoint chain is not linear.");
  }
  return { eligible: true, reason: "continuation" };
}

export function checkpointAgeSeconds(checkpoint, now = new Date()) {
  assert(checkpoint && typeof checkpoint === "object", "Remote checkpoint is missing.");
  const postedAt = parsedTime(checkpoint.posted_at, "remote checkpoint posted_at");
  const nowMs = now instanceof Date ? now.getTime() : Number.NaN;
  assert(Number.isFinite(nowMs), "Current time is invalid.");
  assert(postedAt <= nowMs + 300_000, "Remote checkpoint time is in the future.");
  return (nowMs - postedAt) / 1000;
}

export function assessSourceCommitComparison(comparison, sourceCommit) {
  assert(COMMIT_RE.test(sourceCommit ?? ""), "Source commit is invalid.");
  assert(comparison && typeof comparison === "object", "GitHub comparison is invalid.");
  assert(new Set(["ahead", "identical"]).has(comparison.status), "Published source commit is not an ancestor of trusted main.");
  assert(comparison.base_commit?.sha === sourceCommit, "GitHub comparison base does not match the published source commit.");
  assert(comparison.merge_base_commit?.sha === sourceCommit, "Published source commit is not the trusted-main merge base.");
  const commits = Array.isArray(comparison.commits) ? comparison.commits : [];
  const headCommit = comparison.status === "identical"
    ? sourceCommit
    : commits.at(-1)?.sha;
  assert(COMMIT_RE.test(headCommit ?? ""), "GitHub comparison head is invalid.");
  return { eligible: true, main_commit: headCommit };
}

export function assessCheckpointInputs({
  config,
  report,
  status,
  now = new Date(),
  maxAgeSeconds = null,
}) {
  assert(config && typeof config === "object", "Event config is missing.");
  if (!new Set(["active", "complete"]).has(config.state)) {
    return { eligible: false, reason: "config_not_maintained" };
  }

  assert(report && typeof report === "object", "Public report is missing.");
  assert(status && typeof status === "object", "Public status is missing.");
  assert(report.schema === "swarmproof-report-v1", "Unsupported report schema.");
  assert(status.schema === "swarmproof-status-v1", "Unsupported status schema.");
  assert(DID_RE.test(config.coordinator_did ?? ""), "Coordinator DID is invalid.");
  assert(ROOM_RE.test(config.official_room ?? ""), "Official room must be a valid owned d- room.");
  assert(REPOSITORY_RE.test(config.repository ?? ""), "Repository is invalid.");

  if (report.event_state !== config.state || status.state !== config.state) {
    return { eligible: false, reason: "public_state_mismatch" };
  }

  const nowMs = now instanceof Date ? now.getTime() : Number.NaN;
  assert(Number.isFinite(nowMs), "Current time is invalid.");
  const startsAt = parsedTime(config.starts_at, "starts_at");
  const endsAt = parsedTime(config.ends_at, "ends_at");
  assert(endsAt > startsAt, "ends_at must be after starts_at.");
  assert(endsAt - startsAt === 48 * 60 * 60 * 1000, "Event window must be exactly 48 hours.");
  assert(status.starts_at === config.starts_at && status.ends_at === config.ends_at, "Public status event window does not match config.");
  if (nowMs < startsAt) return { eligible: false, reason: "event_not_started" };
  if (config.state === "active" && nowMs > endsAt) {
    return { eligible: false, reason: "active_event_window_ended" };
  }
  if (config.state === "complete" && nowMs < endsAt) {
    return { eligible: false, reason: "complete_before_event_end" };
  }

  assert(report.generated_at === status.generated_at, "Report and status generation times differ.");
  const generatedAt = parsedTime(status.generated_at, "generated_at");
  assert(generatedAt <= nowMs + 300_000, "Public status is too far in the future.");
  assert(Number.isSafeInteger(status.stale_after_seconds) && status.stale_after_seconds > 0, "Public status staleness bound is invalid.");
  if (maxAgeSeconds !== null) assert(Number.isFinite(maxAgeSeconds) && maxAgeSeconds > 0, "Maximum age must be positive.");
  const effectiveMaxAgeSeconds = maxAgeSeconds === null
    ? status.stale_after_seconds
    : Math.min(maxAgeSeconds, status.stale_after_seconds);
  if (nowMs - generatedAt > effectiveMaxAgeSeconds * 1000) {
    return { eligible: false, reason: "public_status_stale" };
  }

  assert(COMMIT_RE.test(status.source_commit ?? ""), "Public status has no immutable source commit.");
  const reportSha256 = sha256Hex(canonicalize(report));
  assert(HASH_RE.test(status.report_sha256 ?? ""), "Status report hash is invalid.");
  assert(status.report_sha256 === reportSha256, "Status report hash does not match report.json.");
  assert(HASH_RE.test(report.source_digest ?? ""), "Report source digest is invalid.");
  assert(Array.isArray(report.events), "Report events are invalid.");
  assert(Array.isArray(report.rejected), "Report rejected events are invalid.");
  assert(report.evidence && typeof report.evidence === "object", "Report evidence is invalid.");
  assert(report.build_room && typeof report.build_room === "object", "Build-room status is invalid.");
  if (report.build_room.collection_error !== null) {
    return { eligible: false, reason: "build_room_collection_failed" };
  }

  sameCounter(status.signing_keys, report.signing_keys, "signing_keys");
  sameCounter(status.reproducible_artifacts, report.evidence.reproducible, "reproducible_artifacts");
  sameCounter(status.cross_key_reviews, report.evidence.cross_key_reviewed, "cross_key_reviews");
  sameCounter(status.accepted_results, report.evidence.accepted, "accepted_results");

  const sample = report.network_sample;
  assert(sample && typeof sample === "object", "Network sample is missing.");
  assert(NETWORK_SAMPLE_SCHEMAS.has(sample.schema), "Unsupported network sample schema.");
  assert(sample.selection && sample.aggregate, "Network sample is incomplete.");
  const sampleGeneratedAt = parsedTime(sample.generated_at, "network_sample.generated_at");
  assert(sampleGeneratedAt <= generatedAt + 300_000, "Network sample is newer than the public report.");
  const requestedRooms = config.sample?.rooms;
  const requestedMessages = config.sample?.messages_per_room;
  const networkSnapshotHours = config.sample?.network_snapshot_hours;
  assert(Number.isSafeInteger(requestedRooms) && requestedRooms > 0, "Configured room sample is invalid.");
  assert(Number.isSafeInteger(requestedMessages) && requestedMessages > 0, "Configured message sample is invalid.");
  assert(Number.isFinite(networkSnapshotHours) && networkSnapshotHours > 0, "Configured network cadence is invalid.");
  const maximumNetworkAgeSeconds = config.state === "complete"
    ? Math.max(networkSnapshotHours * 3600 + 1800, 26 * 3600)
    : networkSnapshotHours * 3600 + 1800;
  if (nowMs - sampleGeneratedAt > maximumNetworkAgeSeconds * 1000) {
    return { eligible: false, reason: "network_sample_stale" };
  }
  if (
    sample.selection.rooms_requested !== requestedRooms
    || sample.selection.messages_per_room_requested !== requestedMessages
    || sample.selection.rooms_returned !== requestedRooms
    || sample.selection.rooms_failed !== 0
    || !(sample.aggregate.messages > 0)
  ) {
    return { eligible: false, reason: "network_sample_incomplete" };
  }
  assert(Array.isArray(sample.failures), "Network sample failures are invalid.");
  if (sample.failures.length !== 0) {
    return { eligible: false, reason: "network_sample_incomplete" };
  }

  return {
    eligible: true,
    reason: "eligible",
    report_sha256: reportSha256,
    meaningful_sha256: meaningfulCheckpointSha(config, report),
  };
}

export function createCheckpointEnvelope({
  config,
  reportSha256,
  privateKeyPem,
  nonce,
  claimedAt,
  parentEventId = null,
}) {
  assert(HASH_RE.test(reportSha256 ?? ""), "Checkpoint report hash is invalid.");
  assert(/^[0-9]{1,19}$/.test(nonce ?? ""), "Checkpoint nonce is invalid.");
  assert(typeof claimedAt === "string" && Number.isFinite(Date.parse(claimedAt)), "Checkpoint time is invalid.");
  if (parentEventId !== null) assert(HASH_RE.test(parentEventId), "Parent checkpoint event ID is invalid.");

  const created = createEnvelope({
    schema: "swarmproof-event-v1",
    type: "CHECKPOINT",
    task_id: parentEventId === null ? "event-start" : "daily-checkpoint",
    did: config.coordinator_did,
    claimed_at: claimedAt,
    nonce,
    parent_event_ids: parentEventId === null ? [] : [parentEventId],
    content_sha256: reportSha256,
  }, privateKeyPem, {
    allowedRepositories: new Set([config.repository]),
    allowedTasks: new Set(["event-start", "daily-checkpoint"]),
    coordinatorDid: config.coordinator_did,
  });
  assert(created.payload.did === config.coordinator_did, "Private key does not match the coordinator DID.");
  return created;
}
