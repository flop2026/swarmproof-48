import { sha256Hex } from "./crypto.mjs";
import { verifyEnvelope } from "./protocol.mjs";

const WINDOW_TYPES = new Set(["TASK", "CLAIM", "RESULT", "REVIEW", "PROMOTE"]);
const WINDOW_END_TYPES = new Set(["TASK", "CLAIM", "RESULT", "REVIEW"]);
const DAG_EVIDENCE_TYPES = new Set(["TASK", "CLAIM", "RESULT", "REVIEW"]);

function claimedMillis(event) {
  return Date.parse(event.payload.claimed_at);
}

export function compareEventChronology(left, right) {
  if (
    left.source_room
    && left.source_room === right.source_room
    && Number.isSafeInteger(left.source_seq)
    && Number.isSafeInteger(right.source_seq)
    && left.source_seq !== right.source_seq
  ) {
    return left.source_seq - right.source_seq;
  }
  const leftObserved = left.observed_at ?? left.payload.claimed_at;
  const rightObserved = right.observed_at ?? right.payload.claimed_at;
  return leftObserved.localeCompare(rightObserved)
    || (left.source_seq ?? Number.MAX_SAFE_INTEGER) - (right.source_seq ?? Number.MAX_SAFE_INTEGER)
    || left.event_id.localeCompare(right.event_id);
}

export function resultArtifactIdentity(event) {
  const artifact = event.payload.artifact;
  return [
    artifact.repository,
    artifact.sha256,
  ].join("\u0000");
}

function parentPrecedes(parent, child) {
  if (claimedMillis(parent) > claimedMillis(child)) return false;
  const parentSource = Date.parse(parent.source_ts ?? "");
  const childSource = Date.parse(child.source_ts ?? "");
  if (Number.isFinite(parentSource) && Number.isFinite(childSource) && parentSource > childSource) return false;
  if (
    parent.source_room
    && parent.source_room === child.source_room
    && Number.isSafeInteger(parent.source_seq)
    && Number.isSafeInteger(child.source_seq)
  ) {
    return parent.source_seq < child.source_seq;
  }
  return true;
}

function addReason(state, eventId, reason) {
  const key = `${eventId}\u0000${reason}`;
  if (state.reasonKeys.has(key)) return;
  state.reasonKeys.add(key);
  state.reasons.push({ event_id: eventId, reason });
}

function matchingTask(parent, child, coordinatorDid) {
  return parent?.payload.type === "TASK"
    && parent.payload.task_id === child.payload.task_id
    && (!coordinatorDid || parent.payload.did === coordinatorDid);
}

/**
 * Resolve the project-level event DAG after structural signature verification.
 * This does not infer operator independence; it only validates signed ancestry and ordering.
 */
export function analyzeEventSemantics(records, options = {}) {
  const allowedRepositories = options.allowedRepositories
    ? new Set(options.allowedRepositories)
    : undefined;
  const verified = [];
  const rejected = [];
  const seenEventIds = new Set();

  for (const record of records) {
    try {
      const event = verifyEnvelope(record.envelope, {
        allowedRepositories,
        allowedTasks: options.allowedTasks,
        coordinatorDid: options.coordinatorDid,
      });
      if (seenEventIds.has(event.event_id)) continue;
      seenEventIds.add(event.event_id);
      verified.push({
        ...event,
        observed_at: record.observed_at ?? null,
        source_ts: record.source_ts ?? null,
        source_room: record.source_room ?? null,
        source_seq: record.source_seq ?? null,
      });
    } catch (error) {
      rejected.push({
        envelope_sha256: sha256Hex(String(record.envelope ?? "")),
        reason: error.message,
      });
    }
  }

  const eventById = new Map(verified.map(event => [event.event_id, event]));
  const state = { reasons: [], reasonKeys: new Set() };
  const baseEligible = new Set();
  const startsAt = Date.parse(options.startsAt ?? "");
  const endsAt = Date.parse(options.endsAt ?? "");

  for (const event of verified) {
    const claimedAt = claimedMillis(event);
    const observedAt = Date.parse(event.observed_at ?? "");
    const sourceTs = Date.parse(event.source_ts ?? "");
    let reason = null;
    if (Number.isFinite(observedAt) && claimedAt > observedAt + 5 * 60 * 1000) {
      reason = "claimed-at-too-far-after-observation";
    } else if (WINDOW_TYPES.has(event.payload.type) && Number.isFinite(startsAt) && claimedAt < startsAt) {
      reason = "claimed-before-event-window";
    } else if (WINDOW_END_TYPES.has(event.payload.type) && Number.isFinite(endsAt) && claimedAt > endsAt) {
      reason = "claimed-after-event-window";
    } else if (
      DAG_EVIDENCE_TYPES.has(event.payload.type)
      && Number.isFinite(startsAt)
      && Number.isFinite(endsAt)
      && (!Number.isFinite(sourceTs) || sourceTs < startsAt || sourceTs > endsAt)
    ) {
      reason = "source-time-outside-event-window";
    } else if (
      DAG_EVIDENCE_TYPES.has(event.payload.type)
      && Number.isFinite(sourceTs)
      && claimedAt > sourceTs + 5 * 60 * 1000
    ) {
      reason = "claimed-at-too-far-after-source";
    }
    if (reason) addReason(state, event.event_id, reason);
    else baseEligible.add(event.event_id);
  }

  const validTaskIds = new Set();
  for (const event of verified) {
    if (event.payload.type !== "TASK" || !baseEligible.has(event.event_id)) continue;
    validTaskIds.add(event.event_id);
  }

  const validClaimIds = new Set();
  const claimTaskRoot = new Map();
  for (const event of verified) {
    if (event.payload.type !== "CLAIM" || !baseEligible.has(event.event_id)) continue;
    const [parentId] = event.payload.parent_event_ids;
    const parent = eventById.get(parentId);
    if (
      event.payload.parent_event_ids.length !== 1
      || !parent
      || !validTaskIds.has(parentId)
      || !matchingTask(parent, event, options.coordinatorDid)
    ) {
      addReason(state, event.event_id, "claim-parent-is-not-a-matching-coordinator-task");
      continue;
    }
    if (!parentPrecedes(parent, event)) {
      addReason(state, event.event_id, "parent-does-not-precede-child");
      continue;
    }
    validClaimIds.add(event.event_id);
    claimTaskRoot.set(event.event_id, parentId);
  }

  const validResultIds = new Set();
  const resultTaskRoot = new Map();
  for (const event of verified) {
    if (event.payload.type !== "RESULT" || !baseEligible.has(event.event_id)) continue;
    if (event.payload.parent_event_ids.length !== 1) {
      addReason(state, event.event_id, "result-requires-one-task-or-claim-parent");
      continue;
    }
    const parentId = event.payload.parent_event_ids[0];
    const parent = eventById.get(parentId);
    let taskRoot = null;
    if (parent && validTaskIds.has(parentId) && matchingTask(parent, event, options.coordinatorDid)) {
      taskRoot = parentId;
    } else if (
      parent
      && validClaimIds.has(parentId)
      && parent.payload.task_id === event.payload.task_id
      && parent.payload.did === event.payload.did
    ) {
      taskRoot = claimTaskRoot.get(parentId) ?? null;
    }
    if (!taskRoot) {
      addReason(state, event.event_id, "result-parent-has-no-matching-task-ancestry");
      continue;
    }
    if (!parentPrecedes(parent, event)) {
      addReason(state, event.event_id, "parent-does-not-precede-child");
      continue;
    }
    validResultIds.add(event.event_id);
    resultTaskRoot.set(event.event_id, taskRoot);
  }

  const validReviewIds = new Set();
  const validPassReviews = new Map();
  for (const event of verified) {
    if (event.payload.type !== "REVIEW" || !baseEligible.has(event.event_id)) continue;
    const targetId = event.payload.review.target_event_id;
    const target = eventById.get(targetId);
    if (
      event.payload.parent_event_ids.length !== 1
      || event.payload.parent_event_ids[0] !== targetId
      || !target
      || !validResultIds.has(targetId)
      || target.payload.task_id !== event.payload.task_id
      || target.payload.content_sha256 !== event.payload.content_sha256
    ) {
      addReason(state, event.event_id, "review-target-is-not-a-matching-result");
      continue;
    }
    if (!parentPrecedes(target, event)) {
      addReason(state, event.event_id, "parent-does-not-precede-child");
      continue;
    }
    validReviewIds.add(event.event_id);
    if (event.payload.review.verdict === "PASS") {
      const reviewers = validPassReviews.get(targetId) ?? new Set();
      reviewers.add(event.payload.did);
      validPassReviews.set(targetId, reviewers);
    }
  }

  const validPromotionIds = new Set();
  const promotedResultIds = new Set();
  for (const event of verified) {
    if (event.payload.type !== "PROMOTE" || !baseEligible.has(event.event_id)) continue;
    const targetId = event.payload.parent_event_ids[0];
    const target = eventById.get(targetId);
    if (
      event.payload.parent_event_ids.length !== 1
      || !target
      || !validResultIds.has(targetId)
      || target.payload.task_id !== event.payload.task_id
      || target.payload.content_sha256 !== event.payload.content_sha256
    ) {
      addReason(state, event.event_id, "promotion-target-is-not-a-matching-result");
      continue;
    }
    if (!parentPrecedes(target, event)) {
      addReason(state, event.event_id, "parent-does-not-precede-child");
      continue;
    }
    const latestPriorReviewByKey = new Map();
    for (const review of verified
      .filter(candidate => (
        validReviewIds.has(candidate.event_id)
        && candidate.payload.did !== target.payload.did
        && candidate.payload.review?.target_event_id === targetId
        && parentPrecedes(candidate, event)
      ))
      .sort(compareEventChronology)) {
      latestPriorReviewByKey.set(review.payload.did, review);
    }
    const priorCrossKeyPass = [...latestPriorReviewByKey.values()]
      .some(review => review.payload.review.verdict === "PASS");
    if (!priorCrossKeyPass) {
      addReason(state, event.event_id, "promotion-requires-prior-cross-key-pass-review");
      continue;
    }
    validPromotionIds.add(event.event_id);
    promotedResultIds.add(targetId);
  }

  const validCheckpointIds = new Set();
  for (const event of [...verified].sort(compareEventChronology)) {
    if (event.payload.type !== "CHECKPOINT" || !baseEligible.has(event.event_id)) continue;
    if (event.payload.parent_event_ids.length === 0) {
      if (event.payload.task_id === "event-start") validCheckpointIds.add(event.event_id);
      else addReason(state, event.event_id, "root-checkpoint-must-be-event-start");
      continue;
    }
    const parent = eventById.get(event.payload.parent_event_ids[0]);
    if (
      event.payload.task_id !== "daily-checkpoint"
      || !parent
      || parent.payload.type !== "CHECKPOINT"
      || parent.payload.did !== event.payload.did
      || !validCheckpointIds.has(parent.event_id)
    ) {
      addReason(state, event.event_id, "checkpoint-parent-is-not-a-valid-checkpoint");
      continue;
    }
    if (!parentPrecedes(parent, event)) {
      addReason(state, event.event_id, "parent-does-not-precede-child");
      continue;
    }
    validCheckpointIds.add(event.event_id);
  }

  const semanticEligible = new Set([
    ...validTaskIds,
    ...validClaimIds,
    ...validResultIds,
    ...validReviewIds,
    ...validPromotionIds,
    ...validCheckpointIds,
  ]);

  return {
    verified,
    rejected,
    eventById,
    baseEligible,
    semanticEligible,
    validTaskIds,
    validClaimIds,
    validResultIds,
    validReviewIds,
    validPromotionIds,
    validCheckpointIds,
    resultTaskRoot,
    validPassReviews,
    promotedResultIds,
    semanticallyIgnored: state.reasons,
  };
}
