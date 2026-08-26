import { sha256Hex } from "./crypto.mjs";
import { canonicalize } from "./canonical.mjs";
import {
  analyzeEventSemantics,
  compareEventChronology,
  resultArtifactIdentity,
} from "./semantics.mjs";

const PARTS_PER_MILLION = 1_000_000;

function ppm(numerator, denominator) {
  return denominator === 0 ? 0 : Math.round((numerator * PARTS_PER_MILLION) / denominator);
}

function analyzeReviews(graph, reproducibleResultIds) {
  const validReviews = graph.verified
    .filter(event => graph.validReviewIds.has(event.event_id))
    .sort(compareEventChronology);
  const historyByPair = new Map();
  const effectiveByPair = new Map();
  for (const event of validReviews) {
    const targetId = event.payload.review.target_event_id;
    const pair = `${targetId}\u0000${event.payload.did}`;
    const history = historyByPair.get(pair) ?? [];
    history.push(event);
    historyByPair.set(pair, history);
    effectiveByPair.set(pair, event);
  }

  const effective = [...effectiveByPair.values()]
    .sort(compareEventChronology);
  const crossKey = effective.filter(event => (
    graph.eventById.get(event.payload.review.target_event_id)?.payload.did !== event.payload.did
  ));
  const effectivePassReviewersByTarget = new Map();
  for (const event of crossKey) {
    if (event.payload.review.verdict !== "PASS") continue;
    const targetId = event.payload.review.target_event_id;
    const reviewers = effectivePassReviewersByTarget.get(targetId) ?? new Set();
    reviewers.add(event.payload.did);
    effectivePassReviewersByTarget.set(targetId, reviewers);
  }

  const countsByReviewer = new Map();
  const crossKeyReviewersByTarget = new Map();
  const verdicts = { pass: 0, changes: 0, reject: 0 };
  for (const event of crossKey) {
    countsByReviewer.set(event.payload.did, (countsByReviewer.get(event.payload.did) ?? 0) + 1);
    const targetId = event.payload.review.target_event_id;
    const reviewers = crossKeyReviewersByTarget.get(targetId) ?? new Set();
    reviewers.add(event.payload.did);
    crossKeyReviewersByTarget.set(targetId, reviewers);
    verdicts[event.payload.review.verdict.toLowerCase()] += 1;
  }
  const reviewerCounts = [...countsByReviewer.values()];
  const pairCount = crossKey.length;
  const hhiNumerator = reviewerCounts.reduce((sum, count) => sum + count * count, 0);
  const passTargetsReproducible = new Set(
    crossKey
      .filter(event => (
        event.payload.review.verdict === "PASS"
        && reproducibleResultIds.has(event.payload.review.target_event_id)
      ))
      .map(event => event.payload.review.target_event_id),
  );

  return {
    effectivePassReviewersByTarget,
    evidence: {
      basis: "latest-valid-review-per-reviewer-key-and-result",
      valid_review_events: validReviews.length,
      effective_reviewer_result_pairs: effective.length,
      superseded_review_events: validReviews.length - effective.length,
      conflicting_reviewer_result_pairs: [...historyByPair.values()].filter(history => (
        new Set(history.map(event => event.payload.review.verdict)).size > 1
      )).length,
      effective_cross_key_pairs: pairCount,
      effective_cross_key_pass_pairs: verdicts.pass,
      cross_key_pass_pairs_targeting_reproducible_results: crossKey.filter(event => (
        event.payload.review.verdict === "PASS"
        && reproducibleResultIds.has(event.payload.review.target_event_id)
      )).length,
      result_targets_with_cross_key_review: crossKeyReviewersByTarget.size,
      reproducible_result_targets_with_cross_key_pass_review: passTargetsReproducible.size,
      result_targets_with_multiple_cross_key_reviewers: [...crossKeyReviewersByTarget.values()]
        .filter(reviewers => reviewers.size > 1).length,
      unique_cross_key_reviewer_keys: countsByReviewer.size,
      effective_cross_key_verdicts: verdicts,
      top_cross_key_reviewer_share_ppm: ppm(Math.max(0, ...reviewerCounts), pairCount),
      cross_key_reviewer_hhi_ppm: pairCount === 0 ? 0 : ppm(hhiNumerator, pairCount * pairCount),
      independence: "unknown",
    },
  };
}

export function auditEvents(records, options = {}) {
  const allowedRepositories = options.allowedRepositories
    ? new Set(options.allowedRepositories)
    : undefined;
  const artifactChecks = options.artifactChecks ?? {};
  const acceptedIds = new Set(options.acceptedIds ?? []);
  const graph = analyzeEventSemantics(records, {
    allowedRepositories,
    allowedTasks: options.allowedTasks,
    coordinatorDid: options.coordinatorDid,
    startsAt: options.startsAt,
    endsAt: options.endsAt,
  });
  const verified = graph.verified;
  const rejected = graph.rejected;
  const semanticallyIgnored = [...graph.semanticallyIgnored];
  const resultRepresentativeByArtifact = new Map();
  const duplicateResultIds = new Set();
  for (const event of verified
    .filter(candidate => graph.validResultIds.has(candidate.event_id))
    .sort(compareEventChronology)) {
    const identity = resultArtifactIdentity(event);
    if (resultRepresentativeByArtifact.has(identity)) {
      duplicateResultIds.add(event.event_id);
      semanticallyIgnored.push({ event_id: event.event_id, reason: "duplicate-result-artifact" });
    } else {
      resultRepresentativeByArtifact.set(identity, event.event_id);
    }
  }
  for (const target of graph.promotedResultIds) acceptedIds.add(target);
  for (const [eventId, check] of Object.entries(artifactChecks)) {
    if (check?.reason === "duplicate-result-artifact") {
      semanticallyIgnored.push({ event_id: eventId, reason: "duplicate-result-artifact" });
    }
  }

  const reproducibleResultIds = new Set(verified
    .filter(event => (
      graph.validResultIds.has(event.event_id)
      && !duplicateResultIds.has(event.event_id)
      && artifactChecks[event.event_id]?.status === "pass"
    ))
    .map(event => event.event_id));
  const reviewAnalysis = analyzeReviews(graph, reproducibleResultIds);

  const eventSummaries = verified.map(event => {
    const attributable = true;
    const artifactCheck = artifactChecks[event.event_id];
    const reproducible = reproducibleResultIds.has(event.event_id);
    const reviewers = [...(reviewAnalysis.effectivePassReviewersByTarget.get(event.event_id) ?? [])]
      .sort();
    const crossKeyReviewed = reproducible && reviewers.length > 0;
    const accepted = acceptedIds.has(event.event_id) && reproducible && crossKeyReviewed;
    const level = accepted
      ? "ACCEPTED"
      : crossKeyReviewed
        ? "CROSS-KEY-REVIEWED"
        : reproducible
          ? "REPRODUCIBLE"
          : attributable
            ? "ATTRIBUTABLE"
            : "OBSERVED";
    return {
      event_id: event.event_id,
      type: event.payload.type,
      task_id: event.payload.task_id,
      did: event.payload.did,
      claimed_at: event.payload.claimed_at,
      observed_at: event.observed_at,
      source_ts: event.source_ts,
      parent_event_ids: event.payload.parent_event_ids,
      content_sha256: event.payload.content_sha256,
      artifact: event.payload.artifact ?? null,
      artifact_check: event.payload.type === "RESULT"
        ? (artifactCheck ?? { status: "not-checked" })
        : null,
      review: event.payload.review ?? null,
      cross_key_reviewers: reviewers,
      independence: "unknown",
      evidence_level: level,
    };
  });

  const signingKeys = new Set(eventSummaries.map(event => event.did));
  const additionalObserved = Number.isSafeInteger(options.additionalObserved) && options.additionalObserved >= 0
    ? options.additionalObserved
    : 0;
  const evidence = {
    observed: records.length + additionalObserved,
    attributable: eventSummaries.length,
    reproducible: eventSummaries.filter(event => ["REPRODUCIBLE", "CROSS-KEY-REVIEWED", "ACCEPTED"].includes(event.evidence_level)).length,
    cross_key_reviewed: eventSummaries.filter(event => ["CROSS-KEY-REVIEWED", "ACCEPTED"].includes(event.evidence_level)).length,
    accepted: eventSummaries.filter(event => event.evidence_level === "ACCEPTED").length,
  };

  const reportCore = {
    schema: "swarmproof-report-v1",
    source_event_count: records.length,
    unattributable_observation_count: additionalObserved,
    source_digest: sha256Hex(records.map(record => sha256Hex(String(record.envelope ?? ""))).sort().join("\n")),
    signing_keys: signingKeys.size,
    evidence,
    review_evidence: reviewAnalysis.evidence,
    events: eventSummaries.sort((left, right) => left.event_id.localeCompare(right.event_id)),
    rejected: rejected.sort((left, right) => left.envelope_sha256.localeCompare(right.envelope_sha256)),
    semantically_ignored: semanticallyIgnored
      .filter((entry, index, entries) => entries.findIndex(candidate => (
        candidate.event_id === entry.event_id && candidate.reason === entry.reason
      )) === index)
      .sort((left, right) => left.event_id.localeCompare(right.event_id) || left.reason.localeCompare(right.reason)),
    limitations: [
      "A DID proves control of a key, not a human, model, or independent operator.",
      "Review-key concentration and cross-key counts do not prove independent control or review quality.",
      "Only archive-contained, time-ordered TASK ancestry can raise a RESULT above ATTRIBUTABLE.",
      "A successful replay proves pinned bytes passed a fixed check, not authorship or novelty.",
      "The audit core does not ingest the official-room start checkpoint; launch ordering is verified separately by the guarded launcher and official-room readback.",
    ],
  };

  return {
    report: reportCore,
    report_sha256: sha256Hex(canonicalize(reportCore)),
  };
}
