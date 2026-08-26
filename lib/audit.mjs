import { sha256Hex } from "./crypto.mjs";
import { canonicalize } from "./canonical.mjs";
import {
  analyzeEventSemantics,
  compareEventChronology,
  resultArtifactIdentity,
} from "./semantics.mjs";

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

  const eventSummaries = verified.map(event => {
    const attributable = true;
    const artifactCheck = artifactChecks[event.event_id];
    const reproducible = graph.validResultIds.has(event.event_id)
      && !duplicateResultIds.has(event.event_id)
      && event.payload.type === "RESULT"
      && artifactCheck?.status === "pass";
    const reviewers = [...(graph.validPassReviews.get(event.event_id) ?? [])]
      .filter(did => did !== event.payload.did)
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
    events: eventSummaries.sort((left, right) => left.event_id.localeCompare(right.event_id)),
    rejected: rejected.sort((left, right) => left.envelope_sha256.localeCompare(right.envelope_sha256)),
    semantically_ignored: semanticallyIgnored
      .filter((entry, index, entries) => entries.findIndex(candidate => (
        candidate.event_id === entry.event_id && candidate.reason === entry.reason
      )) === index)
      .sort((left, right) => left.event_id.localeCompare(right.event_id) || left.reason.localeCompare(right.reason)),
    limitations: [
      "A DID proves control of a key, not a human, model, or independent operator.",
      "Cross-key review does not prove independent control.",
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
