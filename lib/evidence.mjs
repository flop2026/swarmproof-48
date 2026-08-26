import { replayTrustedCheck, verifyLocalArtifact } from "./artifact.mjs";
import {
  analyzeEventSemantics,
  compareEventChronology,
  resultArtifactIdentity,
} from "./semantics.mjs";

export const ARTIFACT_CHECK_LIMIT = 64;
export const COORDINATOR_ARTIFACT_RESERVATION = 8;
export const ARTIFACTS_PER_PARTICIPANT_DID_LIMIT = 2;
export const ARTIFACTS_PER_TASK_LIMIT = 8;

export function artifactIdentity(event) {
  return resultArtifactIdentity(event);
}

function fairArtifactSelection(candidates, maximum, options = {}) {
  const buckets = new Map();
  for (const event of candidates) {
    const key = `${event.payload.did}\u0000${event.payload.task_id}`;
    const values = buckets.get(key) ?? [];
    values.push(event);
    buckets.set(key, values);
  }
  const orderedBuckets = [...buckets.entries()]
    .map(([key, values]) => ({ key, values: values.sort(compareEventChronology) }))
    .sort((left, right) => compareEventChronology(left.values[0], right.values[0]) || left.key.localeCompare(right.key));
  const byDid = options.countsByDid ?? new Map();
  const byTask = options.countsByTask ?? new Map();
  const selected = [];
  for (let round = 0; selected.length < maximum; round += 1) {
    let added = false;
    for (const bucket of orderedBuckets) {
      const event = bucket.values[round];
      if (!event) continue;
      const did = event.payload.did;
      const task = event.payload.task_id;
      if ((byDid.get(did) ?? 0) >= (options.maximumPerDid ?? Infinity)) continue;
      if ((byTask.get(task) ?? 0) >= (options.maximumPerTask ?? Infinity)) continue;
      selected.push(event);
      byDid.set(did, (byDid.get(did) ?? 0) + 1);
      byTask.set(task, (byTask.get(task) ?? 0) + 1);
      added = true;
      if (selected.length >= maximum) break;
    }
    if (!added) break;
  }
  return selected;
}

export function selectArtifactCandidates(records, options) {
  const graph = analyzeEventSemantics(records, {
    allowedRepositories: options.protocolOptions?.allowedRepositories,
    allowedTasks: options.protocolOptions?.allowedTasks,
    coordinatorDid: options.protocolOptions?.coordinatorDid,
    startsAt: options.startsAt,
    endsAt: options.endsAt,
  });
  const eligible = graph.verified
    .filter(event => graph.validResultIds.has(event.event_id))
    .sort(compareEventChronology);
  const representativeByIdentity = new Map();
  const unique = [];
  const duplicates = [];
  for (const event of eligible) {
    const identity = artifactIdentity(event);
    const representative = representativeByIdentity.get(identity);
    if (representative) {
      duplicates.push({ event, representative });
      continue;
    }
    representativeByIdentity.set(identity, event);
    unique.push(event);
  }

  const maximum = options.maximumArtifacts ?? ARTIFACT_CHECK_LIMIT;
  const coordinatorDid = options.protocolOptions?.coordinatorDid;
  const coordinator = unique.filter(event => event.payload.did === coordinatorDid);
  const participants = unique.filter(event => event.payload.did !== coordinatorDid);
  const countsByTask = new Map();
  const coordinatorSelected = fairArtifactSelection(
    coordinator,
    Math.min(maximum, options.coordinatorReservation ?? COORDINATOR_ARTIFACT_RESERVATION),
    { maximumPerTask: ARTIFACTS_PER_TASK_LIMIT, countsByTask },
  );
  const participantSelected = fairArtifactSelection(
    participants,
    maximum - coordinatorSelected.length,
    {
      maximumPerDid: options.maximumPerDid ?? ARTIFACTS_PER_PARTICIPANT_DID_LIMIT,
      maximumPerTask: options.maximumPerTask ?? ARTIFACTS_PER_TASK_LIMIT,
      countsByTask,
    },
  );
  return {
    graph,
    eligible,
    unique,
    duplicates,
    selected: [...coordinatorSelected, ...participantSelected],
    maximum,
  };
}

export async function verifyArtifactEvidence(records, options) {
  const selection = selectArtifactCandidates(records, options);
  const checks = {};
  for (const { event, representative } of selection.duplicates) {
    checks[event.event_id] = {
      status: "not-checked",
      reason: "duplicate-result-artifact",
      representative_event_id: representative.event_id,
    };
  }
  const selectedIds = new Set(selection.selected.map(event => event.event_id));
  for (const event of selection.unique) {
    if (!selectedIds.has(event.event_id)) {
      checks[event.event_id] = { status: "not-checked", reason: "snapshot-artifact-check-limit" };
    }
  }

  const replayCache = new Map();
  for (const event of selection.selected) {
    const integrity = await verifyLocalArtifact(event.payload.artifact, {
      repositoryRoot: options.repositoryRoot ?? process.cwd(),
      allowedRepository: options.repository,
      trustedRef: options.trustedRef ?? "HEAD",
      timeoutMs: 10_000,
      maximumBytes: 4 * 1024 * 1024,
    });
    if (integrity.status !== "pass") {
      checks[event.event_id] = { status: "fail", reason: integrity.reason, integrity };
      continue;
    }
    const task = options.tasksById.get(event.payload.task_id);
    const replayCommand = task?.replay_check;
    const cacheKey = `${event.payload.artifact.commit}:${JSON.stringify(replayCommand)}`;
    if (!replayCache.has(cacheKey)) {
      replayCache.set(cacheKey, replayTrustedCheck(event.payload.artifact.commit, replayCommand, {
        repositoryRoot: options.repositoryRoot ?? process.cwd(),
        trustedRef: options.trustedRef ?? "HEAD",
        timeoutMs: 30_000,
        replayTimeoutMs: 120_000,
        maximumOutputBytes: 2 * 1024 * 1024,
      }));
    }
    const replay = await replayCache.get(cacheKey);
    checks[event.event_id] = replay.status === "pass"
      ? { status: "pass", integrity, replay }
      : { status: "fail", reason: replay.reason, integrity, replay };
  }
  return {
    checks,
    attempted: selection.selected.length,
    candidates: selection.unique.length,
    duplicate_results: selection.duplicates.length,
    eligible_result_events: selection.eligible.length,
    maximum: selection.maximum,
  };
}
