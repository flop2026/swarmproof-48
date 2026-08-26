import { verifyEnvelope } from "./protocol.mjs";

export const EVENT_RECORD_LIMIT = 1024;
export const PARTICIPANT_RECORD_LIMIT = 960;
export const RECORDS_PER_PARTICIPANT_DID_TYPE_LIMIT = 8;
export const RECORDS_PER_PARTICIPANT_DID_LIMIT = 32;
export const RECORDS_PER_CONTROL_TASK_LIMIT = 8;
export const COORDINATOR_CONTROL_RESERVATION = 64;
export const PROPOSAL_RECORD_LIMIT = 2048;

const CONTROL_TYPES = new Set(["TASK", "PROMOTE", "CHECKPOINT"]);

function validObservation(record, sourceRoom) {
  const observedAt = new Date(record.observed_at);
  if (Number.isNaN(observedAt.getTime()) || observedAt.toISOString() !== record.observed_at) return null;
  if (record.source_room !== sourceRoom) return null;
  const sourceSeq = Number.isSafeInteger(record.source_seq) && record.source_seq >= 0
    ? record.source_seq
    : null;
  let sourceTs = null;
  if (record.source_ts !== null && record.source_ts !== undefined) {
    const parsed = new Date(record.source_ts);
    if (Number.isNaN(parsed.getTime()) || parsed.toISOString() !== record.source_ts) return null;
    sourceTs = record.source_ts;
  }
  return { observedAt: record.observed_at, sourceSeq, sourceTs };
}

function newestFirst(left, right) {
  return right.observed_at.localeCompare(left.observed_at)
    || (right.source_seq ?? -1) - (left.source_seq ?? -1)
    || left.event_id.localeCompare(right.event_id);
}

function mergeDuplicateObservation(previous, next) {
  const observedAt = previous.observed_at <= next.observed_at
    ? previous.observed_at
    : next.observed_at;
  const sequenced = [previous, next].filter(record => Number.isSafeInteger(record.source_seq));
  const conflictingSequences = new Set([
    ...(previous._source_conflicts ?? []),
    ...(next._source_conflicts ?? []),
  ]);
  if (sequenced.length === 0) {
    const sourceTimes = [previous.source_ts, next.source_ts].filter(value => value !== null).sort();
    return {
      ...previous,
      observed_at: observedAt,
      source_seq: null,
      // Without a server sequence, retain the earliest known transport time. This prevents a
      // later repost of the same envelope from hiding an earlier pre-window observation.
      source_ts: sourceTimes[0] ?? null,
      _source_conflicts: [...conflictingSequences],
    };
  }

  const minimumSequence = Math.min(...sequenced.map(record => record.source_seq));
  const matching = sequenced.filter(record => record.source_seq === minimumSequence);
  const sourceTimes = [...new Set(matching.map(record => record.source_ts).filter(value => value !== null))];
  if (sourceTimes.length > 1) conflictingSequences.add(minimumSequence);
  return {
    ...previous,
    observed_at: observedAt,
    source_seq: minimumSequence,
    // Missing metadata may be repaired by another observation of the same immutable envelope.
    // Conflicting non-null timestamps for one server sequence are not resolved by guessing:
    // null keeps window-bound DAG evidence fail-closed while retaining attribution.
    source_ts: sourceTimes.length === 1 && !conflictingSequences.has(minimumSequence)
      ? sourceTimes[0]
      : null,
    _source_conflicts: [...conflictingSequences],
  };
}

function fairRoundRobin(records, maximum, options = {}) {
  if (maximum <= 0) return [];
  const excluded = options.excluded ?? new Set();
  const countsByDid = options.countsByDid ?? new Map();
  const countsByDidType = options.countsByDidType ?? new Map();
  const countsByDidTask = options.countsByDidTask ?? new Map();
  const buckets = new Map();
  for (const record of records) {
    if (excluded.has(record.event_id)) continue;
    const key = `${record.did}\u0000${record.task_id}`;
    const bucket = buckets.get(key) ?? [];
    bucket.push(record);
    buckets.set(key, bucket);
  }
  const orderedBuckets = [...buckets.entries()]
    .map(([key, values]) => ({ key, values: values.sort(newestFirst) }))
    // Recent activity can enter a saturated archive; the first 1024 records do not own it forever.
    .sort((left, right) => newestFirst(left.values[0], right.values[0]) || left.key.localeCompare(right.key));

  const selected = [];
  for (let round = 0; selected.length < maximum; round += 1) {
    let added = false;
    for (const bucket of orderedBuckets) {
      const candidate = bucket.values[round];
      if (!candidate) continue;
      const didType = `${candidate.did}\u0000${candidate.type}`;
      const didTask = `${candidate.did}\u0000${candidate.task_id}`;
      if ((countsByDid.get(candidate.did) ?? 0) >= (options.maximumPerDid ?? Infinity)) continue;
      if ((countsByDidType.get(didType) ?? 0) >= (options.maximumPerDidType ?? Infinity)) continue;
      if ((countsByDidTask.get(didTask) ?? 0) >= (options.maximumPerDidTask ?? Infinity)) continue;
      selected.push(candidate);
      countsByDid.set(candidate.did, (countsByDid.get(candidate.did) ?? 0) + 1);
      countsByDidType.set(didType, (countsByDidType.get(didType) ?? 0) + 1);
      countsByDidTask.set(didTask, (countsByDidTask.get(didTask) ?? 0) + 1);
      added = true;
      if (selected.length >= maximum) break;
    }
    if (!added) break;
  }
  return selected;
}

/**
 * Merge the durable SP1 archive without granting permanent priority to the first arrivals.
 * Coordinator control events get an explicit reservation; all other records are selected in
 * newest-following round-robin order across signing-key/task buckets.
 */
export function mergeProtocolRecords(existing, incoming, options) {
  const {
    protocolOptions,
    sourceRoom,
    coordinatorDid,
    maximum = EVENT_RECORD_LIMIT,
    coordinatorControlReservation = COORDINATOR_CONTROL_RESERVATION,
  } = options;
  const merged = new Map();
  for (const record of [...existing, ...incoming]) {
    try {
      const verified = verifyEnvelope(record.envelope, protocolOptions);
      const observation = validObservation(record, sourceRoom);
      if (!observation) continue;
      const normalized = {
        envelope: verified.envelope,
        observed_at: observation.observedAt,
        source_ts: observation.sourceTs,
        source_room: sourceRoom,
        source_seq: observation.sourceSeq,
        event_id: verified.event_id,
        did: verified.payload.did,
        task_id: verified.payload.task_id,
        type: verified.payload.type,
        _source_conflicts: [],
      };
      const previous = merged.get(verified.event_id);
      merged.set(
        verified.event_id,
        previous ? mergeDuplicateObservation(previous, normalized) : normalized,
      );
    } catch {
      // Invalid envelopes never enter the durable protocol archive.
    }
  }

  const records = [...merged.values()];
  const controls = records.filter(record => (
    record.did === coordinatorDid && CONTROL_TYPES.has(record.type)
  ));
  const participants = records.filter(record => !(
    record.did === coordinatorDid && CONTROL_TYPES.has(record.type)
  ));
  const controlCountsByDid = new Map();
  const controlCountsByDidType = new Map();
  const controlCountsByDidTask = new Map();
  const reservedMaximum = Math.min(maximum, coordinatorControlReservation);
  const selectedControls = fairRoundRobin(
    controls,
    reservedMaximum,
    {
      maximumPerDidTask: RECORDS_PER_CONTROL_TASK_LIMIT,
      countsByDid: controlCountsByDid,
      countsByDidType: controlCountsByDidType,
      countsByDidTask: controlCountsByDidTask,
    },
  );
  const selectedIds = new Set(selectedControls.map(record => record.event_id));
  const selectedParticipants = fairRoundRobin(
    participants,
    Math.min(PARTICIPANT_RECORD_LIMIT, maximum - selectedControls.length),
    {
      maximumPerDid: RECORDS_PER_PARTICIPANT_DID_LIMIT,
      maximumPerDidType: RECORDS_PER_PARTICIPANT_DID_TYPE_LIMIT,
      excluded: selectedIds,
    },
  );
  for (const record of selectedParticipants) selectedIds.add(record.event_id);

  // A reservation is a floor, not a coordinator quota: unused participant capacity may retain
  // additional controls, still under the same per-key/task cap.
  const overflowControls = fairRoundRobin(
    controls,
    maximum - selectedIds.size,
    {
      maximumPerDidTask: RECORDS_PER_CONTROL_TASK_LIMIT,
      excluded: selectedIds,
      countsByDid: controlCountsByDid,
      countsByDidType: controlCountsByDidType,
      countsByDidTask: controlCountsByDidTask,
    },
  );

  return [...selectedControls, ...selectedParticipants, ...overflowControls]
    .map(({
      event_id: _eventId,
      did: _did,
      task_id: _taskId,
      type: _type,
      _source_conflicts: _sourceConflicts,
      ...record
    }) => record)
    .sort((left, right) => left.envelope.localeCompare(right.envelope));
}

export function mergeProposals(existing, incoming, sourceRoom, maximum = PROPOSAL_RECORD_LIMIT) {
  const merged = new Map();
  for (const proposal of [...existing, ...incoming]) {
    if (!/^[0-9a-f]{64}$/.test(proposal.proposal_sha256 ?? "")) continue;
    const observation = validObservation(proposal, sourceRoom);
    if (!observation) continue;
    const normalized = {
      proposal_sha256: proposal.proposal_sha256,
      observed_at: observation.observedAt,
      source_ts: observation.sourceTs,
      source_room: sourceRoom,
      source_seq: observation.sourceSeq,
    };
    const previous = merged.get(proposal.proposal_sha256);
    if (!previous || normalized.observed_at < previous.observed_at) {
      merged.set(proposal.proposal_sha256, normalized);
    }
  }
  return [...merged.values()]
    .sort((left, right) => (
      right.observed_at.localeCompare(left.observed_at)
      || (right.source_seq ?? -1) - (left.source_seq ?? -1)
      || left.proposal_sha256.localeCompare(right.proposal_sha256)
    ))
    .slice(0, maximum)
    .sort((left, right) => left.proposal_sha256.localeCompare(right.proposal_sha256));
}
