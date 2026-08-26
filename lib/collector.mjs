import { setTimeout as sleep } from "node:timers/promises";
import { publicKeyBytesFromDid, sha256Hex } from "./crypto.mjs";
import {
  fingerprintMessage,
  MAX_MESSAGE_UTF8_BYTES,
  sketchSimilarity,
} from "./normalize.mjs";
import { verifyEnvelope } from "./protocol.mjs";

export { MAX_MESSAGE_UTF8_BYTES } from "./normalize.mjs";

export const TECHNCORE_ORIGIN = "https://technocore.chat";
const ROOM_RE = /^[a-z0-9][a-z0-9_-]{0,47}$/;
const HASH_RE = /^[0-9a-f]{64}$/u;
const SKETCH_VALUE_RE = /^[0-9a-f]{8}$/u;
const UTC_TIMESTAMP_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u;
const SOURCE_TIMESTAMP_RE = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?(Z|([+-])(\d{2}):(\d{2}))$/u;

export const MAX_ROOMS_PER_SNAPSHOT = 200;
export const MAX_MESSAGES_PER_ROOM = 200;
export const MAX_NETWORK_RECORDS = MAX_ROOMS_PER_SNAPSHOT * MAX_MESSAGES_PER_ROOM;
export const MAX_SENDER_UTF8_BYTES = 128;
export const MAX_SOURCE_TIMESTAMP_UTF8_BYTES = 64;
export const MAX_SOURCE_RECORD_UTF8_BYTES = MAX_MESSAGE_UTF8_BYTES + 96;
export const MINHASH_SIMILARITY_THRESHOLD = 0.75;
const MINHASH_SKETCH_SIZE = 32;
const MINHASH_LSH_ROWS = 4;
const MINHASH_LSH_BANDS = MINHASH_SKETCH_SIZE / MINHASH_LSH_ROWS;
const MAX_MINHASH_CANDIDATE_PAIRS = 250_000;
const MAX_ARRAY_INSPECTION_MULTIPLIER = 4;

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function utf8Bytes(value) {
  return Buffer.byteLength(value, "utf8");
}

export function canonicalUtcTimestamp(value) {
  if (typeof value !== "string" || utf8Bytes(value) > MAX_SOURCE_TIMESTAMP_UTF8_BYTES) return null;
  const match = SOURCE_TIMESTAMP_RE.exec(value);
  if (!match) return null;

  const year = Number(match[1]);
  const month = Number(match[2]);
  const day = Number(match[3]);
  const hour = Number(match[4]);
  const minute = Number(match[5]);
  const second = Number(match[6]);
  const milliseconds = Number(`${match[7] ?? ""}000`.slice(0, 3));
  const offsetHour = match[8] === "Z" ? 0 : Number(match[10]);
  const offsetMinute = match[8] === "Z" ? 0 : Number(match[11]);
  if (
    year < 1970 || year > 9999
    || month < 1 || month > 12
    || day < 1 || day > new Date(Date.UTC(year, month, 0)).getUTCDate()
    || hour > 23 || minute > 59 || second > 59
    || offsetHour > 23 || offsetMinute > 59
  ) return null;

  const localEpoch = Date.UTC(year, month - 1, day, hour, minute, second, milliseconds);
  const offsetSign = match[8] === "Z" || match[9] === "+" ? 1 : -1;
  const epoch = localEpoch - offsetSign * (offsetHour * 60 + offsetMinute) * 60_000;
  const canonical = new Date(epoch).toISOString();
  return UTC_TIMESTAMP_RE.test(canonical) ? canonical : null;
}

function validEd25519Did(value) {
  if (
    typeof value !== "string"
    || utf8Bytes(value) > MAX_SENDER_UTF8_BYTES
    || !/^did:key:z[1-9A-HJ-NP-Za-km-z]+$/u.test(value)
  ) return false;
  try {
    publicKeyBytesFromDid(value);
    return true;
  } catch {
    return false;
  }
}

function sanitizeSourceMessage(message) {
  if (!message || typeof message !== "object" || Array.isArray(message)) return null;
  if (typeof message.text !== "string" || utf8Bytes(message.text) > MAX_MESSAGE_UTF8_BYTES) return null;
  const actor = message.from === undefined || message.from === null ? "" : message.from;
  if (typeof actor !== "string" || utf8Bytes(actor) > MAX_SENDER_UTF8_BYTES) return null;
  const sourceTs = canonicalUtcTimestamp(message.ts);
  const sourceSeq = Number.isSafeInteger(message.seq) && message.seq >= 0 ? message.seq : null;
  const totalBytes = utf8Bytes(message.text) + utf8Bytes(actor) + (sourceTs ? utf8Bytes(sourceTs) : 0) + 16;
  if (totalBytes > MAX_SOURCE_RECORD_UTF8_BYTES) return null;
  return { seq: sourceSeq, ts: sourceTs, from: actor, text: message.text };
}

function boundedFailureReason(error) {
  const value = error instanceof Error ? error.message : "Unknown collection error.";
  return [...value.replace(/[\p{Cc}\p{Cf}\p{Cs}\p{Co}\p{Zl}\p{Zp}]/gu, " ")].slice(0, 160).join("");
}

async function boundedResponseText(response, maximumBytes) {
  const declaredLength = Number(response.headers.get("content-length"));
  if (Number.isFinite(declaredLength) && declaredLength > maximumBytes) {
    throw new Error(`Response exceeds ${maximumBytes} bytes.`);
  }
  if (!response.body) return "";
  const chunks = [];
  let size = 0;
  for await (const chunk of response.body) {
    size += chunk.byteLength;
    if (size > maximumBytes) throw new Error(`Response exceeds ${maximumBytes} bytes.`);
    chunks.push(Buffer.from(chunk));
  }
  return Buffer.concat(chunks).toString("utf8");
}

export async function fetchTechnocoreJson(path, options = {}) {
  assert(typeof path === "string" && path.startsWith("/"), "Technocore path must be root-relative.");
  const url = new URL(path, TECHNCORE_ORIGIN);
  assert(url.origin === TECHNCORE_ORIGIN, "External origins are forbidden.");
  const fetchImpl = options.fetchImpl ?? fetch;
  const maximumBytes = options.maximumBytes ?? 4 * 1024 * 1024;
  const attempts = options.attempts ?? 4;

  let lastError;
  for (let attempt = 1; attempt <= attempts; attempt += 1) {
    try {
      const response = await fetchImpl(url, {
        headers: { accept: "application/json" },
        redirect: "error",
        signal: AbortSignal.timeout(options.timeoutMs ?? 20_000),
      });
      const body = await boundedResponseText(response, maximumBytes);
      if (response.ok) {
        try {
          return JSON.parse(body);
        } catch {
          const error = new Error("Technocore returned malformed JSON.");
          error.nonRetryable = true;
          throw error;
        }
      }
      const error = new Error(`Technocore returned HTTP ${response.status}.`);
      if (response.status !== 429 && response.status < 500) {
        error.nonRetryable = true;
        throw error;
      }
      lastError = error;
      const retryAfter = Number(response.headers.get("retry-after"));
      const delaySeconds = Number.isFinite(retryAfter)
        ? Math.min(Math.max(retryAfter, 0), 15)
        : Math.min(2 ** attempt, 15);
      await sleep(delaySeconds * 1000);
    } catch (error) {
      lastError = error;
      if (error.nonRetryable) throw error;
      if (attempt < attempts) await sleep(Math.min(2 ** attempt, 10) * 1000);
    }
  }
  throw lastError ?? new Error("Technocore request failed.");
}

export async function listRooms(limit = 200, options = {}) {
  assert(Number.isInteger(limit) && limit >= 1 && limit <= MAX_ROOMS_PER_SNAPSHOT, "Room limit must be 1..200.");
  const data = await fetchTechnocoreJson(`/rooms?format=json&limit=${limit}`, options);
  assert(data && typeof data === "object" && Array.isArray(data.rooms), "Technocore room list is malformed.");
  const rooms = [];
  const seen = new Set();
  let rejected = 0;
  let deduplicated = 0;
  const inspectedEntries = data.rooms.slice(0, limit * MAX_ARRAY_INSPECTION_MULTIPLIER);
  for (const entry of inspectedEntries) {
    const room = entry && typeof entry === "object" && !Array.isArray(entry) ? entry.room : null;
    if (typeof room !== "string" || !ROOM_RE.test(room)) {
      rejected += 1;
      continue;
    }
    if (seen.has(room)) {
      deduplicated += 1;
      continue;
    }
    seen.add(room);
    if (rooms.length < limit) rooms.push({ room });
  }
  return {
    rooms,
    room_entries_rejected: rejected,
    room_entries_deduplicated: deduplicated,
    room_entries_truncated: Math.max(0, seen.size - rooms.length),
    room_entries_uninspected: Math.max(0, data.rooms.length - inspectedEntries.length),
  };
}

export async function readRoom(room, limit = 200, options = {}) {
  assert(ROOM_RE.test(room), "Room name is invalid.");
  assert(Number.isInteger(limit) && limit >= 1 && limit <= MAX_MESSAGES_PER_ROOM, "Message limit must be 1..200.");
  const encodedRoom = encodeURIComponent(room);
  const data = await fetchTechnocoreJson(`/r/${encodedRoom}?format=json&limit=${limit}`, options);
  assert(data && typeof data === "object" && Array.isArray(data.messages), "Technocore room response is malformed.");
  const messages = [];
  const seen = new Set();
  let rejected = 0;
  let deduplicated = 0;
  let unique = 0;
  const inspectedEntries = data.messages.slice(0, limit * MAX_ARRAY_INSPECTION_MULTIPLIER);
  const responseCount = Number.isSafeInteger(data.count) && data.count >= 0 ? data.count : null;
  const responseFirstSeq = data.first_seq === null
    ? null
    : (Number.isSafeInteger(data.first_seq) && data.first_seq >= 1 ? data.first_seq : null);
  const responseLastSeq = Number.isSafeInteger(data.last_seq) && data.last_seq >= 0
    ? data.last_seq
    : null;
  const sequenceMetadataValid = data.room === room
    && responseCount !== null
    && responseCount === data.messages.length
    && responseCount <= limit
    && (
      responseCount === 0
        ? data.first_seq === null && responseLastSeq === 0
        : responseFirstSeq !== null
          && responseLastSeq === responseFirstSeq + responseCount - 1
          && data.messages.every((candidate, index) => (
            candidate
            && typeof candidate === "object"
            && !Array.isArray(candidate)
            && candidate.seq === responseFirstSeq + index
          ))
    );
  for (const candidate of inspectedEntries) {
    let message;
    try {
      message = sanitizeSourceMessage(candidate);
    } catch {
      message = null;
    }
    if (!message) {
      rejected += 1;
      continue;
    }
    const identity = message.seq === null
      ? `content:${sha256Hex(`${message.ts ?? ""}\u0000${message.from}\u0000${message.text}`)}`
      : `seq:${message.seq}`;
    if (seen.has(identity)) {
      deduplicated += 1;
      continue;
    }
    seen.add(identity);
    unique += 1;
    if (messages.length < limit) messages.push(message);
  }
  return {
    messages,
    response_count: responseCount,
    first_seq: responseFirstSeq,
    last_seq: responseLastSeq,
    sequence_metadata_valid: sequenceMetadataValid,
    message_entries_rejected: rejected,
    message_entries_deduplicated: deduplicated,
    message_entries_truncated: Math.max(0, unique - messages.length),
    message_entries_uninspected: Math.max(0, data.messages.length - inspectedEntries.length),
  };
}

export function deriveMessageRecord(room, message, options = {}) {
  assert(ROOM_RE.test(room), "Room name is invalid.");
  const sanitized = sanitizeSourceMessage(message);
  assert(sanitized, "Message is invalid or exceeds collection bounds.");
  const text = sanitized.text;
  const fingerprint = fingerprintMessage(text);
  const actor = sanitized.from;
  const signedDid = validEd25519Did(actor) ? actor : null;
  let protocolEnvelope = null;
  let protocolEventId = null;

  if (text.startsWith("SP1.")) {
    try {
      const verified = verifyEnvelope(text, options.protocolOptions);
      protocolEnvelope = verified.envelope;
      protocolEventId = verified.event_id;
    } catch {
      // Invalid protocol-looking content remains an ordinary hashed observation.
    }
  }

  return {
    room_sha256: sha256Hex(room),
    source_seq: sanitized.seq,
    source_ts: sanitized.ts,
    signed_did: signedDid,
    actor_sha256: signedDid ? null : sha256Hex(actor),
    ...fingerprint,
    protocol_envelope: protocolEnvelope,
    protocol_event_id: protocolEventId,
  };
}

function assertAggregateRecord(record) {
  assert(record && typeof record === "object" && !Array.isArray(record), "Aggregate record is invalid.");
  assert(HASH_RE.test(record.room_sha256), "Aggregate room hash is invalid.");
  assert(HASH_RE.test(record.message_sha256), "Aggregate message hash is invalid.");
  assert(HASH_RE.test(record.normalized_sha256), "Aggregate normalized hash is invalid.");
  assert(
    Array.isArray(record.minhash)
    && record.minhash.length === MINHASH_SKETCH_SIZE
    && record.minhash.every(value => typeof value === "string" && SKETCH_VALUE_RE.test(value)),
    "Aggregate MinHash sketch is invalid.",
  );
  assert(record.signed_did === null || validEd25519Did(record.signed_did), "Aggregate DID-shaped sender is invalid.");
  assert(record.source_ts === null || UTC_TIMESTAMP_RE.test(record.source_ts), "Aggregate source timestamp is invalid.");
}

function similarityClusters(records) {
  const groupedBySketch = new Map();
  for (const record of records) {
    const signature = record.minhash.join("");
    const existing = groupedBySketch.get(signature);
    if (existing) existing.count += 1;
    else groupedBySketch.set(signature, { signature, sketch: record.minhash, count: 1 });
  }
  const groups = [...groupedBySketch.values()].sort((left, right) => left.signature.localeCompare(right.signature));
  const parents = groups.map((_, index) => index);
  const ranks = groups.map(() => 0);
  const find = value => {
    let root = value;
    while (parents[root] !== root) root = parents[root];
    while (parents[value] !== value) {
      const next = parents[value];
      parents[value] = root;
      value = next;
    }
    return root;
  };
  const union = (left, right) => {
    let leftRoot = find(left);
    let rightRoot = find(right);
    if (leftRoot === rightRoot) return;
    if (ranks[leftRoot] < ranks[rightRoot]) [leftRoot, rightRoot] = [rightRoot, leftRoot];
    parents[rightRoot] = leftRoot;
    if (ranks[leftRoot] === ranks[rightRoot]) ranks[leftRoot] += 1;
  };

  const buckets = new Map();
  for (let groupIndex = 0; groupIndex < groups.length; groupIndex += 1) {
    for (let band = 0; band < MINHASH_LSH_BANDS; band += 1) {
      const start = band * MINHASH_LSH_ROWS;
      const key = `${band}:${groups[groupIndex].sketch.slice(start, start + MINHASH_LSH_ROWS).join("")}`;
      const members = buckets.get(key) ?? [];
      members.push(groupIndex);
      buckets.set(key, members);
    }
  }

  const candidatePairs = new Set();
  let truncated = false;
  outer: for (const key of [...buckets.keys()].sort()) {
    const members = buckets.get(key);
    for (let left = 0; left < members.length; left += 1) {
      for (let right = left + 1; right < members.length; right += 1) {
        const pair = `${members[left]}:${members[right]}`;
        if (candidatePairs.has(pair)) continue;
        if (candidatePairs.size >= MAX_MINHASH_CANDIDATE_PAIRS) {
          truncated = true;
          break outer;
        }
        candidatePairs.add(pair);
      }
    }
  }

  for (const pair of candidatePairs) {
    const [left, right] = pair.split(":").map(Number);
    if (sketchSimilarity(groups[left].sketch, groups[right].sketch) >= MINHASH_SIMILARITY_THRESHOLD) {
      union(left, right);
    }
  }

  const components = new Map();
  for (let index = 0; index < groups.length; index += 1) {
    const root = find(index);
    const component = components.get(root) ?? { count: 0, signatures: [] };
    component.count += groups[index].count;
    component.signatures.push(groups[index].signature);
    components.set(root, component);
  }
  const clusters = [...components.values()]
    .filter(component => component.count > 1)
    .map(component => ({
      cluster_sha256: sha256Hex(component.signatures.map(signature => sha256Hex(signature)).sort().join("")),
      count: component.count,
    }))
    .sort((left, right) => right.count - left.count || left.cluster_sha256.localeCompare(right.cluster_sha256));
  return {
    clusters,
    candidatePairsChecked: candidatePairs.size,
    candidateGenerationTruncated: truncated,
  };
}

export function aggregateMessageRecords(records) {
  assert(Array.isArray(records), "Aggregate records must be an array.");
  assert(records.length <= MAX_NETWORK_RECORDS, `Aggregate records exceed ${MAX_NETWORK_RECORDS}.`);
  for (const record of records) assertAggregateRecord(record);
  const total = records.length;
  const exactHashes = new Map();
  const normalizedHashes = new Map();
  const roomsByMessage = new Map();
  const didSenders = new Set();

  for (const record of records) {
    exactHashes.set(record.message_sha256, (exactHashes.get(record.message_sha256) ?? 0) + 1);
    normalizedHashes.set(record.normalized_sha256, (normalizedHashes.get(record.normalized_sha256) ?? 0) + 1);
    const roomSet = roomsByMessage.get(record.message_sha256) ?? new Set();
    roomSet.add(record.room_sha256);
    roomsByMessage.set(record.message_sha256, roomSet);
    if (record.signed_did && validEd25519Did(record.signed_did)) didSenders.add(record.signed_did);
  }

  const topClusters = map => [...map.entries()]
    .filter(([, count]) => count > 1)
    .sort((left, right) => right[1] - left[1] || left[0].localeCompare(right[0]))
    .slice(0, 20)
    .map(([cluster_sha256, count]) => ({ cluster_sha256, count }));

  const duplicateClusterCount = map => [...map.values()]
    .filter(count => count > 1)
    .length;

  const clusteredMessageCount = map => [...map.values()]
    .filter(count => count > 1)
    .reduce((sum, count) => sum + count, 0);

  const crossRoomMessages = [...roomsByMessage.values()].filter(rooms => rooms.size > 1).length;
  const didShapedMessages = records.filter(record => record.signed_did && validEd25519Did(record.signed_did)).length;
  const similarity = similarityClusters(records);
  const similarityMessages = similarity.clusters.reduce((sum, cluster) => sum + cluster.count, 0);
  const exactClusteredMessages = clusteredMessageCount(exactHashes);
  const normalizedClusteredMessages = clusteredMessageCount(normalizedHashes);
  return {
    messages: total,
    did_shaped_senders: didSenders.size,
    did_shaped_message_share: total === 0 ? null : didShapedMessages / total,
    exact_unique_messages: exactHashes.size,
    exact_clustered_messages: exactClusteredMessages,
    exact_clustered_message_share: total === 0 ? null : exactClusteredMessages / total,
    exact_duplicate_share: total === 0 ? null : 1 - exactHashes.size / total,
    exact_duplicate_clusters: duplicateClusterCount(exactHashes),
    normalized_unique_messages: normalizedHashes.size,
    normalized_clustered_messages: normalizedClusteredMessages,
    normalized_clustered_message_share: total === 0 ? null : normalizedClusteredMessages / total,
    normalized_duplicate_share: total === 0 ? null : 1 - normalizedHashes.size / total,
    normalized_duplicate_clusters: duplicateClusterCount(normalizedHashes),
    minhash_similarity_threshold: MINHASH_SIMILARITY_THRESHOLD,
    minhash_lsh_bands: MINHASH_LSH_BANDS,
    minhash_lsh_rows_per_band: MINHASH_LSH_ROWS,
    minhash_similarity_clusters: similarity.clusters.length,
    minhash_similarity_clustered_messages: similarityMessages,
    minhash_similarity_clustered_message_share: total === 0 ? null : similarityMessages / total,
    minhash_similarity_message_share: total === 0 ? null : similarityMessages / total,
    minhash_candidate_pairs_checked: similarity.candidatePairsChecked,
    minhash_candidate_generation_truncated: similarity.candidateGenerationTruncated,
    exact_messages_repeated_across_rooms: crossRoomMessages,
    top_exact_clusters: topClusters(exactHashes),
    top_normalized_clusters: topClusters(normalizedHashes),
    top_minhash_similarity_clusters: similarity.clusters.slice(0, 20),
  };
}

export async function collectNetworkSnapshot(options = {}) {
  const roomLimit = options.roomLimit ?? 200;
  const messageLimit = options.messageLimit ?? 200;
  const paceMs = options.paceMs ?? 300;
  const listed = await listRooms(roomLimit, options);
  const records = [];
  const failures = [];
  let rejectedMessages = 0;
  let deduplicatedMessages = 0;
  let truncatedMessages = 0;
  let uninspectedMessages = 0;
  let previousRequestAt = 0;

  for (const roomEntry of listed.rooms) {
    const room = roomEntry?.room;
    if (!ROOM_RE.test(room ?? "")) continue;
    const elapsed = Date.now() - previousRequestAt;
    if (elapsed < paceMs) await sleep(paceMs - elapsed);
    previousRequestAt = Date.now();
    try {
      const data = await readRoom(room, messageLimit, options);
      rejectedMessages += data.message_entries_rejected;
      deduplicatedMessages += data.message_entries_deduplicated;
      truncatedMessages += data.message_entries_truncated;
      uninspectedMessages += data.message_entries_uninspected;
      for (const message of data.messages) {
        try {
          if (records.length >= MAX_NETWORK_RECORDS) {
            truncatedMessages += 1;
            continue;
          }
          records.push(deriveMessageRecord(room, message, options));
        } catch {
          rejectedMessages += 1;
        }
      }
    } catch (error) {
      failures.push({ room_sha256: sha256Hex(room), reason: boundedFailureReason(error) });
    }
  }

  const generatedAt = new Date().toISOString();
  return {
    schema: "swarmproof-network-sample-v2",
    generated_at: generatedAt,
    selection: {
      endpoint: "/rooms",
      rooms_requested: roomLimit,
      rooms_returned: listed.rooms.length,
      room_entries_rejected: listed.room_entries_rejected,
      room_entries_deduplicated: listed.room_entries_deduplicated,
      room_entries_truncated: listed.room_entries_truncated,
      room_entries_uninspected: listed.room_entries_uninspected,
      messages_per_room_requested: messageLimit,
      message_entries_rejected: rejectedMessages,
      message_entries_deduplicated: deduplicatedMessages,
      message_entries_truncated: truncatedMessages,
      message_entries_uninspected: uninspectedMessages,
      rooms_failed: failures.length,
    },
    aggregate: aggregateMessageRecords(records),
    failures,
    records,
    limitations: [
      "The sample contains only rooms returned first by /rooms and their newest bounded tails.",
      "DID-shaped sender counts validate Ed25519 did:key syntax, not signatures, operators, or independence.",
      "MinHash clusters require at least 75% sketch agreement among deterministic LSH candidates; candidate generation is explicitly bounded.",
      "Similarity clusters are signals, not identity or misconduct determinations.",
    ],
  };
}
