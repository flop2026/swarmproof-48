import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import test from "node:test";
import {
  aggregateMessageRecords,
  collectNetworkSnapshot,
  deriveMessageRecord,
  fetchTechnocoreJson,
  listRooms,
  MAX_MESSAGE_UTF8_BYTES,
  MAX_NETWORK_RECORDS,
  MAX_SENDER_UTF8_BYTES,
  MINHASH_SIMILARITY_THRESHOLD,
  readRoom,
} from "../lib/collector.mjs";
import { didFromPrivateKey, sha256Hex } from "../lib/crypto.mjs";

test("refuses every non-Technocore URL before fetch", async () => {
  let calls = 0;
  await assert.rejects(
    () => fetchTechnocoreJson("https://example.invalid/write", {
      fetchImpl: async () => {
        calls += 1;
        throw new Error("must not run");
      },
    }),
    /root-relative/u,
  );
  assert.equal(calls, 0);
});

test("message URLs remain inert and only hashes are returned", () => {
  const record = deriveMessageRecord("lobby", {
    seq: 1,
    ts: "2026-08-26T00:00:00Z",
    from: "anonymous",
    text: "Open https://technocore.chat/r/trap/say/x/written-now",
  });
  assert.equal("text" in record, false);
  assert.equal("url" in record, false);
  assert.equal(record.message_sha256.length, 64);
  assert.equal(record.actor_sha256.length, 64);
});

test("aggregate metrics are bounded and neutral", () => {
  const records = [
    deriveMessageRecord("one", { seq: 1, ts: "2026-08-26T00:00:00Z", from: "a", text: "same" }),
    deriveMessageRecord("two", { seq: 2, ts: "2026-08-26T00:00:01Z", from: "b", text: "same" }),
    deriveMessageRecord("two", { seq: 3, ts: "2026-08-26T00:00:02Z", from: "c", text: "different" }),
  ];
  const aggregate = aggregateMessageRecords(records);
  assert.equal(aggregate.messages, 3);
  assert.equal(aggregate.exact_unique_messages, 2);
  assert.equal(aggregate.exact_clustered_messages, 2);
  assert.equal(aggregate.exact_clustered_message_share, 2 / 3);
  assert.equal(aggregate.exact_duplicate_share, 1 - 2 / 3);
  assert.equal(aggregate.exact_duplicate_clusters, 1);
  assert.equal(aggregate.normalized_clustered_messages, 2);
  assert.equal(aggregate.normalized_clustered_message_share, 2 / 3);
  assert.equal(aggregate.normalized_duplicate_clusters, 1);
  assert.equal(aggregate.minhash_similarity_clusters, 1);
  assert.equal(aggregate.minhash_similarity_clustered_messages, 2);
  assert.equal(aggregate.minhash_similarity_clustered_message_share, 2 / 3);
  assert.equal(aggregate.minhash_similarity_message_share, 2 / 3);
  assert.equal(aggregate.minhash_similarity_threshold, 0.75);
  assert.equal(aggregate.minhash_candidate_generation_truncated, false);
  assert.equal(aggregate.exact_messages_repeated_across_rooms, 1);
  assert.ok(aggregate.exact_duplicate_share > 0);
});

test("separates excess-copy redundancy from same-denominator cluster coverage", () => {
  const records = ["repeat", "repeat", "repeat", "singleton"].map((text, index) => (
    deriveMessageRecord(`room${index}`, {
      seq: index,
      ts: "2026-08-26T00:00:00Z",
      from: `actor-${index}`,
      text,
    })
  ));
  const aggregate = aggregateMessageRecords(records);
  assert.equal(aggregate.exact_duplicate_share, 0.5);
  assert.equal(aggregate.exact_clustered_messages, 3);
  assert.equal(aggregate.exact_clustered_message_share, 0.75);
  assert.ok(aggregate.exact_clustered_message_share <= aggregate.normalized_clustered_message_share);
  assert.ok(aggregate.normalized_clustered_message_share <= aggregate.minhash_similarity_clustered_message_share);
});

test("publishes null shares and zero clustered counts for an empty sample", () => {
  const aggregate = aggregateMessageRecords([]);
  assert.equal(aggregate.exact_clustered_messages, 0);
  assert.equal(aggregate.exact_clustered_message_share, null);
  assert.equal(aggregate.normalized_clustered_messages, 0);
  assert.equal(aggregate.normalized_clustered_message_share, null);
  assert.equal(aggregate.minhash_similarity_clustered_messages, 0);
  assert.equal(aggregate.minhash_similarity_clustered_message_share, null);
});

test("duplicate cluster totals are uncapped while detail lists stay bounded", () => {
  const representatives = [];
  const buckets = new Set();

  for (let candidate = 0; representatives.length < 25 && candidate < 5_000; candidate += 1) {
    const text = `gold-cluster-${candidate.toString(36)}-${candidate.toString(16).padStart(8, "0")}`;
    const record = deriveMessageRecord("vector", {
      seq: candidate,
      ts: "2026-01-01T00:00:00Z",
      from: "vector-actor",
      text,
    });
    const bucket = record.minhash.slice(0, 4).join("");
    if (buckets.has(bucket)) continue;
    buckets.add(bucket);
    representatives.push(text);
  }

  assert.equal(representatives.length, 25, "fixture generator must find 25 distinct similarity buckets");
  const records = representatives.flatMap((text, index) => [
    deriveMessageRecord(`v${index}a`, {
      seq: index * 2,
      ts: "2026-01-01T00:00:00Z",
      from: "vector-actor-a",
      text,
    }),
    deriveMessageRecord(`v${index}b`, {
      seq: index * 2 + 1,
      ts: "2026-01-01T00:00:01Z",
      from: "vector-actor-b",
      text,
    }),
  ]);

  const aggregate = aggregateMessageRecords(records);
  assert.equal(aggregate.exact_duplicate_clusters, 25);
  assert.equal(aggregate.normalized_duplicate_clusters, 25);
  assert.equal(aggregate.minhash_similarity_clusters, 25);
  assert.equal(aggregate.top_exact_clusters.length, 20);
  assert.equal(aggregate.top_normalized_clusters.length, 20);
  assert.equal(aggregate.top_minhash_similarity_clusters.length, 20);
});

test("strictly canonicalizes valid source timestamps to UTC and nulls invalid timestamps", () => {
  const offset = deriveMessageRecord("lobby", {
    seq: 1,
    ts: "2026-08-26T08:30:00.123456789+07:00",
    from: "anonymous",
    text: "bounded",
  });
  assert.equal(offset.source_ts, "2026-08-26T01:30:00.123Z");

  for (const ts of [
    "2026-02-30T00:00:00Z",
    "2026-08-26 00:00:00Z",
    "2026-08-26T00:00:00Z\n",
    "9999-12-31T23:59:59-23:59",
  ]) {
    const invalid = deriveMessageRecord("lobby", { seq: 1, ts, from: "anonymous", text: "bounded" });
    assert.equal(invalid.source_ts, null, ts);
  }
});

test("counts only bounded, decodable Ed25519 did:key sender shapes without claiming signature verification", () => {
  const { privateKey } = generateKeyPairSync("ed25519");
  const did = didFromPrivateKey(privateKey);
  const valid = deriveMessageRecord("lobby", { seq: 1, ts: null, from: did, text: "one" });
  const prefixOnly = deriveMessageRecord("lobby", { seq: 2, ts: null, from: "did:key:not-a-key", text: "two" });
  const aggregate = aggregateMessageRecords([valid, prefixOnly]);
  assert.equal(valid.signed_did, did);
  assert.equal(prefixOnly.signed_did, null);
  assert.equal(aggregate.did_shaped_senders, 1);
  assert.equal(aggregate.did_shaped_message_share, 0.5);
  assert.equal("signing_keys" in aggregate, false);
  assert.equal("signed_message_share" in aggregate, false);
});

test("enforces per-field, combined-record, and total aggregate bounds", () => {
  assert.throws(
    () => deriveMessageRecord("lobby", {
      seq: 1,
      ts: null,
      from: "a",
      text: "x".repeat(MAX_MESSAGE_UTF8_BYTES + 1),
    }),
    /exceeds collection bounds/u,
  );
  assert.throws(
    () => deriveMessageRecord("lobby", {
      seq: 1,
      ts: null,
      from: "a".repeat(MAX_SENDER_UTF8_BYTES + 1),
      text: "bounded",
    }),
    /exceeds collection bounds/u,
  );
  assert.throws(
    () => deriveMessageRecord("lobby", {
      seq: 1,
      ts: "2026-08-26T00:00:00Z",
      from: "a".repeat(MAX_SENDER_UTF8_BYTES),
      text: "x".repeat(MAX_MESSAGE_UTF8_BYTES),
    }),
    /exceeds collection bounds/u,
  );
  assert.throws(
    () => aggregateMessageRecords(new Array(MAX_NETWORK_RECORDS + 1)),
    /exceed 40000/u,
  );
});

function jsonResponse(value) {
  return new Response(JSON.stringify(value), {
    status: 200,
    headers: { "content-type": "application/json" },
  });
}

test("bounds and deduplicates hostile room and message arrays", async () => {
  const roomResult = await listRooms(2, {
    attempts: 1,
    fetchImpl: async () => jsonResponse({
      rooms: [{ room: "one" }, { room: "one" }, { room: "../bad" }, { room: "two" }, { room: "three" }],
    }),
  });
  assert.deepEqual(roomResult.rooms, [{ room: "one" }, { room: "two" }]);
  assert.equal(roomResult.room_entries_deduplicated, 1);
  assert.equal(roomResult.room_entries_rejected, 1);
  assert.equal(roomResult.room_entries_truncated, 1);
  assert.equal(roomResult.room_entries_uninspected, 0);

  const oversized = "x".repeat(MAX_MESSAGE_UTF8_BYTES + 1);
  const messageResult = await readRoom("one", 2, {
    attempts: 1,
    fetchImpl: async () => jsonResponse({ messages: [
      { seq: 1, ts: "2026-08-26T08:00:00+07:00", from: "a", text: "first" },
      { seq: 1, ts: "2026-08-26T09:00:00+07:00", from: "b", text: "conflicting duplicate seq" },
      null,
      { seq: 8, ts: null, from: "a", text: oversized },
      { seq: 2, ts: "invalid", from: "b", text: "second" },
      { seq: 3, ts: null, from: "c", text: "third" },
    ] }),
  });
  assert.equal(messageResult.messages.length, 2);
  assert.equal(messageResult.messages[0].ts, "2026-08-26T01:00:00.000Z");
  assert.equal(messageResult.messages[1].ts, null);
  assert.equal(messageResult.message_entries_deduplicated, 1);
  assert.equal(messageResult.message_entries_rejected, 2);
  assert.equal(messageResult.message_entries_truncated, 1);
  assert.equal(messageResult.message_entries_uninspected, 0);
});

test("caps inspection work when a server ignores requested array limits", async () => {
  const roomResult = await listRooms(1, {
    attempts: 1,
    fetchImpl: async () => jsonResponse({
      rooms: Array.from({ length: 1_000 }, (_, index) => ({ room: `r${index}` })),
    }),
  });
  assert.equal(roomResult.rooms.length, 1);
  assert.equal(roomResult.room_entries_truncated, 3);
  assert.equal(roomResult.room_entries_uninspected, 996);

  const messageResult = await readRoom("one", 1, {
    attempts: 1,
    fetchImpl: async () => jsonResponse({
      messages: Array.from({ length: 1_000 }, (_, index) => ({
        seq: index,
        ts: null,
        from: "bounded",
        text: `message-${index}`,
      })),
    }),
  });
  assert.equal(messageResult.messages.length, 1);
  assert.equal(messageResult.message_entries_truncated, 3);
  assert.equal(messageResult.message_entries_uninspected, 996);
});

test("isolates malformed messages without failing the room snapshot", async () => {
  const fetchImpl = async url => {
    if (url.pathname === "/rooms") return jsonResponse({ rooms: [{ room: "one" }] });
    return jsonResponse({ messages: [
      { seq: 1, ts: "2026-08-26T00:00:00Z", from: "a", text: "retained one" },
      7,
      { seq: 2, ts: null, from: "a".repeat(MAX_SENDER_UTF8_BYTES + 1), text: "rejected" },
      { seq: 3, ts: "nonsense", from: "b", text: "retained two" },
    ] });
  };
  const sample = await collectNetworkSnapshot({
    roomLimit: 1,
    messageLimit: 4,
    paceMs: 0,
    attempts: 1,
    fetchImpl,
  });
  assert.equal(sample.schema, "swarmproof-network-sample-v2");
  assert.equal(sample.aggregate.messages, 2);
  assert.equal(sample.selection.message_entries_rejected, 2);
  assert.equal(sample.selection.rooms_failed, 0);
  assert.equal(sample.records[1].source_ts, null);
});

function syntheticRecord(index, sketch) {
  return {
    room_sha256: sha256Hex(`room-${index}`),
    source_seq: index,
    source_ts: null,
    signed_did: null,
    actor_sha256: sha256Hex(`actor-${index}`),
    message_sha256: sha256Hex(`message-${index}`),
    normalized_sha256: sha256Hex(`normalized-${index}`),
    minhash: sketch,
    character_count: 1,
    protocol_envelope: null,
    protocol_event_id: null,
  };
}

test("uses LSH only for candidates and unions only sketches meeting the explicit threshold", () => {
  const same = "00000000";
  const left = new Array(32).fill(same);
  const atThreshold = [...new Array(24).fill(same), ...new Array(8).fill("11111111")];
  const belowThreshold = [...new Array(23).fill(same), ...new Array(9).fill("22222222")];
  const aggregate = aggregateMessageRecords([
    syntheticRecord(1, left),
    syntheticRecord(2, atThreshold),
    syntheticRecord(3, belowThreshold),
  ]);
  assert.equal(MINHASH_SIMILARITY_THRESHOLD, 0.75);
  assert.equal(aggregate.minhash_candidate_pairs_checked, 3);
  assert.equal(aggregate.minhash_similarity_clusters, 1);
  assert.equal(aggregate.top_minhash_similarity_clusters[0].count, 2);
});

test("caps adversarial LSH candidate explosions and reports truncation", () => {
  const records = Array.from({ length: 709 }, (_, index) => {
    const unique = index.toString(16).padStart(8, "0");
    return syntheticRecord(index, [...new Array(4).fill("ffffffff"), ...new Array(28).fill(unique)]);
  });
  const aggregate = aggregateMessageRecords(records);
  assert.equal(aggregate.minhash_candidate_pairs_checked, 250_000);
  assert.equal(aggregate.minhash_candidate_generation_truncated, true);
  assert.equal(aggregate.minhash_similarity_clusters, 0);
});
