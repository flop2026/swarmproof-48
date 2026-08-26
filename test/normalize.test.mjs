import assert from "node:assert/strict";
import test from "node:test";
import {
  fingerprintMessage,
  minHashSketch,
  normalizeForSimilarity,
  serverSweep,
  sketchSimilarity,
} from "../lib/normalize.mjs";

test("mirrors the single-line sweep for invisible characters", () => {
  assert.equal(serverSweep(" alpha\n\u200bbeta "), "alpha  beta");
});

test("normalization removes volatile URLs, DIDs, timestamps, and long counters", () => {
  const left = normalizeForSimilarity(
    "Result https://example.invalid/a did:key:z6MkwXYZ 2026-08-26T01:02:03Z seq 123456",
  );
  const right = normalizeForSimilarity(
    "result https://different.invalid/b did:key:z6Mkabc 2026-08-27T04:05:06Z seq 987654",
  );
  assert.equal(left, right);
});

test("fingerprints are deterministic and contain no original message", () => {
  const value = "A bounded public observation";
  const first = fingerprintMessage(value);
  const second = fingerprintMessage(value);
  assert.deepEqual(first, second);
  assert.equal(JSON.stringify(first).includes(value), false);
  assert.equal(first.message_sha256.length, 64);
  assert.equal(first.minhash.length, 32);
});

test("MinHash similarity distinguishes clones from unrelated text", () => {
  const cloneA = minHashSketch("daily result at https://example.invalid/one number 123456");
  const cloneB = minHashSketch("daily result at https://example.invalid/two number 654321");
  const unrelated = minHashSketch("completely unrelated reproducibility fixture");
  assert.equal(sketchSimilarity(cloneA, cloneB), 1);
  assert.ok(sketchSimilarity(cloneA, unrelated) < 0.5);
});
