import { sha256Hex } from "./crypto.mjs";

export const MAX_MESSAGE_UTF8_BYTES = 16 * 1024;

const INVISIBLE_RE = /[\p{Cc}\p{Cf}\p{Cs}\p{Co}\p{Zl}\p{Zp}]/u;
const URL_RE = /\bhttps?:\/\/[^\s]+/giu;
const DID_RE = /did:key:z[1-9A-HJ-NP-Za-km-z]+/gu;
const ISO_TIME_RE = /\b\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?(?:Z|[+-]\d{2}:?\d{2})\b/giu;
const LONG_NUMBER_RE = /\b\d{6,}\b/gu;

export function serverSweep(value) {
  return [...String(value)]
    .map((character) => INVISIBLE_RE.test(character) ? " " : character)
    .join("")
    .trim();
}

export function normalizeForSimilarity(value) {
  return serverSweep(value)
    .normalize("NFKC")
    .toLocaleLowerCase("und")
    .replace(URL_RE, " <url> ")
    .replace(DID_RE, " <did> ")
    .replace(ISO_TIME_RE, " <time> ")
    .replace(LONG_NUMBER_RE, " <n> ")
    .replace(/\s+/gu, " ")
    .trim();
}

function fnv1a32(value) {
  let hash = 0x811c9dc5;
  const bytes = Buffer.from(value, "utf8");
  for (const byte of bytes) {
    hash ^= byte;
    hash = Math.imul(hash, 0x01000193) >>> 0;
  }
  return hash >>> 0;
}

function mix32(value) {
  let mixed = value >>> 0;
  mixed ^= mixed >>> 16;
  mixed = Math.imul(mixed, 0x7feb352d) >>> 0;
  mixed ^= mixed >>> 15;
  mixed = Math.imul(mixed, 0x846ca68b) >>> 0;
  mixed ^= mixed >>> 16;
  return mixed >>> 0;
}

function boundedShingles(value, width = 5, maximum = 128) {
  const characters = [...value];
  if (characters.length <= width) return [characters.join("")];
  const count = characters.length - width + 1;
  const step = Math.max(1, Math.ceil(count / maximum));
  const shingles = [];
  for (let index = 0; index < count; index += step) {
    shingles.push(characters.slice(index, index + width).join(""));
  }
  return shingles;
}

export function minHashSketch(value, size = 32) {
  const normalized = normalizeForSimilarity(value);
  const baseHashes = boundedShingles(normalized).map(fnv1a32);
  const sketch = [];
  for (let seed = 0; seed < size; seed += 1) {
    let minimum = 0xffffffff;
    const salt = Math.imul(seed + 1, 0x9e3779b1) >>> 0;
    for (const baseHash of baseHashes) minimum = Math.min(minimum, mix32(baseHash ^ salt));
    sketch.push(minimum.toString(16).padStart(8, "0"));
  }
  return sketch;
}

export function sketchSimilarity(left, right) {
  if (!Array.isArray(left) || left.length === 0 || left.length !== right?.length) return 0;
  let matches = 0;
  for (let index = 0; index < left.length; index += 1) {
    if (left[index] === right[index]) matches += 1;
  }
  return matches / left.length;
}

export function fingerprintMessage(value) {
  if (typeof value !== "string") throw new Error("Message text must be a string.");
  if (Buffer.byteLength(value, "utf8") > MAX_MESSAGE_UTF8_BYTES) {
    throw new Error(`Message text exceeds ${MAX_MESSAGE_UTF8_BYTES} UTF-8 bytes.`);
  }
  const swept = serverSweep(value);
  const normalized = normalizeForSimilarity(swept);
  return {
    message_sha256: sha256Hex(swept),
    normalized_sha256: sha256Hex(normalized),
    minhash: minHashSketch(normalized),
    character_count: [...swept].length,
  };
}
