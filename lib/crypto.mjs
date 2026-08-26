import {
  createHash,
  createPrivateKey,
  createPublicKey,
  sign as ed25519Sign,
  verify as ed25519Verify,
} from "node:crypto";

const BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const BASE58_INDEX = new Map([...BASE58_ALPHABET].map((character, index) => [character, index]));
const ED25519_MULTICODEC = Buffer.from([0xed, 0x01]);
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

export function sha256Hex(value) {
  return createHash("sha256").update(value).digest("hex");
}

export function parsePrivateKeyAndZeroInput(bytes, parser = createPrivateKey) {
  if (!Buffer.isBuffer(bytes)) throw new Error("Private-key input must be a Buffer.");
  try {
    return parser(bytes);
  } finally {
    bytes.fill(0);
  }
}

export function base58Encode(input) {
  const bytes = Buffer.from(input);
  let value = bytes.length === 0 ? 0n : BigInt(`0x${bytes.toString("hex")}`);
  let encoded = "";

  while (value > 0n) {
    encoded = BASE58_ALPHABET[Number(value % 58n)] + encoded;
    value /= 58n;
  }

  let leadingZeros = 0;
  while (leadingZeros < bytes.length && bytes[leadingZeros] === 0) leadingZeros += 1;
  return "1".repeat(leadingZeros) + (encoded || (leadingZeros === 0 ? "1" : ""));
}

export function base58Decode(value) {
  if (typeof value !== "string" || value.length === 0) throw new Error("Invalid base58 value.");
  let number = 0n;
  for (const character of value) {
    const digit = BASE58_INDEX.get(character);
    if (digit === undefined) throw new Error("Invalid base58 character.");
    number = number * 58n + BigInt(digit);
  }

  let decoded = Buffer.alloc(0);
  if (number > 0n) {
    let hex = number.toString(16);
    if (hex.length % 2 !== 0) hex = `0${hex}`;
    decoded = Buffer.from(hex, "hex");
  }

  let leadingOnes = 0;
  while (leadingOnes < value.length && value[leadingOnes] === "1") leadingOnes += 1;
  return Buffer.concat([Buffer.alloc(leadingOnes), decoded]);
}

export function publicKeyBytesFromDid(did) {
  if (typeof did !== "string" || !did.startsWith("did:key:z")) {
    throw new Error("Only base58btc did:key identifiers are supported.");
  }
  const decoded = base58Decode(did.slice("did:key:z".length));
  if (decoded.length !== 34 || !decoded.subarray(0, 2).equals(ED25519_MULTICODEC)) {
    throw new Error("Only Ed25519 did:key identifiers are supported.");
  }
  return decoded.subarray(2);
}

export function publicKeyFromDid(did) {
  return createPublicKey({
    key: Buffer.concat([ED25519_SPKI_PREFIX, publicKeyBytesFromDid(did)]),
    format: "der",
    type: "spki",
  });
}

export function didFromPrivateKey(privateKeyInput) {
  const privateKey = typeof privateKeyInput === "string" || Buffer.isBuffer(privateKeyInput)
    ? createPrivateKey(privateKeyInput)
    : privateKeyInput;
  const spki = createPublicKey(privateKey).export({ format: "der", type: "spki" });
  const rawPublicKey = spki.subarray(-32);
  return `did:key:z${base58Encode(Buffer.concat([ED25519_MULTICODEC, rawPublicKey]))}`;
}

export function signUtf8(privateKeyInput, value) {
  const privateKey = typeof privateKeyInput === "string" || Buffer.isBuffer(privateKeyInput)
    ? createPrivateKey(privateKeyInput)
    : privateKeyInput;
  return ed25519Sign(null, Buffer.from(value, "utf8"), privateKey);
}

export function verifyUtf8(did, value, signature) {
  return ed25519Verify(
    null,
    Buffer.from(value, "utf8"),
    publicKeyFromDid(did),
    Buffer.from(signature),
  );
}
