import assert from "node:assert/strict";
import { createPrivateKey } from "node:crypto";
import test from "node:test";
import { canonicalize } from "../lib/canonical.mjs";
import {
  CONTROL_CLAIM_DOMAIN,
  CONTROL_CLAIM_PUBLICATIONS,
  canonicalControlClaimPayload,
  createControlClaim,
  parseControlClaim,
  serializeControlClaim,
  verifyControlClaim,
  verifyControlClaimPublications,
} from "../lib/control-claim.mjs";
import { didFromPrivateKey, signUtf8 } from "../lib/crypto.mjs";

const ISSUED_AT = "2026-08-26T12:00:00.000Z";
const EXPIRES_AT = "2027-08-27T12:00:00.000Z";
const VERIFY_AT = "2026-08-27T12:00:00.000Z";
const fixedSigner = createPrivateKey({
  key: Buffer.concat([
    Buffer.from("302e020100300506032b657004220420", "hex"),
    Buffer.from("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "hex"),
  ]),
  format: "der",
  type: "pkcs8",
});
const fixtureDid = didFromPrivateKey(fixedSigner);
const fixtureOptions = {
  issuedAt: ISSUED_AT,
  expiresAt: EXPIRES_AT,
  expectedController: fixtureDid,
};
const verifyOptions = { expectedController: fixtureDid, at: VERIFY_AT };

function fixture() {
  return createControlClaim(fixedSigner, fixtureOptions);
}

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

function resign(document, signingInput = null) {
  const next = clone(document);
  next.proof.value = signUtf8(
    fixedSigner,
    signingInput ?? `${CONTROL_CLAIM_DOMAIN}${canonicalize(next.payload)}`,
  ).toString("base64url");
  return next;
}

test("control claim fixed conformance vector is canonical and domain-separated", () => {
  const created = fixture();
  const expectedPayload = "{\"controller\":\"did:key:z6MkehRgf7yJbgaGfYsdoAsKdBPE3dj2CYhowQdcjqSJgvVd\",\"expires_at\":\"2027-08-27T12:00:00.000Z\",\"issued_at\":\"2026-08-26T12:00:00.000Z\",\"project\":\"swarmproof-48-e463\",\"purpose\":\"project-resource-binding\",\"resources\":[{\"type\":\"github-repository\",\"uri\":\"https://github.com/flop2026/swarmproof-48\"},{\"type\":\"https-origin\",\"uri\":\"https://swarmproof-48-e463.pages.dev\"}],\"schema\":\"swarmproof-control-claim-v1\"}";
  const expectedSignature = "oGX73KdVIZCZKj18otrPn8RPPl5xKT0x9h-9RLTb-yPhBteKN9jnvIEKRloFmmIjZXI85pS1K3v4b9ovoVkyBQ";
  const expectedSha256 = "c0184b4ccd731cd615cc9556cdaf7bc8b0f2a16f1f0e10eca84d8507351040ab";
  assert.equal(canonicalControlClaimPayload(created.document.payload, verifyOptions), expectedPayload);
  assert.equal(created.document.proof.value, expectedSignature);
  assert.equal(created.claim_sha256, expectedSha256);
  assert.equal(created.serialized, `${canonicalize(created.document)}\n`);

  const verified = verifyControlClaim(created.serialized, verifyOptions);
  assert.equal(verified.signature_valid, true);
  assert.equal(verified.claim_sha256, created.claim_sha256);
  assert.equal(parseControlClaim(created.serialized, verifyOptions).payload.controller, fixtureDid);
});

test("SP1-like signing bytes cannot be reused as a control-claim proof", () => {
  const created = fixture();
  const payloadBase64 = Buffer.from(canonicalize(created.document.payload), "utf8").toString("base64url");
  const wrongDomain = `swarmproof-event-v1|swarmproof-48-e463|${payloadBase64}`;
  const crossProtocol = resign(created.document, wrongDomain);
  assert.throws(
    () => verifyControlClaim(crossProtocol, verifyOptions),
    /signature is invalid/u,
  );
});

test("control claim rejects non-canonical JSON bytes, duplicate keys, and extra bytes", () => {
  const created = fixture();
  assert.throws(
    () => parseControlClaim(JSON.stringify(created.document, null, 2), verifyOptions),
    /not canonical JSON/u,
  );
  assert.throws(
    () => parseControlClaim(`${created.serialized}\n`, verifyOptions),
    /not canonical JSON/u,
  );
  const canonicalPayload = canonicalize(created.document.payload);
  const canonicalProof = canonicalize(created.document.proof);
  const duplicatePayload = `{"payload":${canonicalPayload},"payload":${canonicalPayload},"proof":${canonicalProof}}\n`;
  assert.throws(
    () => parseControlClaim(duplicatePayload, verifyOptions),
    /not canonical JSON/u,
  );
});

test("control claim rejects unknown fields and unconfigured resources", () => {
  const created = fixture();
  const vectors = [
    {
      name: "unknown document field",
      mutate: document => { document.unbound = true; },
      expected: /document has an invalid field set/u,
    },
    {
      name: "unknown payload field",
      mutate: document => { document.payload.statement = "owner"; },
      expected: /payload has an invalid field set/u,
    },
    {
      name: "unknown proof field",
      mutate: document => { document.proof.key_path = "/private/key"; },
      expected: /proof has an invalid field set/u,
    },
    {
      name: "wrong schema",
      mutate: document => { document.payload.schema = "swarmproof-event-v1"; },
      expected: /schema is unsupported/u,
    },
    {
      name: "wrong project",
      mutate: document => { document.payload.project = "other-project"; },
      expected: /project domain is invalid/u,
    },
    {
      name: "wrong purpose",
      mutate: document => { document.payload.purpose = "wallet-control"; },
      expected: /purpose is invalid/u,
    },
    {
      name: "controller mismatch",
      mutate: document => { document.payload.controller = `${fixtureDid}1`; },
      expected: /canonical Ed25519 did:key/u,
    },
    {
      name: "resource order",
      mutate: document => { document.payload.resources.reverse(); },
      expected: /resource 1 is not the configured resource/u,
    },
    {
      name: "resource query",
      mutate: document => { document.payload.resources[1].uri += "?copy=1"; },
      expected: /resource 2 is not the configured resource/u,
    },
    {
      name: "resource field",
      mutate: document => { document.payload.resources[0].branch = "main"; },
      expected: /resource 1 has an invalid field set/u,
    },
    {
      name: "missing resource",
      mutate: document => { document.payload.resources.pop(); },
      expected: /resources have an invalid length/u,
    },
  ];

  for (const vector of vectors) {
    const document = clone(created.document);
    vector.mutate(document);
    assert.throws(
      () => verifyControlClaim(document, verifyOptions),
      vector.expected,
      vector.name,
    );
  }
});

test("control claim enforces canonical times and a bounded validity window", () => {
  const created = fixture();
  const vectors = [
    {
      name: "non-canonical issued_at",
      mutate: document => { document.payload.issued_at = "2026-08-26T12:00:00Z"; },
      expected: /issued_at must be canonical UTC/u,
    },
    {
      name: "invalid expires_at",
      mutate: document => { document.payload.expires_at = "not-a-time"; },
      expected: /expires_at must be canonical UTC/u,
    },
    {
      name: "non-positive window",
      mutate: document => { document.payload.expires_at = document.payload.issued_at; },
      expected: /must be after issued_at/u,
    },
    {
      name: "overlong window",
      mutate: document => { document.payload.expires_at = "2027-08-28T12:00:00.001Z"; },
      expected: /exceeds 366 days/u,
    },
  ];
  for (const vector of vectors) {
    const document = clone(created.document);
    vector.mutate(document);
    assert.throws(() => verifyControlClaim(document, verifyOptions), vector.expected, vector.name);
  }

  assert.throws(
    () => verifyControlClaim(created.document, { ...verifyOptions, at: "2026-08-26T11:54:59.999Z" }),
    /not yet valid/u,
  );
  assert.equal(
    verifyControlClaim(created.document, { ...verifyOptions, at: "2026-08-26T11:55:00.000Z" }).signature_valid,
    true,
  );
  assert.throws(
    () => verifyControlClaim(created.document, { ...verifyOptions, at: EXPIRES_AT }),
    /has expired/u,
  );
});

test("control claim rejects malformed proofs and signed-payload mutation", () => {
  const created = fixture();
  const vectors = [
    {
      name: "proof type",
      mutate: document => { document.proof.type = "Ed25519Signature2020"; },
      expected: /proof type is invalid/u,
    },
    {
      name: "proof encoding",
      mutate: document => { document.proof.encoding = "base64"; },
      expected: /proof encoding is invalid/u,
    },
    {
      name: "base64 padding",
      mutate: document => { document.proof.value += "="; },
      expected: /unpadded base64url/u,
    },
    {
      name: "short signature",
      mutate: document => { document.proof.value = Buffer.alloc(63).toString("base64url"); },
      expected: /must be 64 bytes/u,
    },
    {
      name: "signature bit flip",
      mutate: document => {
        const bytes = Buffer.from(document.proof.value, "base64url");
        bytes[0] ^= 1;
        document.proof.value = bytes.toString("base64url");
      },
      expected: /signature is invalid/u,
    },
    {
      name: "payload mutation with old signature",
      mutate: document => { document.payload.expires_at = "2027-08-26T12:00:00.000Z"; },
      expected: /signature is invalid/u,
    },
  ];
  for (const vector of vectors) {
    const document = clone(created.document);
    vector.mutate(document);
    assert.throws(() => verifyControlClaim(document, verifyOptions), vector.expected, vector.name);
  }
});

test("fixed publication verification fetches no claim-supplied URL and requires exact bytes", async () => {
  const created = fixture();
  const calls = [];
  const fetchImplementation = async (url, options) => {
    calls.push({ url, options });
    return new Response(created.serialized, {
      status: 200,
      headers: { "content-length": String(Buffer.byteLength(created.serialized)) },
    });
  };
  const verified = await verifyControlClaimPublications(created.serialized, {
    ...verifyOptions,
    fetchImplementation,
  });
  assert.deepEqual(calls.map(call => call.url), CONTROL_CLAIM_PUBLICATIONS.map(item => item.url));
  assert.ok(calls.every(call => call.options.redirect === "error"));
  assert.equal(verified.publications.length, 2);
  assert.ok(verified.publications.every(publication => publication.status === "pass"));
  assert.ok(verified.publications.every(publication => publication.claim_sha256 === created.claim_sha256));

  let count = 0;
  await assert.rejects(
    verifyControlClaimPublications(created.serialized, {
      ...verifyOptions,
      fetchImplementation: async () => new Response(
        count++ === 0 ? created.serialized : `${created.serialized}\n`,
        { status: 200 },
      ),
    }),
    /publication mismatch/u,
  );
});

test("fixed publication verification rejects non-200 and oversized responses", async () => {
  const created = fixture();
  await assert.rejects(
    verifyControlClaimPublications(created.serialized, {
      ...verifyOptions,
      fetchImplementation: async () => new Response("missing", { status: 404 }),
    }),
    /did not return HTTP 200/u,
  );
  await assert.rejects(
    verifyControlClaimPublications(created.serialized, {
      ...verifyOptions,
      fetchImplementation: async () => new Response("x", {
        status: 200,
        headers: { "content-length": String(8193) },
      }),
    }),
    /publication is oversized/u,
  );
});

test("serialize rejects unsigned unknown metadata instead of normalizing it away", () => {
  const created = fixture();
  const document = clone(created.document);
  document.proof.generated_by = "local-machine";
  assert.throws(
    () => serializeControlClaim(document, verifyOptions),
    /proof has an invalid field set/u,
  );
});
