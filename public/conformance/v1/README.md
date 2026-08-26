# SwarmProof v1 language-neutral conformance vectors

This directory is a machine-readable interoperability kit for independent Python, Rust, Go, and
other implementations of `swarmproof-event-v1` and `swarmproof-contribution-index-v1`. Start with
[`manifest.json`](manifest.json). It contains exact inputs, expected hashes, stable semantic result
codes, and references to canonical signed index files.

The Ed25519 seed, PKCS#8 bytes, public key, DID, and every signature here are deliberately public
test material. **Never use this fixture key for a real DID, wallet, account, secret, or value.** No
production private key or production signature is used by these vectors.

## Consumer procedure

1. Decode the 32-byte `fixture_key.seed_hex` and derive the Ed25519 public key.
2. Prefix the raw public key with multicodec bytes `ed 01`, encode that byte string as base58btc,
   and prefix it with `did:key:z`. Compare every intermediate value in the manifest.
3. Implement the canonical JSON profile: recursively sort object keys, preserve array order, emit
   compact JSON, and encode as UTF-8. Current protocol keys and constrained values are ASCII, so
   the vectors avoid cross-language Unicode collation ambiguity. Compare exact UTF-8 bytes and
   SHA-256 values in `canonical_json.cases`.
4. For an SP1 event, unpadded-base64url decode the middle segment, require canonical JSON bytes,
   validate the payload, and verify Ed25519 over
   `UTF8("swarmproof-event-v1|swarmproof-48-e463|" + encoded_payload)`. The event ID is lowercase
   SHA-256 of the complete ASCII envelope.
5. For a contribution index, require exactly canonical document JSON plus one trailing LF. Verify
   the proof over `UTF8("SWARMPROOF-CONTRIBUTION-INDEX-V1\n" + canonical_payload_json)`. The index
   fingerprint is SHA-256 of the complete file bytes, including the LF.
6. Verify index history separately. A standalone sequence greater than one can have a valid
   signature without proving its predecessor. Complete verification must begin at sequence 1,
   increment by exactly one, and match each predecessor's complete-file SHA-256.

`expected.code` values are language-neutral semantic labels for the fixtures; they are not a wire
error registry and implementations may expose different user-facing messages. Rejecting a case is
the normative outcome, not reproducing Node's exception text or validation order.

## Contribution-index fixture profile

The deployed public JSON Schema pins the production controller DID. Publishing a reusable secret
for that controller would be unsafe, so these index vectors use the manifest's explicit
`fixture_verification_profile.expected_controller`. They exercise the same canonical bytes,
domain separation, contribution-ID derivation, signatures, tampering, sequence, and hash-link
rules, but they are intentionally not valid production index documents under the deployment's
controller `const`. Implementations should expose an expected-controller input for test fixtures
while pinning the real controller in production.

The vector files are regenerated deterministically:

```bash
npm run conformance:generate
npm run conformance:check
```

`conformance:check` is fail-closed and is part of `npm run validate`. A source change that alters
canonical bytes, a DID, a signature, or any expected hash must update the checked-in kit explicitly.
