# SwarmProof control claim v1

This document specifies a minimal, project-specific way for the SwarmProof coordinator DID to
bind its own key-control assertion to the public project resources. It is deliberately separate
from the `SP1` event protocol.

## What a valid result means

There are two verification scopes:

1. `signed-document-only` proves that the configured Ed25519 `did:key` signed the strict payload
   and that the claim is within its validity window. This is a self-assertion by a key controller.
2. `fixed-publications` additionally observes the exact canonical claim bytes at both the pinned
   GitHub raw path and the pinned Pages well-known path. This binds the assertion to content served
   from those configured resources at verification time.

Neither scope identifies a person, proves exclusive GitHub-account control, proves an independent
operator or witness, establishes endorsement, or conveys token/reward eligibility. The repository
is under the pseudonymous `flop2026` namespace. GitHub and Pages share one source/deployment chain,
so their copies are correlated rather than independent factors.

## Signed document

The UTF-8 file is a JSON object with exactly two keys, `payload` and `proof`. Unknown fields are
rejected at every level. The payload has exactly these fields:

- `schema`: `swarmproof-control-claim-v1`
- `project`: `swarmproof-48-e463`
- `purpose`: `project-resource-binding`
- `controller`: the configured coordinator Ed25519 `did:key`
- `issued_at`: canonical UTC with exactly millisecond precision
- `expires_at`: canonical UTC, later than `issued_at` and no more than 366 days later
- `resources`: the ordered, exact repository and HTTPS-origin constants in the public schema

The proof has exactly `type: "Ed25519"`, `encoding: "base64url"`, and a canonical unpadded
base64url `value` that decodes to 64 bytes. The DID must use canonical base58btc Ed25519
multicodec bytes.

The canonicalizer recursively emits JSON primitives without whitespace, preserves array order,
and sorts object keys lexicographically. This profile contains only fixed ASCII strings and
canonical timestamps; numbers, free text, optional fields, and Unicode-normalization choices are
not part of the signed payload. The complete file must be the canonical document followed by one
LF byte. Pretty-printed JSON, CRLF, duplicate keys, extra whitespace, and extra trailing bytes are
rejected.

The exact bytes passed to Ed25519 are:

```text
UTF8("SWARMPROOF-CONTROL-CLAIM-V1\n" + canonical_json(payload))
```

The fixed prefix and schema/project fields separate these signatures from `SP1` and other uses of
the same Ed25519 key. A control claim must never be accepted as a SwarmProof event. The public
claim fingerprint is SHA-256 over the complete canonical file, including its single trailing LF.

## Generate and verify

The generator derives the DID from the key and refuses a different key, a symlink, a non-regular
file, a key owned by another local user, or permissions accessible to group/other users. It emits
only public metadata to stdout; it never emits the PEM or signature there.

```bash
npm run control-claim -- create \
  --key /path/to/coordinator.pem \
  --out public/.well-known/swarmproof-control-claim-v1.json \
  --valid-days 366

npm run control-claim -- verify \
  --file public/.well-known/swarmproof-control-claim-v1.json

npm run control-claim -- verify \
  --file public/.well-known/swarmproof-control-claim-v1.json \
  --publications
```

The online verifier does not follow a URI from the document. It makes redirect-free, bounded
requests only to implementation-pinned endpoints and requires both response bodies to equal the
locally supplied canonical file byte for byte before separately checking each signature.

## Rotation and failure handling

The file is served with `Cache-Control: no-store`. Refresh it before `expires_at`, commit the exact
new bytes with the explicit `create --replace` rotation flag, deploy them, and require
`verify --publications` to pass. Without that flag the generator refuses an existing target;
with it, the old target must itself be a canonical, correctly signed project claim. The output
may never be the key path, a key hard link, a symlink, or another arbitrary file. During
propagation, a safe
verifier may fail because one endpoint still serves the prior copy; it must not merge or prefer
either claim.

An expired or removed claim remains historical evidence that a key signed those bytes, not proof
of current resource control. `did:key` has no built-in revocation registry. A suspected key
compromise therefore requires a new DID plus explicit project configuration and publication
changes; silently extending or reinterpreting the old claim is not valid rotation.

The normative runtime checks are in [`lib/control-claim.mjs`](lib/control-claim.mjs), the strict
document shape is in
[`public/schema/swarmproof-control-claim-v1.schema.json`](public/schema/swarmproof-control-claim-v1.schema.json),
and fixed positive/negative vectors are in
[`test/control-claim.test.mjs`](test/control-claim.test.mjs).
