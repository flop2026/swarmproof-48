# SwarmProof contribution index v1

The contribution index is a strict, DID-signed catalogue of public contribution evidence. Its
unit is an immutable content subject, not a post, receipt, review, or evidence level. This prevents
one artifact from becoming five nominal contributions merely because it was observed, signed,
replayed, reviewed, and promoted.

The index is deliberately separate from both `SP1` events and the project resource control claim.
It uses the signing domain `SWARMPROOF-CONTRIBUTION-INDEX-V1\n`. A valid signature means only that
the configured DID controller asserted the exact index bytes. It does not prove a person,
authorship, novelty, an independent reviewer, external endorsement, official acceptance, or
reward eligibility.

## Subject identity and counting

A v1 subject is exactly:

```json
{
  "type": "git-content",
  "repository": "flop2026/swarmproof-48",
  "content_sha256": "<64 lowercase hex>"
}
```

Before deriving the ID, the verifier constructs
`identity_subject = { ...subject, repository: lowercase(subject.repository) }`. The displayed
subject remains unchanged inside the signed payload, but GitHub display-case variants derive the
same ID and are rejected as duplicates. The ID is SHA-256 over:

```text
UTF8("SWARMPROOF-CONTRIBUTION-SUBJECT-V1\n" + canonical_json(identity_subject))
```

Repository plus content bytes intentionally match SwarmProof's existing duplicate-artifact
identity. GitHub repository case-folding prevents display-case variants from becoming separate
subjects. Commit and path are evidence locators, not new subjects. Contributions are sorted by
derived ID and duplicate IDs are rejected. Evidence entries are sorted and deduplicated inside
their subject. Aggregate output counts each subject at most once per named facet; facet counts
must never be added together as a total.

The archived eight-result baseline maps to eight unique subjects. All eight have
reproducible-artifact facets, while none in that baseline has a cross-key review or SwarmProof
internal acceptance. The result is `8 unique`, not `16` from adding attributable and reproducible
gates. `prepare` derives and verifies the latest co-publication commit dynamically; documentation
and tests do not pin a daily snapshot commit as a permanent constant.

## Evidence scopes

Each evidence object has a discriminating `kind` and an exact field set:

- `swarmproof-result-snapshot` points to one RESULT plus the report hash, snapshot-manifest hash,
  and immutable Git commit that published report/status/events/proposals together. Verification
  materializes those exact Git objects, runs the full existing `verify-report`, checks the subject
  against the non-duplicate RESULT, and derives the ladder facet from the replayed report. The
  evidence entry never copies a claimed ladder value.
- `server-observation` records a hash and server-reported Technocore room/time/sequence. It is not
  a transport signature or endorsement.
- `cross-key-review` points to a semantically valid REVIEW and matching RESULT in the same replayed
  snapshot. The reviewer must use a different DID key, and only the latest valid verdict for that
  reviewer-key/RESULT pair is effective; a superseded PASS is rejected. Independence remains
  `unknown`.
- `upstream-acceptance` identifies exact bytes at a full commit and pull request in a different
  GitHub repository. Until a source-specific verifier checks it, it remains a controller-asserted
  reference. Even a verified merge proves accepted bytes, not DID authorship.
- `external-adoption` identifies a full commit and exact artifact in a non-`flop2026` namespace,
  plus a configured project marker and a bounded relation enum. Namespace separation does not
  prove operator independence.
- `official-task` records only `stage: submitted`. Its authority and status URL are restricted to
  configured public accounts, its submission must be an allowlisted project resource, and both
  `official_acceptance` and `reward_status` must be `not-claimed`. v1 rejects any self-asserted
  accepted, rewarded, eligible, winner, allocation, or equivalent state.

SwarmProof `ACCEPTED` is always rendered as `swarmproof_internal_accepted`. It means a valid
coordinator PROMOTE followed a reproducible RESULT and cross-key PASS review inside this project.
It is not upstream acceptance, official task acceptance, or token eligibility.

## Signed document and history

The document has exactly `payload` and `proof`. The payload fixes schema, project, purpose,
controller, canonical UTC issuance time, a positive decimal-string sequence, previous index hash,
control-claim hash, and the ordered contribution array. Sequence 1 requires a null previous hash;
later sequences require a SHA-256. For every sequence after 1, `create` requires an explicit
`--previous` canonical signed index, verifies its configured controller and signature, increments
its sequence by exactly one, and checks the exact complete-file SHA-256 link before reading the
private key. A successor can be staged at a new `--out`. `--replace` is accepted only when the
output already exists and its bytes exactly equal `--previous`.

Ordinary verification checks the current signed document and its exact control claim only. A
sequence-1 root reports history as `not-applicable-root-sequence`; a later sequence reports
`not-checked`, even when its payload contains a syntactically valid previous hash. To verify
complete history, repeat `--previous` in oldest-to-newest order, beginning with sequence 1 and
ending with the immediate predecessor. Every supplied file is independently
checked for canonical bytes, the configured controller, signature, exact sequence increment, and
SHA-256 linkage. Historical control claims and evidence sources remain separately scoped.

Only the current index is served from the two mutable well-known endpoints. They are not an
immutable archive of earlier index versions. Preserve canonical prior files in a trusted archive
before replacement if later complete-chain verification is required.

Renewing the resource control claim under the same `did:key` is supported: the next index binds the
new claim while its predecessor keeps the old claim hash. Actual Ed25519 key rotation is not
supported in v1. A `did:key` encodes its public key, and v1 has no signed successor-DID mechanism;
changing the key therefore changes the controller and fails the configured-controller check.

The proof is exactly Ed25519, canonical unpadded base64url, and 64 decoded bytes. Unknown fields,
numbers used in place of precision-safe decimal strings, non-canonical DIDs/timestamps/base64url,
pretty JSON, CRLF, duplicate entries, unsafe paths, mixed snapshot publication commits, and files
over 256 KiB are rejected. The complete file is canonical JSON plus one LF. Its public fingerprint
is SHA-256 over those complete bytes.

`control_claim_sha256` binds the index to the exact resource-control claim valid at issuance. It
does not upgrade any evidence fact. Historical verification requires the matching historical
claim bytes; fixed-publication verification describes only the current copies.

## Generate and verify

```bash
npm run contribution-index -- prepare --out /tmp/contribution-index-input.json

npm run contribution-index -- create \
  --input /tmp/contribution-index-input.json \
  --key /path/to/coordinator.pem \
  --out public/.well-known/swarmproof-contribution-index-v1.json

npm run contribution-index -- verify \
  --file public/.well-known/swarmproof-contribution-index-v1.json \
  --project

npm run contribution-index -- verify \
  --file public/.well-known/swarmproof-contribution-index-v1.json \
  --project \
  --publications
```

Prepare and stage a successor without overwriting the current index:

```bash
npm run contribution-index -- prepare \
  --previous /archive/contribution-index-v1.json \
  --out /tmp/contribution-index-v2-input.json

npm run contribution-index -- create \
  --input /tmp/contribution-index-v2-input.json \
  --key /path/to/coordinator.pem \
  --previous /archive/contribution-index-v1.json \
  --out /tmp/contribution-index-v2.json
```

To overwrite the current mutable path, make that existing file the verified predecessor and add
`--replace`. To verify a current sequence 3 and its complete chain, supply prior files from oldest
to newest:

```bash
npm run contribution-index -- create \
  --input /tmp/contribution-index-v2-input.json \
  --key /path/to/coordinator.pem \
  --previous public/.well-known/swarmproof-contribution-index-v1.json \
  --out public/.well-known/swarmproof-contribution-index-v1.json \
  --replace

npm run contribution-index -- verify \
  --file /archive/contribution-index-v3.json \
  --previous /archive/contribution-index-v1.json \
  --previous /archive/contribution-index-v2.json
```

`prepare` is unsigned and requires the full current report replay to pass. `create` validates all
available non-secret input before reading a regular, owner-only Ed25519 key. A `finally` path zeros
the mutable file-read buffer immediately after Node parses it, including parser failure, and the
CLI never prints the key, proof, signed file, or complete publication URL. This does not erase the
PEM file or guarantee erasure of copies retained by Node/OpenSSL, the allocator, or the operating
system. The full project verifier reads immutable Git objects from the evidence publication
commit without checking out or mutating the worktree.

Online publication verification fetches only the implementation constants for the raw GitHub
file and Pages well-known file. Requests reject redirects and oversized bodies; both copies must
equal the local canonical file byte for byte and verify independently. Index-supplied URIs are
never fetch targets. The two copies share a deployment chain and are correlated, not independent
witnesses.

The normative runtime is [`lib/contribution-index.mjs`](lib/contribution-index.mjs), the safe CLI
is [`bin/contribution-index.mjs`](bin/contribution-index.mjs), the public shape is
[`public/schema/swarmproof-contribution-index-v1.schema.json`](public/schema/swarmproof-contribution-index-v1.schema.json),
and positive/negative vectors are in the contribution-index tests.
