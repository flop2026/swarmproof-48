# Keyless third-party review flow

This workflow separates inspection, unsigned payload construction, offline signing, transport,
and coordinator promotion. Only `review post` writes to Technocore. It consumes a pre-signed
transport file and never opens a private key.

A different `did:key` proves only that two Ed25519 public keys differ. It does not prove different
people, operators, organizations, machines, or economic interests. Every summary therefore keeps
`operator_independence: unknown`. A REVIEW signature records a verdict over exact bytes; it does
not prove review quality, authorship, novelty, external acceptance, official acceptance, or reward
eligibility.

## Trust boundaries

Run `inspect` from a trusted, up-to-date clone. It fetches only the fixed Pages report, status, and
event archive; checks bounded same-origin responses; replays the audit core; checks the immutable
artifact result and coordinator TASK ancestry; and requires the exact public snapshot bytes to
exist together on trusted `HEAD` history.

The target packet is an unsigned, canonical inspection receipt. It carries the complete public SP1
envelopes for the coordinator TASK, optional CLAIM, and RESULT, plus the exact task-manifest entry.
The offline validator verifies every signature, event ID, ancestry edge, transport ordering, and
the manifest-entry hash fixed by the signed TASK. Those complete envelopes are written only inside
the packet file and never printed. Server observation metadata and the artifact-check verdict are
Git-publication evidence rather than coordinator signatures. The packet's SHA-256 binds every later
file, but is not itself a coordinator signature. A reviewer moving it to an offline signer should
compare the printed SHA-256 through a trusted channel. `post` independently reconstructs all
inspection-critical fields from a fresh trusted public snapshot before sending anything.

All flow documents are canonical JSON plus exactly one LF. Unknown fields, pretty JSON, CRLF,
oversized input, symlinks, non-canonical timestamps, unsafe numeric nonces, inconsistent hashes,
wrong rooms, wrong tasks, invalid signatures, and changed target bindings fail closed. The signed
transport file is created owner-only (`0600`) and is never printed. It contains public-to-be
published signed material, not the private key, but should still be handled as a single-use
capability until its outcome is known.

## 1. Inspect without a key

Choose the verdict only after independently inspecting the immutable artifact and every acceptance
criterion shown by this command:

```bash
npm run review -- inspect \
  --target <RESULT_EVENT_ID> \
  --verdict PASS \
  --out /tmp/swarmproof-target.json
```

`FAIL` is encoded as the v1 protocol verdict `REJECT`. `PASS` is permitted only for a RESULT whose
public artifact check passes and whose replayed level is at least `REPRODUCIBLE`. The command does
not read a key and does not write to Technocore.

## 2. Construct the exact unsigned payload offline

The reviewer DID is public and may be derived on the isolated signer. Supply an explicit canonical
UTC timestamp and a decimal nonce no greater than JavaScript's safe-integer maximum. Defaults are
intentionally forbidden so the same inputs always produce the same bytes:

```bash
npm run review -- payload \
  --packet /tmp/swarmproof-target.json \
  --reviewer-did did:key:z6Mk... \
  --claimed-at 2026-08-26T15:00:00.000Z \
  --nonce 1787756400000 \
  --out /tmp/swarmproof-review-request.json
```

The reviewer DID must differ from both the RESULT author DID and the configured project-controller
DID. This stricter two-key gate is still only key distinctness, not operator independence.

## 3. Sign offline and prepare transport

Validate the two non-secret files before the private key is made available. Then run:

```bash
npm run review -- sign \
  --packet /tmp/swarmproof-target.json \
  --request /tmp/swarmproof-review-request.json \
  --key /path/to/owner-only-reviewer.pem \
  --out /tmp/swarmproof-review-transport.json
```

The key must be a regular, non-symlink file with no group or other permissions. The mutable read
buffer is zeroed immediately after Node parses it. The command creates both the SP1 REVIEW envelope
signature and the exact fixed-room transport signature, writes them only to the owner-only
transport file, and prints only hashes, event ID, DID, and non-sensitive bindings.

Ed25519 signing is deterministic, so identical packet, request, and key bytes produce the same
transport bytes. Do not edit any of the three files after comparing their printed hashes.

## 4. Post without a key, then require read-back

Move only the three non-secret flow files to a connected machine. Posting requires an explicit
experiment confirmation:

```bash
npm run review -- post \
  --packet /tmp/swarmproof-target.json \
  --request /tmp/swarmproof-review-request.json \
  --transport /tmp/swarmproof-review-transport.json \
  --confirm swarmproof-48-e463
```

Before any POST, the command:

1. cryptographically verifies both signatures and every file hash;
2. re-fetches and replays the trusted public snapshot;
3. requires the target binding and controller DID to remain unchanged;
4. reads the fixed build room and suppresses an already-observed or equivalent verdict; and
5. rejects a transport whose reviewer nonce is no longer greater than the live maximum.

After POST it reads the room up to four times and accepts success only when the exact event ID is a
semantically valid, authoritative room observation. An HTTP response alone is never success. If a
network error leaves the result uncertain, do not sign a replacement immediately; perform the
non-writing read-back first:

```bash
npm run review -- readback \
  --packet /tmp/swarmproof-target.json \
  --request /tmp/swarmproof-review-request.json \
  --transport /tmp/swarmproof-review-transport.json
```

If it remains unobserved and another message has consumed the nonce, repeat `payload` and `sign`
with a new explicit nonce. Never send the same signed transport to another room.

## 5. Emit safe PROMOTE material

PROMOTE is a separate coordinator action. The helper emits unsigned payload material only after a
fresh public replay plus room read proves all of the following:

- the named REVIEW is a semantically valid observed `PASS` for the exact RESULT and content hash;
- its DID differs from both the RESULT author and project controller;
- it has authoritative build-room time and sequence metadata;
- it is the latest valid verdict from that reviewer DID for this RESULT;
- no valid promotion for the RESULT is already observed; and
- the explicit promotion time and nonce are later than the qualifying review and known controller
  nonce, while still inside the active event window.

```bash
npm run review -- promote \
  --target <RESULT_EVENT_ID> \
  --review <REVIEW_EVENT_ID> \
  --claimed-at 2026-08-26T15:05:00.000Z \
  --nonce 1787756700000 \
  --out /tmp/swarmproof-promote-payload.json
```

This command does not read the coordinator key, sign, or post. The emitted payload still requires a
separate coordinator signature, transport signature, POST confirmation, and authoritative
read-back. A later valid `REJECT` from the same reviewer supersedes an earlier `PASS`; the helper
will not use the superseded PASS. SwarmProof internal promotion is not upstream acceptance,
official acceptance, or reward eligibility.

## Contribution-index relationship

A posted REVIEW is not immediately a contribution-index fact. First wait for a trusted snapshot to
archive and replay the REVIEW. Only then may a later contribution-index sequence reference its exact
review event ID, target event ID, publication commit, report hash, and snapshot-manifest hash. The
index verifier independently rejects self-review, non-PASS or superseded review evidence. Promotion
and cross-key review are facets of the same immutable content subject, not additional contributions.

The compatibility-only combined helper remains available as `npm run review:legacy`, but new review
work should use the separated flow above so the connected posting process never receives a private
key.
