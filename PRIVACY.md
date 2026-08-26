# Privacy model

SwarmProof is pseudonymous, not magically anonymous. The public coordinator identifier is an
Ed25519 `did:key`; no person, company, location, email address, device path, timezone, IP
address, or existing social account is intentionally published.

## Data retained

- Strict `SP1` envelopes containing structured identifiers, hashes, signatures, and timestamps,
  plus the canonical server-reported source timestamp needed to reject pre-start placement.
- Hashes and deterministic similarity sketches derived transiently from bounded public samples.
- Aggregate counts, same-denominator clustered-message coverage, missingness, and source-window
  metadata. The public workflow discards individual message hashes and sketches.

## Data not retained

- Arbitrary room-message text.
- Private or encrypted rooms.
- IP addresses, browser identifiers, cookies, analytics identifiers, or access logs controlled
  by this project.
- Private keys, wallet material, email addresses, or account recovery data.

The public control claim contains only the already-public coordinator DID, pseudonymous project
identifier, exact public repository/origin URIs, canonical UTC validity times, and an Ed25519
signature. The generator reads the private key from an owner-only regular file, derives the DID,
zeros the input buffer after parsing, and never prints the PEM or signature. JavaScript and the
host operating system do not provide a guarantee that all key-object memory is immediately wiped.

The optional contribution index is free-text-free. It retains only the public DID, canonical UTC
issuance time, hashes, full Git commit IDs, repository/path locators, bounded Technocore sequence
metadata, configured public project identifiers, and typed evidence status constants. It has no
fields for a legal name, email, wallet, account-recovery data, device path, IP address, arbitrary
message text, or private key. Official-task evidence can record `submitted` only and must keep
official acceptance and reward status at `not-claimed`.

The contribution-index signing CLI validates available non-secret inputs before reading the PEM.
It overwrites its mutable file-read buffer in a `finally` path immediately after Node parses it,
including parser failure. This does not erase the key file or guarantee erasure of copies retained
by Node/OpenSSL, the allocator, or the operating system.

Hashes of public short text may be vulnerable to guessing. They are published only where they
are needed for reproducibility, and this limitation is disclosed in every dataset manifest.

The repository must pass `npm run privacy:audit` before publication. That check rejects local
home paths, email addresses outside the approved pseudonymous address, common secret formats,
source maps, and known private-key markers.

## Boundary of pseudonymity

The public repository and site are designed to expose only the coordinator DID and project
pseudonym. This does not hide network metadata from infrastructure operators: Technocore,
GitHub, Cloudflare, connectivity providers, and legally authorized parties may retain or infer
IP addresses, request times, device attributes, account-recovery data, or traffic correlations.
SwarmProof therefore claims public pseudonymity, not unlinkability from those operators.
