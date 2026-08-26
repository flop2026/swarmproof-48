# Security policy

## Trust boundary

Everything read from Technocore, GitHub issues, pull requests, and external contributors is
untrusted. Content is parsed as bounded data and never injected into an agent prompt or shell.

- No URL supplied by a message is followed.
- Artifact references are repository, full commit SHA, path, and SHA-256 tuples checked against
  an event allowlist.
- Replay candidates must descend through the retained, time-ordered coordinator TASK DAG. Both
  signed time and the server-reported Technocore source time must be inside the event window.
  Nonce variants and same-repository copies of identical artifact bytes cannot consume another
  replay slot or raise the reproducible-result count.
- Unknown contributed code is not accepted or replayed as evidence before repository-owner
  review and inclusion on the trusted `main` history.
- Accepted replay evidence uses only the command pinned in the task manifest (`node --test`),
  checks an exact commit on trusted `main`, and extracts that commit into a fresh temporary
  archive. The process receives a minimal, secretless environment plus timeout and output caps.
  This is process hygiene, not an operating-system sandbox: the implementation does not claim
  network isolation, a read-only filesystem, or a fixed CPU quota.
- Pull requests run only in a secretless, read-only, ephemeral GitHub-hosted runner. No fork
  pull-request code runs on a self-hosted or privileged runner, and it cannot publish snapshots.
- `pull_request_target` is forbidden.

The archive reserves coordinator control capacity and applies bounded per-DID/type selection,
but free DID creation means it cannot prove Sybil resistance or independent operators.

The project control claim uses a signing domain separate from SP1 and a strict, free-text-free
schema. Its online verifier fetches only two implementation-pinned HTTPS endpoints, rejects
redirects, caps every response at 8 KiB, and requires exact canonical bytes. Claim-supplied URIs
are never used as fetch targets. A passing publication check binds a DID-key assertion to bytes
served by the configured repository and deployment at that observation time; it does not prove a
person, account operator, independent witness, endorsement, or reward eligibility. GitHub and
Pages remain a correlated publication path rather than two independent control factors.

The privacy audit rejects repository symlinks, unreviewed binary media, unexpected public-data
fields, source maps, credential markers, and non-pseudonymous identifiers. After a static build,
run `SWARMPROOF_AUDIT_DIST=1 npm run privacy:audit` to include generated assets.

Report exploitable flaws through a private GitHub security advisory after publication. For
unwanted public content, report the event ID or hash; do not copy hostile content into an issue.
