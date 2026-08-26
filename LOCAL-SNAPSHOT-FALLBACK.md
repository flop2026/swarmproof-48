# Emergency local snapshot fallback (macOS)

This is a best-effort deadman for the public snapshot workflow. It is not a high-availability
guarantee, a second coordinator, or a replacement for monitoring. Its only purpose is to let one
pre-provisioned Mac publish a snapshot when the normal GitHub Actions publisher appears to have
stopped before an active status reaches its four-hour stale boundary.

The repository contains only a LaunchAgent **example**. It is not installed or loaded by this
project, and preparing it does not authorize an immediate run or push.

## Safety boundary

- Use a dedicated checkout whose checked-out branch is `main`. Do not develop, review, or keep
  unrelated files in that checkout.
- The checkout must be completely clean, including untracked files, before every attempt. The
  fallback fails closed rather than stashing, resetting, cleaning, or deleting anything.
- `origin` must be the expected SSH GitHub remote. Updating local `main` is fast-forward-only;
  rebases, merge commits, force pushes, and force-with-lease are forbidden.
- A shared, owner-checked lock in the checkout's Git common directory serializes the complete
  fallback attempt. The underlying snapshot and finalizer also retain their repository mutation
  lock. Neither layer removes another owner's lock, including a stale-looking lock.
- The fallback has no coordinator signing key, GitHub credential, or Cloudflare credential. Public
  status and Actions state are read anonymously. The only publication authority is an SSH identity
  already available through a preconfigured `ssh-agent`; the runner does not start an agent, load a
  key, or read a key file.
- Logs contain only bounded operational decisions, commit/hash identifiers, and generic errors.
  They must not contain response bodies, environment dumps, request headers, repository-local
  secrets, or SSH material.

## Activation gate

The LaunchAgent wakes every ten minutes, but a wake is normally a no-op. A normal keepalive attempt
may begin only when all of these checks succeed:

1. The canonical Cloudflare Pages `data/status.json` is valid and its `generated_at` age is at
   least **3 hours 15 minutes**. This is deliberately 45 minutes before the active status
   `stale_after_seconds` limit of four hours.
2. The latest run of the canonical snapshot Actions workflow is not queued, waiting, pending, or
   in progress, and the workflow has been quiet for at least **30 minutes**. Missing, ambiguous,
   rate-limited, or malformed Actions data causes a skip.
3. The dedicated checkout passes every branch, cleanliness, origin, dependency, clock, and
   `ssh-agent` preflight.
4. After the remote and local preflights, the runner reads the canonical public status again and
   requires the status identity to be unchanged. A normal publisher update wins the race and makes
   the fallback stop without mutation.

At or after `ends_at`, the required final drain bypasses only the 3-hour-15-minute status-age
threshold so a recently refreshed status cannot postpone the archive boundary. It still requires
the valid active status, the 30-minute Actions quiet period, every local preflight, persistent
backoff eligibility, and the unchanged-status race check.

These gates reduce overlap; they cannot prove that a delayed GitHub job will not start later. The
normal workflow and this runner therefore also rely on fast-forward publication and exact public
read-back. This remains best-effort recovery, not an availability or exclusivity guarantee.

Retryable failures are subject to persistent exponential backoff, capped at six hours. A `429`
honors a bounded `Retry-After` before that exponential step is applied. The runner keeps the
owner-only state in the checkout's shared Git common directory, outside tracked files. Restarting
the Mac or restarting launchd must not erase it. Do not delete or edit the runner's state to force
an attempt; inspect the recorded failure and repository state first.

## One eligible attempt

After acquiring the shared lock, the runner follows one fail-closed sequence:

1. Recheck that the checkout is clean on local `main`, fetch `origin/main` over SSH, and update by
   fast-forward only. A divergent or locally-ahead starting checkout requires an operator.
2. Ask the lifecycle checker whether the event boundary requires the final drain.
3. For a normal keepalive, run the bounded snapshot with `SWARMPROOF_NETWORK=0` and
   `SWARMPROOF_RETAIN_SKETCHES=0`. This still polls the configured build-room tail; it avoids the
   broad network sample.
4. When the final drain is due, use `SWARMPROOF_NETWORK=1` with the sample sizes from
   `config/event.json`, retain no per-message sketches, require the snapshot action to be
   `final_drain`, and run the transactional finalizer. A final sample must return every configured
   room with no failures, and the room tail and cursor checks must pass. The runner does not weaken
   or expand those bounds.
5. Refuse any changed path outside `config/event.json` and `public/data/`. If those allowed paths
   changed, stage only them and create one local commit. The allowed pseudonymous identity is
   `SwarmProof Coordinator <321255904+flop2026@users.noreply.github.com>` with
   `user.useConfigOnly=true`.
6. Validate the immutable local candidate before publication with the complete check set defined
   by `npm run validate`. Run the privacy audit with `SWARMPROOF_CHECK_HISTORY=1`; for a final
   drain, also run the report verifier. Any failure leaves the candidate and all recovery journals
   intact for inspection.
7. Recheck that the original public status identity and observed Actions run are still unchanged,
   that no recent Actions run can still publish, and that the remote `main` tip is still the exact
   parent of the candidate. Then perform exactly one ordinary SSH push of the candidate to `main`.
   There is no automatic push retry.
8. If the push result is unknown, perform exactly one read-only `git ls-remote` of
   `refs/heads/main`. Continue only if it proves that the remote tip is the exact candidate. A
   different tip, an ambiguous response, or a failed lookup is preserved as an incident; the
   runner must not push again.
9. Require the exact candidate status to appear at the canonical Cloudflare Pages origin. The
   entire canonical status must match, including the expected report hash, source commit,
   generation time, state, and event window. A timeout or mismatch is a failure and never triggers
   another push.

If the snapshot produces no allowed change, the runner exits without committing or pushing.

## LaunchAgent template

The example is [`ops/org.swarmproof.local-snapshot-fallback.plist.example`](ops/org.swarmproof.local-snapshot-fallback.plist.example).
Before operator-controlled installation:

1. Replace every `__REPOSITORY_ROOT__` with the absolute path of the dedicated checkout.
2. Replace every `__NODE_BINARY__` with the absolute path to the pinned Node.js binary compatible
   with `.nvmrc`. launchd does not load interactive shell initialization.
3. Replace every `__STATE_DIRECTORY__` with an absolute path to a dedicated log directory outside
   the checkout, and create that directory with mode `0700` before the LaunchAgent is loaded. It
   holds only the secretless `stdout.log` and `stderr.log`; persistent runner state stays in the
   shared Git common directory.
4. Ensure locked dependencies are already installed, the checkout's SSH `origin` is correct, and
   the LaunchAgent environment can reach the preconfigured `ssh-agent`. Do not put a key path,
   passphrase, credential, or SSH command override in the plist.
5. Check that no placeholders remain and validate the file with `plutil -lint`.

Loading, bootstrapping, or enabling the LaunchAgent is a separate operator decision and is not
performed by repository setup. The example uses `StartInterval=600`; launchd does not start a
second copy when the prior invocation is still running. Sleep and a long-running invocation can
also cause interval wakes to be missed, so the standby Mac needs reliable power, networking, and
time synchronization even though the mechanism still provides no four-hour availability guarantee.

## Incident handling

Every failure is intentionally non-destructive. Leave the checkout, local candidate commit,
shared lock, finalization transaction, persistent backoff record, and logs as found. In particular,
do not automatically reset `main`, delete a lock or transaction journal, amend a candidate, or
repeat a push whose outcome was not proven.

An operator should inspect, in order:

- the canonical public status and the latest snapshot Actions run;
- the persistent fallback decision and its next eligible time;
- local `HEAD`, `origin/main`, and a fresh read-only remote tip;
- the working tree, shared lock ownership, and any finalization transaction journal;
- validation and exact Cloudflare read-back output.

Resume only after the operator can classify the attempt as not published, published exactly, or
superseded by the normal publisher. Ambiguity is a reason to stop, not a reason to retry.
