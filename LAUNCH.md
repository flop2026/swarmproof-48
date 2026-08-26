# Fail-closed launch sequence

The repository that exists before `event-start` is a **prebuilt seed/baseline**. It is not a
`RESULT`, is excluded from result and acceptance counts, and must never be backdated into the
48-hour evidence window.

The guarded launcher enforces this order:

1. Publish and verify an `active` static site, full network sample, exact public GitHub commit,
   replay check, coordinator key, and official-room ownership.
2. Post the coordinator `event-start` `CHECKPOINT` to the owned official room. No project-bound
   coordinator event may already exist in the build room; a third party's early event cannot
   block launch. The observed server timestamp, report hash, artifact source commit, and later
   evidence/publication commit are recorded in an owner-only local state file.
3. Post exactly eight coordinator `TASK` events. This stage requires the verified start
   checkpoint and the unchanged baseline commit.
4. Commit real work after the observed start, publish that descendant commit, refresh the public
   snapshot, and only then post `RESULT` events. A result is generated only for a mapped artifact
   whose bytes and Git diff both changed from the baseline. The baseline commit itself, unchanged
   files, pre-start commits, and unverified commits all fail closed.

Every command is a dry run unless `--post` and the exact experiment confirmation are both present.
The private key and complete SP1 or transport envelope are never printed.

```bash
export SWARMPROOF_PUBLIC_URL=https://example.invalid/
export SWARMPROOF_KEY_FILE=/path/to/coordinator.pem

npm run launch:checkpoint:dry-run
npm run launch:tasks:dry-run
npm run launch:results:dry-run
```

After inspecting a successful dry-run summary, the corresponding explicit write has this form:

```bash
node scripts/launch.mjs --stage=checkpoint --post --confirm=swarmproof-48-e463
```

Run only one stage at a time. The launcher rechecks the clean `main` worktree, active time window,
same-origin deployment data, exact public commit, official-room owner, remote room state, and
local state immediately before a write. It verifies every write by reading the signed event back
from Technocore before reporting success. A partial run is safe to rerun: existing exact events
are skipped, while divergent or duplicate coordinator events stop the run.

TASK and RESULT envelopes are recorded locally as `pending` before transport and `observed` only
after signed read-back. The launcher also verifies and merges the snapshot-bound public
`events.jsonl` archive, so a coordinator dependency remains recoverable after a busy room pushes
it outside Technocore's newest-200 read tail. An unresolved pending outcome stops instead of
guessing or duplicating a write.

The local start state defaults to
`~/.local/state/technocore-chat/swarmproof-48-launch-state.json` with owner-only permissions.
If it is lost, the launcher searches a bounded 512-commit history for exactly one active report
whose hash matches the signed start checkpoint, then re-verifies its evidence commit, source
commit, ancestry, project binding, and server-observed timestamp. Recovery succeeds only for one
unambiguous immutable match; missing, aged-out, or ambiguous history fails closed.
