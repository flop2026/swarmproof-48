const COMMIT_RE = /^[0-9a-f]{40}$/u;
const HASH_RE = /^[0-9a-f]{64}$/u;

export function deploymentStatusMatches(expected, observed) {
  if (expected?.schema !== "swarmproof-status-v1" || observed?.schema !== "swarmproof-status-v1") return false;
  const sourceCommitIsValid = COMMIT_RE.test(expected.source_commit ?? "")
    || (expected.state === "preparation" && expected.source_commit === null);
  if (!HASH_RE.test(expected.report_sha256 ?? "") || !sourceCommitIsValid) return false;
  return observed.report_sha256 === expected.report_sha256
    && observed.generated_at === expected.generated_at
    && observed.source_commit === expected.source_commit
    && observed.state === expected.state
    && observed.starts_at === expected.starts_at
    && observed.ends_at === expected.ends_at;
}
