import assert from "node:assert/strict";
import { createPrivateKey, generateKeyPairSync } from "node:crypto";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { canonicalize } from "../lib/canonical.mjs";
import {
  CONTRIBUTION_INDEX_DOMAIN,
  CONTRIBUTION_INDEX_PUBLICATIONS,
  CONTRIBUTION_INDEX_SCHEMA,
  contributionIdForSubject,
  contributionsFromSwarmproofReport,
  createContributionIndex,
  deriveContributionFacets,
  parseContributionIndex,
  serializeContributionIndex,
  verifyContributionIndex,
  verifyContributionIndexControlClaim,
  verifyContributionIndexPublications,
  verifyContributionIndexReplacement,
} from "../lib/contribution-index.mjs";
import {
  CONTROL_CLAIM_DOMAIN,
  createControlClaim,
} from "../lib/control-claim.mjs";
import { createEnvelope } from "../lib/protocol.mjs";
import { didFromPrivateKey, sha256Hex, signUtf8 } from "../lib/crypto.mjs";

const ISSUED_AT = "2026-08-26T12:30:00.000Z";
const HASH_A = "a".repeat(64);
const HASH_B = "b".repeat(64);
const HASH_C = "c".repeat(64);
const HASH_D = "d".repeat(64);
const COMMIT_A = "a".repeat(40);
const PUBLICATION_COMMIT = "24e6dfe6549cc791a64ed2d6e7d7364784b23959";
const REPOSITORY = "flop2026/swarmproof-48";
const fixedSigner = createPrivateKey({
  key: Buffer.concat([
    Buffer.from("302e020100300506032b657004220420", "hex"),
    Buffer.from("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "hex"),
  ]),
  format: "der",
  type: "pkcs8",
});
const fixtureDid = didFromPrivateKey(fixedSigner);
const verifyOptions = { expectedController: fixtureDid };

function subject(hash = HASH_A) {
  return { type: "git-content", repository: REPOSITORY, content_sha256: hash };
}

function resultEvidence(overrides = {}) {
  return {
    kind: "swarmproof-result-snapshot",
    result_event_id: HASH_B,
    publication_commit: PUBLICATION_COMMIT,
    report_sha256: HASH_C,
    snapshot_manifest_sha256: HASH_D,
    ...overrides,
  };
}

function fixture(overrides = {}) {
  return createContributionIndex([
    {
      subject: subject(),
      evidence: [resultEvidence()],
    },
  ], fixedSigner, {
    issuedAt: ISSUED_AT,
    sequence: "1",
    previousIndexSha256: null,
    controlClaimSha256: HASH_D,
    expectedController: fixtureDid,
    ...overrides,
  });
}

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

function resign(document, signingInput = null) {
  const next = clone(document);
  next.proof.value = signUtf8(
    fixedSigner,
    signingInput ?? `${CONTRIBUTION_INDEX_DOMAIN}${canonicalize(next.payload)}`,
  ).toString("base64url");
  return next;
}

test("contribution index has a deterministic canonical domain-separated vector", () => {
  const created = fixture();
  assert.equal(created.document.payload.schema, CONTRIBUTION_INDEX_SCHEMA);
  assert.equal(created.document.payload.controller, fixtureDid);
  assert.equal(
    created.document.payload.contributions[0].contribution_id,
    "2db567448cecd5db5aafd06f013c7da2793bca524c8caf8f86abe268aa6cfad5",
  );
  assert.equal(created.document.payload.contributions[0].contribution_id, contributionIdForSubject(subject()));
  assert.equal(
    created.document.proof.value,
    "_xU4_SJ1UrN1H4_1l-rRs6rjQoTFORb5mwD_6uJp1VwnFyloscFazfIMyL2dyoHIqxdp9W6DXIDlG3uHBgq2DQ",
  );
  assert.equal(created.index_sha256, "3f0e38484858993aceeb6c07a1d0f1d00cb8df191017221bc9c5d9fd17604b40");
  assert.equal(created.serialized, `${canonicalize(created.document)}\n`);
  assert.match(created.document.proof.value, /^[A-Za-z0-9_-]{86}$/u);
  assert.equal(verifyContributionIndex(created.serialized, verifyOptions).signature_valid, true);
  assert.equal(parseContributionIndex(created.serialized, verifyOptions).payload.sequence, "1");
  assert.equal(created.index_sha256, sha256Hex(created.serialized));
});

test("control-claim and SP1 signing bytes cannot be reused as an index proof", () => {
  const created = fixture();
  const wrongControlDomain = resign(
    created.document,
    `${CONTROL_CLAIM_DOMAIN}${canonicalize(created.document.payload)}`,
  );
  assert.throws(
    () => verifyContributionIndex(wrongControlDomain, verifyOptions),
    /signature is invalid/u,
  );
  const payloadBase64 = Buffer.from(canonicalize(created.document.payload), "utf8").toString("base64url");
  const wrongSp1Domain = resign(
    created.document,
    `swarmproof-event-v1|swarmproof-48-e463|${payloadBase64}`,
  );
  assert.throws(
    () => verifyContributionIndex(wrongSp1Domain, verifyOptions),
    /signature is invalid/u,
  );
});

test("index rejects non-canonical bytes, extra fields, and signed mutation", () => {
  const created = fixture();
  assert.throws(
    () => parseContributionIndex(JSON.stringify(created.document, null, 2), verifyOptions),
    /not canonical JSON/u,
  );
  assert.throws(
    () => parseContributionIndex(`${created.serialized}\n`, verifyOptions),
    /not canonical JSON/u,
  );
  const extra = clone(created.document);
  extra.payload.note = "unbound";
  assert.throws(() => serializeContributionIndex(extra, verifyOptions), /invalid field set/u);
  const mutation = clone(created.document);
  mutation.payload.issued_at = "2026-08-26T12:31:00.000Z";
  assert.throws(() => verifyContributionIndex(mutation, verifyOptions), /signature is invalid/u);
});

test("index requires derived IDs, canonical ordering, uniqueness, and one snapshot commit", () => {
  const created = createContributionIndex([
    { subject: subject(HASH_B), evidence: [resultEvidence({ result_event_id: HASH_C })] },
    { subject: subject(HASH_A), evidence: [resultEvidence()] },
  ], fixedSigner, {
    issuedAt: ISSUED_AT,
    sequence: "1",
    controlClaimSha256: HASH_D,
    expectedController: fixtureDid,
  });
  const ids = created.document.payload.contributions.map(item => item.contribution_id);
  assert.deepEqual(ids, [...ids].sort());

  const wrongId = resign(created.document);
  wrongId.payload.contributions[0].contribution_id = HASH_D;
  assert.throws(() => verifyContributionIndex(resign(wrongId), verifyOptions), /does not match its subject/u);

  const duplicate = clone(created.document);
  duplicate.payload.contributions.push(clone(duplicate.payload.contributions[0]));
  assert.throws(() => verifyContributionIndex(resign(duplicate), verifyOptions), /duplicated|canonical contribution_id order/u);

  const caseVariant = clone(created.document);
  caseVariant.payload.contributions.push(clone(caseVariant.payload.contributions[0]));
  const caseVariantContribution = caseVariant.payload.contributions.at(-1);
  caseVariantContribution.subject.repository = "FLOP2026/SWARMPROOF-48";
  assert.equal(
    contributionIdForSubject(caseVariantContribution.subject),
    caseVariant.payload.contributions[0].contribution_id,
  );
  assert.throws(
    () => verifyContributionIndex(resign(caseVariant), verifyOptions),
    /duplicated|canonical contribution_id order/u,
  );

  const mixedPublication = clone(created.document);
  mixedPublication.payload.contributions[1].evidence[0].publication_commit = "b".repeat(40);
  assert.throws(
    () => verifyContributionIndex(resign(mixedPublication), verifyOptions),
    /only one immutable publication commit/u,
  );
});

test("sequence and previous-index linkage are canonical and fail closed", () => {
  assert.throws(
    () => createContributionIndex([], fixedSigner, {
      issuedAt: ISSUED_AT,
      sequence: "1",
      controlClaimSha256: HASH_D,
      expectedController: fixtureDid,
    }),
    /at least one contribution/u,
  );
  assert.throws(() => fixture({ sequence: "01" }), /sequence is invalid/u);
  assert.throws(() => fixture({ sequence: "1", previousIndexSha256: HASH_A }), /sequence 1 cannot/u);
  assert.throws(() => fixture({ sequence: "2", previousIndexSha256: null }), /requires a previous index/u);
  const second = fixture({ sequence: "2", previousIndexSha256: HASH_A });
  assert.equal(second.document.payload.previous_index_sha256, HASH_A);
});

test("replacement verifies the prior signature and chain without binding it to a rotated claim", () => {
  const previous = fixture({ controlClaimSha256: HASH_A });
  const verified = verifyContributionIndexReplacement(previous.serialized, {
    sequence: "2",
    previous_index_sha256: previous.index_sha256,
  }, verifyOptions);
  assert.equal(verified.index_sha256, previous.index_sha256);
  const next = fixture({
    sequence: "2",
    previousIndexSha256: previous.index_sha256,
    controlClaimSha256: HASH_B,
  });
  assert.equal(next.document.payload.control_claim_sha256, HASH_B);
  assert.throws(
    () => verifyContributionIndexReplacement(previous.serialized, {
      sequence: "3",
      previous_index_sha256: previous.index_sha256,
    }, verifyOptions),
    /increment the existing index/u,
  );
  assert.throws(
    () => verifyContributionIndexReplacement(previous.serialized, {
      sequence: "2",
      previous_index_sha256: HASH_D,
    }, verifyOptions),
    /does not name the existing index/u,
  );
  const tampered = clone(previous.document);
  tampered.payload.issued_at = "2026-08-26T12:31:00.000Z";
  assert.throws(
    () => verifyContributionIndexReplacement(tampered, {
      sequence: "2",
      previous_index_sha256: previous.index_sha256,
    }, verifyOptions),
    /signature is invalid/u,
  );
});

test("evidence classes preserve separate semantics and reject overclaims", () => {
  const base = fixture();
  const vectors = [
    {
      name: "server transport overclaim",
      evidence: {
        kind: "server-observation",
        service: "technocore.chat",
        room: "agentscout",
        source_seq: "8",
        source_ts: ISSUED_AT,
        message_sha256: HASH_B,
        transport_authentication: "verified-signature",
      },
      expected: /must remain server-reported/u,
    },
    {
      name: "self upstream",
      evidence: {
        kind: "upstream-acceptance",
        forge: "github",
        repository: REPOSITORY,
        pull_request: "1",
        accepted_commit: COMMIT_A,
        path: "lib/protocol.mjs",
        content_sha256: HASH_A,
      },
      expected: /must be an upstream repository/u,
    },
    {
      name: "case-variant self upstream",
      evidence: {
        kind: "upstream-acceptance",
        forge: "github",
        repository: "FLOP2026/SWARMPROOF-48",
        pull_request: "1",
        accepted_commit: COMMIT_A,
        path: "lib/protocol.mjs",
        content_sha256: HASH_A,
      },
      expected: /must be an upstream repository/u,
    },
    {
      name: "self adoption",
      evidence: {
        kind: "external-adoption",
        forge: "github",
        repository: "flop2026/another",
        commit: COMMIT_A,
        path: "README.md",
        content_sha256: HASH_B,
        relation: "citation",
        marker: "https://github.com/flop2026/swarmproof-48",
      },
      expected: /external namespace/u,
    },
    {
      name: "case-variant self adoption",
      evidence: {
        kind: "external-adoption",
        forge: "github",
        repository: "FlOp2026/another",
        commit: COMMIT_A,
        path: "README.md",
        content_sha256: HASH_B,
        relation: "citation",
        marker: "https://github.com/flop2026/swarmproof-48",
      },
      expected: /external namespace/u,
    },
    {
      name: "official GitHub repository-prefix escape",
      evidence: {
        kind: "official-task",
        authority: "flop-labs-x",
        task_uri: "https://x.com/flop_labs/status/2091830155270672521",
        task_source_sha256: HASH_B,
        submission_uri: "https://github.com/flop2026/swarmproof-48evil",
        submission_sha256: HASH_A,
        stage: "submitted",
        official_acceptance: "not-claimed",
        reward_status: "not-claimed",
      },
      expected: /not an allowlisted project resource/u,
    },
    {
      name: "official Technocore room-suffix escape",
      evidence: {
        kind: "official-task",
        authority: "flop-labs-x",
        task_uri: "https://x.com/flop_labs/status/2091830155270672521",
        task_source_sha256: HASH_B,
        submission_uri: "https://technocore.chat/r/agentscout/extra",
        submission_sha256: HASH_A,
        stage: "submitted",
        official_acceptance: "not-claimed",
        reward_status: "not-claimed",
      },
      expected: /not an allowlisted project resource/u,
    },
    {
      name: "official acceptance overclaim",
      evidence: {
        kind: "official-task",
        authority: "flop-labs-x",
        task_uri: "https://x.com/flop_labs/status/2091830155270672521",
        task_source_sha256: HASH_B,
        submission_uri: "https://github.com/flop2026/swarmproof-48",
        submission_sha256: HASH_A,
        stage: "accepted",
        official_acceptance: "claimed",
        reward_status: "eligible",
      },
      expected: /stage may only be submitted|official_acceptance|reward_status/u,
    },
  ];
  for (const vector of vectors) {
    const document = clone(base.document);
    document.payload.contributions[0].evidence = [vector.evidence];
    assert.throws(
      () => verifyContributionIndex(resign(document), verifyOptions),
      vector.expected,
      vector.name,
    );
  }
});

test("valid typed references remain claims until their source-specific verifier runs", () => {
  const evidence = [
    {
      kind: "external-adoption",
      forge: "github",
      repository: "outside/example",
      commit: COMMIT_A,
      path: "README.md",
      content_sha256: HASH_B,
      relation: "citation",
      marker: "https://github.com/flop2026/swarmproof-48",
    },
    {
      kind: "official-task",
      authority: "flop-labs-x",
      task_uri: "https://x.com/flop_labs/status/2091830155270672521",
      task_source_sha256: HASH_B,
      submission_uri: "https://technocore.chat/r/agentscout",
      submission_sha256: HASH_A,
      stage: "submitted",
      official_acceptance: "not-claimed",
      reward_status: "not-claimed",
    },
    resultEvidence(),
  ];
  const created = createContributionIndex([{ subject: subject(), evidence }], fixedSigner, {
    issuedAt: ISSUED_AT,
    sequence: "1",
    controlClaimSha256: HASH_D,
    expectedController: fixtureDid,
  });
  assert.equal(verifyContributionIndex(created.serialized, verifyOptions).signature_valid, true);
});

test("control-claim binding is exact and evaluated at index issuance", () => {
  const claim = createControlClaim(fixedSigner, {
    issuedAt: "2026-08-26T12:00:00.000Z",
    expiresAt: "2026-08-27T12:00:00.000Z",
    expectedController: fixtureDid,
  });
  const created = fixture({ controlClaimSha256: claim.claim_sha256 });
  const verified = verifyContributionIndexControlClaim(created.serialized, claim.serialized, verifyOptions);
  assert.equal(verified.control_claim.claim_sha256, claim.claim_sha256);
  const wrong = fixture({ controlClaimSha256: HASH_A });
  assert.throws(
    () => verifyContributionIndexControlClaim(wrong.serialized, claim.serialized, verifyOptions),
    /control-claim hash does not match/u,
  );
});

test("fixed publication verification follows no index-supplied URL", async () => {
  const created = fixture();
  const calls = [];
  const verified = await verifyContributionIndexPublications(created.serialized, {
    ...verifyOptions,
    fetchImplementation: async (url, options) => {
      calls.push({ url, options });
      return new Response(created.serialized, {
        status: 200,
        headers: { "content-length": String(Buffer.byteLength(created.serialized)) },
      });
    },
  });
  assert.deepEqual(calls.map(call => call.url), CONTRIBUTION_INDEX_PUBLICATIONS.map(item => item.url));
  assert.ok(calls.every(call => call.options.redirect === "error"));
  assert.ok(verified.publications.every(item => item.status === "pass"));
  await assert.rejects(
    verifyContributionIndexPublications(created.serialized, {
      ...verifyOptions,
      fetchImplementation: async (_url, _options) => new Response(`${created.serialized}\n`, { status: 200 }),
    }),
    /publication mismatch/u,
  );
});

test("current public snapshot becomes eight subjects, not additive ladder events", async () => {
  const [reportText, statusText, events, configText, tasksText] = await Promise.all([
    readFile(new URL("../public/data/report.json", import.meta.url), "utf8"),
    readFile(new URL("../public/data/status.json", import.meta.url), "utf8"),
    readFile(new URL("../public/data/events.jsonl", import.meta.url), "utf8"),
    readFile(new URL("../config/event.json", import.meta.url), "utf8"),
    readFile(new URL("../config/tasks.json", import.meta.url), "utf8"),
  ]);
  const report = JSON.parse(reportText);
  const status = JSON.parse(statusText);
  const config = JSON.parse(configText);
  const tasks = JSON.parse(tasksText);
  const contributions = contributionsFromSwarmproofReport(report, status, PUBLICATION_COMMIT);
  assert.equal(contributions.length, 8);
  assert.equal(new Set(contributions.map(item => item.contribution_id)).size, 8);
  assert.ok(contributions.every(item => item.evidence.length === 1));
  assert.ok(contributions.every(item => item.evidence[0].publication_commit === PUBLICATION_COMMIT));

  const payload = {
    schema: CONTRIBUTION_INDEX_SCHEMA,
    project: "swarmproof-48-e463",
    purpose: "controller-curated-contribution-evidence-index",
    controller: config.coordinator_did,
    issued_at: ISSUED_AT,
    sequence: "1",
    previous_index_sha256: null,
    control_claim_sha256: HASH_A,
    contributions,
  };
  const reportSha256 = sha256Hex(canonicalize(report));
  const snapshotManifestSha256 = sha256Hex(canonicalize(report.snapshot_manifest));
  const facets = deriveContributionFacets({ payload }, {
    report,
    status,
    events,
    config,
    tasks,
    publicationCommit: PUBLICATION_COMMIT,
    reportVerification: {
      schema: "swarmproof-report-verification-v1",
      validation_scope: "project-context",
      report_sha256: reportSha256,
      snapshot_manifest_sha256: snapshotManifestSha256,
      checks: {
        report_status_binding: "pass",
        audit_core_replay: "pass",
        archive_manifest_binding: "pass",
        evidence_status_binding: "pass",
      },
    },
  });
  assert.deepEqual(facets.counts, {
    unique_contributions: 8,
    with_swarmproof_attribution: 8,
    with_reproducible_artifact: 8,
    with_cross_key_review: 0,
    with_cross_key_pass_review: 0,
    with_swarmproof_internal_acceptance: 0,
    with_upstream_acceptance_reference: 0,
    with_external_adoption_reference: 0,
    with_official_task_submission: 0,
  });
  assert.ok(facets.contributions.every(item => item.facets.swarmproof.evidence_level === "REPRODUCIBLE"));

  assert.throws(
    () => deriveContributionFacets({ payload }, {
      report,
      status,
      events,
      config,
      tasks,
      publicationCommit: PUBLICATION_COMMIT,
    }),
    /matching full project report replay/u,
  );
});

test("report preparation excludes attributable-only and duplicate RESULT entries", async () => {
  const report = JSON.parse(await readFile(new URL("../public/data/report.json", import.meta.url), "utf8"));
  const status = JSON.parse(await readFile(new URL("../public/data/status.json", import.meta.url), "utf8"));
  const attributable = clone(report.events.find(event => event.type === "RESULT"));
  attributable.event_id = HASH_A;
  attributable.artifact.sha256 = HASH_B;
  attributable.evidence_level = "ATTRIBUTABLE";
  const duplicate = clone(report.events.find(event => event.type === "RESULT"));
  duplicate.event_id = HASH_C;
  duplicate.artifact.sha256 = HASH_D;
  report.events.push(attributable, duplicate);
  report.semantically_ignored.push({ event_id: duplicate.event_id, reason: "duplicate-result-artifact" });
  status.report_sha256 = sha256Hex(canonicalize(report));
  const prepared = contributionsFromSwarmproofReport(report, status, PUBLICATION_COMMIT);
  assert.equal(prepared.length, 8);
});

test("cross-key review evidence requires a valid different-key REVIEW for the same subject", () => {
  const { privateKey: reviewerKey } = generateKeyPairSync("ed25519");
  const coordinatorDid = fixtureDid;
  const startsAt = "2026-08-26T00:00:00.000Z";
  const endsAt = "2026-08-27T00:00:00.000Z";
  const task = createEnvelope({
    schema: "swarmproof-event-v1",
    type: "TASK",
    task_id: "collector",
    claimed_at: startsAt,
    nonce: "1",
    parent_event_ids: [],
    content_sha256: HASH_A,
  }, fixedSigner, { coordinatorDid });
  const result = createEnvelope({
    schema: "swarmproof-event-v1",
    type: "RESULT",
    task_id: "collector",
    claimed_at: "2026-08-26T00:10:00.000Z",
    nonce: "2",
    parent_event_ids: [task.event_id],
    content_sha256: HASH_B,
    artifact: { repository: REPOSITORY, commit: COMMIT_A, path: "lib/collector.mjs", sha256: HASH_B },
  }, fixedSigner, { coordinatorDid, allowedRepositories: new Set([REPOSITORY]) });
  const review = createEnvelope({
    schema: "swarmproof-event-v1",
    type: "REVIEW",
    task_id: "collector",
    claimed_at: "2026-08-26T00:20:00.000Z",
    nonce: "3",
    parent_event_ids: [result.event_id],
    content_sha256: HASH_B,
    review: { target_event_id: result.event_id, verdict: "PASS" },
  }, reviewerKey, { coordinatorDid });
  const records = [task, result, review].map((event, index) => ({
    envelope: event.envelope,
    observed_at: "2026-08-26T00:30:00.000Z",
    source_ts: event.payload.claimed_at,
    source_room: "build",
    source_seq: index + 1,
  }));
  const report = {
    schema: "swarmproof-report-v1",
    snapshot_manifest: { schema: "swarmproof-snapshot-manifest-v1", source_commit: COMMIT_A },
    snapshot_manifest_sha256: "",
    events: [
      {
        event_id: result.event_id,
        type: "RESULT",
        did: result.payload.did,
        source_ts: result.payload.claimed_at,
        artifact: result.payload.artifact,
        artifact_check: { status: "pass" },
        evidence_level: "CROSS-KEY-REVIEWED",
        cross_key_reviewers: [review.payload.did],
      },
      {
        event_id: review.event_id,
        type: "REVIEW",
        did: review.payload.did,
        source_ts: review.payload.claimed_at,
        artifact: null,
        artifact_check: null,
        evidence_level: "ATTRIBUTABLE",
        cross_key_reviewers: [],
      },
    ],
    semantically_ignored: [],
  };
  report.snapshot_manifest_sha256 = sha256Hex(canonicalize(report.snapshot_manifest));
  const status = {
    schema: "swarmproof-status-v1",
    report_sha256: sha256Hex(canonicalize(report)),
    snapshot_manifest_sha256: report.snapshot_manifest_sha256,
  };
  const evidence = [
    {
      kind: "cross-key-review",
      review_event_id: review.event_id,
      target_event_id: result.event_id,
      publication_commit: COMMIT_A,
      report_sha256: status.report_sha256,
      snapshot_manifest_sha256: report.snapshot_manifest_sha256,
    },
    {
      kind: "swarmproof-result-snapshot",
      result_event_id: result.event_id,
      publication_commit: COMMIT_A,
      report_sha256: status.report_sha256,
      snapshot_manifest_sha256: report.snapshot_manifest_sha256,
    },
  ];
  const created = createContributionIndex([{ subject: subject(HASH_B), evidence }], fixedSigner, {
    issuedAt: ISSUED_AT,
    sequence: "1",
    controlClaimSha256: HASH_A,
    expectedController: fixtureDid,
  });
  const verification = {
    schema: "swarmproof-report-verification-v1",
    validation_scope: "project-context",
    report_sha256: status.report_sha256,
    snapshot_manifest_sha256: report.snapshot_manifest_sha256,
    checks: {
      report_status_binding: "pass",
      audit_core_replay: "pass",
      archive_manifest_binding: "pass",
      evidence_status_binding: "pass",
    },
  };
  const facets = deriveContributionFacets(created.document, {
    report,
    status,
    events: records,
    config: {
      repository: REPOSITORY,
      coordinator_did: coordinatorDid,
      starts_at: startsAt,
      ends_at: endsAt,
    },
    tasks: { tasks: [{ id: "collector" }] },
    publicationCommit: COMMIT_A,
    reportVerification: verification,
  });
  assert.equal(facets.counts.unique_contributions, 1);
  assert.equal(facets.counts.with_cross_key_review, 1);
  assert.equal(facets.counts.with_cross_key_pass_review, 1);
  assert.equal(facets.contributions[0].facets.cross_key_reviews[0].independence, "unknown");
  assert.equal(facets.contributions[0].facets.cross_key_reviews[0].verdict, "PASS");

  const reject = createEnvelope({
    schema: "swarmproof-event-v1",
    type: "REVIEW",
    task_id: "collector",
    claimed_at: "2026-08-26T00:25:00.000Z",
    nonce: "4",
    parent_event_ids: [result.event_id],
    content_sha256: HASH_B,
    review: { target_event_id: result.event_id, verdict: "REJECT" },
  }, reviewerKey, { coordinatorDid });
  const supersededRecords = [...records, {
    envelope: reject.envelope,
    observed_at: "2026-08-26T00:30:00.000Z",
    source_ts: reject.payload.claimed_at,
    source_room: "build",
    source_seq: 4,
  }];
  const supersededReport = clone(report);
  supersededReport.events[0].evidence_level = "REPRODUCIBLE";
  supersededReport.events[0].cross_key_reviewers = [];
  supersededReport.events.push({
    event_id: reject.event_id,
    type: "REVIEW",
    did: reject.payload.did,
    source_ts: reject.payload.claimed_at,
    artifact: null,
    artifact_check: null,
    evidence_level: "ATTRIBUTABLE",
    cross_key_reviewers: [],
  });
  const supersededStatus = {
    ...status,
    report_sha256: sha256Hex(canonicalize(supersededReport)),
  };
  const supersededVerification = {
    ...verification,
    report_sha256: supersededStatus.report_sha256,
  };
  const evidenceFor = reviewEventId => [
    {
      kind: "cross-key-review",
      review_event_id: reviewEventId,
      target_event_id: result.event_id,
      publication_commit: COMMIT_A,
      report_sha256: supersededStatus.report_sha256,
      snapshot_manifest_sha256: supersededReport.snapshot_manifest_sha256,
    },
    {
      kind: "swarmproof-result-snapshot",
      result_event_id: result.event_id,
      publication_commit: COMMIT_A,
      report_sha256: supersededStatus.report_sha256,
      snapshot_manifest_sha256: supersededReport.snapshot_manifest_sha256,
    },
  ];
  const supersededPass = createContributionIndex([
    { subject: subject(HASH_B), evidence: evidenceFor(review.event_id) },
  ], fixedSigner, {
    issuedAt: ISSUED_AT,
    sequence: "1",
    controlClaimSha256: HASH_A,
    expectedController: fixtureDid,
  });
  const supersededProject = {
    report: supersededReport,
    status: supersededStatus,
    events: supersededRecords,
    config: {
      repository: REPOSITORY,
      coordinator_did: coordinatorDid,
      starts_at: startsAt,
      ends_at: endsAt,
    },
    tasks: { tasks: [{ id: "collector" }] },
    publicationCommit: COMMIT_A,
    reportVerification: supersededVerification,
  };
  assert.throws(
    () => deriveContributionFacets(supersededPass.document, supersededProject),
    /superseded by a later valid verdict/u,
  );

  const effectiveReject = createContributionIndex([
    { subject: subject(HASH_B), evidence: evidenceFor(reject.event_id) },
  ], fixedSigner, {
    issuedAt: ISSUED_AT,
    sequence: "1",
    controlClaimSha256: HASH_A,
    expectedController: fixtureDid,
  });
  const rejectFacets = deriveContributionFacets(effectiveReject.document, supersededProject);
  assert.equal(rejectFacets.counts.with_cross_key_review, 1);
  assert.equal(rejectFacets.counts.with_cross_key_pass_review, 0);
  assert.equal(rejectFacets.contributions[0].facets.cross_key_reviews[0].verdict, "REJECT");
  assert.equal(rejectFacets.contributions[0].facets.cross_key_reviews[0].effective, true);
});
