import assert from "node:assert/strict";
import test from "node:test";
import { deploymentStatusMatches } from "../lib/deployment.mjs";
import { reconcilePublishedState, transitionEventLifecycle } from "../lib/lifecycle.mjs";

function activeConfig() {
  return {
    schema: "swarmproof-event-config-v1",
    state: "active",
    starts_at: "2026-08-26T05:00:00.000Z",
    ends_at: "2026-08-28T05:00:00.000Z",
  };
}

test("event lifecycle finalizes exactly at the declared 48-hour boundary", () => {
  const config = activeConfig();
  const before = transitionEventLifecycle(config, new Date("2026-08-28T04:59:59.999Z"));
  assert.equal(before.action, "skip");
  const atBoundary = transitionEventLifecycle(config, new Date(config.ends_at));
  assert.equal(atBoundary.action, "finalized");
  assert.equal(atBoundary.config.state, "complete");
  assert.equal(config.state, "active");
});

test("event lifecycle rejects a non-48-hour window", () => {
  const config = { ...activeConfig(), ends_at: "2026-08-28T04:59:59.999Z" };
  assert.throws(() => transitionEventLifecycle(config, new Date("2026-08-28T05:00:00.000Z")), /exactly 48 hours/u);
});

test("published complete state can safely advance a still-active local config", () => {
  const config = activeConfig();
  const status = {
    schema: "swarmproof-status-v1",
    state: "complete",
    starts_at: config.starts_at,
    ends_at: config.ends_at,
  };
  assert.equal(reconcilePublishedState(config, status).state, "complete");
  assert.throws(
    () => reconcilePublishedState({ ...config, state: "preparation", starts_at: null, ends_at: null }, status),
    /window|cannot be reconciled/u,
  );
});

test("deployment verification requires an exact status identity", () => {
  const expected = {
    schema: "swarmproof-status-v1",
    state: "active",
    generated_at: "2026-08-26T05:00:00.000Z",
    starts_at: "2026-08-26T05:00:00.000Z",
    ends_at: "2026-08-28T05:00:00.000Z",
    report_sha256: "a".repeat(64),
    source_commit: "b".repeat(40),
  };
  assert.equal(deploymentStatusMatches(expected, { ...expected }), true);
  assert.equal(deploymentStatusMatches(expected, { ...expected, report_sha256: "c".repeat(64) }), false);
});
