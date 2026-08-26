const EVENT_STATES = new Set(["preparation", "active", "complete"]);
const CANONICAL_TIME_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u;
const WINDOW_MS = 48 * 60 * 60 * 1000;

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function canonicalMilliseconds(value, label) {
  assert(typeof value === "string" && CANONICAL_TIME_RE.test(value), `${label} must be canonical UTC.`);
  const milliseconds = Date.parse(value);
  assert(Number.isFinite(milliseconds) && new Date(milliseconds).toISOString() === value, `${label} is invalid.`);
  return milliseconds;
}

function validateWindow(config) {
  const startsAt = canonicalMilliseconds(config.starts_at, "starts_at");
  const endsAt = canonicalMilliseconds(config.ends_at, "ends_at");
  assert(endsAt - startsAt === WINDOW_MS, "Event window must be exactly 48 hours.");
  return { startsAt, endsAt };
}

export function transitionEventLifecycle(config, now = new Date()) {
  assert(config && typeof config === "object" && !Array.isArray(config), "Event config is invalid.");
  assert(EVENT_STATES.has(config.state), "Event state is invalid.");
  const nowMs = now instanceof Date ? now.getTime() : Number.NaN;
  assert(Number.isFinite(nowMs), "Current time is invalid.");

  if (config.state === "preparation") {
    assert(config.starts_at === null && config.ends_at === null, "Preparation window must be unset.");
    return { action: "skip", reason: "preparation", config };
  }

  const { endsAt } = validateWindow(config);
  if (config.state === "complete") {
    assert(nowMs >= endsAt, "Complete state cannot precede the event end.");
    return { action: "skip", reason: "already_complete", config };
  }
  if (nowMs < endsAt) return { action: "skip", reason: "not_due", config };
  return {
    action: "finalized",
    reason: "event_window_ended",
    config: { ...config, state: "complete" },
  };
}

export function reconcilePublishedState(localConfig, publicStatus) {
  assert(localConfig && typeof localConfig === "object", "Local event config is invalid.");
  assert(publicStatus?.schema === "swarmproof-status-v1", "Published status schema is invalid.");
  assert(EVENT_STATES.has(localConfig.state) && EVENT_STATES.has(publicStatus.state), "Published lifecycle state is invalid.");
  assert(
    publicStatus.starts_at === localConfig.starts_at && publicStatus.ends_at === localConfig.ends_at,
    "Published event window does not match the local config.",
  );
  if (publicStatus.state === localConfig.state) return localConfig;
  if (localConfig.state === "active" && publicStatus.state === "complete") {
    return { ...localConfig, state: "complete" };
  }
  throw new Error("Published lifecycle state cannot be reconciled with the local config.");
}
