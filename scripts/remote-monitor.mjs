#!/usr/bin/env node

import { readFile } from "node:fs/promises";
import {
  REMOTE_MONITOR_POLICY,
  remoteMonitorEndpoints,
  validateRemoteMonitor,
} from "../lib/remote-monitor.mjs";

const CONFIG_FILE = new URL("../config/event.json", import.meta.url);
const REQUEST_TIMEOUT_MS = 20_000;
const RESPONSE_LIMITS = Object.freeze({
  status: 65_536,
  profile: 16_384,
  owner: 16_384,
  room: 2_000_000,
});

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

const sleep = milliseconds => new Promise(resolve => setTimeout(resolve, milliseconds));

async function readBounded(response, maximumBytes, label) {
  const declaredHeader = response.headers.get("content-length");
  if (declaredHeader !== null) {
    assert(/^\d+$/u.test(declaredHeader), `${label} content length is invalid.`);
    assert(Number(declaredHeader) <= maximumBytes, `${label} response is oversized.`);
  }
  assert(response.body !== null, `${label} response body is missing.`);
  const reader = response.body.getReader();
  const chunks = [];
  let bytes = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      bytes += value.byteLength;
      if (bytes > maximumBytes) throw new Error(`${label} response is oversized.`);
      chunks.push(Buffer.from(value));
    }
  } catch (error) {
    await reader.cancel().catch(() => {});
    throw error;
  }
  return Buffer.concat(chunks, bytes).toString("utf8");
}

async function fetchExact(endpoint, options) {
  const expectedUrl = new URL(endpoint);
  assert(
    expectedUrl.origin === REMOTE_MONITOR_POLICY.publicOrigin
      || expectedUrl.origin === REMOTE_MONITOR_POLICY.technocoreOrigin,
    `${options.label} endpoint origin is not allowlisted.`,
  );
  let lastError;
  for (let attempt = 1; attempt <= 3; attempt += 1) {
    try {
      const response = await fetch(expectedUrl, {
        redirect: "error",
        cache: "no-store",
        headers: {
          accept: options.mediaType === "application/json" ? "application/json" : "text/plain",
          "cache-control": "no-cache",
          "user-agent": "swarmproof-48-public-monitor/1",
        },
        signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
      });
      assert(response.url === expectedUrl.href, `${options.label} response URL changed.`);
      if (!response.ok) {
        const error = new Error(`${options.label} returned HTTP ${response.status}.`);
        error.retryable = response.status === 429 || response.status >= 500;
        throw error;
      }
      const contentType = response.headers.get("content-type")?.split(";", 1)[0].trim().toLowerCase();
      assert(contentType === options.mediaType, `${options.label} response media type is invalid.`);
      return await readBounded(response, options.maximumBytes, options.label);
    } catch (error) {
      lastError = error;
      if (error.retryable === false || attempt === 3) break;
      await sleep(attempt * 1_000);
    }
  }
  throw lastError;
}

function parseJson(body, label) {
  try {
    return JSON.parse(body);
  } catch {
    throw new Error(`${label} response is not valid JSON.`);
  }
}

async function main() {
  const config = JSON.parse(await readFile(CONFIG_FILE, "utf8"));
  const nonce = String(Date.now());
  const endpoints = remoteMonitorEndpoints(config, nonce);
  const [statusBody, profileBody, ownerBody, roomBody] = await Promise.all([
    fetchExact(endpoints.status, {
      label: "Published status",
      maximumBytes: RESPONSE_LIMITS.status,
      mediaType: "application/json",
    }),
    fetchExact(endpoints.profile, {
      label: "DID profile",
      maximumBytes: RESPONSE_LIMITS.profile,
      mediaType: "text/plain",
    }),
    fetchExact(endpoints.owner, {
      label: "Official-room owner",
      maximumBytes: RESPONSE_LIMITS.owner,
      mediaType: "text/plain",
    }),
    fetchExact(endpoints.room, {
      label: "Official room",
      maximumBytes: RESPONSE_LIMITS.room,
      mediaType: "application/json",
    }),
  ]);
  const result = validateRemoteMonitor({
    config,
    status: parseJson(statusBody, "Published status"),
    profileBody,
    ownerBody,
    room: parseJson(roomBody, "Official room"),
  });
  process.stdout.write(`${JSON.stringify({
    action: "healthy",
    state: result.state,
    status_age_seconds: Math.floor(result.statusAgeSeconds),
    profile_age_seconds: Math.floor(result.profileAgeSeconds),
    checkpoint_age_seconds: Math.floor(result.checkpointAgeSeconds),
    latest_checkpoint_event_id: result.latestCheckpointEventId,
    checkpoint_count: result.checkpointCount,
  })}\n`);
}

main().catch(error => {
  console.error(`public monitor failed: ${error.message}`);
  process.exit(1);
});
