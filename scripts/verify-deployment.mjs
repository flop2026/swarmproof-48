#!/usr/bin/env node

import { readFile } from "node:fs/promises";
import { deploymentStatusMatches } from "../lib/deployment.mjs";

const PUBLIC_ORIGIN = "https://swarmproof-48-e463.pages.dev";
const STATUS_FILE = process.env.SWARMPROOF_STATUS_FILE ?? "public/data/status.json";
const MAXIMUM_BYTES = 65_536;

const sleep = milliseconds => new Promise(resolve => setTimeout(resolve, milliseconds));

async function readBoundedStatus(response) {
  const declared = Number(response.headers.get("content-length"));
  if (Number.isFinite(declared) && declared > MAXIMUM_BYTES) throw new Error("Published status is oversized.");
  const body = await response.text();
  if (Buffer.byteLength(body, "utf8") > MAXIMUM_BYTES) throw new Error("Published status is oversized.");
  return JSON.parse(body);
}

async function main() {
  const expected = JSON.parse(await readFile(STATUS_FILE, "utf8"));
  const timeoutSeconds = Number(process.env.SWARMPROOF_DEPLOY_VERIFY_TIMEOUT_SECONDS ?? 420);
  if (!Number.isFinite(timeoutSeconds) || timeoutSeconds < 10 || timeoutSeconds > 900) {
    throw new Error("Deployment verification timeout is invalid.");
  }
  const deadline = Date.now() + timeoutSeconds * 1000;
  let lastReason = "not yet observed";
  while (Date.now() < deadline) {
    try {
      const response = await fetch(`${PUBLIC_ORIGIN}/data/status.json?n=${Date.now()}`, {
        headers: { "cache-control": "no-cache" },
        signal: AbortSignal.timeout(20_000),
      });
      if (!response.ok) {
        lastReason = `HTTP ${response.status}`;
      } else {
        const observed = await readBoundedStatus(response);
        if (deploymentStatusMatches(expected, observed)) {
          process.stdout.write(`${JSON.stringify({
            action: "verified",
            report_sha256: expected.report_sha256,
            source_commit: expected.source_commit,
            generated_at: expected.generated_at,
          })}\n`);
          return;
        }
        lastReason = "published status does not yet match the pushed snapshot";
      }
    } catch (error) {
      lastReason = error.message;
    }
    await sleep(10_000);
  }
  throw new Error(`Timed out waiting for Cloudflare Pages: ${lastReason}`);
}

main().catch(error => {
  console.error(`deployment verification failed: ${error.message}`);
  process.exit(1);
});
