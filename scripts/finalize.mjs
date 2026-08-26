#!/usr/bin/env node

import { readFile, rename, writeFile } from "node:fs/promises";
import { transitionEventLifecycle } from "../lib/lifecycle.mjs";

const CONFIG_FILE = process.env.SWARMPROOF_CONFIG_FILE ?? "config/event.json";

async function main() {
  const config = JSON.parse(await readFile(CONFIG_FILE, "utf8"));
  const now = process.env.SWARMPROOF_NOW === undefined
    ? new Date()
    : new Date(process.env.SWARMPROOF_NOW);
  const result = transitionEventLifecycle(config, now);
  if (result.action === "finalized") {
    const temporary = `${CONFIG_FILE}.tmp-${process.pid}`;
    await writeFile(temporary, `${JSON.stringify(result.config, null, 2)}\n`, { encoding: "utf8", mode: 0o644 });
    await rename(temporary, CONFIG_FILE);
  }
  process.stdout.write(`${JSON.stringify({ action: result.action, reason: result.reason })}\n`);
}

main().catch(error => {
  console.error(`event finalizer failed: ${error.message}`);
  process.exit(1);
});
