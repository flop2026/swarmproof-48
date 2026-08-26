import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import test from "node:test";

const WORKFLOW = fileURLToPath(new URL("../.github/workflows/snapshot.yml", import.meta.url));

test("snapshot workflow validates an immutable local commit before publishing it", async () => {
  const source = await readFile(WORKFLOW, "utf8");
  const stage = source.indexOf("- name: Stage immutable snapshot commit");
  const validate = source.indexOf("- name: Validate immutable snapshot");
  const publish = source.indexOf("- name: Publish validated snapshot update");
  const deployment = source.indexOf("- name: Verify the exact snapshot reached Cloudflare Pages");

  assert.ok(stage >= 0 && stage < validate, "Snapshot bytes must be committed locally before validation.");
  assert.ok(validate < publish, "A snapshot must pass validation before it is pushed.");
  assert.ok(publish < deployment, "Deployment read-back must follow publication.");

  const stageBlock = source.slice(stage, validate);
  const validateBlock = source.slice(validate, publish);
  const publishBlock = source.slice(publish, deployment);
  assert.match(stageBlock, /git commit -m/u);
  assert.match(stageBlock, /sha=\$\(git rev-parse HEAD\)/u);
  assert.match(validateBlock, /npm run validate/u);
  assert.doesNotMatch(source.slice(0, publish), /git push/u);
  assert.match(publishBlock, /test "\$\(git rev-parse HEAD\)" = "\$\{\{ steps\.snapshot_commit\.outputs\.sha \}\}"/u);
  assert.match(publishBlock, /git push origin HEAD:main/u);
});
