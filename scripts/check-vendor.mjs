import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { parseArgs } from "node:util";
import { ROOT } from "./dojo.mjs";
import { contentHash, VENDOR_FILES } from "./lib/vendor.mjs";

const { values } = parseArgs({ options: { source: { type: "string" } } });
const manifest = JSON.parse(readFileSync(join(ROOT, "vendor", "pawprint.manifest.json"), "utf8"));
assert.equal(manifest.version, 1);
assert.equal(manifest.source, "https://github.com/ninjapaw/pawprint");
assert.match(manifest.sourceRevision, /^working-tree@[0-9a-f]{40}$/);
assert.deepEqual(manifest.files.map((entry) => entry.path), VENDOR_FILES);
for (const entry of manifest.files) {
  const vendored = readFileSync(join(ROOT, "vendor", "pawprint", entry.path), "utf8");
  assert.equal(contentHash(vendored), entry.sha256, `Vendored content drift: ${entry.path}`);
  if (values.source) {
    assert.equal(contentHash(readFileSync(join(resolve(values.source), entry.path), "utf8")),
      entry.sha256, `Pawprint source drift: ${entry.path}`);
  }
}
assert.equal(contentHash(readFileSync(join(ROOT, "bicepconfig.json"), "utf8")),
  manifest.files.find((entry) => entry.path === "bicepconfig.json").sha256, "Root Bicep rules drifted.");
console.log(`Verified ${manifest.files.length} Pawprint source hashes${values.source ? " and local upstream source" : ""}.`);
