import { copyFileSync, readFileSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { parseArgs } from "node:util";
import { ROOT } from "./dojo.mjs";
import { runTool } from "./lib/azure.mjs";
import { contentHash, VENDOR_FILES } from "./lib/vendor.mjs";

const { values } = parseArgs({ options: { source: { type: "string" } } });
if (!values.source) throw new Error("Supply --source with the local Pawprint checkout.");
const source = resolve(values.source);
const pkg = JSON.parse(readFileSync(join(source, "package.json"), "utf8"));
if (pkg.name !== "@ninjapaw/pawprint") throw new Error("The selected source is not Pawprint.");
const output = runTool(process.execPath, [
  join(source, "scripts", "vendor-sync.mjs"), "--target", ROOT,
  ...VENDOR_FILES.flatMap((file) => ["--add", file]),
]);
process.stdout.write(output);
copyFileSync(join(source, "bicepconfig.json"), join(ROOT, "bicepconfig.json"));
const baseCommit = runTool("git", ["-C", source, "rev-parse", "HEAD"]).trim();
const files = VENDOR_FILES.map((path) => ({
  path, sha256: contentHash(readFileSync(join(ROOT, "vendor", "pawprint", path), "utf8")),
}));
writeFileSync(join(ROOT, "vendor", "pawprint.manifest.json"), `${JSON.stringify({
  version: 1,
  source: "https://github.com/ninjapaw/pawprint",
  sourceRevision: `working-tree@${baseCommit}`,
  note: "Content hashes, not the base commit, identify this complete source snapshot. Publish shared-source changes alongside the consumer.",
  files,
}, null, 2)}\n`);
console.log("Synced auditable Pawprint source snapshot and canonical Bicep rules.");
