import { lstatSync, readFileSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { publicSnapshot } from "./evidence.mjs";

if (process.argv.length !== 4) throw new Error("Usage: node operator/export-evidence.mjs <private-capture.json> <new-reviewed-snapshot.json>");
const [input, output] = process.argv.slice(2);
const info = lstatSync(input);
if (!info.isFile() || info.isSymbolicLink() || info.size > 524_288) throw new Error("Capture must be a bounded regular JSON file.");
const snapshot = publicSnapshot(JSON.parse(readFileSync(input, "utf8")));
const text = `${JSON.stringify(snapshot, null, 2)}\n`;
writeFileSync(output, text, { flag: "wx", mode: 0o600 });
console.log(JSON.stringify({
  status: "requires-manual-review", output,
  sha256: createHash("sha256").update(text).digest("hex"),
  note: "Static export only. No public deployment, live query or automatic publication was performed.",
}));
