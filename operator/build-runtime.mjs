import { readFileSync, writeFileSync, mkdirSync, lstatSync } from "node:fs";
import { join, resolve } from "node:path";
import { createHash } from "node:crypto";
import { gzipSync } from "node:zlib";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { transformSync } from "esbuild";

export const RUNTIME_FILES = Object.freeze([
  "package.json", "config/dev.json", "config/operator.dev.json",
  "scripts/dojo.mjs", "scripts/lib/config.mjs", "scripts/lib/azure.mjs", "scripts/lib/safety.mjs",
  "detections/correlation.kql", "vendor/pawprint/LICENSE", "vendor/pawprint/scripts/cloudflare-dns.mjs",
  "operator/package.json", "operator/package-lock.json", "operator/style.css",
  "operator/config.mjs", "operator/live-config.mjs", "operator/auth.mjs", "operator/azure.mjs", "operator/store.mjs",
  "operator/control.mjs", "operator/evidence.mjs", "operator/server.mjs", "operator/initialize.mjs",
]);

const root = resolve(fileURLToPath(new URL("..", import.meta.url)));
const output = process.argv[2] && resolve(process.argv[2]);
if (!output || process.argv.length !== 3 || !process.env.npm_execpath) {
  throw new Error("Run npm --prefix operator run build:runtime -- <new-session-artifact-directory>.");
}
mkdirSync(output);
const metadata = join(output, "metadata");
mkdirSync(metadata);
const manifest = JSON.parse(readFileSync(join(root, "operator", "package.json"), "utf8"));
delete manifest.devDependencies;
writeFileSync(join(metadata, "package.json"), `${JSON.stringify(manifest, null, 2)}\n`);
writeFileSync(join(metadata, "package-lock.json"), readFileSync(join(root, "operator", "package-lock.json")));
const install = spawnSync(process.execPath, [
  process.env.npm_execpath, "install", "--package-lock-only", "--ignore-scripts", "--omit=dev", "--prefix", metadata,
], { encoding: "utf8", timeout: 120_000, maxBuffer: 1_048_576, shell: false });
if (install.status !== 0 || install.error) throw new Error("Production-only locked runtime manifest generation failed.");
const files = {};
for (const name of RUNTIME_FILES.toSorted()) {
  const path = join(root, ...name.split("/"));
  if (!lstatSync(path).isFile() || lstatSync(path).isSymbolicLink()) throw new Error("Runtime source must contain only regular allowlisted files.");
  let text = readFileSync(path, "utf8");
  if (name === "operator/package.json") text = readFileSync(join(metadata, "package.json"), "utf8");
  if (name === "operator/package-lock.json") text = readFileSync(join(metadata, "package-lock.json"), "utf8");
  if (name.endsWith(".mjs")) text = transformSync(text, {
    loader: "js", format: "esm", target: "node24", minify: true,
    legalComments: "inline",
  }).code;
  files[name] = text;
}
const content = gzipSync(JSON.stringify({ schemaVersion: 1, files }), { level: 9, memLevel: 9 });
const encoded = content.toString("base64");
if (encoded.length + 2 > 61_440) throw new Error(`Runtime exceeds the unchanged protected-source cap (${encoded.length + 2}/61440). No truncated output is emitted.`);
const sha256 = createHash("sha256").update(content).digest("hex");
writeFileSync(join(output, "runtime.json.gz"), content);
const stages = [];
for (let index = 0; index < Math.ceil(encoded.length / 4000); index += 1) {
  const chunk = encoded.slice(index * 4000, (index + 1) * 4000);
  const path = join(output, `source-${String(index).padStart(2, "0")}.txt`);
  writeFileSync(path, chunk);
  stages.push({ index, path, length: chunk.length });
}
writeFileSync(join(output, "manifest.json"), `${JSON.stringify({ schemaVersion: 1, sha256, encodedBytes: encoded.length, files: RUNTIME_FILES, stages }, null, 2)}\n`);
console.log(JSON.stringify({ sha256, encodedBytes: encoded.length, combinedProtectedBytes: encoded.length + 2, files: RUNTIME_FILES.length, stages: stages.length, output }));
