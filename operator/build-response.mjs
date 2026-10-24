import { readFileSync, mkdirSync, writeFileSync, lstatSync } from "node:fs";
import { join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { createHash } from "node:crypto";
import { gzipSync } from "node:zlib";
import { buildSync, transformSync } from "esbuild";

export const RESPONSE_FILES = Object.freeze([
  "scripts/lib/response.mjs", "scripts/response.mjs", "operator/response.mjs",
  "operator/config.mjs", "operator/control.mjs", "operator/server.mjs", "operator/public-scripts/response.mjs",
]);
export function responseArtifact(output) {
  const root = fileURLToPath(new URL("../", import.meta.url));
  const license = readFileSync(join(root, "vendor", "pawprint", "LICENSE"), "utf8");
  const bundled = buildSync({
    stdin: { contents: `import { responseCli } from "./scripts/response.mjs";
import { redact } from "./scripts/lib/safety.mjs";
responseCli(process.argv.slice(2)).then(result => {
  if ((result.kind === "response-verification" && !result.resolved) || result.sourceGaps?.length) process.exitCode = 2;
}).catch(error => {
  console.error("ERROR: response failed; do not replay an uncertain change: " + redact(error.message));
  process.exitCode = 1;
});`, resolveDir: root, sourcefile: "php2proof-response-entry.mjs" },
    bundle: true, write: false,
    platform: "node", format: "esm", target: "node24", legalComments: "inline",
    // Imported libraries must not run their own CLI guards from the bundled entry URL.
    define: { "import.meta.url": JSON.stringify("php2proof:response-bundle") },
    banner: { js: `/* Includes Pawprint validation helpers.\n${license.replaceAll("*/", "* /")}\n*/` },
  }).outputFiles[0].text;
  const files = Object.fromEntries(RESPONSE_FILES.toSorted().map((name) => {
    if (name === "operator/public-scripts/response.mjs") return [name, bundled];
    const path = join(root, ...name.split("/"));
    if (!lstatSync(path).isFile() || lstatSync(path).isSymbolicLink()) throw new Error("Only exact regular response source files can be published.");
    const source = readFileSync(path, "utf8");
    return [name, transformSync(source, { format: "esm", target: "node24", minify: true, legalComments: "inline" }).code];
  }));
  const bytes = gzipSync(JSON.stringify({ schemaVersion: 1, kind: "response-maintenance", files }), { level: 9, memLevel: 9 });
  const encoded = bytes.toString("base64");
  if (encoded.length + 2 > 61440) throw new Error("Response overlay exceeds the unchanged protected-source limit; no truncated artifact is emitted.");
  mkdirSync(output);
  writeFileSync(join(output, "response.json.gz"), bytes);
  writeFileSync(join(output, "php2proof-response.mjs"), bundled);
  const stages = [];
  for (let i = 0; i < Math.ceil(encoded.length / 4000); i += 1) {
    const text = encoded.slice(i * 4000, (i + 1) * 4000);
    const path = join(output, `source-${String(i).padStart(2, "0")}.txt`);
    writeFileSync(path, text);
    stages.push({ index: i, path, length: text.length });
  }
  const manifest = { schemaVersion: 1, kind: "response-maintenance", sha256: createHash("sha256").update(bytes).digest("hex"),
    files: RESPONSE_FILES, encodedBytes: encoded.length, combinedProtectedBytes: encoded.length + 2, stages };
  writeFileSync(join(output, "manifest.json"), `${JSON.stringify(manifest, null, 2)}\n`);
  return manifest;
}
if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  if (process.argv.length !== 3) throw new Error("Usage: node operator\\build-response.mjs <new-output-directory>");
  console.log(JSON.stringify(responseArtifact(resolve(process.argv[2]))));
}
