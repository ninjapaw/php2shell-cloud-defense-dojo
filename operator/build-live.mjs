import { readFileSync, mkdirSync, writeFileSync, lstatSync } from "node:fs";
import { join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { createHash } from "node:crypto";
import { gzipSync } from "node:zlib";
import { transformSync } from "esbuild";
import { validateReviewedLive } from "./live-public.mjs";
import { LIVE_INTEGRITY_FILES } from "./live-integrity.mjs";

export const LIVE_RUNTIME_FILES = Object.freeze([
  "operator/config.mjs", "operator/auth.mjs", "operator/azure.mjs", "operator/control.mjs", "operator/server.mjs",
  "operator/store.mjs", "operator/style.css", "operator/live-config.mjs", "operator/live-authorize.mjs",
  "operator/live-control.mjs", "operator/live-waf.mjs", "operator/live-azure.mjs", "operator/live.mjs",
  "operator/live-evidence.mjs", "operator/live-public.mjs", "operator/live-capture.mjs",
  "operator/live-integrity.mjs",
]);
export const LIVE_FOUNDATION_FILES = Object.freeze([
  "scripts/lib/private-live.mjs", "scripts/lib/container-lab.mjs", "scripts/lib/response.mjs", "container-lab/images.json",
  "operator/public-live-template.json",
]);

export function buildLiveArtifact(output, kind = "private-live-runtime", templatePath) {
  if (!["private-live-foundation", "private-live-runtime", "private-live-recording"].includes(kind)) throw new Error("Unknown fixed private live publication kind.");
  const root = fileURLToPath(new URL("../", import.meta.url));
  const paths = kind === "private-live-foundation" ? LIVE_FOUNDATION_FILES
    : kind === "private-live-runtime" ? [...LIVE_RUNTIME_FILES, "operator/live-integrity.json"] : ["operator/public-evidence/live.json"];
  const load = (name) => {
    if (name === "operator/public-live-template.json") {
      if (!templatePath) throw new Error("The exact natively compiled private-live template path is required for foundation publication.");
      const template = JSON.parse(readFileSync(templatePath, "utf8"));
      if (template.$schema !== "https://schema.management.azure.com/schemas/2018-05-01/subscriptionDeploymentTemplate.json#"
          || template.metadata?._generator?.name !== "bicep" || !template.metadata._generator.templateHash
          || !template.parameters?.window || !Array.isArray(template.resources) || template.resources.length !== 7) {
        throw new Error("Foundation publication requires the reviewed native private-live subscription template.");
      }
      return JSON.stringify(template);
    }
    const path = join(root, ...name.split("/"));
    if (!lstatSync(path).isFile() || lstatSync(path).isSymbolicLink()) throw new Error("Only exact regular private-live source files can be published.");
    const text = readFileSync(path, "utf8");
    return name.endsWith(".mjs") ? transformSync(text, { format: "esm", target: "node24", minify: true, legalComments: "inline" }).code : text;
  };
  const files = Object.fromEntries(paths.toSorted().map((name) => [name, name === "operator/live-integrity.json"
    ? JSON.stringify({ schemaVersion: 1, files: Object.fromEntries(LIVE_INTEGRITY_FILES.toSorted().map((file) =>
      [file, createHash("sha256").update(load(file)).digest("hex")])) }) : load(name)]));
  if (kind === "private-live-recording") validateReviewedLive(JSON.parse(files[paths[0]]));
  const content = gzipSync(JSON.stringify({ schemaVersion: 1, kind, files }), { level: 9, memLevel: 9 });
  const encoded = content.toString("base64");
  if (encoded.length + 2 > 61_440) throw new Error(`Private live overlay exceeds the unchanged protected-source cap (${encoded.length + 2}/61440); no truncated artifact is emitted.`);
  mkdirSync(output);
  writeFileSync(join(output, "live.json.gz"), content);
  const stages = [];
  for (let index = 0; index < Math.ceil(encoded.length / 4000); index += 1) {
    const text = encoded.slice(index * 4000, (index + 1) * 4000);
    const path = join(output, `source-${String(index).padStart(2, "0")}.txt`);
    writeFileSync(path, text);
    const bytes = createHash("sha1").update(Buffer.from("11fb06fb712d4ddd98c7e71bbd588830", "hex")).update(text).digest().subarray(0, 16);
    bytes[6] = (bytes[6] & 15) | 80;
    bytes[8] = (bytes[8] & 63) | 128;
    const hex = bytes.toString("hex");
    stages.push({ index, path, length: text.length, fingerprint: `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}` });
  }
  const manifest = { schemaVersion: 1, kind, sha256: createHash("sha256").update(content).digest("hex"),
    files: paths, encodedBytes: encoded.length, combinedProtectedBytes: encoded.length + 2, stages };
  writeFileSync(join(output, "manifest.json"), `${JSON.stringify(manifest, null, 2)}\n`);
  return manifest;
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  if (process.argv.length < 3 || process.argv.length > 5) throw new Error("Usage: node operator\\build-live.mjs <new-output-directory> [private-live-foundation|private-live-runtime|private-live-recording] [compiled-private-live.json]");
  console.log(JSON.stringify(buildLiveArtifact(resolve(process.argv[2]), process.argv[3], process.argv[4])));
}
