import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { gzipSync } from "node:zlib";
import { createHash } from "node:crypto";
import { transformSync } from "esbuild";
import { loadHuntPack } from "./hunts.mjs";

export function buildHuntingArtifact(output, kind = "release") {
  if (!["release", "recording", "module"].includes(kind)) throw new Error("Unknown fixed hunting publication kind.");
  const root = fileURLToPath(new URL("../", import.meta.url));
  const pack = loadHuntPack();
  const paths = kind === "release"
    ? ["operator/hunts.mjs", "operator/config.mjs", "operator/control.mjs", "operator/azure.mjs",
      "operator/server.mjs", "detections/catalog.json", ...pack.queries.map((entry) => entry.path)]
    : kind === "module" ? ["operator/hunts.mjs"] : ["operator/public-evidence/hunting.json"];
  const files = Object.fromEntries(paths.toSorted().map((path) => {
    let text = readFileSync(join(root, ...path.split("/")), "utf8");
    if (path.endsWith(".mjs")) text = transformSync(text, { loader: "js", format: "esm", target: "node24", minify: true, legalComments: "inline" }).code;
    return [path, text];
  }));
  if (kind === "recording") {
    const snapshot = JSON.parse(files[paths[0]]);
    if (snapshot.kind !== "reviewed-hunting" || snapshot.reviewed !== true
        || snapshot.source.revision !== pack.source.revision || snapshot.results.length !== pack.queries.length) {
      throw new Error("A complete separately reviewed hunting snapshot is required.");
    }
  }
  const bytes = gzipSync(JSON.stringify({ schemaVersion: 1, kind, files }), { level: 9, memLevel: 9 });
  const encoded = bytes.toString("base64");
  if (encoded.length + 2 > 61440) throw new Error("Hunting artifact exceeds the unchanged protected-input cap.");
  mkdirSync(output);
  writeFileSync(join(output, "hunting.json.gz"), bytes);
  const stages = [];
  for (let index = 0; index < Math.ceil(encoded.length / 4000); index += 1) {
    const chunk = encoded.slice(index * 4000, (index + 1) * 4000);
    const path = join(output, `source-${String(index).padStart(2, "0")}.txt`);
    writeFileSync(path, chunk);
    const hash = createHash("sha1").update(Buffer.from("11fb06fb712d4ddd98c7e71bbd588830", "hex")).update(chunk).digest().subarray(0, 16);
    hash[6] = (hash[6] & 15) | 80;
    hash[8] = (hash[8] & 63) | 128;
    const hex = hash.toString("hex");
    stages.push({ index, path, length: chunk.length, fingerprint: `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}` });
  }
  const manifest = { schemaVersion: 1, kind, sha256: createHash("sha256").update(bytes).digest("hex"),
    encodedBytes: encoded.length, combinedProtectedBytes: encoded.length + 2, files: paths, stages };
  writeFileSync(join(output, "manifest.json"), `${JSON.stringify(manifest, null, 2)}\n`);
  return manifest;
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  if (process.argv.length < 3 || process.argv.length > 4) throw new Error("Usage: node operator\\build-hunts.mjs <new-artifact-directory> [release|recording|module]");
  console.log(JSON.stringify(buildHuntingArtifact(resolve(process.argv[2]), process.argv[3])));
}
