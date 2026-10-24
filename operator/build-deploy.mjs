import { readFileSync, writeFileSync, mkdirSync, lstatSync } from "node:fs";
import { join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { createHash } from "node:crypto";
import { gzipSync } from "node:zlib";
import { spawnSync } from "node:child_process";
import { transformSync } from "esbuild";
import { CLOUD_CONTEXT_FILES } from "../scripts/cloud-runner.mjs";

export const DEPLOY_FILES = Object.freeze([
  ...CLOUD_CONTEXT_FILES.filter((file) => !["scripts/cloud-runner.mjs", "scripts/cloud-deploy.sh"].includes(file)),
  "scripts/wizard.mjs", "scripts/start.sh", "scripts/start.ps1", "scripts/lib/windows-tools.cjs",
  "README.md", "DISCLAIMER.md", "LICENSE", "docs/deployment.md", "operator/README.md", "docs/container-lab.md",
]);

export function buildDeployment(output) {
  const root = fileURLToPath(new URL("../", import.meta.url));
  const files = Object.fromEntries(DEPLOY_FILES.toSorted().map((file) => {
    const path = join(root, ...file.split("/"));
    if (!lstatSync(path).isFile() || lstatSync(path).isSymbolicLink()) throw new Error("Deployment distribution accepts only its exact regular-file allowlist.");
    let source = readFileSync(path, "utf8").replaceAll("\r\n", "\n");
    if (file === "config/dev.json") source = JSON.stringify({ ...JSON.parse(source), customDomain: "" });
    if (file === "README.md") source = `# PHP to Proof core deployment wizard

Review docs/deployment.md and DISCLAIMER.md, then run:

    node scripts/wizard.mjs --check
    node scripts/wizard.mjs

Reuse the saved nonsecret .azure/profiles/<suffix>.json for all later actions.
Only the core public dev lab is automated. Private operator/container guides are
reference material; obtain the full project for those separate advanced tracks:
https://github.com/ninjapaw/php2shell-cloud-defense-dojo

No Azure CLI, credentials, npm dependencies or private captures are bundled.
Azure resources and optional services are billable. Expiry is not deletion.
`;
    if (file === "package.json") source = JSON.stringify({
      name: "php2proof-core-deployment-wizard", private: true, type: "module",
      engines: { node: ">=24.19.0 <25" }, scripts: { start: "node scripts/wizard.mjs", check: "node scripts/wizard.mjs --check" },
    });
    if (/\.(?:mjs|cjs)$/.test(file) && file !== "scripts/wizard.mjs") source = transformSync(source, {
      loader: "js", format: file.endsWith(".cjs") ? "cjs" : "esm", target: "node24", minify: true, legalComments: "inline",
    }).code;
    return [file, source];
  }));
  const python = `import io,json,sys,zipfile
files=json.load(sys.stdin)
out=io.BytesIO()
with zipfile.ZipFile(out,'w',zipfile.ZIP_DEFLATED,compresslevel=9) as archive:
 for name,source in files.items():
  info=zipfile.ZipInfo(name,(2026,1,1,0,0,0))
  info.compress_type=zipfile.ZIP_DEFLATED
  info.external_attr=0o100644 << 16
  archive.writestr(info,source.encode('utf-8'),compress_type=zipfile.ZIP_DEFLATED,compresslevel=9)
sys.stdout.buffer.write(out.getvalue())`;
  const packaged = spawnSync(process.platform === "win32" ? "python" : "python3", ["-c", python], {
    input: JSON.stringify(files), maxBuffer: 1048576, timeout: 30000, shell: false,
  });
  if (packaged.error || packaged.status !== 0) throw new Error("Deployment source ZIP build failed; Python3 standard-library zipfile is required.");
  const zip = packaged.stdout;
  const manifest = { schemaVersion: 1, kind: "core-wizard-source", sha256: createHash("sha256").update(zip).digest("hex"),
    bytes: zip.length, files: Object.keys(files), coreOnly: true, parts: 2 };
  const encodedZip = zip.toString("base64");
  const split = Math.ceil(encodedZip.length / 8) * 4;
  const payloads = {
    "deployment-guide-maintenance": {
      "operator/deploy.mjs": transformSync(readFileSync(join(root, "operator", "deploy.mjs"), "utf8"), { format: "esm", target: "node24", minify: true }).code,
      "operator/server.mjs": transformSync(readFileSync(join(root, "operator", "server.mjs"), "utf8"), { format: "esm", target: "node24", minify: true }).code,
    },
    "deployment-download-maintenance": {
      "operator/public-deployment/manifest.json": JSON.stringify(manifest),
      "operator/public-deployment/source.zip.00.b64": encodedZip.slice(0, split),
    },
    "deployment-tail-maintenance": {
      "operator/public-deployment/source.zip.01.b64": encodedZip.slice(split),
    },
    "public-navigation-maintenance": Object.fromEntries(["app/index.php", "app/walkthrough.php", "app/assets/style.css"].map((file) => [file, readFileSync(join(root, ...file.split("/")), "utf8")])),
  };
  const results = Object.entries(payloads).map(([kind, contents]) => {
    const bytes = gzipSync(JSON.stringify({ schemaVersion: 1, kind, files: contents }), { level: 9, memLevel: 9 });
    const encoded = bytes.toString("base64");
    if (encoded.length + 2 > 61440) throw new Error(`${kind} exceeds the unchanged publication limit (${encoded.length + 2}/61440); no truncation is allowed.`);
    return { kind, bytes, encoded, sha256: createHash("sha256").update(bytes).digest("hex"), files: Object.keys(contents) };
  });
  mkdirSync(output);
  writeFileSync(join(output, "php2proof-deploy.zip"), zip);
  writeFileSync(join(output, "manifest.json"), `${JSON.stringify(manifest, null, 2)}\n`);
  const overlays = results.map(({ bytes, encoded, ...metadata }) => {
    const directory = join(output, metadata.kind);
    mkdirSync(directory);
    writeFileSync(join(directory, "source.json.gz"), bytes);
    const chunks = [];
    for (let index = 0; index < Math.ceil(encoded.length / 4000); index += 1) {
      const path = join(directory, `source-${String(index).padStart(2, "0")}.txt`);
      const chunk = encoded.slice(index * 4000, (index + 1) * 4000);
      writeFileSync(path, chunk);
      chunks.push({ index, path, length: chunk.length });
    }
    const report = { ...metadata, combinedProtectedBytes: encoded.length + 2, chunks };
    writeFileSync(join(directory, "manifest.json"), JSON.stringify(report, null, 2));
    return report;
  });
  return { ...manifest, overlays };
}
if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  if (process.argv.length !== 3) throw new Error("Usage: node operator\\build-deploy.mjs <new-output-directory>");
  console.log(JSON.stringify(buildDeployment(resolve(process.argv[2]))));
}
