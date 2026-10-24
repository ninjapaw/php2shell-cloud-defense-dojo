import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import { gunzipSync } from "node:zlib";
import { buildDeployment, DEPLOY_FILES } from "../operator/build-deploy.mjs";
import { decodeDeployment, renderDeploymentPage, validateDeploymentManifest } from "../operator/deploy.mjs";
import { packageApp } from "../scripts/lib/azure.mjs";

test("actual core deployment ZIP is bounded, complete, credential-free and works without npm dependencies", (t) => {
  const directory = mkdtempSync(join(tmpdir(), "php2proof-deploy-test-"));
  t.after(() => rmSync(directory, { recursive: true }));
  const output = join(directory, "artifact");
  const built = buildDeployment(output);
  assert.equal(built.coreOnly, true);
  assert.deepEqual(built.files, [...DEPLOY_FILES].sort());
  assert.equal(built.parts, 2);
  assert.ok(built.overlays.every((item) => item.combinedProtectedBytes <= 61440));
  assert.ok(built.overlays.every((item) => `php2proof-hunting-${item.kind}-abcdefghijkl`.length <= 64), "Maximum-length suffix must fit the actual ARM report name.");
  const values = Object.assign({}, ...built.overlays.map((overlay) =>
    JSON.parse(gunzipSync(readFileSync(join(output, overlay.kind, "source.json.gz")))).files));
  const manifest = JSON.parse(values["operator/public-deployment/manifest.json"]);
  const decoded = decodeDeployment(manifest, [
    values["operator/public-deployment/source.zip.00.b64"], values["operator/public-deployment/source.zip.01.b64"],
  ]);
  assert.deepEqual(decoded, readFileSync(join(output, "php2proof-deploy.zip")));
  assert.throws(() => decodeDeployment({ ...manifest, sha256: "0".repeat(64) }, [
    values["operator/public-deployment/source.zip.00.b64"], values["operator/public-deployment/source.zip.01.b64"],
  ]), /checksum mismatch/);
  assert.throws(() => decodeDeployment(manifest, ["part"]), /Both fixed/);
  const extract = join(directory, "source");
  const python = spawnSync(process.platform === "win32" ? "python" : "python3", ["-c",
    "import json,sys,zipfile;z=zipfile.ZipFile(sys.argv[1]);z.extractall(sys.argv[2]);print(json.dumps(z.namelist()))",
    join(output, "php2proof-deploy.zip"), extract], { encoding: "utf8", timeout: 10000 });
  assert.equal(python.status, 0, python.stderr);
  assert.deepEqual(JSON.parse(python.stdout), manifest.files);
  const config = JSON.parse(readFileSync(join(extract, "config", "dev.json"), "utf8"));
  assert.equal(config.customDomain, "");
  const pkg = JSON.parse(readFileSync(join(extract, "package.json"), "utf8"));
  assert.equal(pkg.dependencies, undefined);
  assert.equal(pkg.devDependencies, undefined);
  assert.ok(manifest.files.every((file) => !/(?:^|\/)(?:node_modules|\.env|\.git|public-evidence|container-lab)(?:\/|$)/.test(file)));
  const result = spawnSync(process.execPath, [join(extract, "scripts", "wizard.mjs"), "--help"], { encoding: "utf8", timeout: 10000 });
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /No custom app registration/);
  const page = renderDeploymentPage(manifest);
  assert.match(page, /core public PHP story/);
  assert.match(page, /not silently installed/);
  assert.match(page, /Microsoft's existing client/);
  assert.equal((page.match(/<form\b/g) ?? []).length, 0);
  assert.ok(page.includes(manifest.sha256));
  assert.throws(() => validateDeploymentManifest({ ...manifest, files: ["../escape"] }), /invalid/);
});

test("native application ZIP packaging preserves actual file shape without a shell", (t) => {
  const directory = mkdtempSync(join(tmpdir(), "php2proof archive & space-"));
  t.after(() => rmSync(directory, { recursive: true }));
  mkdirSync(join(directory, "app"));
  writeFileSync(join(directory, "app", "index.php"), "<?php echo 'harmless';\n");
  const artifact = packageApp(directory);
  t.after(artifact.cleanup);
  const bytes = readFileSync(artifact.path);
  assert.equal(bytes.subarray(0, 2).toString(), "PK");
  const result = spawnSync(process.platform === "win32" ? "python" : "python3", ["-c",
    "import json,sys,zipfile;print(json.dumps(zipfile.ZipFile(sys.argv[1]).namelist()))", artifact.path], { encoding: "utf8", timeout: 10000 });
  assert.equal(result.status, 0, result.stderr);
  assert.ok(JSON.parse(result.stdout).some((name) => name.replace(/^\.\//, "") === "index.php"));
});
