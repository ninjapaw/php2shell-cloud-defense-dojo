import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { gunzipSync } from "node:zlib";
import { runTool } from "../../scripts/lib/azure.mjs";

test("the actual production runtime stays complete and inside the publisher's unchanged protected-source cap", {
  skip: !process.env.npm_execpath && "Run npm test to exercise the documented npm runtime builder.",
}, (t) => {
  const directory = mkdtempSync(join(tmpdir(), "php2proof-runtime-test-"));
  t.after(() => rmSync(directory, { recursive: true }));
  const output = join(directory, "runtime");
  const result = spawnSync(process.execPath, [fileURLToPath(new URL("../build-runtime.mjs", import.meta.url)), output], {
    encoding: "utf8", timeout: 120_000, maxBuffer: 1_048_576,
    env: { ...process.env, npm_config_offline: "true", npm_config_audit: "false", npm_config_fund: "false" },
  });
  assert.equal(result.status, 0, result.stderr);
  const manifest = JSON.parse(readFileSync(join(output, "manifest.json"), "utf8"));
  const content = readFileSync(join(output, "runtime.json.gz"));
  const chunks = manifest.stages.map((stage, index) => {
    assert.equal(stage.index, index);
    const chunk = readFileSync(stage.path, "utf8");
    assert.equal(chunk.length, stage.length);
    assert.ok(chunk.length > 0 && chunk.length <= 4000);
    return chunk;
  });
  assert.ok(chunks.length > 0 && chunks.length <= 16);
  assert.equal(chunks.join("").length, manifest.encodedBytes);
  assert.ok(manifest.encodedBytes + 2 <= 61_440);
  assert.deepEqual(Buffer.from(chunks.join(""), "base64"), content);
  assert.equal(createHash("sha256").update(content).digest("hex"), manifest.sha256);
  const source = JSON.parse(gunzipSync(content, { maxOutputLength: 2_097_152 }));
  assert.equal(source.schemaVersion, 1);
  assert.equal(manifest.files.length, 22);
  assert.deepEqual(Object.keys(source.files).sort(), [...manifest.files].sort());
  const runtime = JSON.parse(source.files["operator/package.json"]);
  const locked = JSON.parse(source.files["operator/package-lock.json"]);
  assert.equal(runtime.devDependencies, undefined);
  assert.equal(locked.packages[""].devDependencies, undefined);
  assert.ok(Object.values(locked.packages).every((entry) => !entry.dev));
  assert.equal(locked.packages["node_modules/@gfx/zopfli"], undefined);
  assert.equal(locked.packages["node_modules/esbuild"], undefined);
  for (const [name, version] of Object.entries(runtime.dependencies)) {
    assert.equal(locked.packages[`node_modules/${name}`].version, version);
  }
});

test("publisher uses the established gzip Node pin and keeps source bounds/isolated code deployment", () => {
  const script = readFileSync(new URL("../publish-runtime.sh", import.meta.url), "utf8");
  const prior = readFileSync(new URL("../../scripts/cloud-deploy.sh", import.meta.url), "utf8");
  const pin = /node_sha256=([a-f0-9]{64})/.exec(script)?.[1];
  assert.ok(pin && prior.includes(`expected = "${pin}"`));
  assert.match(script, /node-v\$\{node_version\}-linux-x64\.tar\.gz/);
  assert.match(script, /tarfile\.open\(sys\.argv\[1\], "r:gz"\)/);
  assert.match(script, /extractall\(sys\.argv\[2\], filter="data"\)/);
  assert.doesNotMatch(script, /tar\.xz|tar -xJf/);
  assert.match(script, /encoded\.length \+ 2 > 61440/);
  assert.match(script, /count > 16/);
  assert.match(script, /chunk\.length > 4000/);
  assert.match(script, /maxOutputLength: 2097152/);
  assert.match(script, /zipfile\.ZipFile/);
  assert.doesNotMatch(script, /^tar |^zip |tdnf install/m);
  assert.match(script, /--resource-group "\$OPERATOR_GROUP"/);
  assert.match(script, /--async false --track-status false/);
  assert.doesNotMatch(script, /account get-access-token|list-keys|account-key|generate-sas/);
});

test("publisher archive operations execute using the CLI image's Python standard library, not missing tar/zip binaries", () => {
  const script = readFileSync(new URL("../publish-runtime.sh", import.meta.url), "utf8");
  const blocks = [...script.matchAll(/python3[^\n]*<<'PY'\n([\s\S]*?)\nPY/g)].map((match) => match[1]);
  assert.equal(blocks.length, 2);
  const check = `
import pathlib, sys, tarfile, tempfile, zipfile
with tempfile.TemporaryDirectory(prefix="php2proof-publisher-test-") as directory:
    root = pathlib.Path(directory)
    source = root / "source"
    source.mkdir()
    (source / "fixture.txt").write_text("bounded fixture")
    archive = root / "node.tar.gz"
    with tarfile.open(archive, "w:gz") as package:
        package.add(source / "fixture.txt", arcname="fixture.txt")
    destination = root / "unpacked"
    destination.mkdir()
    sys.argv = ["extract", str(archive), str(destination)]
    exec(${JSON.stringify(blocks[0])})
    assert (destination / "fixture.txt").read_text() == "bounded fixture"
    output = root / "operator.zip"
    sys.argv = ["package", str(destination), str(output)]
    exec(${JSON.stringify(blocks[1])})
    with zipfile.ZipFile(output) as package:
        assert package.namelist() == ["fixture.txt"]
        assert package.read("fixture.txt") == b"bounded fixture"
print("stdlib archive checks passed")
`;
  assert.match(runTool("python", ["-c", check]), /stdlib archive checks passed/);
});

test("private owner renewal grants only the exact verifier's data-plane set permission", () => {
  const root = readFileSync(new URL("../../infra/private-live.bicep", import.meta.url), "utf8");
  const access = readFileSync(new URL("../../infra/private-live-operator-access.bicep", import.meta.url), "utf8");
  const role = root.split("\n").find((line) => line.includes("key: 'verifier'"));
  assert.match(role, /actions: \[\], dataActions: \['Microsoft\.KeyVault\/vaults\/secrets\/setSecret\/action'\]/);
  assert.doesNotMatch(role, /secrets\/write|secrets\/\*|getSecret|readMetadata/);
  assert.match(access, /name: 'operator-admin-verifier'/);
  assert.match(access, /resource verifierWriter[\s\S]*?scope: verifier[\s\S]*?roleDefinitionId: verifierRoleId/);
  assert.doesNotMatch(access, /operator-admin-password|operator-admin-username/);
});

test("expiry cleanup retains completed-pair progress in one bounded stateful run before deleting the group", () => {
  const source = readFileSync(new URL("../../infra/private-live-cleanup.bicep", import.meta.url), "utf8");
  assert.match(source, /RetryRevocation: \{\s+type: 'Until'/);
  assert.match(source, /limit: \{ count: 120, timeout: 'PT1H' \}/);
  assert.match(source, /parameters\(\\'externalGrants\\'\)\[variables\(\\'CleanupCount\\'\)\]\[\\'worker\\'\]/);
  assert.match(source, /parameters\(\\'externalGrants\\'\)\[variables\(\\'CleanupCount\\'\)\]\[\\'own\\'\]/);
  assert.match(source, /CountCompletedPair: \{ type: 'IncrementVariable'/);
  assert.match(source, /runAfter: \{ RetryRevocation: \['Succeeded', 'Failed', 'TimedOut'\] \}/);
  assert.doesNotMatch(source, /type: 'Foreach'|items\(\\'RevokeExternal\\'\)/);
  assert.match(source, /Private resources remain billable; an owner must reconcile cleanup/);
  assert.match(source, /greaterOrEquals: \['@ticks\(utcNow\(\)\)'/);
});
