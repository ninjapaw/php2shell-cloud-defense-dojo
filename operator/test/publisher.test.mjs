import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { runTool } from "../../scripts/lib/azure.mjs";

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
