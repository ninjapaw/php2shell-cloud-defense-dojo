import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync, rmSync } from "node:fs";
import { dirname, join } from "node:path";
import { tmpdir } from "node:os";
import { pathToFileURL } from "node:url";
import { LIVE_INTEGRITY_FILES } from "../live-integrity.mjs";

test("live startup requires all 21 exact source hashes and rejects mixed, missing or foreign assets", async () => {
  const root = mkdtempSync(join(tmpdir(), "php2proof-live-integrity-"));
  try {
    const hashes = {};
    for (const name of LIVE_INTEGRITY_FILES) {
      const path = join(root, ...name.split("/"));
      mkdirSync(dirname(path), { recursive: true });
      const content = name === "operator/live-integrity.mjs"
        ? readFileSync(new URL("../live-integrity.mjs", import.meta.url))
        : Buffer.from(`unit-integrity-fixture:${name}\n`);
      writeFileSync(path, content);
      hashes[name] = createHash("sha256").update(content).digest("hex");
    }
    assert.equal(LIVE_INTEGRITY_FILES.length, 21);
    const manifestPath = join(root, "operator", "live-integrity.json");
    const manifest = () => writeFileSync(manifestPath, JSON.stringify({ schemaVersion: 1, files: hashes }));
    manifest();
    const runtime = await import(pathToFileURL(join(root, "operator", "live-integrity.mjs")).href);
    await runtime.assertLiveRuntimeIntegrity();
    const stylePath = join(root, "operator", "style.css");
    const original = readFileSync(stylePath);
    writeFileSync(stylePath, "unit mixed-overlay bytes");
    await assert.rejects(runtime.assertLiveRuntimeIntegrity(), /source-integrity mismatch: operator\/style\.css/);
    rmSync(stylePath);
    await assert.rejects(runtime.assertLiveRuntimeIntegrity(), /ENOENT/);
    writeFileSync(stylePath, original);
    hashes["operator/style.css"] = "not-a-sha256";
    manifest();
    await assert.rejects(runtime.assertLiveRuntimeIntegrity(), /Invalid private live source-integrity fingerprint/);
    delete hashes["operator/style.css"];
    hashes["operator/foreign.css"] = "a".repeat(64);
    manifest();
    await assert.rejects(runtime.assertLiveRuntimeIntegrity(), /manifest is incomplete/);
  } finally {
    rmSync(root, { recursive: true });
  }
});
