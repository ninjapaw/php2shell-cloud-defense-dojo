import assert from "node:assert/strict";
import test from "node:test";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { gunzipSync, gzipSync } from "node:zlib";
import { assertCloudJobTemplate, assertRunnerCleanupTargets, cloudContext, CLOUD_CONTEXT_FILES, runCloudOperation, writeCloudReport } from "../scripts/cloud-runner.mjs";
import { ROOT } from "../scripts/dojo.mjs";
import { configuration, SUBSCRIPTION } from "./support/harness.mjs";

test("cloud artifact verification catches stale embedded scripts, public ingress, and unprotected source inputs", () => {
  const template = {
    parameters: { sourceBundle: { type: "secureObject" } },
    variables: {
      startup: readFileSync(join(ROOT, "scripts", "cloud-deploy.sh"), "utf8"),
      copy: [{ name: "sourceVariables", input: { secureValue: "[parameters('sourceBundle').chunks[copyIndex('sourceVariables')]]" } }],
    },
    resources: [{
      type: "Microsoft.ContainerInstance/containerGroups",
      properties: {
        restartPolicy: "Never",
        containers: [{ properties: {
          image: "mcr.microsoft.com/azure-cli@sha256:b23e5168ce9654b1385c565a2c6cf60695f7b0d03056f7a0fafdc7c59a084512",
          resources: { requests: { cpu: 1, memoryInGB: 2 } },
          command: ["python3", "-c", "timeout=5400", "[variables('startup')]"],
        } }],
      },
    }],
  };
  assertCloudJobTemplate(template);
  for (const mutate of [
    (value) => { value.variables.startup = "stale startup"; },
    (value) => { value.parameters.sourceBundle.type = "object"; },
    (value) => { value.resources[0].properties.ipAddress = { type: "Public" }; },
    (value) => { value.variables.copy[0].input.value = "exposed source"; },
  ]) {
    const changed = structuredClone(template);
    mutate(changed);
    assert.throws(() => assertCloudJobTemplate(changed), /Cloud job|Compiled/);
  }
});

test("runner cleanup refuses the public group, foreign resources, and unverified invocation/role identities", () => {
  const subscriptionId = `/subscriptions/${SUBSCRIPTION}`;
  const expected = {
    subscription: SUBSCRIPTION, resourceGroup: "NP-PHPToProof-Dev-CentralUS",
    helperGroup: "NP-PHPToProof-Deploy-Temp-test", invocationId: "unit-test-invocation",
    metadataRoleId: `${subscriptionId}/providers/Microsoft.Authorization/roleDefinitions/11111111-1111-4111-8111-111111111111`,
    metadataRoleAssignmentId: `${subscriptionId}/providers/Microsoft.Authorization/roleAssignments/22222222-2222-4222-8222-222222222222`,
    workloadRoleAssignmentId: `${subscriptionId}/resourceGroups/NP-PHPToProof-Dev-CentralUS/providers/Microsoft.Authorization/roleAssignments/33333333-3333-4333-8333-333333333333`,
  };
  const stack = {
    tags: { "dojo.scenario": "php2proof-deployment-runner", "dojo.invocationId": expected.invocationId },
    properties: { resources: [
      { id: `${subscriptionId}/resourceGroups/${expected.helperGroup}` },
      { id: `${subscriptionId}/resourceGroups/${expected.helperGroup}/providers/Microsoft.ManagedIdentity/userAssignedIdentities/operator` },
      ...[expected.metadataRoleId, expected.metadataRoleAssignmentId, expected.workloadRoleAssignmentId].map((id) => ({ id })),
    ] },
  };
  assertRunnerCleanupTargets(stack, expected);
  for (const id of [
    `${subscriptionId}/resourceGroups/${expected.resourceGroup}`,
    `${subscriptionId}/resourceGroups/foreign/providers/Microsoft.Storage/storageAccounts/foreign`,
    `${subscriptionId}/providers/Microsoft.Authorization/roleAssignments/44444444-4444-4444-8444-444444444444`,
  ]) {
    assert.throws(() => assertRunnerCleanupTargets({
      ...stack, properties: { resources: [...stack.properties.resources, { id }] },
    }, expected), /outside this invocation/);
  }
  assert.throws(() => assertRunnerCleanupTargets({ ...stack, tags: {} }, expected), /ownership/);
});

test("cloud context contains only reviewed current deployment sources, never credentials or the private lab", () => {
  const bundle = cloudContext();
  assert.match(bundle.sha256, /^[a-f0-9]{64}$/);
  const decoded = JSON.parse(gunzipSync(bundle.content));
  assert.equal(decoded.schemaVersion, 2);
  assert.deepEqual(Object.keys(decoded.files), CLOUD_CONTEXT_FILES);
  for (const [path, content] of Object.entries(decoded.files)) {
    assert.doesNotMatch(path, /(?:^|\/)(?:\.env|\.git|node_modules|output|container-lab)(?:\/|$)/);
    assert.ok(Buffer.from(content, "utf8").equals(readFileSync(join(ROOT, path))), path);
  }
  assert.ok(!decoded.files["detections/catalog.json"]);
  assert.ok(decoded.files["app/walkthrough.php"].includes("PHP to Proof | Guided Walkthrough"));
  assert.ok(bundle.sourceBundle.chunks.every((chunk) => chunk.length <= 8000));
  assert.ok(bundle.sourceBundle.chunks.join("").length <= 60 * 1024);
  assert.ok(Buffer.from(bundle.sourceBundle.chunks.join(""), "base64").equals(bundle.content));
});

test("protected startup verifies reviewed overlays, rejects duplicates, and enforces the exact combined budget", () => {
  const directory = mkdtempSync(join(tmpdir(), "php2proof-source-test-"));
  try {
    const block = readFileSync(join(ROOT, "scripts", "cloud-deploy.sh"), "utf8")
      .match(/python3 - <<'PY'\n([\s\S]*?)\nPY/)?.[1];
    assert.ok(block);
    const script = block.replace('pathlib.Path("/tmp/php2proof-context")', `pathlib.Path(${JSON.stringify(directory)})`);
    const paths = ["scripts/lib/azure.mjs", "infra/main.bicep", "config/dev.json"];
    const baseline = gzipSync(JSON.stringify({
      schemaVersion: 2, files: Object.fromEntries(paths.map((path) => [path, "baseline"])),
    }));
    const encoded = baseline.toString("base64");
    const sha256 = (content) => createHash("sha256").update(content).digest("hex");
    const overlay = (path, content) => ({ path, content, sha256: sha256(content) });
    const run = (overlays) => {
      const result = spawnSync(process.platform === "win32" ? "python" : "python3", ["-c", script], {
        encoding: "utf8",
        env: {
          ...process.env, SOURCE_PART_COUNT: "1", SOURCE_PART_0: encoded,
          SOURCE_SHA256: sha256(baseline), SOURCE_OVERLAYS: JSON.stringify(overlays),
        },
      });
      assert.ifError(result.error);
      return result;
    };
    const overlays = paths.map((path) => overlay(path, `reviewed ${path}`));
    const accepted = run(overlays);
    assert.equal(accepted.status, 0, accepted.stderr);
    for (const entry of overlays) assert.equal(readFileSync(join(directory, entry.path), "utf8"), entry.content);
    for (const [inputs, message] of [
      [[overlays[0], overlays[0]], /Duplicate or unreviewed/],
      [[overlay("app/health.php", "unreviewed")], /Duplicate or unreviewed/],
      [[{ ...overlays[0], sha256: "0".repeat(64) }], /checksum mismatch/],
      [[...overlays, overlays[0]], /overlay count/],
    ]) {
      const rejected = run(inputs);
      assert.notEqual(rejected.status, 0);
      assert.match(rejected.stderr, message);
    }
    const overhead = encoded.length + Buffer.byteLength(JSON.stringify([overlay(paths[0], "")]));
    const boundary = overlay(paths[0], "x".repeat(60 * 1024 - overhead));
    assert.equal(encoded.length + Buffer.byteLength(JSON.stringify([boundary])), 60 * 1024);
    const atLimit = run([boundary]);
    assert.equal(atLimit.status, 0, atLimit.stderr);
    const aboveLimit = run([{ ...boundary, content: `${boundary.content}x` }]);
    assert.notEqual(aboveLimit.status, 0);
    assert.match(aboveLimit.stderr, /size budget/);
  } finally {
    rmSync(directory, { recursive: true });
  }
});

test("cloud runner accepts only guarded lifecycle operations and reports verified results", async () => {
  for (const command of ["doctor", "deploy", "validate"]) {
    const reports = [];
    const result = command === "doctor" ? { preflight: "passed" } : { validated: true };
    const report = await runCloudOperation(configuration(command), {
      execute: async () => result, persist: (_config, value) => reports.push(value),
    });
    assert.equal(report.status, "succeeded");
    assert.equal(report.result, result);
    assert.deepEqual(reports, [report]);
  }
  await assert.rejects(runCloudOperation(configuration("uninstall")), /only doctor/);
  const reports = [];
  await assert.rejects(runCloudOperation(configuration("deploy"), {
    execute: async () => ({ validated: false }), persist: (_config, value) => reports.push(value),
  }), /required verified result/);
  assert.equal(reports[0].status, "failed");
});

test("cloud failures stay failures, redact diagnostics, and surface report persistence errors", async () => {
  const reports = [];
  await assert.rejects(runCloudOperation(configuration("deploy"), {
    execute: async () => { throw new Error("token=unit-test-sensitive-value"); },
    persist: (_config, value) => reports.push(value),
  }), /unit-test-sensitive-value/);
  assert.equal(reports[0].status, "failed");
  assert.ok(!JSON.stringify(reports).includes("unit-test-sensitive-value"));
  await assert.rejects(runCloudOperation(configuration("deploy"), {
    execute: async () => { throw new Error("Original failure."); },
    persist: () => { throw new Error("Report failure."); },
  }), /Original failure.*Report also failed.*Report failure/);
});

test("cloud reports are output-only Incremental deployments and reject unexpected changes", () => {
  const calls = [];
  const az = (args) => {
    calls.push(args);
    const template = JSON.parse(readFileSync(args[args.indexOf("--template-file") + 1], "utf8"));
    assert.deepEqual(template.resources, []);
    assert.equal(template.parameters.report.type, "object");
    return args[2] === "what-if" ? { status: "Succeeded", changes: [] } : { properties: { provisioningState: "Succeeded" } };
  };
  writeCloudReport(configuration("validate"), { status: "succeeded" }, az);
  assert.equal(calls.length, 2);
  assert.equal(calls[0][2], "what-if");
  assert.ok(calls[1].includes("Incremental"));
  assert.throws(() => writeCloudReport(configuration("validate"), {}, () => ({
    status: "Succeeded", changes: [{ changeType: "Delete" }],
  })), /unexpectedly contains resource changes/);
});
