import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { gunzipSync } from "node:zlib";
import { ROOT } from "../scripts/dojo.mjs";
import { assertContainerWhatIf, containerActionParameters, executeContainerLab } from "../scripts/container-lab.mjs";
import { assertContainerGroup, assertContainerIsolation, containerConfig, containerNames, containerTags, containerWorkload, readContainerImages } from "../scripts/lib/container-lab.mjs";

const subscription = "11111111-2222-4333-8444-555555555555";
const config = (command = "plan", extra = []) => containerConfig([command, "--suffix", "test1234", "--subscription", subscription, ...extra], {});
const group = (settings = config()) => ({
  id: `/subscriptions/${subscription}/resourceGroups/${containerNames(settings).group}`,
  location: "centralus", tags: containerTags(settings, new Date("2026-10-23T12:00:00Z")),
});

test("isolated container configuration rejects production, arbitrary targets and destructive overrides", () => {
  assert.equal(config().command, "plan");
  for (const args of [["--environment", "prod"], ["--suffix", "../other"], ["--subscription", "invalid"], ["--url", "http://example.org"], ["--resource-group", "foreign"], ["--confirm-resource-group", "foreign"]]) {
    assert.throws(() => config("deploy", args));
  }
  assert.throws(() => containerConfig(["deploy", "--suffix", "test1234"], {}), /explicit subscription/);
});

test("actual upstream comparison versions and immutable official image references are retained", () => {
  const images = readContainerImages(ROOT);
  assert.equal(images.vulnerable.version, "8.4.26");
  assert.equal(images.fixed.version, "8.4.27");
  assert.notEqual(images.vulnerable.source, images.fixed.source);
  assert.equal(images.advisories.length, 2);
});

test("container hunts cover observed modern image assessments as well as legacy subassessments", () => {
  for (const name of ["container-cve-findings.kql", "container-php-findings.kql"]) {
    const query = readFileSync(join(ROOT, "detections", "resource-graph", name), "utf8");
    assert.match(query, /"microsoft.security\/assessments", "microsoft.security\/assessments\/subassessments"/);
    assert.match(query, /securityentitydata/);
    assert.match(query, /properties\.resourceDetails\.Id/);
  }
  const cves = readFileSync(join(ROOT, "detections", "resource-graph", "container-cve-findings.kql"), "utf8");
  assert.match(cves, /Additional\.CvesDetails/);
  assert.match(cves, /mv-expand Cve = CveRows/);
  assert.match(cves, /tostring\(Cve\.CveId\)/);
});

test("workload has no ingress, identity token, privilege, mutable image or permanent writable volume", () => {
  const manifest = containerWorkload("p2sctest1234.azurecr.io", `sha256:${"a".repeat(64)}`, "vulnerable");
  const deployment = manifest.items.find((item) => item.kind === "Deployment");
  const pod = deployment.spec.template.spec;
  const container = pod.containers[0];
  assert.equal(pod.automountServiceAccountToken, false);
  assert.equal(pod.securityContext.runAsNonRoot, true);
  assert.equal(pod.securityContext.runAsUser, 10001);
  assert.equal(container.securityContext.readOnlyRootFilesystem, true);
  assert.equal(container.securityContext.allowPrivilegeEscalation, false);
  assert.deepEqual(container.securityContext.capabilities.drop, ["ALL"]);
  assert.equal(pod.volumes[0].emptyDir.medium, "Memory");
  assert.match(container.image, /@sha256:[a-f0-9]{64}$/);
  const policy = manifest.items.find((item) => item.kind === "NetworkPolicy");
  assert.deepEqual(policy.spec.policyTypes, ["Ingress", "Egress"]);
  assert.deepEqual(policy.spec.ingress, []);
  assert.deepEqual(policy.spec.egress, []);
  assert.equal(manifest.items.some((item) => ["Service", "Ingress", "ClusterRoleBinding"].includes(item.kind)), false);
  assert.equal(manifest.items.find((item) => item.kind === "ResourceQuota").spec.hard.services, "0");
  for (const args of [["evil.example.org", `sha256:${"a".repeat(64)}`, "vulnerable"], ["p2sctest1234.azurecr.io", "latest", "vulnerable"], ["p2sctest1234.azurecr.io", `sha256:${"a".repeat(64)}`, "prod"]]) {
    assert.throws(() => containerWorkload(...args));
  }
});

test("ownership and what-if prevent foreign adoption, pricing writes and deletion", () => {
  const settings = config();
  assertContainerGroup(group(), settings);
  for (const patch of [{ id: `${group().id}-foreign` }, { location: "westus" }, { tags: { ...group().tags, "dojo.scenario": "other" } }, { tags: { ...group().tags, "dojo.containerState": "unknown" } }]) {
    assert.throws(() => assertContainerGroup({ ...group(), ...patch }, settings));
  }
  assertContainerWhatIf({ changes: [{ resourceId: `${group().id}/providers/Microsoft.ContainerRegistry/registries/lab`, changeType: "Create" }] }, settings);
  for (const change of [
    { resourceId: `${group().id}/providers/Microsoft.Web/sites/lab`, changeType: "Delete" },
    { resourceId: `${group().id}-foreign/providers/Microsoft.Web/sites/lab`, changeType: "Create" },
    { resourceId: `${group().id}/providers/Microsoft.Security/pricings/Containers`, changeType: "Modify" },
  ]) assert.throws(() => assertContainerWhatIf({ changes: [change] }, settings));
});

test("build context is allowlisted and remediation cannot recreate the vulnerable state", () => {
  const settings = config("remediate", ["--yes"]);
  const owned = group(settings);
  owned.tags["dojo.containerState"] = "fixed";
  const params = containerActionParameters(settings, owned, "test-invocation");
  assert.equal(params.variant.value, "fixed");
  assert.equal(params.workload.value.items.find((item) => item.kind === "Deployment").spec.template.metadata.annotations["dojo.variant"], "fixed");
  const bundle = JSON.parse(gunzipSync(Buffer.from(params.contextBundle.value, "base64")));
  assert.equal(bundle.script, readFileSync(join(ROOT, "scripts", "container-lab-cloud.sh"), "utf8"));
  assert.deepEqual(Object.keys(bundle.files), [
    "container-lab/Dockerfile", "container-lab/apache.conf", "container-lab/php.ini",
    "container-lab/index.php", "container-lab/health.php", "app/lab.php", "app/assets/style.css",
  ]);
  const ignore = readFileSync(join(ROOT, ".dockerignore"), "utf8").split(/\r?\n/);
  assert.equal(ignore[0], "**");
  for (const path of Object.keys(bundle.files)) assert.ok(ignore.includes(`!${path}`), path);
});

test("live isolation verification rejects policy drift, services, tokens and privilege escalation", () => {
  const manifest = containerWorkload("p2sctest1234.azurecr.io", `sha256:${"a".repeat(64)}`, "vulnerable");
  const namespace = manifest.items[0];
  const policy = manifest.items[1];
  const pod = manifest.items[3].spec.template;
  assertContainerIsolation(namespace, policy, { items: [] }, pod);
  for (const mutate of [
    (value) => { value.spec.automountServiceAccountToken = true; },
    (value) => { value.spec.hostNetwork = true; },
    (value) => { value.spec.containers[0].securityContext.privileged = true; },
    (value) => { value.spec.volumes.push({ name: "host", hostPath: { path: "/" } }); },
  ]) {
    const changed = structuredClone(pod);
    mutate(changed);
    assert.throws(() => assertContainerIsolation(namespace, policy, { items: [] }, changed));
  }
  assert.throws(() => assertContainerIsolation(namespace, policy, { items: [{ kind: "Service" }] }, pod));
  assert.throws(() => assertContainerIsolation(namespace, { ...policy, spec: { ...policy.spec, egress: [{}] } }, { items: [] }, pod));
});

test("offline plan makes no Azure calls and writes require explicit acknowledgement", async () => {
  const az = () => { throw new Error("Unexpected Azure call"); };
  const plan = await executeContainerLab(config(), { az, log: () => {} });
  assert.match(plan.costs, /does not auto-delete/);
  for (const command of ["deploy", "validate", "remediate", "test-detection"]) {
    await assert.rejects(executeContainerLab(config(command), { az }), /--yes/);
  }
  await assert.rejects(executeContainerLab(config("uninstall", ["--yes"]), { az }), /--confirm-resource-group/);
});

test("validation consumes current managed-identity evidence without human Kubernetes permissions", async () => {
  let invocation;
  let removed = false;
  let stale = false;
  const digest = `sha256:${"a".repeat(64)}`;
  const az = (args) => {
    if (args[0] === "account") return { id: subscription, state: "Enabled" };
    if (args[0] === "cloud") return { name: "AzureCloud" };
    if (args[0] === "group" && args[1] === "exists") return true;
    if (args[0] === "group" && args[1] === "show") return group();
    if (args[0] === "deployment" && args[2] === "what-if") return { changes: [] };
    if (args[0] === "deployment" && args[2] === "create") {
      invocation = JSON.parse(args[args.indexOf("--parameters") + 1]).invocationId.value;
      return { properties: { provisioningState: "Succeeded", outputs: { runnerName: { value: "p2sc-test1234-runner-test" } } } };
    }
    if (args[0] === "container" && args[1] === "show") return { containers: [{ instanceView: { currentState: { state: "Terminated", exitCode: 0 } } }] };
    if (args[0] === "container" && args[1] === "delete") { removed = true; return null; }
    if (args[0] === "aks" && args[1] === "show") return {
      provisioningState: "Succeeded", apiServerAccessProfile: { enablePrivateCluster: true },
      disableLocalAccounts: true, securityProfile: { defender: { securityMonitoring: { enabled: true } } },
      agentPoolProfiles: [{ enableNodePublicIP: false }],
    };
    if (args[0] === "acr") return { digest };
    throw new Error("The human caller must not execute Kubernetes commands directly.");
  };
  const runner = (command, args) => {
    assert.equal(command, "az");
    assert.deepEqual(args.slice(0, 2), ["container", "logs"]);
    assert.equal(args[args.indexOf("--output") + 1], "tsv");
    return `build output\nPHP2SHELL_RESULT ${JSON.stringify({
      health: { scenario: "php2shell-container-lab", environment: "dev", variant: "vulnerable",
        sapi: "apache2handler", phpVersion: "8.4.26", matchesExpectedRuntime: true },
      image: `p2sctest1234.azurecr.io/php2shell@${digest}`,
      sensorDaemonsets: [{ name: "microsoft-defender-collector-ds", desired: 1, ready: 1 }],
      namespace: "php2shell-isolated", isolationVerified: true, invocationId: stale ? "previous-invocation" : invocation,
      evidenceKind: "live-managed-identity-container-validation",
    })}\n`;
  };
  const evidence = await executeContainerLab(config("validate", ["--yes"]), { az, runner, log: () => {} });
  assert.equal(evidence.health.phpVersion, "8.4.26");
  assert.equal(removed, true);
  stale = true;
  removed = false;
  await assert.rejects(executeContainerLab(config("validate", ["--yes"]), { az, runner, log: () => {} }), /current managed-identity job/);
  assert.equal(removed, false, "Invalid evidence must retain the runner for inspection.");
});

test("investigation follows native CLI continuation fields without silently truncating evidence", async () => {
  const calls = [];
  const az = (args) => {
    calls.push(args);
    if (args[0] === "account") return { id: subscription, state: "Enabled" };
    if (args[0] === "cloud") return { name: "AzureCloud" };
    if (args[0] === "group" && args[1] === "exists") return true;
    if (args[0] === "group" && args[1] === "show") return group();
    if (args[0] === "graph") {
      const query = args[args.indexOf("--graph-query") + 1];
      assert.ok(query.includes(subscription));
      assert.ok(query.includes("rg-p2sc-test1234-dev") || query.includes("p2sc-test1234-aks"));
      if (query.includes("locations/alerts")) return { data: [], total_records: 0 };
      if (args.includes("--skip-token")) return { data: [{ id: "second" }], total_records: 2 };
      return { data: [{ id: "first" }], total_records: 2, skip_token: "next-page" };
    }
    throw new Error(`Unexpected Azure call: ${args[0]}`);
  };
  const result = await executeContainerLab(config("investigate"), { az, log: () => {} });
  assert.deepEqual(result.phpAssessments, [{ id: "first" }, { id: "second" }]);
  assert.deepEqual(result.recentAlerts, []);
  assert.equal(calls.filter((args) => args[0] === "graph").length, 3);
});

test("cloud action never adds an exploit, privileged workload or a promised alert", () => {
  const script = readFileSync(join(ROOT, "scripts", "container-lab-cloud.sh"), "utf8");
  assert.match(script, /set -euo pipefail/);
  assert.match(script, /\.provisioningState == "Succeeded" and \.exitCode == 0/);
  assert.match(script, /\.reason/);
  assert.match(script, /no alert is fabricated/);
  assert.match(script, /--file \/tmp\/php2shell-context\/container-lab\/Dockerfile/);
  assert.doesNotMatch(script, /curl.+\|\s*(sh|bash)|--privileged|helm.*mdc-simulation|az security pricing create/);
  const template = readFileSync(join(ROOT, "infra", "container-lab.bicep"), "utf8");
  assert.match(template, /enablePrivateCluster: true/);
  assert.match(template, /enableNodePublicIP: false/);
  assert.match(template, /sshAccess: 'Disabled'/);
  assert.match(template, /securityMonitoring: \{ enabled: true \}/);
  assert.match(template, /b1ff04bb-8a4e-4dc4-8eb5-8693973ce19b/);
  assert.doesNotMatch(template, /Microsoft\.Security\/pricings|roleDefinitions', '8e3af657/);
  const apache = readFileSync(join(ROOT, "container-lab", "apache.conf"), "utf8");
  assert.match(apache, /<FilesMatch "\\\.php\$">\s+SetHandler application\/x-httpd-php\s+<\/FilesMatch>/);
});
