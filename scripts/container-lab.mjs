#!/usr/bin/env node
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { randomUUID } from "node:crypto";
import { gzipSync } from "node:zlib";
import { setTimeout as delay } from "node:timers/promises";
import { ROOT } from "./dojo.mjs";
import { createAzureClient, runTool } from "./lib/azure.mjs";
import {
  assertContainerGroup, assertContainerIsolation, containerConfig, containerNames, containerTags, containerWorkload, readContainerImages,
} from "./lib/container-lab.mjs";
import { redact } from "./lib/safety.mjs";

export const CONTEXT_FILES = [
  "container-lab/Dockerfile", "container-lab/apache.conf", "container-lab/php.ini",
  "container-lab/index.php", "container-lab/health.php", "app/lab.php", "app/assets/style.css",
];

export function containerActionParameters(config, group, invocationId = randomUUID()) {
  const n = containerNames(config);
  const variant = group.tags["dojo.containerState"];
  const workload = containerWorkload(`${n.registry}.azurecr.io`, `sha256:${"0".repeat(64)}`, variant);
  assertContainerIsolation(
    workload.items.find((item) => item.kind === "Namespace"),
    workload.items.find((item) => item.kind === "NetworkPolicy"),
    { items: workload.items.filter((item) => item.kind === "Service") },
    workload.items.find((item) => item.kind === "Deployment")?.spec?.template,
  );
  return {
    suffix: { value: config.suffix }, location: { value: config.location },
    action: { value: config.command }, variant: { value: variant },
    contextBundle: { value: gzipSync(JSON.stringify({
      files: Object.fromEntries(CONTEXT_FILES.map((path) => [path, readFileSync(join(ROOT, path), "utf8")])),
      script: readFileSync(join(ROOT, "scripts", "container-lab-cloud.sh"), "utf8"),
    })).toString("base64") },
    workload: { value: workload },
    images: { value: readContainerImages(ROOT) }, invocationId: { value: invocationId },
    tags: { value: group.tags },
  };
}

export function assertContainerWhatIf(result, config) {
  const groupId = `/subscriptions/${config.subscription}/resourceGroups/${containerNames(config).group}`.toLowerCase();
  if (!Array.isArray(result?.changes)) throw new Error("What-if did not return a changes collection.");
  for (const change of result.changes) {
    if (!change.resourceId?.toLowerCase().startsWith(`${groupId}/`)
        || !["Create", "Modify", "NoChange", "Ignore", "Deploy"].includes(change.changeType)
        || change.resourceId.toLowerCase().includes("/microsoft.security/pricings/")) {
      throw new Error("Container what-if exceeded the exact lab resource group or requested deletion.");
    }
  }
}

export async function executeContainerLab(config, dependencies = {}) {
  const n = containerNames(config);
  const log = dependencies.log ?? console.log;
  if (config.command === "plan") {
    const plan = {
      scenario: "php2shell-container-lab", environment: "dev", names: n,
      subscription: config.subscription ?? "explicit subscription required for cloud operations",
      images: readContainerImages(ROOT),
      resources: ["Private AKS with one D2s_v6 Azure Linux 3 node", "Basic ACR", "Log Analytics", "Outbound-only managed NAT", "Keyless managed-identity container job"],
      access: "No public app ingress or cluster API; restricted non-root pod, read-only root, deny-all network policy, no service-account token.",
      permissions: "Operator managed identity: Contributor only at this registry and cluster, plus Kubernetes RBAC Cluster Admin only on this isolated cluster for namespace bootstrap/validation. Kubelet: AcrPull only at this registry. Application: no Azure roles.",
      effects: "Explicit deployment can register missing required providers. Existing Defender Containers/CSPM Standard and registry assessment extensions are required, never silently changed.",
      costs: "Compute/disks, ACR/builds, NAT/public egress IP, container-job compute, logs and protected vCores can bill. The 1 GB/day cap is not a total budget. The 24-hour expiry tag does not auto-delete.",
      teardown: `Delete only the confirmed ${n.group}; AKS also removes its dedicated managed node group ${n.base}-nodes-dev.`,
      evidence: "Real affected runtime and actual scanner/sensor records; no exploit endpoint, guaranteed alert, or fabricated compromise.",
      note: "Offline only; no Azure calls or writes.",
    };
    log(JSON.stringify(plan, null, 2));
    return plan;
  }
  if (["deploy", "validate", "remediate", "test-detection"].includes(config.command) && !config.yes) throw new Error("This operation requires --yes to acknowledge authorized activity and applicable charges.");
  if (config.command === "uninstall" && config.confirmation !== n.group) throw new Error(`Uninstall requires --confirm-resource-group ${n.group}; --yes is not confirmation.`);
  const az = dependencies.az ?? createAzureClient(config);
  const account = az(["account", "show"]);
  if (account?.id?.toLowerCase() !== config.subscription.toLowerCase() || account.state !== "Enabled"
      || az(["cloud", "show"])?.name !== "AzureCloud") throw new Error("Explicit enabled subscription and public AzureCloud context must match.");
  const exists = az(["group", "exists", "--name", n.group]);
  if (typeof exists !== "boolean") throw new Error("Invalid resource-group existence response.");
  let group = exists ? assertContainerGroup(az(["group", "show", "--name", n.group]), config) : undefined;
  if (config.command !== "deploy" && !group) throw new Error("The exact isolated container lab has not been deployed.");
  if (config.command === "uninstall") {
    az(["group", "delete", "--name", n.group, "--yes"]);
    if (az(["group", "exists", "--name", n.group]) !== false) throw new Error("Teardown is not complete.");
    log(`Deleted only ${n.group} and its AKS-managed resources. Subscription pricing was not changed.`);
    return { deleted: n.group };
  }
  if (config.command === "deploy") {
    for (const plan of ["Containers", "CloudPosture"]) {
      const pricing = az(["security", "pricing", "show", "--name", plan]);
      if (pricing?.pricingTier !== "Standard") throw new Error(`${plan} Standard is required; review and enable that subscription-wide plan separately.`);
      if (!pricing.extensions?.some((extension) => extension.name === "ContainerRegistriesVulnerabilityAssessments" && extension.isEnabled === "True")) {
        throw new Error(`${plan} registry-assessment extension is not enabled; no coverage is assumed.`);
      }
    }
    for (const namespace of ["Microsoft.ContainerService", "Microsoft.ContainerRegistry", "Microsoft.Network", "Microsoft.ManagedIdentity", "Microsoft.OperationalInsights", "Microsoft.ContainerInstance"]) {
      if (az(["provider", "show", "--namespace", namespace])?.registrationState !== "Registered") {
        log(`Explicit dev deployment is registering required provider ${namespace}.`);
        az(["provider", "register", "--namespace", namespace, "--wait"]);
      }
    }
    if (!group) group = assertContainerGroup(az(["group", "create", "--name", n.group, "--location", config.location,
      "--tags", ...Object.entries(containerTags(config, dependencies.now)).map(([key, value]) => `${key}=${value}`)]), config);
    const parameters = { environmentName: { value: "dev" }, suffix: { value: config.suffix }, location: { value: config.location }, tags: { value: group.tags } };
    const args = ["deployment", "group", "what-if", "--resource-group", n.group, "--template-file", join(ROOT, "infra", "container-lab.bicep"),
      "--parameters", JSON.stringify(parameters), "--result-format", "ResourceIdOnly"];
    assertContainerWhatIf(az(args), config);
    const deployment = az(["deployment", "group", "create", "--resource-group", n.group, "--name", `${n.base}-foundation`,
      "--template-file", join(ROOT, "infra", "container-lab.bicep"), "--parameters", JSON.stringify(parameters)]);
    if (deployment?.properties?.provisioningState !== "Succeeded") throw new Error("Container foundation deployment did not succeed.");
  }
  if (config.command === "remediate") {
    group = assertContainerGroup(az(["group", "update", "--name", n.group, "--set",
      `tags=${JSON.stringify({ ...group.tags, "dojo.containerState": "fixed" })}`]), config);
  }
  let runnerEvidence;
  let completedRunner;
  let expectedInvocation;
  if (["deploy", "validate", "remediate", "test-detection"].includes(config.command)) {
    const parameters = containerActionParameters(config, group);
    expectedInvocation = parameters.invocationId.value;
    assertContainerWhatIf(az(["deployment", "group", "what-if", "--resource-group", n.group,
      "--template-file", join(ROOT, "infra", "container-lab-action.bicep"), "--parameters", JSON.stringify(parameters),
      "--result-format", "ResourceIdOnly"]), config);
    const deployment = az(["deployment", "group", "create", "--resource-group", n.group, "--name", `${n.base}-action`,
      "--template-file", join(ROOT, "infra", "container-lab-action.bicep"), "--parameters", JSON.stringify(parameters)]);
    if (deployment?.properties?.provisioningState !== "Succeeded") throw new Error("Container operation did not succeed; no deployment or alert success is asserted.");
    const runnerName = deployment.properties.outputs?.runnerName?.value;
    if (typeof runnerName !== "string" || !runnerName.startsWith(`${n.base}-runner-`) || !/^[a-z0-9-]+$/.test(runnerName)) throw new Error("Invalid isolated operation runner identity.");
    let completed = false;
    for (let attempt = 0; attempt < 120; attempt += 1) {
      const runner = az(["container", "show", "--resource-group", n.group, "--name", runnerName]);
      const state = runner?.containers?.[0]?.instanceView?.currentState;
      if (state?.state === "Terminated") {
        if (state.exitCode !== 0) {
          const output = (dependencies.runner ?? runTool)("az", ["container", "logs", "--subscription", config.subscription,
            "--resource-group", n.group, "--name", runnerName, "--container-name", "operator", "--only-show-errors", "--output", "tsv"]);
          throw new Error(`Keyless container operation failed (${state.exitCode}): ${redact(output)}`);
        }
        completed = true;
        break;
      }
      if (runner?.provisioningState === "Failed") throw new Error("Keyless operation runner provisioning failed.");
      await (dependencies.sleep ?? delay)(10_000);
    }
    if (!completed) throw new Error("Keyless operation exceeded its bounded 20-minute wait; inspect the exact runner before retrying.");
    const output = (dependencies.runner ?? runTool)("az", ["container", "logs", "--subscription", config.subscription,
      "--resource-group", n.group, "--name", runnerName, "--container-name", "operator", "--only-show-errors", "--output", "tsv"]);
    const markers = output.split(/\r?\n/).filter((line) => line.startsWith("PHP2SHELL_RESULT "));
    if (markers.length !== 1) throw new Error("The exact keyless runner did not return one structured validation result.");
    try { runnerEvidence = JSON.parse(markers[0].slice("PHP2SHELL_RESULT ".length)); }
    catch { throw new Error("The keyless runner returned invalid structured validation evidence."); }
    completedRunner = runnerName;
  }
  if (config.command === "investigate") {
    const groupId = group.id.toLowerCase();
    const queries = {
      phpAssessments: `securityresources | where subscriptionId =~ '${config.subscription}' | where type in~ ('microsoft.security/assessments','microsoft.security/assessments/subassessments') | where tolower(id) startswith '${groupId}/' or tolower(tostring(properties.resourceDetails.id)) startswith '${groupId}/' or tolower(tostring(properties.resourceDetails.Id)) startswith '${groupId}/' | project id, Title=tostring(properties.displayName), Status=tostring(properties.status.code), Details=properties.additionalData`,
      recentAlerts: `securityresources | where subscriptionId =~ '${config.subscription}' | where type =~ 'microsoft.security/locations/alerts' | where todatetime(properties.TimeGeneratedUtc) >= ago(1d) | where tostring(properties) contains '${n.cluster}' or tostring(properties) contains '${n.registry}' | project id, Title=tostring(properties.AlertDisplayName), Status=tostring(properties.Status), Severity=tostring(properties.Severity), Generated=todatetime(properties.TimeGeneratedUtc), Entity=tostring(properties.CompromisedEntity)`,
    };
    const results = {};
    for (const [name, query] of Object.entries(queries)) {
      const rows = [];
      let token;
      let complete = false;
      for (let page = 0; page < 20; page += 1) {
        const args = ["graph", "query", "--subscriptions", config.subscription, "--graph-query", query, "--first", "100"];
        if (token) args.push("--skip-token", token);
        const result = az(args);
        if (!Array.isArray(result?.data)) throw new Error("Resource Graph did not return an evidence collection.");
        const total = result.total_records ?? result.totalRecords;
        if (!Number.isInteger(total) || total < 0) throw new Error("Resource Graph did not report valid evidence-count metadata.");
        rows.push(...result.data);
        token = result.skip_token ?? result.skipToken;
        if (token != null && (typeof token !== "string" || token.length === 0)) throw new Error("Resource Graph returned an invalid continuation token.");
        if (!token) {
          if (rows.length < total) throw new Error("Evidence is incomplete but Resource Graph supplied no continuation token.");
          complete = true;
          break;
        }
      }
      if (!complete) throw new Error("Evidence pagination exceeded 20 pages; no complete investigation is asserted.");
      results[name] = rows;
    }
    log(JSON.stringify(results, null, 2));
    log("Empty rows are not clearance; verify scan completion, sensor health, permissions, and supported coverage.");
    return results;
  }
  const cluster = az(["aks", "show", "--resource-group", n.group, "--name", n.cluster]);
  if (cluster?.provisioningState !== "Succeeded" || cluster.apiServerAccessProfile?.enablePrivateCluster !== true
      || cluster.apiServerAccessProfile.enablePrivateClusterPublicFQDN === true || cluster.disableLocalAccounts !== true
      || cluster.securityProfile?.defender?.securityMonitoring?.enabled !== true
      || cluster.agentPoolProfiles?.some((pool) => pool.enableNodePublicIP === true)) {
    throw new Error("Private cluster isolation or Defender monitoring is not verified.");
  }
  const variant = group.tags["dojo.containerState"];
  const health = runnerEvidence?.health;
  if (runnerEvidence?.evidenceKind !== "live-managed-identity-container-validation"
      || runnerEvidence.invocationId !== expectedInvocation || runnerEvidence.namespace !== n.namespace
      || runnerEvidence.isolationVerified !== true
      || health?.scenario !== "php2shell-container-lab" || health.environment !== "dev"
      || health.variant !== variant || health.sapi !== "apache2handler"
      || health.matchesExpectedRuntime !== true || health.phpVersion !== readContainerImages(ROOT)[variant].version) {
    throw new Error("The current managed-identity job did not verify the intended isolated Apache PHP runtime.");
  }
  const image = az(["acr", "repository", "show", "--name", n.registry, "--image", `php2shell:${health.phpVersion}`]);
  if (!/^sha256:[a-f0-9]{64}$/.test(image?.digest ?? "")
      || runnerEvidence.image !== `${n.registry}.azurecr.io/php2shell@${image.digest}`) {
    throw new Error("The verified ready pod and independently read immutable ACR image do not match.");
  }
  const sensors = runnerEvidence.sensorDaemonsets;
  if (!Array.isArray(sensors) || !sensors.length || sensors.some((item) =>
    typeof item.name !== "string" || !item.name.includes("defender")
    || !Number.isInteger(item.desired) || item.desired < 1 || item.ready !== item.desired)) {
    throw new Error("The actual Defender sensor daemonsets are not ready; no runtime coverage is asserted.");
  }
  if (config.command === "test-detection" && (typeof runnerEvidence.telemetryIdentity !== "string"
      || !runnerEvidence.telemetryIdentity.startsWith("uid=10001"))) throw new Error("The bounded read-only identity test was not verified.");
  if (!completedRunner) throw new Error("No completed owned validation runner was recorded.");
  az(["container", "delete", "--resource-group", n.group, "--name", completedRunner, "--yes"]);
  const result = { resourceGroup: n.group, ...runnerEvidence,
    alerts: "not inferred from configuration or version evidence" };
  log(JSON.stringify(result, null, 2));
  return result;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try { await executeContainerLab(containerConfig(process.argv.slice(2))); }
  catch (error) { console.error(`Container lab failed: ${redact(error.message)}`); process.exitCode = 1; }
}
