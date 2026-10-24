import { lstatSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { gzipSync } from "node:zlib";
import { execute, ROOT } from "./dojo.mjs";
import { parseConfigJson, parseInvocation } from "./lib/config.mjs";
import { createAzureClient } from "./lib/azure.mjs";
import { redact, sameId } from "./lib/safety.mjs";

export const CLOUD_CONTEXT_FILES = [
  "package.json", "bicepconfig.json", "config/dev.json",
  "app/index.php", "app/walkthrough.php", "app/health.php", "app/lab.php", "app/assets/style.css", "app/conf.d/dojo.ini",
  "scripts/dojo.mjs", "scripts/cloud-runner.mjs", "scripts/cloud-deploy.sh",
  "scripts/lib/config.mjs", "scripts/lib/azure.mjs", "scripts/lib/safety.mjs",
  "infra/main.bicep", "infra/resources.bicep", "infra/modules/sentinel.bicep", "infra/modules/defender-cspm.bicep",
  "detections/correlation.kql",
  "vendor/pawprint/LICENSE", "vendor/pawprint/bicepconfig.json", "vendor/pawprint/modules/types.bicep",
  "vendor/pawprint/modules/php-web-app/main.bicep", "vendor/pawprint/modules/monitoring/main.bicep",
  "vendor/pawprint/modules/front-door-waf/profile.bicep", "vendor/pawprint/modules/front-door-waf/main.bicep",
  "vendor/pawprint/scripts/cloudflare-dns.mjs",
];
const OPERATIONS = ["doctor", "deploy", "validate"];

export function assertCloudJobTemplate(template, root = ROOT) {
  if (!template || typeof template !== "object" || Array.isArray(template)) throw new Error("Compiled cloud job must be an ARM template object.");
  const resources = Object.values(template.resources ?? {});
  const resource = resources[0];
  const container = resource?.properties?.containers?.[0]?.properties;
  if (template.parameters?.sourceBundle?.type !== "secureObject" || resources.length !== 1
      || resource?.type !== "Microsoft.ContainerInstance/containerGroups" || resource.properties?.ipAddress
      || resource.properties?.restartPolicy !== "Never" || resource.properties?.containers?.length !== 1
      || container?.image !== "mcr.microsoft.com/azure-cli@sha256:b23e5168ce9654b1385c565a2c6cf60695f7b0d03056f7a0fafdc7c59a084512"
      || container.resources?.requests?.cpu !== 1 || container.resources?.requests?.memoryInGB !== 2
      || !container.command?.[2]?.includes("timeout=5400")) {
    throw new Error("Cloud job must be one bounded, outbound-only, digest-pinned container with protected source inputs.");
  }
  const script = readFileSync(join(root, "scripts", "cloud-deploy.sh"), "utf8");
  if (!Object.values(template.variables ?? {}).includes(script) && !container.command.includes(script)) {
    throw new Error("Compiled startup differs from current source; rebuild with a fresh compiler, not a stale cached artifact.");
  }
  const sourceCopy = template.variables?.copy?.find((entry) => entry.name === "sourceVariables");
  if (sourceCopy?.input?.secureValue !== "[parameters('sourceBundle').chunks[copyIndex('sourceVariables')]]"
      || sourceCopy.input.value !== undefined) {
    throw new Error("Compiled source chunks must use only secure environment values.");
  }
}

export function assertRunnerCleanupTargets(stack, expected) {
  const { subscription, resourceGroup, helperGroup, invocationId } = expected;
  const subscriptionId = `/subscriptions/${subscription}`;
  const mainId = `${subscriptionId}/resourceGroups/${resourceGroup}`;
  const helperId = `${subscriptionId}/resourceGroups/${helperGroup}`;
  const roles = [
    [expected.metadataRoleId, `${subscriptionId}/providers/Microsoft.Authorization/roleDefinitions/`],
    [expected.metadataRoleAssignmentId, `${subscriptionId}/providers/Microsoft.Authorization/roleAssignments/`],
    [expected.workloadRoleAssignmentId, `${mainId}/providers/Microsoft.Authorization/roleAssignments/`],
  ];
  if (sameId(mainId, helperId) || stack.tags?.["dojo.invocationId"] !== invocationId
      || stack.tags?.["dojo.scenario"] !== "php2proof-deployment-runner"
      || !Array.isArray(stack.properties?.resources)
      || roles.some(([id, prefix]) => typeof id !== "string" || !id.toLowerCase().startsWith(prefix.toLowerCase())
        || !/^[0-9a-f-]{36}$/i.test(id.slice(prefix.length)))) {
    throw new Error("Runner cleanup ownership and exact role IDs must be independently verified.");
  }
  for (const resource of stack.properties.resources) {
    const id = resource.id;
    if (sameId(id, mainId) || !(sameId(id, helperId)
        || (typeof id === "string" && id.toLowerCase().startsWith(`${helperId.toLowerCase()}/`))
        || roles.some(([roleId]) => sameId(id, roleId)))) {
      throw new Error("Runner cleanup contains a resource outside this invocation's helper group and exact temporary roles.");
    }
  }
}

export function cloudContext(root = ROOT) {
  const files = Object.fromEntries(CLOUD_CONTEXT_FILES.map((path) => {
    const absolute = join(root, path);
    if (!lstatSync(absolute).isFile()) throw new Error(`Cloud context must contain only regular allowlisted files: ${path}.`);
    const bytes = readFileSync(absolute);
    const text = bytes.toString("utf8");
    if (!Buffer.from(text, "utf8").equals(bytes)) throw new Error(`Cloud context source is not lossless UTF-8: ${path}.`);
    return [path, text];
  }));
  const content = gzipSync(JSON.stringify({ schemaVersion: 2, files }), { level: 9 });
  const encoded = content.toString("base64");
  if (encoded.length > 60 * 1024) throw new Error("Cloud source exceeds the protected-input budget; do not silently truncate it.");
  const chunks = Array.from({ length: Math.ceil(encoded.length / 8000) }, (_, index) => encoded.slice(index * 8000, (index + 1) * 8000));
  return { content, sha256: createHash("sha256").update(content).digest("hex"), sourceBundle: { chunks } };
}

export function writeCloudReport(config, report, az = createAzureClient(config)) {
  const directory = mkdtempSync(join(tmpdir(), "php2proof-report-"));
  const templatePath = join(directory, "report.json");
  const template = {
    $schema: "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
    contentVersion: "1.0.0.0",
    parameters: { report: { type: "object" } },
    resources: [],
    outputs: { result: { type: "object", value: "[parameters('report')]" } },
  };
  try {
    writeFileSync(templatePath, JSON.stringify(template));
    const args = [
      "--resource-group", config.resourceGroup, "--name", `php2proof-cloud-${config.command}-${config.suffix}`,
      "--template-file", templatePath, "--parameters", JSON.stringify({ report: { value: report } }),
    ];
    const preview = az(["deployment", "group", "what-if", ...args, "--result-format", "FullResourcePayloads"]);
    if (preview?.status !== "Succeeded" || !Array.isArray(preview.changes)
        || preview.changes.some((change) => !["Ignore", "NoChange"].includes(change.changeType))) {
      throw new Error("The output-only report preview unexpectedly contains resource changes.");
    }
    const deployment = az(["deployment", "group", "create", ...args, "--mode", "Incremental"]);
    if (deployment?.properties?.provisioningState !== "Succeeded") throw new Error("Cloud operation report was not persisted successfully.");
  } finally {
    rmSync(directory, { recursive: true });
  }
}

export async function runCloudOperation(config, dependencies = {}) {
  if (!OPERATIONS.includes(config.command)) throw new Error("Cloud runner accepts only doctor, deploy, or validate.");
  const persist = dependencies.persist ?? writeCloudReport;
  let result;
  try {
    result = await (dependencies.execute ?? execute)(config);
    if (config.command === "doctor" ? result?.preflight !== "passed" : result?.validated !== true) {
      throw new Error("The guarded lifecycle did not return the required verified result.");
    }
  } catch (error) {
    const message = redact(error.message).slice(0, 1600);
    try {
      persist(config, { status: "failed", operation: config.command, timestamp: new Date().toISOString(), error: message });
    } catch (reportError) {
      throw new Error(`Cloud operation failed: ${message}. Report also failed: ${redact(reportError.message)}`);
    }
    throw error;
  }
  const report = { status: "succeeded", operation: config.command, timestamp: new Date().toISOString(), result };
  persist(config, report);
  return report;
}

async function main(args) {
  if (args[0] === "verify-template" && args.length === 2) {
    assertCloudJobTemplate(JSON.parse(readFileSync(args[1], "utf8")));
    console.log("Verified bounded cloud job, protected inputs, and exact startup source.");
    return;
  }
  if (args[0] === "bundle" && args.length === 2) {
    const bundle = cloudContext();
    writeFileSync(args[1], bundle.content, { flag: "wx" });
    console.log(JSON.stringify({ path: resolve(args[1]), sha256: bundle.sha256, files: CLOUD_CONTEXT_FILES.length }));
    return;
  }
  if (args[0] !== "run" || args.length !== 1) throw new Error("Use cloud-runner.mjs bundle <new-output-file>, verify-template <compiled-job>, or run.");
  const operation = process.env.DOJO_CLOUD_OPERATION;
  if (!OPERATIONS.includes(operation)) throw new Error("Unsupported cloud operation.");
  const config = parseInvocation([
    operation, "--suffix", process.env.DOJO_SUFFIX, "--subscription", process.env.AZURE_SUBSCRIPTION_ID,
    ...(operation === "deploy" ? ["--yes"] : []),
  ], parseConfigJson(readFileSync(join(ROOT, "config", "dev.json"), "utf8")), {});
  if (config.resourceGroup !== process.env.DOJO_CLOUD_GROUP) throw new Error("Cloud runner group must exactly match the checked-in dev configuration.");
  console.log(JSON.stringify(await runCloudOperation(config), null, 2));
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  main(process.argv.slice(2)).catch((error) => {
    console.error(`ERROR: ${redact(error.message)}`);
    process.exitCode = 1;
  });
}
