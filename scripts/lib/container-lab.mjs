import { readFileSync } from "node:fs";
import { join } from "node:path";
import { parseArgs } from "node:util";
import { UUID } from "./config.mjs";

export const CONTAINER_SCENARIO = "php2shell-container-lab";
export const CONTAINER_NAMESPACE = "php2shell-isolated";
export const CONTAINER_COMMANDS = ["plan", "deploy", "validate", "test-detection", "remediate", "investigate", "uninstall"];

export function containerConfig(args, environment = process.env) {
  const { values, positionals } = parseArgs({
    args, allowPositionals: true,
    options: {
      environment: { type: "string", default: "dev" },
      subscription: { type: "string" },
      suffix: { type: "string" },
      location: { type: "string", default: "centralus" },
      yes: { type: "boolean", default: false },
      "confirm-resource-group": { type: "string" },
    },
  });
  if (values.environment !== "dev") throw new Error("Only the dev container lab is permitted.");
  if (positionals.length !== 1 || !CONTAINER_COMMANDS.includes(positionals[0])) throw new Error("Supply one supported container-lab command.");
  const subscription = values.subscription ?? environment.AZURE_SUBSCRIPTION_ID;
  if (subscription !== undefined && !UUID.test(subscription)) throw new Error("Invalid subscription UUID.");
  if (positionals[0] !== "plan" && !subscription) throw new Error("An explicit subscription UUID is required.");
  const suffix = values.suffix ?? environment.DOJO_SUFFIX;
  if (!/^[a-z0-9]{4,12}$/.test(suffix ?? "")) throw new Error("The lab suffix must contain 4-12 lowercase letters/digits.");
  if (!/^[a-z][a-z0-9]{2,31}$/.test(values.location)) throw new Error("Invalid Azure region.");
  if (values["confirm-resource-group"] !== undefined && positionals[0] !== "uninstall") throw new Error("Confirmation is only accepted for uninstall.");
  return { command: positionals[0], subscription, suffix, location: values.location, yes: values.yes, confirmation: values["confirm-resource-group"] };
}

export function containerNames(config) {
  const group = `rg-p2sc-${config.suffix}-dev`;
  const base = `p2sc-${config.suffix}`;
  return { group, base, cluster: `${base}-aks`, registry: `p2sc${config.suffix}`, workspace: `${base}-logs`, identity: `${base}-operator`, nodes: `${base}-nodes-dev`, namespace: CONTAINER_NAMESPACE };
}

export function containerTags(config, now = new Date()) {
  return {
    "pawprint.managed": "true", "pawprint.environment": "dev",
    "pawprint.expiresAt": new Date(now.getTime() + 24 * 60 * 60 * 1000).toISOString(),
    "dojo.scenario": CONTAINER_SCENARIO, "dojo.suffix": config.suffix,
    "dojo.repository": "ninjapaw/php2shell-cloud-defense-dojo", "dojo.containerState": "vulnerable",
  };
}

export function assertContainerGroup(group, config) {
  const expected = `/subscriptions/${config.subscription}/resourceGroups/${containerNames(config).group}`.toLowerCase();
  if (group?.id?.toLowerCase() !== expected
      || group.location?.toLowerCase() !== config.location
      || group.tags?.["dojo.scenario"] !== CONTAINER_SCENARIO
      || group.tags?.["dojo.suffix"] !== config.suffix
      || group.tags?.["dojo.repository"] !== "ninjapaw/php2shell-cloud-defense-dojo"
      || group.tags?.["pawprint.environment"] !== "dev"
      || group.tags?.["pawprint.managed"] !== "true"
      || !["vulnerable", "fixed"].includes(group.tags?.["dojo.containerState"])
      || !Number.isFinite(Date.parse(group.tags?.["pawprint.expiresAt"]))) {
    throw new Error("The exact dev container resource group and ownership tags must match; foreign resources are not adopted.");
  }
  return group;
}

export function assertContainerIsolation(namespace, policy, services, pod) {
  const security = pod?.spec?.securityContext;
  const container = pod?.spec?.containers?.[0];
  const protection = container?.securityContext;
  if (namespace?.metadata?.labels?.["pod-security.kubernetes.io/enforce"] !== "restricted"
      || namespace.metadata.name !== CONTAINER_NAMESPACE
      || policy?.metadata?.namespace !== CONTAINER_NAMESPACE
      || policy.metadata.name !== "deny-all"
      || Object.keys(policy.spec?.podSelector ?? { invalid: true }).length !== 0
      || policy.spec?.policyTypes?.length !== 2
      || !["Ingress", "Egress"].every((direction) => policy.spec.policyTypes.includes(direction))
      || (policy.spec.ingress?.length ?? 0) !== 0 || (policy.spec.egress?.length ?? 0) !== 0
      || !Array.isArray(services?.items) || services.items.length !== 0
      || pod?.spec?.automountServiceAccountToken !== false
      || pod.spec.hostNetwork === true || pod.spec.hostPID === true || pod.spec.hostIPC === true
      || pod.spec.containers.length !== 1
      || (pod.spec.initContainers?.length ?? 0) !== 0
      || pod.spec.volumes?.some((volume) => volume.hostPath || volume.secret || volume.projected)
      || security?.runAsNonRoot !== true || security.runAsUser !== 10001
      || security.seccompProfile?.type !== "RuntimeDefault"
      || protection?.allowPrivilegeEscalation !== false || protection.privileged !== false
      || protection.readOnlyRootFilesystem !== true
      || protection.capabilities?.drop?.length !== 1 || protection.capabilities.drop[0] !== "ALL"
      || (protection.capabilities.add?.length ?? 0) !== 0) {
    throw new Error("Actual namespace, network isolation, workload token, or pod privilege differs from the reviewed container boundary.");
  }
}

export function readContainerImages(root) {
  const images = JSON.parse(readFileSync(join(root, "container-lab", "images.json"), "utf8"));
  for (const variant of ["vulnerable", "fixed"]) {
    const version = variant === "vulnerable" ? "8.4.26" : "8.4.27";
    if (images[variant]?.version !== version || !/^docker\.io\/library\/php@sha256:[a-f0-9]{64}$/.test(images[variant]?.source ?? "")) {
      throw new Error("Container comparisons require the reviewed official PHP versions and immutable source digests.");
    }
  }
  return images;
}

export function containerWorkload(registry, digest, variant) {
  if (!/^[a-z0-9]{5,50}\.azurecr\.io$/.test(registry) || !/^sha256:[a-f0-9]{64}$/.test(digest) || !["vulnerable", "fixed"].includes(variant)) {
    throw new Error("The workload requires an independently read ACR host, immutable digest, and supported comparison state.");
  }
  const labels = { app: CONTAINER_SCENARIO };
  return {
    apiVersion: "v1", kind: "List",
    items: [
      { apiVersion: "v1", kind: "Namespace", metadata: { name: CONTAINER_NAMESPACE, labels: {
        "pod-security.kubernetes.io/enforce": "restricted",
        "pod-security.kubernetes.io/audit": "restricted",
        "pod-security.kubernetes.io/warn": "restricted",
        "dojo.scenario": CONTAINER_SCENARIO,
      } } },
      { apiVersion: "networking.k8s.io/v1", kind: "NetworkPolicy", metadata: { name: "deny-all", namespace: CONTAINER_NAMESPACE },
        spec: { podSelector: {}, policyTypes: ["Ingress", "Egress"], ingress: [], egress: [] } },
      { apiVersion: "v1", kind: "ResourceQuota", metadata: { name: "lab-bounds", namespace: CONTAINER_NAMESPACE },
        spec: { hard: { pods: "4", "requests.cpu": "1", "requests.memory": "1Gi", "limits.cpu": "2", "limits.memory": "2Gi", services: "0", persistentvolumeclaims: "0" } } },
      { apiVersion: "apps/v1", kind: "Deployment", metadata: { name: "php-runtime", namespace: CONTAINER_NAMESPACE },
        spec: { replicas: 1, revisionHistoryLimit: 1, selector: { matchLabels: labels }, template: {
          metadata: { labels, annotations: { "dojo.variant": variant } },
          spec: {
            automountServiceAccountToken: false, terminationGracePeriodSeconds: 10,
            securityContext: { runAsNonRoot: true, runAsUser: 10001, runAsGroup: 10001, fsGroup: 10001, seccompProfile: { type: "RuntimeDefault" } },
            containers: [{
              name: "php", image: `${registry}/php2shell@${digest}`, imagePullPolicy: "Always",
              ports: [{ containerPort: 8080 }],
              resources: { requests: { cpu: "100m", memory: "128Mi" }, limits: { cpu: "500m", memory: "384Mi" } },
              securityContext: { allowPrivilegeEscalation: false, privileged: false, readOnlyRootFilesystem: true, capabilities: { drop: ["ALL"] } },
              volumeMounts: [{ name: "temporary", mountPath: "/tmp" }],
              readinessProbe: { httpGet: { path: "/health.php", port: 8080 }, initialDelaySeconds: 5, periodSeconds: 10 },
              livenessProbe: { httpGet: { path: "/health.php", port: 8080 }, initialDelaySeconds: 15, periodSeconds: 20 },
            }],
            volumes: [{ name: "temporary", emptyDir: { medium: "Memory", sizeLimit: "64Mi" } }],
          },
        } } },
    ],
  };
}
