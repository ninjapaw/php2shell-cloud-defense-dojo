import { parseArgs } from "node:util";
import { validateDomain } from "../../vendor/pawprint/scripts/cloudflare-dns.mjs";

export const SCENARIO = "php2shell-cloud-defense-dojo";
export const SENTINEL_RULE_DISPLAY_NAME = "PHP to Proof - SYNTHETIC multi-signal training correlation";
export const COMMANDS = [
  "plan", "doctor", "deploy", "validate", "simulate", "investigate",
  "protect", "remediate", "repair", "uninstall", "domain", "domain-check",
];
export const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export function parseConfigJson(text) {
  try {
    return validateConfig(JSON.parse(text));
  } catch (error) {
    if (error instanceof SyntaxError) throw new Error("Invalid dev configuration JSON; contents omitted to protect accidental secrets.");
    throw error;
  }
}

export function validateConfig(config) {
  const keys = ["environment", "resourceGroup", "location", "ttlHours", "phpVersion", "customDomain"];
  if (!config || typeof config !== "object" || Array.isArray(config)
      || Object.keys(config).some((key) => !keys.includes(key))) {
    throw new Error("Configuration must be an object containing only the documented dev settings.");
  }
  if (config.environment !== "dev") throw new Error("Only the dev training environment is supported.");
  if (typeof config.resourceGroup !== "string" || config.resourceGroup !== config.resourceGroup.trim()
      || !/^[A-Za-z0-9][A-Za-z0-9_.()-]{0,89}$/.test(config.resourceGroup)
      || config.resourceGroup.endsWith(".")) {
    throw new Error("resourceGroup must be a 1-90 character Azure group name starting with a letter/digit, containing only letters, digits, underscores, periods, parentheses or hyphens, and not ending in a period.");
  }
  if (typeof config.location !== "string" || !/^[a-z][a-z0-9]{2,31}$/.test(config.location)) {
    throw new Error("location must be an Azure region identifier.");
  }
  if (!Number.isInteger(config.ttlHours) || config.ttlHours < 1 || config.ttlHours > 72) {
    throw new Error("ttlHours must be an integer from 1 to 72.");
  }
  if (!["8.4", "8.5"].includes(config.phpVersion)) throw new Error("Unsupported PHP training stack.");
  const customDomain = config.customDomain === undefined || config.customDomain === "" ? "" : validateDomain(config.customDomain);
  return { ...config, customDomain };
}

export function parseInvocation(args, config, environment = process.env) {
  const { values, positionals } = parseArgs({
    args,
    allowPositionals: true,
    options: {
      environment: { type: "string", default: "dev" },
      suffix: { type: "string" },
      subscription: { type: "string" },
      location: { type: "string" },
      "custom-domain": { type: "string" },
      "waf-mode": { type: "string" },
      "enable-defender-cspm": { type: "boolean", default: false },
      "enable-sentinel": { type: "boolean", default: false },
      "enable-analytics": { type: "boolean", default: false },
      "confirm-resource-group": { type: "string" },
      yes: { type: "boolean", default: false },
      help: { type: "boolean", default: false },
    },
  });
  if (values.environment !== "dev") throw new Error("Only --environment dev is permitted; no production override exists.");
  const settings = validateConfig({ ...config, location: values.location ?? config.location });
  if (values.help) return { help: true };
  if (positionals.length !== 1 || !COMMANDS.includes(positionals[0])) {
    throw new Error(`Supply exactly one command: ${COMMANDS.join(", ")}.`);
  }
  const suffix = values.suffix ?? environment.DOJO_SUFFIX;
  if (typeof suffix !== "string" || !/^[a-z0-9]{4,12}$/.test(suffix)) {
    throw new Error("--suffix (or DOJO_SUFFIX) must contain 4-12 lowercase letters/digits.");
  }
  const subscription = values.subscription ?? environment.AZURE_SUBSCRIPTION_ID;
  if (subscription !== undefined && !UUID.test(subscription)) throw new Error("Invalid subscription UUID.");
  if (positionals[0] !== "plan" && !subscription) throw new Error("Azure commands require an explicit subscription UUID.");
  if (values["waf-mode"] !== undefined && !["Detection", "Prevention"].includes(values["waf-mode"])) {
    throw new Error("--waf-mode must be Detection or Prevention.");
  }
  const command = positionals[0];
  if (values["custom-domain"] !== undefined && !["plan", "domain", "domain-check"].includes(command)) {
    throw new Error("--custom-domain applies only to plan, domain, or domain-check; simulation targets cannot be overridden.");
  }
  const configuredDomain = values["custom-domain"] ?? environment.DOJO_CUSTOM_DOMAIN ?? settings.customDomain;
  const customDomain = configuredDomain === "" ? "" : validateDomain(configuredDomain);
  if (values["waf-mode"] && !["plan", "doctor", "deploy", "repair"].includes(command)) {
    throw new Error("--waf-mode applies only to plan, doctor, deploy or repair. protect/remediate explicitly enforce Prevention.");
  }
  if ((values["enable-defender-cspm"] || values["enable-sentinel"] || values["enable-analytics"])
      && !["plan", "doctor", "deploy", "repair", "protect", "remediate"].includes(command)) {
    throw new Error("Billable deployment opt-ins do not apply to this read/simulation/teardown command.");
  }
  if (values["confirm-resource-group"] !== undefined && command !== "uninstall") {
    throw new Error("--confirm-resource-group applies only to uninstall.");
  }
  return {
    ...settings,
    command,
    customDomain,
    suffix,
    subscription,
    wafMode: values["waf-mode"],
    enableDefenderCspm: values["enable-defender-cspm"],
    enableSentinel: values["enable-sentinel"],
    enableAnalytics: values["enable-analytics"],
    confirmation: values["confirm-resource-group"],
    yes: values.yes,
  };
}

export function names(config) {
  const base = `p2s-${config.suffix}`;
  const group = config.resourceGroup;
  const groupId = config.subscription ? `/subscriptions/${config.subscription}/resourceGroups/${group}` : undefined;
  return {
    group, groupId,
    app: `${base}-app`,
    plan: `${base}-plan`,
    profile: `${base}-edge`,
    endpoint: `${base}-entry`,
    policy: `p2s${config.suffix}waf`,
    workspace: `${base}-logs`,
    deployment: `php2shell-${config.suffix}-dev`,
    appId: groupId && `${groupId}/providers/Microsoft.Web/sites/${base}-app`,
    profileId: groupId && `${groupId}/providers/Microsoft.Cdn/profiles/${base}-edge`,
    endpointId: groupId && `${groupId}/providers/Microsoft.Cdn/profiles/${base}-edge/afdEndpoints/${base}-entry`,
    policyId: groupId && `${groupId}/providers/Microsoft.Network/frontDoorWebApplicationFirewallPolicies/p2s${config.suffix}waf`,
    customDomainId: groupId && `${groupId}/providers/Microsoft.Cdn/profiles/${base}-edge/customDomains/application-domain`,
    planId: groupId && `${groupId}/providers/Microsoft.Web/serverfarms/${base}-plan`,
    workspaceId: groupId && `${groupId}/providers/Microsoft.OperationalInsights/workspaces/${base}-logs`,
  };
}
