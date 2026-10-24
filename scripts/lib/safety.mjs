import { SCENARIO, UUID, names } from "./config.mjs";
import { validateDomain } from "../../vendor/pawprint/scripts/cloudflare-dns.mjs";

export function redact(value) {
  return String(value)
    .replace(/\bBearer\s+\S+/gi, "Bearer [REDACTED]")
    .replace(/\beyJ[\w-]+\.[\w-]+\.[\w-]+\b/g, "[REDACTED]")
    .replace(/(["']?(?:password|(?:client[_-]?)?secret|(?:access[_-]?)?token|accountkey|connectionstring|authorization|sig)["']?\s*[:=]\s*)("(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*')/gi, '$1"[REDACTED]"')
    .replace(/((?:password|(?:client[_-]?)?secret|(?:access[_-]?)?token|accountkey|connectionstring|sig)\s*[:=]\s*)[^&;\r\n]+/gi, "$1[REDACTED]");
}

export function sameId(actual, expected) {
  return typeof actual === "string" && typeof expected === "string"
    && actual.toLowerCase() === expected.toLowerCase();
}

export function assertOwnedGroup(group, config) {
  const expected = names(config);
  if (!group || !sameId(group.name, expected.group) || !sameId(group.id, expected.groupId)
      || group.tags?.["dojo.scenario"] !== SCENARIO
      || group.tags?.["dojo.suffix"] !== config.suffix
      || group.tags?.["pawprint.managed"] !== "true"
      || group.tags?.["pawprint.environment"] !== "dev") {
    throw new Error("Resource group identity/ownership does not match this exact dev scenario; refusing to continue.");
  }
  if (group.location?.toLowerCase() !== config.location) throw new Error("Existing resource-group location differs; refusing relocation.");
  for (const key of ["pawprint.startedAt", "pawprint.expiresAt"]) {
    if (!Number.isFinite(Date.parse(group.tags[key]))) throw new Error(`Invalid ownership metadata: ${key}.`);
  }
  if (!/^(?:[1-9]|[1-6][0-9]|7[0-2])$/.test(group.tags["pawprint.ttlHours"] ?? "")) {
    throw new Error("Invalid persisted expiry lifetime.");
  }
  if (!["training", "fixed"].includes(group.tags["dojo.state"])
      || !["Detection", "Prevention"].includes(group.tags["dojo.wafMode"])) {
    throw new Error("Invalid persisted lab state; manual review is required.");
  }
  for (const key of ["dojo.defenderCspmExpected", "dojo.sentinel", "dojo.analytics"]) {
    if (!["true", "false"].includes(group.tags[key])) throw new Error(`Invalid persisted opt-in: ${key}.`);
  }
  const domain = group.tags["dojo.customDomain"] ?? "";
  const domainReady = group.tags["dojo.customDomainReady"];
  if ((domain && validateDomain(domain) !== domain)
      || (domainReady !== undefined && !["true", "false"].includes(domainReady))
      || (domainReady === "true" && !domain)) {
    throw new Error("Invalid persisted custom-domain ownership metadata.");
  }
  return group;
}

export function desiredState(config, group, now = new Date()) {
  if (group) assertOwnedGroup(group, config);
  if (["repair", "protect", "remediate"].includes(config.command) && !group) {
    throw new Error(`${config.command} requires an existing, owned lab resource group.`);
  }
  const tags = group?.tags;
  const fixed = config.command === "remediate" || tags?.["dojo.state"] === "fixed";
  const previousMode = tags?.["dojo.wafMode"];
  const wafMode = ["protect", "remediate"].includes(config.command) || fixed
    ? "Prevention" : config.wafMode ?? previousMode ?? "Detection";
  if (config.wafMode === "Detection" && (fixed || previousMode === "Prevention")) {
    throw new Error("Downgrading a protected/remediated lab to Detection is not supported; use a new isolated resource group and suffix.");
  }
  const sentinel = config.enableSentinel || tags?.["dojo.sentinel"] === "true";
  const analytics = config.enableAnalytics || tags?.["dojo.analytics"] === "true";
  if (analytics && !sentinel) throw new Error("Analytics opt-in requires Sentinel opt-in.");
  return {
    labState: fixed ? "fixed" : "training",
    wafMode,
    startedAt: tags?.["pawprint.startedAt"] ?? now.toISOString(),
    expiresAt: tags?.["pawprint.expiresAt"] ?? new Date(now.valueOf() + config.ttlHours * 3_600_000).toISOString(),
    ttlHours: tags ? Number(tags["pawprint.ttlHours"]) : config.ttlHours,
    defenderCspmExpected: config.enableDefenderCspm || tags?.["dojo.defenderCspmExpected"] === "true",
    enableSentinel: sentinel,
    enableAnalytics: analytics,
    customDomainName: tags?.["dojo.customDomain"] ?? "",
    associateCustomDomain: tags?.["dojo.customDomainReady"] === "true",
  };
}

export function assertResource(resource, expectedId) {
  if (!sameId(resource?.id, expectedId)) throw new Error("Live Azure resource identity does not match the expected scenario resource.");
  return resource;
}

export function assertEndpointHost(host, endpointName) {
  if (typeof host !== "string" || host !== host.toLowerCase()
      || !/^[a-z0-9-]+(?:\.[a-z0-9-]+)*\.azurefd\.net$/.test(host)
      || !(host.split(".")[0] === endpointName || host.startsWith(`${endpointName}-`))) {
    throw new Error("Invalid live Front Door hostname; arbitrary simulation targets are forbidden.");
  }
  return `https://${host}`;
}

export function assertOriginHost(host, appName) {
  if (typeof host !== "string"
      || !/^[a-z0-9-]+(?:\.[a-z0-9-]+)*\.azurewebsites\.net$/.test(host)
      || !(host.split(".")[0] === appName || host.startsWith(`${appName}-`))) {
    throw new Error("Invalid live App Service origin hostname.");
  }
  return `https://${host}`;
}

export function assertOriginRestrictions(webConfig, frontDoorId) {
  const rules = webConfig?.ipSecurityRestrictions;
  const allowed = rules?.filter((rule) => rule.action === "Allow");
  if (!UUID.test(frontDoorId) || webConfig?.ipSecurityRestrictionsDefaultAction !== "Deny"
      || allowed?.length !== 1
      || allowed[0].ipAddress !== "AzureFrontDoor.Backend"
      || allowed[0].tag !== "ServiceTag"
      || allowed[0].headers?.["x-azure-fdid"]?.length !== 1
      || allowed[0].headers["x-azure-fdid"][0] !== frontDoorId) {
    throw new Error("Origin must deny by default and allow only this Front Door service-tag/profile-header pair.");
  }
}

export function assertWhatIf(result, config) {
  if (!Array.isArray(result?.changes) || result.status !== "Succeeded") throw new Error("What-if did not return a successful, complete change list.");
  const groupId = names(config).groupId.toLowerCase();
  const pricingId = `/subscriptions/${config.subscription}/providers/Microsoft.Security/pricings/CloudPosture`.toLowerCase();
  for (const change of result.changes) {
    const id = String(change.resourceId ?? "").toLowerCase();
    const inGroup = id === groupId || id.startsWith(`${groupId}/`);
    if (!inGroup && !(config.enableDefenderCspm && id === pricingId)) {
      throw new Error("What-if contains a change outside the scenario boundary.");
    }
    if (!["Create", "Modify", "NoChange", "Deploy"].includes(change.changeType)) {
      throw new Error(`What-if contains an unsafe or unevaluated change: ${change.changeType}.`);
    }
  }
}

export function hasPermission(permissions, action) {
  const matches = (pattern) => {
    const expression = pattern.replace(/[.+?^${}()|[\]\\]/g, "\\$&").replaceAll("*", ".*");
    return new RegExp(`^${expression}$`, "i").test(action);
  };
  return permissions.some((permission) =>
    permission.actions?.some(matches) && !permission.notActions?.some(matches));
}

export async function request(url, { headers = {}, fetchImpl = fetch } = {}) {
  const response = await fetchImpl(url, {
    method: "GET", headers, redirect: "manual", signal: AbortSignal.timeout(15_000),
  });
  if (response.status >= 300 && response.status < 400) {
    await response.body?.cancel();
    throw new Error("Redirects are forbidden during lab validation and simulation.");
  }
  const reader = response.body?.getReader();
  const chunks = [];
  let size = 0;
  if (reader) {
    try {
      while (true) {
        const { value, done } = await reader.read();
        if (done) break;
        size += value.byteLength;
        if (size > 65_536) throw new Error("Lab response exceeded the 64 KiB safety limit.");
        chunks.push(value);
      }
    } finally {
      await reader.cancel();
    }
  }
  return { status: response.status, text: Buffer.concat(chunks).toString("utf8") };
}
