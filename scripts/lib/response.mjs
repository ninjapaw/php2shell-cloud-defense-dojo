import { createHash, randomUUID } from "node:crypto";
import { setTimeout as delay } from "node:timers/promises";
import { SCENARIO, UUID } from "./config.mjs";
import { assertEndpointHost, assertOriginHost, assertOriginRestrictions, assertOwnedGroup, assertResource, redact, request, sameId } from "./safety.mjs";

export const RESPONSE_GUIDANCE = Object.freeze({
  reviewedAt: "2026-10-24",
  updatedAt: "2026-10-22",
  response: "https://techcommunity.microsoft.com/blog/azurenetworksecurityblog/addressing-php2shell-cve-2026-109618-and-cve-2026-109619-upgrade-guidance-and-az/4566623",
  customRules: "https://techcommunity.microsoft.com/blog/azurenetworksecurityblog/azure-waf-custom-rules-for-php2shell-mitigation/4566684",
  php: "https://www.php.net/releases/8_4_27.php",
  managedRules: "https://learn.microsoft.com/en-us/rest/api/frontdoorservice/webapplicationfirewall/managed-rule-sets/list?view=rest-frontdoorservice-webapplicationfirewall-2025-03-01",
  fixed: { "8.2": 35, "8.3": 36, "8.4": 27, "8.5": 12 },
  responseGroup: "MS-ThreatIntel-Response-CVEs",
  responseRule: "99006001",
  rolloutExpectedBy: "2026-10-28",
});
export const RESPONSE_API = Object.freeze({ group: "2025-04-01", web: "2025-03-01", waf: "2025-03-01", cdn: "2025-04-15", tags: "2021-04-01" });
export const RESPONSE_ACTIONS = Object.freeze([
  { id: "plan", title: "Preview the exact owned-lab response plan", writes: false },
  { id: "prevention", title: "Enable WAF Prevention; retain existing rules", writes: true },
  { id: "session-log", title: "Stage session-upload-progress rule in Log", writes: true },
  { id: "session-block", title: "Enforce the reviewed session-upload-progress rule", writes: true },
  { id: "form-log", title: "Stage URL-encoded nesting policy in Log", writes: true },
  { id: "form-block", title: "Enforce the reviewed URL-encoded nesting policy", writes: true },
  { id: "multipart-log", title: "Stage multipart nesting policy in Log", writes: true },
  { id: "multipart-block", title: "Enforce the reviewed multipart nesting policy", writes: true },
  { id: "response-rule", title: "Enable available response rule 99006001", writes: true },
  { id: "resolve-fixtures", title: "Remove GhostPaw fixtures (not a PHP security update)", writes: true },
  { id: "verify", title: "Verify actual PHP version, fixture closure and isolation", writes: false },
]);
const HASH = /^[a-f0-9]{64}$/;
const canonical = (value) => Array.isArray(value) ? value.map(canonical) : value && typeof value === "object"
  ? Object.fromEntries(Object.keys(value).toSorted().map((key) => [key, canonical(value[key])])) : value;
const digest = (value) => createHash("sha256").update(JSON.stringify(canonical(value))).digest("hex");

export function responseAction(id) {
  const action = RESPONSE_ACTIONS.find((entry) => entry.id === id);
  if (!action) throw new Error("Unknown fixed response action; commands, targets and query text are not accepted.");
  return action;
}

export function assertResponseWindow(config, now = Date.now()) {
  if (!Number.isFinite(config.expiresAt) || now >= config.expiresAt) {
    throw new Error("The approved lab execution window has ended; no response read, probe or mutation is authorized.");
  }
}

export function assessPhpVersion(version) {
  const match = typeof version === "string" && /^(8\.[2-5])\.(0|[1-9]\d*)$/.exec(version);
  if (!match) return { status: "unverified-version", observed: version, reason: "A supported complete release version is required; prereleases, unknown branches and vendor backports need separate vendor evidence." };
  const minimum = `${match[1]}.${RESPONSE_GUIDANCE.fixed[match[1]]}`;
  return {
    status: Number(match[2]) >= RESPONSE_GUIDANCE.fixed[match[1]] ? "meets-advisory-version" : "patch-review-required",
    observed: version, minimum,
    note: "Version evidence only, not a compromise assessment or proof that every deployment/replica has been updated.",
  };
}

export function responseRule(kind, hosts, action = "Log") {
  if (!["session", "form", "multipart"].includes(kind) || !["Log", "Block"].includes(action)
      || !Array.isArray(hosts) || !hosts.length || hosts.length > 2
      || hosts.some((host) => typeof host !== "string" || !/^[a-z0-9.-]+$/.test(host))) {
    throw new Error("Invalid fixed request-rule configuration.");
  }
  const header = (value) => ({ matchVariable: "RequestHeader", selector: "Content-Type", operator: "BeginsWith",
    negateCondition: false, transforms: ["Trim", "Lowercase"], matchValue: [value] });
  const body = kind === "session"
    ? { matchVariable: "RequestBody", operator: "Contains", negateCondition: false, transforms: ["Lowercase"], matchValue: ["php_session_upload_progress"] }
    : { matchVariable: "RequestBody", operator: "RegEx", negateCondition: false,
      transforms: kind === "form" ? ["UrlDecode"] : ["Lowercase"],
      matchValue: [kind === "form"
        ? "(?:^|&)[^&=\\[\\]]+(?:\\[[^\\]&=]*\\]){20,}"
        : "(?:^|\\r?\\n)content-disposition:[ \\t]*form-data[^\\r\\n]*;[ \\t]*name[ \\t]*=[ \\t]*(?:\"(?:\\\\[^\\r\\n]|[^\"\\\\\\r\\n\\[])+(?:\\[(?:\\\\[^\\r\\n]|[^\"\\\\\\r\\n\\]])*\\]){20,}|[^ \\t\\r\\n;\"\\[]+(?:\\[[^ \\t\\r\\n;\"\\]]*\\]){20,})"] };
  return {
    name: `P2p${{ session: "SessionProgress", form: "FormDepth", multipart: "MultipartDepth" }[kind]}`,
    priority: { session: 171, form: 172, multipart: 173 }[kind],
    enabledState: "Enabled", ruleType: "MatchRule", action,
    matchConditions: [
      { matchVariable: "RequestHeader", selector: "Host", operator: "RegEx", negateCondition: false, transforms: ["Lowercase"],
        matchValue: [`^(?:${hosts.map((host) => host.replaceAll(".", "\\.")).join("|")})\\.?(?::443)?$`] },
      { matchVariable: "RequestUri", operator: "RegEx", negateCondition: false, transforms: ["Lowercase"],
        matchValue: ["^(?:https?://[^/]+)?/(?:index\\.php|health\\.php|walkthrough\\.php)?(?:\\?.*)?$"] },
      header(kind === "form" ? "application/x-www-form-urlencoded" : "multipart/form-data"), body,
    ],
  };
}

function policyBody(policy) {
  const { policySettings, customRules, managedRules } = policy.properties ?? {};
  if (!policySettings || !Array.isArray(customRules?.rules) || !Array.isArray(managedRules?.managedRuleSets)) {
    throw new Error("WAF policy shape is incomplete; no existing configuration may be replaced.");
  }
  return structuredClone({
    location: policy.location, sku: policy.sku, ...(policy.etag ? { etag: policy.etag } : {}),
    ...(policy.tags ? { tags: policy.tags } : {}), properties: { policySettings, customRules, managedRules },
  });
}

async function readState(config, io, { now = Date.now, guard = async () => {}, log = console.error, catalog = true } = {}) {
  const n = config.names;
  const read = async (id, api) => { assertResponseWindow(config, now()); await guard(); return assertResource(await io.read(id, api), id); };
  const group = assertOwnedGroup(await read(n.groupId, RESPONSE_API.group), config.invocation);
  if (group.tags["pawprint.expiresAt"] !== config.expiry) throw new Error("Response authorization does not match the original persisted lab expiry.");
  const profile = await read(n.profileId, RESPONSE_API.cdn);
  const endpoint = await read(n.endpointId, RESPONSE_API.cdn);
  const policy = await read(n.policyId, RESPONSE_API.waf);
  const app = await read(n.appId, RESPONSE_API.web);
  const web = await read(`${n.appId}/config/web`, RESPONSE_API.web);
  const association = (await read(`${n.profileId}/securityPolicies/application-waf`, RESPONSE_API.cdn)).properties?.parameters;
  const edge = assertEndpointHost(endpoint.properties?.hostName, n.endpoint);
  const hosts = [new URL(edge).hostname];
  const domains = [n.endpointId];
  if (group.tags["dojo.customDomainReady"] === "true") {
    const domain = await read(n.customDomainId, RESPONSE_API.cdn);
    if (domain.properties?.hostName !== group.tags["dojo.customDomain"]) throw new Error("Response custom-domain identity drifted.");
    hosts.push(domain.properties.hostName);
    domains.push(n.customDomainId);
  }
  if (association?.type !== "WebApplicationFirewall" || !sameId(association.wafPolicy?.id, n.policyId)
      || association.associations?.length !== 1 || association.associations[0].domains?.length !== domains.length
      || !domains.every((id) => association.associations[0].domains.some((entry) => sameId(entry?.id, id)))
      || JSON.stringify(association.associations[0].patternsToMatch) !== '["/*"]') {
    throw new Error("WAF association is not the exact reviewed public-lab domain scope.");
  }
  assertOriginRestrictions(web.properties, profile.properties?.frontDoorId);
  if (profile.sku?.name !== "Premium_AzureFrontDoor" || policy.sku?.name !== "Premium_AzureFrontDoor"
      || app.properties?.httpsOnly !== true || !sameId(app.properties?.serverFarmId, n.planId)
      || web.properties?.linuxFxVersion !== `PHP|${config.invocation.phpVersion}` || !UUID.test(app.identity?.principalId)) {
    throw new Error("Response target/runtime/identity differs from the reviewed owned App Service lab.");
  }
  const writable = policyBody(policy);
  if (writable.properties.policySettings.mode !== group.tags["dojo.wafMode"]) throw new Error("WAF state/tag drift requires manual reconciliation before response.");
  let availableRules = [];
  let catalogError;
  if (catalog) {
    try {
      await guard();
      availableRules = await io.catalog();
      if (!Array.isArray(availableRules)) throw new Error("Managed-rule catalogue shape is invalid.");
    } catch (error) {
      catalogError = `Managed-rule availability unavailable: ${redact(error.message)}`;
      log(`ERROR: ${catalogError}`);
    }
  }
  const fingerprint = digest({ group: { id: group.id, tags: group.tags }, policy: writable,
    app: { id: app.id, principalId: app.identity.principalId, planId: app.properties.serverFarmId },
    runtime: web.properties.linuxFxVersion, hosts });
  return { group, policy, writable, app, profile, hosts, edge, fingerprint, availableRules, catalogError };
}

function desiredPolicy(state, id) {
  const body = structuredClone(state.writable);
  const p = body.properties;
  p.policySettings.enabledState = "Enabled";
  if (id === "prevention") { p.policySettings.mode = "Prevention"; return body; }
  if (p.policySettings.mode !== "Prevention") throw new Error("Select the separate Prevention action before staging or enforcing mitigation rules.");
  if (id === "response-rule") {
    const sets = p.managedRules.managedRuleSets.filter((set) =>
      ["Microsoft_DefaultRuleSet", "DefaultRuleSet"].includes(set.ruleSetType) && ["2.0", "2.1", "2.2"].includes(set.ruleSetVersion));
    if (sets.length !== 1 || sets[0].ruleSetAction !== "Block") {
      throw new Error("A single already-reviewed DRS2.0/2.1/2.2 with ruleSetAction Block is required; this script never installs or retunes an entire DRS.");
    }
    const set = sets[0];
    const published = state.availableRules.some((entry) => entry.properties?.ruleSetType === set.ruleSetType
      && entry.properties?.ruleSetVersion === set.ruleSetVersion
      && entry.properties?.ruleGroups?.some((group) => group.ruleGroupName === RESPONSE_GUIDANCE.responseGroup
        && group.rules?.some((rule) => rule.ruleId === RESPONSE_GUIDANCE.responseRule)));
    if (!published) throw new Error(state.catalogError ?? "Response rule99006001 is not in this subscription's available DRS catalogue; rollout is not assumed complete.");
    set.ruleGroupOverrides ??= [];
    let group = set.ruleGroupOverrides.find((entry) => entry.ruleGroupName === RESPONSE_GUIDANCE.responseGroup);
    if (!group) { group = { ruleGroupName: RESPONSE_GUIDANCE.responseGroup, rules: [] }; set.ruleGroupOverrides.push(group); }
    group.rules ??= [];
    const previous = group.rules.find((rule) => rule.ruleId === RESPONSE_GUIDANCE.responseRule);
    const replacement = { ...previous, ruleId: RESPONSE_GUIDANCE.responseRule, enabledState: "Enabled", action: "AnomalyScoring" };
    group.rules = [...group.rules.filter((rule) => rule.ruleId !== RESPONSE_GUIDANCE.responseRule), replacement];
    return body;
  }
  const [kind, mode] = id.split("-");
  const rule = responseRule(kind, state.hosts, mode === "block" ? "Block" : "Log");
  const rules = p.customRules.rules;
  const previous = rules.find((entry) => entry.name === rule.name);
  if (rules.some((entry) => entry.name !== rule.name && entry.priority === rule.priority)) throw new Error("Reserved response rule priority is occupied; no existing rule is overwritten.");
  if (rules.some((entry) => entry.enabledState !== "Disabled" && entry.action === "Allow" && entry.priority < rule.priority)) {
    throw new Error("An earlier terminal Allow rule could bypass this mitigation; review precedence separately.");
  }
  if (previous && (!["Log", "Block"].includes(previous.action)
      || digest({ ...previous, action: "Log" }) !== digest({ ...rule, action: "Log" }))) {
    throw new Error("The reserved response rule differs from this exact reviewed adaptation; refusing silent adoption.");
  }
  if (previous?.action === "Block" && mode === "log") throw new Error("Downgrading an enforced response rule to Log is forbidden.");
  if (mode === "block" && !previous) throw new Error("Stage and independently review this rule in Log before explicitly selecting enforcement.");
  p.policySettings.requestBodyCheck = "Enabled";
  p.customRules.rules = [...rules.filter((entry) => entry.name !== rule.name), rule];
  return body;
}

export async function buildResponsePlan(config, io, options = {}) {
  const now = options.now ?? Date.now;
  const state = await readState(config, io, options);
  const actions = RESPONSE_ACTIONS.filter((action) => action.writes).map((action) => {
    try {
      if (action.id === "resolve-fixtures") {
        if (state.group.tags["dojo.wafMode"] !== "Prevention") throw new Error("Enable and validate Prevention before closing the training surface.");
        return { ...action, available: true, change: { LAB_STATE: "fixed", runtimePatchedByThisAction: false } };
      }
      const policy = desiredPolicy(state, action.id);
      return { ...action, available: true, change: policy };
    } catch (error) { return { ...action, available: false, reason: error.message }; }
  });
  return {
    kind: "response-plan", schemaVersion: 1, guidanceReviewedAt: RESPONSE_GUIDANCE.reviewedAt,
    createdAt: new Date(now()).toISOString(), expiresAt: config.expiry,
    scope: { groupId: config.names.groupId, appId: config.names.appId, policyId: config.names.policyId, hosts: state.hosts },
    fingerprint: state.fingerprint, actions,
    sourceGaps: state.catalogError ? [state.catalogError] : [],
    boundary: "Preview only. No PHP update, mitigation, role grant, test request or Defender change was performed.",
  };
}

export async function applyResponse(config, io, id, preview, options = {}) {
  if (!responseAction(id).writes || config.responseWritesEnabled !== true) throw new Error("Response writes are disabled; explicit deployment authorization and exact scoped permissions are required.");
  const now = options.now ?? Date.now;
  if (preview?.kind !== "response-plan" || preview.schemaVersion !== 1 || !HASH.test(preview.fingerprint ?? "")
      || preview.expiresAt !== config.expiry || !sameId(preview.scope?.appId, config.names.appId)
      || !sameId(preview.scope?.groupId, config.names.groupId) || !sameId(preview.scope?.policyId, config.names.policyId)
      || preview.guidanceReviewedAt !== RESPONSE_GUIDANCE.reviewedAt
      || !Number.isFinite(Date.parse(preview.createdAt)) || Date.parse(preview.createdAt) > now()
      || now() - Date.parse(preview.createdAt) > 600_000) {
    throw new Error("A fresh reviewed exact-lab response plan is required before any mutation.");
  }
  const state = await readState(config, io, options);
  if (state.fingerprint !== preview.fingerprint) throw new Error("Live configuration changed after preview; create and review a new plan.");
  if (typeof options.audit !== "function" || typeof io.write !== "function") throw new Error("An explicit audit sink and bounded response writer are required.");
  const audit = options.audit;
  const guard = options.guard ?? (async () => {});
  let acceptedWrites = 0;
  let invoked = false;
  const write = async (target, method, apiVersion, body) => {
    assertResponseWindow(config, now()); await guard();
    await audit("response-write-intent", { action: id, target, method });
    assertResponseWindow(config, now()); await guard();
    invoked = true;
    await io.write(target, method, apiVersion, body);
    acceptedWrites += 1;
    await audit("response-write-accepted", { action: id, target });
  };
  try {
    if (id === "resolve-fixtures") {
      if (state.group.tags["dojo.wafMode"] !== "Prevention") throw new Error("Prevention is required before fixture resolution.");
      const settings = await io.settings();
      if (!settings || typeof settings !== "object" || Array.isArray(settings)
          || Object.values(settings).some((value) => typeof value !== "string")
          || settings.LAB_ENVIRONMENT !== "dev" || !sameId(settings.LAB_RESOURCE_ID, config.names.appId)) {
        throw new Error("Public application settings do not identify this exact dev lab; contents are never exposed.");
      }
      await write(`${config.names.appId}/config/appsettings`, "PUT", RESPONSE_API.web, { properties: { ...settings, LAB_STATE: "fixed" } });
    } else {
      const desired = desiredPolicy(state, id);
      await write(config.names.policyId, "PUT", RESPONSE_API.waf, desired);
      assertResponseWindow(config, now()); await guard();
      let matched = false;
      for (let attempt = 0; attempt < 12; attempt += 1) {
        assertResponseWindow(config, now()); await guard();
        const observed = assertResource(await io.read(config.names.policyId, RESPONSE_API.waf), config.names.policyId);
        matched = observed.properties?.provisioningState === "Succeeded"
          && digest({ ...policyBody(observed), etag: undefined }) === digest({ ...desired, etag: undefined });
        if (matched) break;
        options.log?.("WAF write accepted; waiting for bounded provider readback, not claiming edge enforcement.");
        if (attempt < 11) await (options.sleep ?? delay)(3000);
      }
      if (!matched) throw new Error("WAF write was accepted but the full reviewed policy is not yet read back; reconciliation is required.");
    }
    await write(`${config.names.groupId}/providers/Microsoft.Resources/tags/default`, "PATCH", RESPONSE_API.tags,
      { operation: "Merge", properties: { tags: { "dojo.wafMode": "Prevention", ...(id === "resolve-fixtures" ? { "dojo.state": "fixed" } : {}) } } });
    if (id === "resolve-fixtures" && (await io.settings()).LAB_STATE !== "fixed") throw new Error("Fixture closure was not read back; reconcile before retrying.");
    const group = assertOwnedGroup(await io.read(config.names.groupId, RESPONSE_API.group), config.invocation);
    if (group.tags["pawprint.expiresAt"] !== config.expiry || group.tags["dojo.wafMode"] !== "Prevention"
        || (id === "resolve-fixtures" && group.tags["dojo.state"] !== "fixed")) throw new Error("Response state/expiry readback failed; reconcile before retrying.");
    return {
      kind: "response-change", action: id, appliedAt: new Date(now()).toISOString(), acceptedWrites,
      outcome: id === "resolve-fixtures" ? "training-surface-closed-not-a-PHP-update" : "configuration-written-validation-required",
      runtimePatchedByThisAction: false,
      responseRuleLogsExpected: id === "response-rule" ? false : undefined,
      next: "Run verify and review actual evidence. Never reopen exposure or automatically replay an uncertain write.",
    };
  } catch (error) {
    error.mutationMayHaveOccurred = acceptedWrites > 0 || (invoked && ![400, 401, 403, 404, 409, 412].includes(error.status));
    throw error;
  }
}

export async function verifyResponse(config, io, options = {}) {
  const state = await readState(config, io, { ...options, catalog: false });
  const now = options.now ?? Date.now;
  const observed = [];
  const runId = randomUUID();
  let version;
  const readHttp = async (url, headers = {}) => {
    assertResponseWindow(config, now()); await options.guard?.();
    const result = await request(url, { headers, fetchImpl: io.fetchImpl });
    observed.push({ url, status: result.status });
    return result;
  };
  for (const host of state.hosts) {
    const health = await readHttp(`https://${host}/health.php`);
    if (health.status !== 200) throw new Error("Response verification requires healthy HTTP200, not a block/error page.");
    let identity;
    try { identity = JSON.parse(health.text); } catch { throw new Error("Health is not the lab's JSON runtime evidence."); }
    if (identity.scenario !== SCENARIO || identity.environment !== "dev" || !sameId(identity.resourceId, config.names.appId)
        || identity.state !== state.group.tags["dojo.state"]
        || identity.syntheticEndpointsEnabled !== (identity.state === "training")
        || typeof identity.phpVersion !== "string" || !identity.phpVersion.startsWith(`${config.invocation.phpVersion}.`)) {
      throw new Error("Response health did not identify the exact application, runtime and intended state.");
    }
    const current = assessPhpVersion(identity.phpVersion);
    if (current.status === "unverified-version") throw new Error(current.reason);
    if (version && version.observed !== current.observed) throw new Error("PHP version differs across the verified public endpoints.");
    version = current;
    for (const signal of ["request", "php-error", "process-synthetic", "outbound-synthetic", "canary"]) {
      await readHttp(`https://${host}/index.php?signal=${signal}&runId=${runId}`);
    }
    await readHttp(`https://${host}/index.php?signal=request&runId=${runId}&dojoProbe=waf-marker`);
  }
  const origin = assertOriginHost(state.app.properties.defaultHostName, config.names.app);
  for (const headers of [{}, { "X-Azure-FDID": state.profile.properties.frontDoorId }]) {
    if ((await readHttp(`${origin}/health.php`, headers)).status !== 403) throw new Error("Origin isolation failed, including copied-header bypass testing.");
  }
  const grants = await io.roles();
  if (!Array.isArray(grants)) throw new Error("Runtime role evidence is unavailable; no zero-grant result is inferred.");
  const runtimeGrants = grants.filter((entry) => sameId(entry.properties?.principalId, state.app.identity.principalId));
  if (runtimeGrants.length) throw new Error("The public PHP identity has Azure role grants; resolution is not validated.");
  const fixturesClosed = state.group.tags["dojo.state"] === "fixed"
    && observed.filter((entry) => entry.url.includes("/index.php?") && !entry.url.includes("dojoProbe=")).every((entry) => entry.status === 404);
  const preventionObserved = state.group.tags["dojo.wafMode"] === "Prevention"
    && observed.filter((entry) => entry.url.includes("dojoProbe=")).every((entry) => entry.status === 403);
  return {
    kind: "response-verification", runId, capturedAt: new Date(now()).toISOString(), runtime: version,
    fixturesClosed, preventionObserved, originRejected: true, publicRuntimeGrants: 0, observed,
    resolved: fixturesClosed && preventionObserved && version.status === "meets-advisory-version",
    boundary: "Actual bounded HTTP/version/configuration evidence, not an exploit, detector guarantee, replica-wide attestation or incident-response clearance. Rule99006001 creates no WAF log/hit count.",
  };
}
