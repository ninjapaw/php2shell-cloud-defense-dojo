#!/usr/bin/env node
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { randomUUID } from "node:crypto";
import { setTimeout as delay } from "node:timers/promises";
import { COMMANDS, SCENARIO, SENTINEL_RULE_DISPLAY_NAME, UUID, names, parseConfigJson, parseInvocation } from "./lib/config.mjs";
import {
  assertEndpointHost, assertOriginHost, assertOriginRestrictions, assertOwnedGroup,
  assertResource, assertWhatIf, desiredState, hasPermission, redact, request, sameId,
} from "./lib/safety.mjs";
import { checkTools, createAzureClient, packageApp, readAzureCollection } from "./lib/azure.mjs";
import { huntingGuide } from "./lib/hunting.mjs";
import {
  assertDomainInZone, createCloudflareClient, reconcileAzureDns, validateDomain, verifyAzureDns,
} from "../vendor/pawprint/scripts/cloudflare-dns.mjs";

export const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const CDN_API = "2025-04-15";
const WAF_API = "2025-03-01";
const WRITE_COMMANDS = ["deploy", "repair", "protect", "remediate", "simulate", "domain"];

function parameters(config, desired) {
  return Object.entries({
    environmentName: "dev", suffix: config.suffix, location: config.location,
    startedAt: desired.startedAt, expiresAt: desired.expiresAt, ttlHours: desired.ttlHours,
    labState: desired.labState, wafMode: desired.wafMode, phpVersion: config.phpVersion,
    enableDefenderCspm: config.enableDefenderCspm,
    defenderCspmExpected: desired.defenderCspmExpected,
    enableSentinel: desired.enableSentinel, enableAnalytics: desired.enableAnalytics,
    customDomainName: desired.customDomainName, associateCustomDomain: desired.associateCustomDomain,
  }).map(([key, value]) => `${key}=${value}`);
}

function assertLabHealth(response, config, context) {
  if (response.status !== 200) throw new Error("Lab HTTPS health is not HTTP 200; no successful validation is asserted.");
  let body;
  try { body = JSON.parse(response.text); } catch { throw new Error("Edge health is not the lab JSON application."); }
  if (!body || typeof body !== "object" || body.scenario !== SCENARIO || body.environment !== "dev"
      || body.state !== context.labState || !sameId(body.resourceId, names(config).appId)
      || typeof body.phpVersion !== "string" || !body.phpVersion.startsWith(`${config.phpVersion}.`)
      || body.syntheticEndpointsEnabled !== (context.labState === "training")) {
    throw new Error("Edge health does not identify the expected live application/state/runtime.");
  }
}

export function offlinePlan(config, now) {
  const desired = desiredState(config, undefined, now);
  return {
    scenario: SCENARIO, environment: "dev", names: names(config),
    subscription: config.subscription ?? "explicit UUID required before Azure operations",
    location: config.location, initialState: desired,
    resources: ["Front Door Premium + WAF", "Linux App Service B1", "Log Analytics (1 GB/day ingestion cap)", "Linked Application Insights"],
    optional: {
      subscriptionWideBillableCloudPosture: config.enableDefenderCspm,
      workspaceBillableSentinel: desired.enableSentinel,
      syntheticAnalytics: desired.enableAnalytics,
    },
    dns: {
      customDomain: config.customDomain || null,
      activation: "Optional, separate domain --yes command after the base lab is deployed. DNS-only Cloudflare TXT/CNAME point to Front Door, never the origin.",
      sharedOwnership: "Pawprint supplies the reconciler; this repository and suffix own only their records. No shared zone, mail, proxy, or account settings are changed.",
    },
    cost: "No prices assumed. Front Door base/traffic/WAF, App Service capacity, log ingestion/retention, and optional Defender/Sentinel are billable. The ingestion cap is not a total spending limit.",
    safety: "HTTPS; origin service-tag AND profile-header restriction; no runtime roles/secrets; at most five benign simulator requests; expiry is metadata, not automatic teardown.",
    note: "Offline initial plan only. Existing fixed/Prevention state and original expiry are read and preserved by Azure commands. No Azure calls or writes were made.",
  };
}

export async function execute(config, dependencies = {}) {
  const log = dependencies.log ?? console.log;
  if (config.command === "plan") {
    const result = offlinePlan(config, dependencies.now);
    log(JSON.stringify(result, null, 2));
    return result;
  }
  const n = names(config);
  if (WRITE_COMMANDS.includes(config.command) && !config.yes) {
    throw new Error(`${config.command} requires --yes to acknowledge authorized training activity and applicable charges.`);
  }
  if (config.command === "uninstall" && config.confirmation !== n.group) {
    throw new Error(`Uninstall requires --confirm-resource-group with the exact scenario group name (${n.group}); --yes cannot bypass this.`);
  }
  const az = dependencies.az ?? createAzureClient(config);
  const sleep = dependencies.sleep ?? delay;
  const get = (id, version) => assertResource(az(["resource", "show", "--ids", id, "--api-version", version]), id);
  const account = az(["account", "show"]);
  if (!sameId(account?.id, config.subscription) || account.state !== "Enabled") {
    throw new Error("Selected enabled Azure subscription must exactly match --subscription. Set it explicitly with az account set.");
  }
  if (az(["cloud", "show"])?.name !== "AzureCloud") throw new Error("Only the public AzureCloud cloud is supported by this scaffold.");
  const exists = az(["group", "exists", "--name", n.group]);
  if (typeof exists !== "boolean") throw new Error("Azure did not return a valid resource-group existence result.");
  const group = exists ? assertOwnedGroup(az(["group", "show", "--name", n.group]), config) : undefined;

  if (config.command === "uninstall") {
    if (!group) throw new Error("The confirmed scenario resource group does not exist.");
    if (group.tags["dojo.customDomain"]) {
      log(`WARNING: Remove this run's Cloudflare CNAME for ${group.tags["dojo.customDomain"]} before releasing the hostname. Teardown deletes only Azure resources, not DNS or shared records.`);
    }
    az(["group", "delete", "--name", n.group, "--yes"]);
    if (az(["group", "exists", "--name", n.group]) !== false) throw new Error("Teardown has not completed; the resource group still exists.");
    log(`Deleted only ${n.group}. Subscription Defender pricing was NOT changed. Review it separately; do not disable a plan used by others.`);
    return { deleted: n.group, subscriptionPlansChanged: false, dnsRecordsRetained: Boolean(group.tags["dojo.customDomain"]) };
  }

  function deployInfrastructure(desired) {
    const deployment = az([
      "deployment", "sub", "create", "--name", n.deployment, "--location", config.location,
      "--template-file", join(ROOT, "infra", "main.bicep"),
      "--parameters", ...parameters(config, desired),
    ]);
    if (deployment?.properties?.provisioningState !== "Succeeded") {
      throw new Error("Azure infrastructure deployment did not reach Succeeded; no application deployment or success report follows.");
    }
  }

  async function preflight(desired) {
    (dependencies.checkTools ?? checkTools)();
    const providers = ["Microsoft.Web", "Microsoft.Cdn", "Microsoft.Network", "Microsoft.OperationalInsights", "Microsoft.Insights", "Microsoft.Security"];
    if (desired.enableSentinel) providers.push("Microsoft.SecurityInsights");
    for (const provider of providers) {
      if (az(["provider", "show", "--namespace", provider])?.registrationState !== "Registered") {
        throw new Error(`${provider} is not registered. Register it explicitly after reviewing subscription-wide effects, then rerun doctor.`);
      }
    }
    const regions = az(["appservice", "list-locations", "--sku", "B1", "--linux-workers-enabled"]);
    if (!Array.isArray(regions) || !regions.some((region) => region.name?.replaceAll(" ", "").toLowerCase() === config.location)) {
      throw new Error("Selected region is unavailable for Linux App Service B1; select a supported training region.");
    }
    const runtimes = az(["webapp", "list-runtimes", "--os", "linux"]);
    if (!Array.isArray(runtimes) || !runtimes.some((runtime) => String(runtime).replace(":", "|") === `PHP|${config.phpVersion}`)) {
      throw new Error("Selected PHP stack is not advertised by App Service; do not silently substitute a runtime.");
    }
    for (const [scope, actions] of [
      [`/subscriptions/${config.subscription}`, ["Microsoft.Resources/deployments/write", ...(config.enableDefenderCspm ? ["Microsoft.Security/pricings/write"] : [])]],
      [group ? n.groupId : `/subscriptions/${config.subscription}`, [
        "Microsoft.Resources/deployments/write", "Microsoft.Resources/subscriptions/resourceGroups/write",
        "Microsoft.Web/sites/write", "Microsoft.Web/serverfarms/write",
        "Microsoft.Cdn/profiles/write", "Microsoft.Network/frontDoorWebApplicationFirewallPolicies/write",
        ...(desired.customDomainName ? [
          "Microsoft.Cdn/profiles/customDomains/write", "Microsoft.Cdn/profiles/afdEndpoints/routes/write",
          "Microsoft.Cdn/profiles/securityPolicies/write",
        ] : []),
        "Microsoft.OperationalInsights/workspaces/write", "Microsoft.Insights/components/write",
        "Microsoft.Insights/diagnosticSettings/write",
        ...(desired.enableSentinel ? ["Microsoft.SecurityInsights/onboardingStates/write", "Microsoft.SecurityInsights/alertRules/write"] : []),
      ]],
    ]) {
      const permissions = readAzureCollection(az,
        `https://management.azure.com${scope}/providers/Microsoft.Authorization/permissions?api-version=2022-04-01`);
      if (actions.some((action) => !hasPermission(permissions, action))) {
        throw new Error(`Required deployment permissions are missing at ${scope}. See docs/operations.md; do not grant broad roles automatically.`);
      }
    }
    const result = az([
      "deployment", "sub", "what-if", "--name", n.deployment, "--location", config.location,
      "--template-file", join(ROOT, "infra", "main.bicep"),
      "--parameters", ...parameters(config, desired), "--result-format", "FullResourcePayloads",
    ]);
    assertWhatIf(result, config);
    for (const change of result.changes) log(`what-if: ${change.changeType} ${change.resourceId}`);
    log("Read-only preflight and bounded Bicep what-if passed. Quota/capacity and policy are still enforced by Azure at deployment.");
  }

  if (["doctor", "deploy", "repair", "protect", "remediate"].includes(config.command)) {
    const desired = desiredState(config, group, dependencies.now);
    await preflight(desired);
    if (config.command === "doctor") return { preflight: "passed", desired };
    deployInfrastructure(desired);
    const artifact = (dependencies.packageApp ?? packageApp)(ROOT);
    try {
      az(["webapp", "deploy", "--resource-group", n.group, "--name", n.app,
        "--src-path", artifact.path, "--type", "zip", "--clean", "true", "--restart", "true",
        "--async", "false", "--track-status", "true", "--timeout", "600000"]);
    } finally {
      artifact.cleanup();
    }
    const updated = assertOwnedGroup(az(["group", "show", "--name", n.group]), config);
    return validate(updated, true);
  }

  if (!group) throw new Error("Deploy the exact isolated scenario before this command.");

  function liveContext(currentGroup, { requireDomainReady = true } = {}) {
    const profile = get(n.profileId, CDN_API);
    const endpoint = get(n.endpointId, CDN_API);
    const app = assertResource(az(["webapp", "show", "--resource-group", n.group, "--name", n.app]), n.appId);
    const policy = get(n.policyId, WAF_API);
    const association = get(`${n.profileId}/securityPolicies/application-waf`, CDN_API).properties?.parameters;
    const route = get(`${n.endpointId}/routes/application`, CDN_API).properties;
    const origin = get(`${n.profileId}/originGroups/application/origins/application`, CDN_API).properties;
    const plan = get(n.planId, "2025-03-01");
    const settings = az(["webapp", "config", "show", "--resource-group", n.group, "--name", n.app]);
    const hasCustomDomain = currentGroup.tags["dojo.customDomainReady"] === "true";
    const expectedDomains = [n.endpointId, ...(hasCustomDomain ? [n.customDomainId] : [])];
    const sameDomains = (actual, expected) => Array.isArray(actual) && actual.length === expected.length
      && expected.every((id) => actual.some((entry) => sameId(entry?.id, id)));
    const frontDoorId = profile.properties?.frontDoorId;
    assertOriginRestrictions(settings, frontDoorId);
    const wafMode = policy.properties?.policySettings?.mode;
    if (wafMode !== currentGroup.tags["dojo.wafMode"] || policy.properties?.policySettings?.enabledState !== "Enabled") {
      throw new Error("Live WAF mode/enabled state differs from the intended lab state. Run repair after review.");
    }
    if (profile.sku?.name !== "Premium_AzureFrontDoor" || endpoint.properties?.enabledState !== "Enabled"
        || app.state !== "Running" || app.httpsOnly !== true || settings.ftpsState !== "Disabled"
        || settings.linuxFxVersion !== `PHP|${config.phpVersion}`) {
      throw new Error("The live workload, HTTPS, PHP runtime, publishing, or Premium edge configuration is unhealthy.");
    }
    if (!sameId(app.serverFarmId, n.planId) || plan.sku?.name !== "B1" || plan.sku?.capacity !== 1
        || plan.properties?.reserved !== true) {
      throw new Error("Live App Service plan differs from the reviewed Linux B1 single-instance cost boundary.");
    }
    if (association?.type !== "WebApplicationFirewall" || !sameId(association.wafPolicy?.id, n.policyId)
        || association.associations?.length !== 1
        || !sameDomains(association.associations[0].domains, expectedDomains)
        || JSON.stringify(association.associations[0].patternsToMatch) !== '["/*"]'
        || route?.enabledState !== "Enabled" || route.forwardingProtocol !== "HttpsOnly"
        || JSON.stringify(route.supportedProtocols) !== '["Https"]'
        || !sameId(route.originGroup?.id, `${n.profileId}/originGroups/application`)
        || route.linkToDefaultDomain !== "Enabled" || route.cacheConfiguration
        || !sameDomains(route.customDomains ?? [], hasCustomDomain ? [n.customDomainId] : [])
        || origin?.hostName !== app.defaultHostName || origin.originHostHeader !== app.defaultHostName
        || origin.httpsPort !== 443 || origin.enforceCertificateNameCheck !== true) {
      throw new Error("WAF association or HTTPS origin routing differs from the reviewed design.");
    }
    const managed = policy.properties?.managedRules?.managedRuleSets;
    const custom = policy.properties?.customRules?.rules;
    if (!managed?.some((set) => set.ruleSetType === "Microsoft_DefaultRuleSet" && set.ruleSetVersion === "2.1"
        && set.ruleSetAction === "Block" && (set.ruleGroupOverrides == null
          || (Array.isArray(set.ruleGroupOverrides) && set.ruleGroupOverrides.length === 0)))
        || custom?.length !== 1 || custom[0].name !== "DojoBenignMarker" || custom[0].action !== "Block"
        || custom[0].enabledState !== "Enabled" || custom[0].priority !== 10 || custom[0].ruleType !== "MatchRule"
        || custom[0].matchConditions?.length !== 1
        || custom[0].matchConditions[0].matchVariable !== "QueryString"
        || custom[0].matchConditions[0].operator !== "Contains"
        || ![undefined, null, false].includes(custom[0].matchConditions[0].negateCondition)
        || JSON.stringify(custom[0].matchConditions[0].matchValue) !== '["dojoProbe=waf-marker"]') {
      throw new Error("Managed WAF or the benign correlation rule differs from the documented configuration.");
    }
    if (!UUID.test(app.identity?.principalId)) throw new Error("App Service managed identity is missing.");
    const customDomain = hasCustomDomain ? get(n.customDomainId, CDN_API).properties : undefined;
    if (hasCustomDomain && (customDomain?.hostName !== currentGroup.tags["dojo.customDomain"]
        || customDomain.tlsSettings?.certificateType !== "ManagedCertificate"
        || customDomain.tlsSettings?.minimumTlsVersion !== "TLS12"
        || (requireDomainReady && (customDomain.domainValidationState !== "Approved"
          || customDomain.deploymentStatus !== "Succeeded" || customDomain.provisioningState !== "Succeeded")))) {
      throw new Error("The exact Front Door custom domain, Azure ownership approval, or managed HTTPS deployment is not ready.");
    }
    return {
      edge: assertEndpointHost(endpoint.properties?.hostName, n.endpoint),
      origin: assertOriginHost(app.defaultHostName, n.app),
      frontDoorId, wafMode, principalId: app.identity.principalId,
      labState: currentGroup.tags["dojo.state"],
      customDomain,
    };
  }

  async function validate(currentGroup, retry = false) {
    const context = liveContext(currentGroup);
    const http = (url, options = {}) => request(url, { ...options, fetchImpl: dependencies.fetchImpl });
    let health;
    let readinessError;
    for (let attempt = 0; attempt < (retry ? 12 : 1); attempt += 1) {
      try {
        health = await http(`${context.edge}/health.php`);
      } catch (error) {
        if (!retry || !(error instanceof TypeError || ["AbortError", "TimeoutError"].includes(error.name))) throw error;
        readinessError = error;
        log(`Edge readiness ${attempt + 1}/12 failed: ${redact(error.message)}. No success asserted.`);
      }
      if (health?.status === 200) break;
      if (attempt < 11 && retry) await sleep(10_000);
    }
    if (health?.status !== 200) {
      throw new Error(`Edge health is not HTTP 200. Deployment is NOT validated; allow edge propagation and rerun validate.${readinessError ? ` Last network error: ${redact(readinessError.message)}` : ""}`);
    }
    assertLabHealth(health, config, context);
    for (const headers of [{}, { "X-Azure-FDID": context.frontDoorId }]) {
      if ((await http(`${context.origin}/health.php`, { headers })).status !== 403) {
        throw new Error("DIRECT ORIGIN BYPASS: the origin must return HTTP 403, even with a copied Front Door header.");
      }
    }
    const runId = randomUUID();
    async function checkMarker(base) {
      const marker = await http(`${base}/index.php?signal=request&runId=${runId}&dojoProbe=waf-marker`);
      const markerStatus = context.wafMode === "Prevention" ? 403 : 200;
      if (marker.status !== markerStatus) throw new Error(`WAF marker expected HTTP ${markerStatus}; verify association and edge propagation.`);
      if (marker.status === 200) {
        let event;
        try { event = JSON.parse(marker.text); } catch { throw new Error("WAF Detection marker did not return lab JSON."); }
        if (event?.scenario !== SCENARIO || event.synthetic !== true || event.runId !== runId || event.signal !== "request") {
          throw new Error("WAF Detection marker response did not identify this benign lab run.");
        }
      }
    }
    await checkMarker(context.edge);
    const customEndpoint = context.customDomain ? `https://${context.customDomain.hostName}` : undefined;
    if (customEndpoint) {
      await verifyAzureDns({
        service: "front-door", domain: context.customDomain.hostName,
        azureHostname: new URL(context.edge).hostname,
        verificationId: context.customDomain.validationProperties?.validationToken,
      }, dependencies.resolver);
      assertLabHealth(await http(`${customEndpoint}/health.php`), config, context);
      await checkMarker(customEndpoint);
    }
    if (context.labState === "fixed") {
      for (const endpoint of [context.edge, ...(customEndpoint ? [customEndpoint] : [])]) {
        for (const signal of ["request", "php-error", "process-synthetic", "outbound-synthetic", "canary"]) {
          if ((await http(`${endpoint}/index.php?signal=${signal}&runId=${runId}`)).status !== 404) {
            throw new Error("Remediated training endpoints remain accessible.");
          }
        }
      }
    }
    const workspace = get(n.workspaceId, "2025-07-01");
    if (workspace.properties?.provisioningState !== "Succeeded") throw new Error("Workspace is not healthy.");
    if (workspace.properties?.workspaceCapping?.dailyQuotaGb !== 1 || workspace.properties?.retentionInDays !== 30) {
      throw new Error("Workspace ingestion/retention differs from the reviewed cost boundary.");
    }
    for (const [id, categories] of [
      [n.profileId, ["FrontDoorAccessLog", "FrontDoorWebApplicationFirewallLog", "FrontDoorHealthProbeLog"]],
      [n.appId, ["AppServiceHTTPLogs", "AppServiceConsoleLogs"]],
    ]) {
      const diagnostics = az(["monitor", "diagnostic-settings", "list", "--resource", id]);
      const entries = Array.isArray(diagnostics) ? diagnostics : diagnostics?.value;
      if (!Array.isArray(entries) || !categories.every((category) => entries.some((entry) =>
        sameId(entry.workspaceId ?? entry.properties?.workspaceId, n.workspaceId)
        && (entry.logs ?? entry.properties?.logs)?.some((item) => item.category === category && item.enabled === true)))) {
        throw new Error("Required diagnostic categories are not routed to the exact lab workspace.");
      }
    }
    for (const policy of ["ftp", "scm"]) {
      const resource = get(`${n.appId}/basicPublishingCredentialsPolicies/${policy}`, "2025-03-01");
      if (resource.properties?.allow !== false) throw new Error("Basic publishing credentials must remain disabled.");
    }
    const roles = az(["role", "assignment", "list", "--scope", n.appId, "--include-inherited",
      "--fill-principal-name", "false",
      "--query", `[?principalId=='${context.principalId}'].{id:id,roleDefinitionId:roleDefinitionId}`]);
    if (!Array.isArray(roles) || roles.length !== 0) throw new Error("The app identity has unexpected role grants. Review and remove unnecessary permissions; this lab needs none.");
    const posture = az(["security", "pricing", "show", "--name", "CloudPosture"]);
    if (!["Free", "Standard"].includes(posture?.pricingTier)) throw new Error("Cannot establish Defender CSPM pricing state.");
    if (currentGroup.tags["dojo.defenderCspmExpected"] === "true" && posture.pricingTier !== "Standard") {
      throw new Error("Explicitly requested Defender CSPM does not report Standard.");
    }
    let sentinel = null;
    if (currentGroup.tags["dojo.sentinel"] === "true") {
      get(`${n.workspaceId}/providers/Microsoft.SecurityInsights/onboardingStates/default`, "2025-09-01");
      const collectionId = `${n.workspaceId}/providers/Microsoft.SecurityInsights/alertRules`;
      const rules = readAzureCollection(az, `https://management.azure.com${collectionId}?api-version=2025-09-01`)
        .filter((rule) => rule?.properties?.displayName === SENTINEL_RULE_DISPLAY_NAME);
      if (rules.length !== 1) throw new Error("Sentinel synthetic rule is missing or ambiguous; run repair after review.");
      const [rule] = rules;
      const idParts = typeof rule.id === "string" ? rule.id.split("/") : [];
      const ruleName = idParts.pop();
      const properties = rule.properties;
      const query = typeof properties.query === "string" ? properties.query.replaceAll("\r\n", "\n").trim() : "";
      const appScope = /^let AppResourceId = "([^"]+)";$/m.exec(query);
      const expectedQuery = readFileSync(join(ROOT, "detections", "correlation.kql"), "utf8")
        .replaceAll("\r\n", "\n").trim().replaceAll("__APP_RESOURCE_ID__", appScope?.[1] ?? "");
      const enabled = currentGroup.tags["dojo.analytics"] === "true";
      if (!sameId(idParts.join("/"), collectionId) || !UUID.test(ruleName) || rule.kind !== "Scheduled"
          || properties.enabled !== enabled || properties.severity !== "Informational"
          || properties.queryFrequency !== "PT15M" || properties.queryPeriod !== "PT1H"
          || properties.triggerOperator !== "GreaterThan" || properties.triggerThreshold !== 0
          || properties.suppressionEnabled !== false || properties.incidentConfiguration?.createIncident !== false
          || !appScope || !sameId(appScope[1], n.appId) || query !== expectedQuery
          || properties.eventGroupingSettings?.aggregationKind !== "SingleAlert"
          || properties.customDetails?.RunId !== "RunId" || properties.customDetails?.AppResourceId !== "AppResourceId"
          || properties.customDetails?.EvidenceKind !== "EvidenceKind") {
        throw new Error("Sentinel synthetic rule scope, query, opt-in state or training configuration drifted; run repair after review.");
      }
      sentinel = { onboarded: true, syntheticRuleConfigured: true, analyticsEnabled: enabled };
    }
    const result = {
      validated: true, resourceGroup: n.group, endpoint: context.edge, state: context.labState,
      wafMode: context.wafMode, directOriginBlocked: true, basicPublishingDisabled: true,
      customDomain: customEndpoint ?? null,
      sentinel,
      runtimeRoleAssignmentsAtAppScope: 0, defenderCspm: posture.pricingTier,
      permissionBoundary: "Direct and scope-inherited assignments to this app principal only; group-based and out-of-scope grants require separate review.",
      evidence: "Live routing/configuration checks only. Log ingestion, CVE assessments, runtime alerts, and attack paths are not asserted.",
    };
    log(JSON.stringify(result, null, 2));
    return result;
  }

  if (["domain", "domain-check"].includes(config.command)) {
    const existingDomain = group.tags["dojo.customDomain"] ?? "";
    const domain = validateDomain(config.customDomain || existingDomain);
    if (existingDomain && domain !== existingDomain) {
      throw new Error("An existing run's custom domain cannot be renamed implicitly. Review DNS removal and Azure ownership before using a new suffix.");
    }
    if (config.command === "domain-check") {
      if (!existingDomain || group.tags["dojo.customDomainReady"] !== "true") {
        throw new Error("The custom domain is not associated yet. Review plan and run domain --yes; this check makes no changes.");
      }
      return validate(group);
    }
    const context = liveContext(group, { requireDomainReady: false });
    const environment = dependencies.environment ?? process.env;
    const dns = {
      service: "front-door", owner: `ninjapaw/${SCENARIO}:dev:${config.suffix}`, domain,
      azureHostname: new URL(context.edge).hostname,
      zoneId: environment.CLOUDFLARE_ZONE_ID || undefined,
      zoneName: environment.CLOUDFLARE_ZONE_NAME || undefined,
      token: environment.CLOUDFLARE_API_TOKEN,
    };
    const cloudflare = createCloudflareClient(dns, { fetcher: dependencies.cloudflareFetch });
    assertDomainInZone(domain, await cloudflare.loadZone());
    const desired = { ...desiredState(config, group, dependencies.now), customDomainName: domain };
    await preflight(desired);
    deployInfrastructure(desired);
    const pending = get(n.customDomainId, CDN_API).properties;
    if (pending?.hostName !== domain || pending.tlsSettings?.certificateType !== "ManagedCertificate"
        || pending.tlsSettings?.minimumTlsVersion !== "TLS12") {
      throw new Error("Azure did not create the exact managed-TLS Front Door custom domain; no DNS records were written.");
    }
    dns.verificationId = pending.validationProperties?.validationToken;
    for (const action of await reconcileAzureDns(dns, { apply: true, fetcher: dependencies.cloudflareFetch })) {
      log(`[${action.action}] ${action.type} ${action.name}`);
    }
    await verifyAzureDns(dns, dependencies.resolver);
    const approved = get(n.customDomainId, CDN_API).properties;
    if (approved?.hostName !== domain || approved.domainValidationState !== "Approved") {
      throw new Error("Azure custom-domain ownership is not Approved yet. Allow DNS propagation and rerun domain. Expired/rejected validation needs explicit Azure token regeneration; no new route association was attempted.");
    }
    const associated = { ...desired, associateCustomDomain: true };
    await preflight(associated);
    deployInfrastructure(associated);
    const updated = assertOwnedGroup(az(["group", "show", "--name", n.group]), config);
    return validate(updated, true);
  }

  if (config.command === "validate") return validate(group);
  if (config.command === "simulate") {
    await validate(group);
    const context = liveContext(group);
    if (context.labState !== "training") throw new Error("Simulation surfaces are disabled after remediation. Use validate for closure checks.");
    const runId = randomUUID();
    const startedAt = new Date().toISOString();
    const signals = ["request", "php-error", "process-synthetic", "outbound-synthetic", "canary"];
    const observations = [];
    for (const [index, signal] of signals.entries()) {
      const marker = index === 0 ? "&dojoProbe=waf-marker" : "";
      const response = await request(`${context.edge}/index.php?signal=${signal}&runId=${runId}${marker}`, { fetchImpl: dependencies.fetchImpl });
      const expected = index === 0 && context.wafMode === "Prevention" ? 403 : 200;
      if (response.status !== expected) throw new Error(`Bounded simulation failed for ${signal}: expected HTTP ${expected}.`);
      if (response.status === 200) {
        let body;
        try { body = JSON.parse(response.text); } catch { throw new Error("Simulator did not receive structured lab telemetry."); }
        if (body.scenario !== SCENARIO || body.synthetic !== true || body.runId !== runId || body.signal !== signal) {
          throw new Error("Simulator response failed scenario/run-ID/synthetic identity validation.");
        }
      }
      observations.push({ signal, status: response.status, synthetic: true });
      if (index < signals.length - 1) await sleep(250);
    }
    const result = { runId, startedAt, endedAt: new Date().toISOString(), synthetic: true, requests: observations };
    log(JSON.stringify(result, null, 2));
    log("These are harmless marker/log requests, NOT process execution, outbound traffic, real canary access, an exploit, or proof of compromise.");
    return result;
  }
  if (config.command === "investigate") {
    const context = liveContext(group);
    const query = `securityresources
| where type in~ ('microsoft.security/assessments', 'microsoft.security/assessments/subassessments')
| extend Details = tostring(properties)
| extend AssessedResourceId = coalesce(tostring(properties.resourceDetails.id), tostring(properties.resourceDetails.Id))
| where id startswith '${n.groupId}/' or AssessedResourceId startswith '${n.groupId}/' or AssessedResourceId =~ '${n.appId}'
| where Details contains 'PHP' or Details contains 'CVE-2026-109618' or Details contains 'CVE-2026-109619'
| project AssessmentId=id, DisplayName=tostring(properties.displayName), Status=tostring(properties.status.code)
| limit 50`;
    const records = az(["graph", "query", "--graph-query", query, "--subscriptions", config.subscription]);
    if (!Array.isArray(records?.data)) throw new Error("Invalid Resource Graph assessment response. Install the resource-graph Azure CLI extension if missing.");
    log(JSON.stringify({
      resourceGroup: n.group,
      appResourceId: n.appId, endpoint: context.edge,
      portal: `https://portal.azure.com/#@/resource${n.groupId}/overview`,
      workspace: `https://portal.azure.com/#@/resource${n.workspaceId}/logs`,
      assessments: records.data,
      hunting: huntingGuide(),
      note: records.data.length ? "Observed matching assessments; inspect the actual details before drawing conclusions."
        : "No matching PHP/CVE assessments returned. Absence, unsupported assessment coverage, or discovery latency is not proof of safety. Do not manufacture findings.",
      next: "Use the six lab queries with the simulation run ID and UTC window. Follow the platform-specific hunting catalog and evidence checklist for the wider estate; those queries are not executed automatically. Synthetic runtime-shaped events are not workload-protection alerts.",
    }, null, 2));
    return records.data;
  }
  throw new Error("Unhandled command.");
}

export async function main(args = process.argv.slice(2)) {
  const config = parseConfigJson(readFileSync(join(ROOT, "config", "dev.json"), "utf8"));
  const invocation = parseInvocation(args, config);
  if (invocation.help) {
    console.log(`Usage: bash scripts/dojo.sh <${COMMANDS.join("|")}> --environment dev --suffix <4-12 lowercase letters/digits>
Azure commands: --subscription <UUID> (or AZURE_SUBSCRIPTION_ID)
Writes/simulation: --yes
Teardown: --confirm-resource-group <exact-name> (cannot be bypassed)
Explicit billable choices: --enable-defender-cspm, --enable-sentinel, --enable-analytics
Validated protection step: protect --yes (or explicit --waf-mode Prevention)
Optional regional override: --location <region>
Optional domain intent: --custom-domain <subdomain> with plan/domain/domain-check, or DOJO_CUSTOM_DOMAIN.
domain --yes reconciles only this run's Cloudflare records and the Front Door managed-TLS/WAF association.
domain-check is read-only. Repair preserves pending/associated domains; simulation still uses the verified Azure endpoint.
No arbitrary targets, production environment, or secret arguments are accepted.`);
    return;
  }
  await execute(invocation);
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  main().catch((error) => {
    console.error(`ERROR: ${redact(error.message)}`);
    process.exitCode = 1;
  });
}
