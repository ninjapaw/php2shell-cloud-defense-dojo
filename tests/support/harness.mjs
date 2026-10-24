import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { ROOT } from "../../scripts/dojo.mjs";
import { names, SCENARIO, SENTINEL_RULE_DISPLAY_NAME } from "../../scripts/lib/config.mjs";

export const SUBSCRIPTION = "11111111-1111-4111-8111-111111111111";
export const PRINCIPAL = "22222222-2222-4222-8222-222222222222";
export const FDID = "33333333-3333-4333-8333-333333333333";
export const DEFAULT_CONFIG = {
  environment: "dev", resourceGroup: "NP-PHPToProof-Dev-CentralUS",
  location: "centralus", ttlHours: 24, phpVersion: "8.4",
};

export function configuration(command, overrides = {}) {
  return {
    ...DEFAULT_CONFIG, command, subscription: SUBSCRIPTION, suffix: "demo1234",
    enableDefenderCspm: false, enableSentinel: false, enableAnalytics: false,
    yes: false, ...overrides,
  };
}

export function ownedGroup(config = configuration("validate"), tags = {}) {
  const n = names(config);
  return {
    id: n.groupId, name: n.group, location: config.location,
    tags: {
      "dojo.scenario": SCENARIO, "dojo.suffix": config.suffix,
      "pawprint.managed": "true", "pawprint.environment": "dev",
      "pawprint.runId": `php2shell-${config.suffix}-dev`,
      "pawprint.startedAt": "2026-10-20T12:00:00.000Z",
      "pawprint.expiresAt": "2026-10-21T12:00:00.000Z",
      "pawprint.ttlHours": "24", "dojo.state": "training", "dojo.wafMode": "Detection",
      "dojo.defenderCspmExpected": "false", "dojo.sentinel": "false", "dojo.analytics": "false",
      ...tags,
    },
  };
}

export function restrictedConfig() {
  return {
    ipSecurityRestrictionsDefaultAction: "Deny",
    ipSecurityRestrictions: [{
      name: "ThisFrontDoorOnly", ipAddress: "AzureFrontDoor.Backend", tag: "ServiceTag",
      action: "Allow", priority: 100, headers: { "x-azure-fdid": [FDID] },
    }],
    linuxFxVersion: "PHP|8.4", ftpsState: "Disabled",
  };
}

export function syntheticRule(config, enabled = false) {
  const n = names(config);
  return {
    id: `${n.workspaceId}/providers/Microsoft.SecurityInsights/alertRules/55555555-5555-4555-8555-555555555555`,
    kind: "Scheduled",
    properties: {
      displayName: SENTINEL_RULE_DISPLAY_NAME, enabled, severity: "Informational",
      query: readFileSync(join(ROOT, "detections", "correlation.kql"), "utf8").replaceAll("__APP_RESOURCE_ID__", n.appId),
      queryFrequency: "PT15M", queryPeriod: "PT1H", triggerOperator: "GreaterThan", triggerThreshold: 0,
      suppressionEnabled: false, incidentConfiguration: { createIncident: false },
      eventGroupingSettings: { aggregationKind: "SingleAlert" },
      customDetails: { RunId: "RunId", AppResourceId: "AppResourceId", EvidenceKind: "EvidenceKind" },
    },
  };
}

export function harness(config, options = {}) {
  const n = names(config);
  const calls = [];
  const requests = [];
  const logs = [];
  const state = {
    group: options.absent ? undefined : ownedGroup(config, options.tags),
    deleted: false, packaged: 0, cleaned: 0, tools: 0, slept: [],
  };
  const appHost = `${n.app}-fingerprint.${config.location}-01.azurewebsites.net`;
  const edgeHost = `${n.endpoint}-fingerprint.z01.azurefd.net`;
  function resource(id, properties, extra = {}) {
    return { id, properties, ...extra };
  }
  const az = (args) => {
    calls.push(args);
    const command = args.slice(0, 3).join(" ");
    if (options.azOverride) {
      const value = options.azOverride(args, state);
      if (value !== undefined) return value;
    }
    if (command === "account show") return { id: SUBSCRIPTION, state: "Enabled" };
    if (command === "cloud show") return { name: "AzureCloud" };
    if (command === "group exists --name") return Boolean(state.group) && !state.deleted;
    if (command === "group show --name") return structuredClone(state.group);
    if (command === "group delete --name") { state.deleted = true; return null; }
    if (command === "provider show --namespace") return { registrationState: "Registered" };
    if (command === "appservice list-locations --sku") return [{ name: config.location }];
    if (command === "webapp list-runtimes --os") return ["PHP:8.4", "PHP:8.5"];
    if (command === "rest --method get") {
      if (new URL(args[4]).pathname.toLowerCase() === `${n.workspaceId}/providers/Microsoft.SecurityInsights/alertRules`.toLowerCase()) {
        return { value: options.sentinelRules ?? [syntheticRule(config, state.group.tags["dojo.analytics"] === "true")] };
      }
      return { value: [{ actions: ["*"], notActions: [] }] };
    }
    if (command === "deployment sub what-if") return { status: "Succeeded", changes: [{ resourceId: n.groupId, changeType: state.group ? "NoChange" : "Create" }] };
    if (command === "deployment sub create") {
      const values = Object.fromEntries(args.slice(args.indexOf("--parameters") + 1).map((value) => {
        const separator = value.indexOf("=");
        return [value.slice(0, separator), value.slice(separator + 1)];
      }));
      state.group = ownedGroup(config, {
        "dojo.state": values.labState, "dojo.wafMode": values.wafMode,
        "pawprint.startedAt": values.startedAt, "pawprint.expiresAt": values.expiresAt,
        "pawprint.ttlHours": values.ttlHours,
        "dojo.defenderCspmExpected": values.defenderCspmExpected,
        "dojo.sentinel": values.enableSentinel, "dojo.analytics": values.enableAnalytics,
        "dojo.customDomain": values.customDomainName ?? "",
        "dojo.customDomainReady": values.associateCustomDomain ?? "false",
      });
      return { properties: { provisioningState: "Succeeded" } };
    }
    if (command === "webapp deploy --resource-group") {
      if (options.deployError) throw new Error("Code deployment failed.");
      return { status: "Succeeded" };
    }
    if (command === "webapp show --resource-group") return {
      id: n.appId, defaultHostName: appHost, state: "Running", httpsOnly: true,
      serverFarmId: n.planId, identity: { principalId: PRINCIPAL },
    };
    if (command === "webapp config show") return restrictedConfig();
    if (command === "resource show --ids") {
      const id = args[3];
      if (id === n.profileId) return resource(id, { frontDoorId: FDID }, { sku: { name: "Premium_AzureFrontDoor" } });
      if (id === n.endpointId) return resource(id, { hostName: edgeHost, enabledState: "Enabled" });
      if (id === n.policyId) return resource(id, {
        policySettings: { mode: state.group.tags["dojo.wafMode"], enabledState: "Enabled" },
        managedRules: { managedRuleSets: [{
          ruleSetType: "Microsoft_DefaultRuleSet", ruleSetVersion: "2.1", ruleSetAction: "Block", ruleGroupOverrides: [],
        }] },
        customRules: { rules: [{
          name: "DojoBenignMarker", action: "Block", enabledState: "Enabled", priority: 10, ruleType: "MatchRule",
          matchConditions: [{ matchVariable: "QueryString", operator: "Contains", matchValue: ["dojoProbe=waf-marker"], negateCondition: false }],
        }] },
      });
      if (id === `${n.profileId}/securityPolicies/application-waf`) return resource(id, { parameters: {
        type: "WebApplicationFirewall", wafPolicy: { id: n.policyId },
        associations: [{
          domains: [{ id: n.endpointId }, ...(state.group.tags["dojo.customDomainReady"] === "true" ? [{ id: n.customDomainId }] : [])],
          patternsToMatch: ["/*"],
        }],
      } });
      if (id === `${n.endpointId}/routes/application`) return resource(id, {
        enabledState: "Enabled", forwardingProtocol: "HttpsOnly", supportedProtocols: ["Https"],
        originGroup: { id: `${n.profileId}/originGroups/application` }, linkToDefaultDomain: "Enabled",
        customDomains: state.group.tags["dojo.customDomainReady"] === "true" ? [{ id: n.customDomainId }] : [],
      });
      if (id === n.customDomainId) return resource(id, {
        hostName: state.group.tags["dojo.customDomain"],
        tlsSettings: { certificateType: "ManagedCertificate", minimumTlsVersion: "TLS12" },
        validationProperties: { validationToken: "azure-validation-token" },
        domainValidationState: options.domainValidationState ?? "Approved",
        deploymentStatus: options.domainDeploymentStatus ?? "Succeeded",
        provisioningState: "Succeeded",
      });
      if (id === `${n.profileId}/originGroups/application/origins/application`) return resource(id, {
        hostName: appHost, originHostHeader: appHost, httpsPort: 443, enforceCertificateNameCheck: true,
      });
      if (id === n.planId) return resource(id, { reserved: true }, { sku: { name: "B1", capacity: 1 } });
      if (id === n.workspaceId) return resource(id, { provisioningState: "Succeeded", workspaceCapping: { dailyQuotaGb: 1 }, retentionInDays: 30 });
      if (id.startsWith(`${n.appId}/basicPublishingCredentialsPolicies/`)) return resource(id, { allow: false });
      if (id === `${n.workspaceId}/providers/Microsoft.SecurityInsights/onboardingStates/default`) return resource(id, {});
    }
    if (command === "monitor diagnostic-settings list") {
      const edge = args.includes(n.profileId);
      return { value: [{
        workspaceId: n.workspaceId,
        logs: (edge ? ["FrontDoorAccessLog", "FrontDoorWebApplicationFirewallLog", "FrontDoorHealthProbeLog"]
          : ["AppServiceHTTPLogs", "AppServiceConsoleLogs"]).map((category) => ({ category, enabled: true })),
      }] };
    }
    if (command === "role assignment list") return [];
    if (command === "security pricing show") return { pricingTier: options.pricingTier ?? "Free" };
    if (command === "graph query --graph-query") return { data: options.assessments ?? [] };
    throw new Error(`Unexpected mocked Azure command: ${args.join(" ")}`);
  };
  const fetchImpl = async (url, requestOptions) => {
    requests.push({ url, options: requestOptions });
    if (options.fetchOverride) {
      const result = await options.fetchOverride(url, requestOptions, state);
      if (result) return result;
    }
    const parsed = new URL(url);
    const domain = state.group.tags["dojo.customDomainReady"] === "true" ? state.group.tags["dojo.customDomain"] : undefined;
    assert.ok([appHost, edgeHost, domain].includes(parsed.hostname), "No arbitrary network target is accepted.");
    assert.equal(parsed.protocol, "https:");
    assert.equal(requestOptions.redirect, "manual");
    if (parsed.hostname === appHost) return new Response("Forbidden", { status: options.originStatus ?? 403 });
    if (parsed.pathname === "/health.php") return Response.json({
      scenario: SCENARIO, environment: "dev", state: state.group.tags["dojo.state"],
      resourceId: n.appId, phpVersion: "8.4.99", syntheticEndpointsEnabled: state.group.tags["dojo.state"] === "training",
    });
    if (parsed.searchParams.has("dojoProbe") && state.group.tags["dojo.wafMode"] === "Prevention") {
      return new Response("Blocked benign marker", { status: 403 });
    }
    if (state.group.tags["dojo.state"] === "fixed") return new Response("Removed", { status: 404 });
    return Response.json({
      scenario: SCENARIO, synthetic: true, runId: parsed.searchParams.get("runId"),
      signal: parsed.searchParams.get("signal"),
    });
  };
  return {
    state, calls, requests, logs,
    dependencies: {
      az, fetchImpl, log: (value) => logs.push(value),
      checkTools: () => { state.tools += 1; },
      sleep: async (milliseconds) => { state.slept.push(milliseconds); },
      packageApp: () => {
        state.packaged += 1;
        return { path: "synthetic-test-app.zip", cleanup: () => { state.cleaned += 1; } };
      },
    },
  };
}
