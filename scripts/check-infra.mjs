import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { SENTINEL_RULE_DISPLAY_NAME } from "./lib/config.mjs";

if (process.argv.length !== 3) throw new Error("Supply the compiled infra/main.bicep ARM JSON path.");
const root = JSON.parse(readFileSync(process.argv[2], "utf8"));
const resources = [];
function collect(template, parent) {
  for (const resource of Object.values(template.resources ?? {})) {
    if (resource.existing === true) continue;
    resources.push({ resource, template, parent });
    if (resource.type === "Microsoft.Resources/deployments") {
      assert.equal(resource.properties.mode, "Incremental", "Repair must not use Complete mode.");
      assert.ok(resource.properties?.template, "All nested templates must be local and auditable.");
      collect(resource.properties.template, resource);
    }
  }
}
collect(root);
const find = (type) => resources.filter((entry) => entry.resource.type.toLowerCase() === type.toLowerCase());
const only = (type) => {
  const matches = find(type);
  assert.equal(matches.length, 1, type);
  return matches[0];
};
assert.deepEqual(root.parameters.environmentName.allowedValues, ["dev"]);
assert.equal(root.parameters.groupName.type, "string");
assert.equal(root.parameters.groupName.minLength, 1);
assert.equal(root.parameters.groupName.maxLength, 90);
assert.ok(!Object.hasOwn(root.parameters.groupName, "defaultValue"), "The group name must come from configuration.");
assert.equal(root.parameters.enableDefenderCspm.defaultValue, false);
assert.equal(root.parameters.enableSentinel.defaultValue, false);
assert.equal(root.parameters.enableAnalytics.defaultValue, false);
assert.equal(root.parameters.customDomainName.defaultValue, "");
assert.equal(root.parameters.associateCustomDomain.defaultValue, false);
for (const resource of Object.values(root.resources)) {
  if (resource.type === "Microsoft.Resources/resourceGroups") continue;
  assert.equal(resource.type, "Microsoft.Resources/deployments");
  if (resource.resourceGroup) {
    assert.equal(resource.resourceGroup, "[parameters('groupName')]");
  } else {
    assert.equal(resource.condition, "[parameters('enableDefenderCspm')]");
    assert.deepEqual(Object.values(resource.properties.template.resources).map((entry) => entry.type), ["Microsoft.Security/pricings"]);
  }
}
assert.equal(only("Microsoft.Resources/resourceGroups").resource.name, "[parameters('groupName')]");
for (const [tag, parameter] of [
  ["dojo.defenderCspmExpected", "defenderCspmExpected"],
  ["dojo.sentinel", "enableSentinel"],
  ["dojo.analytics", "enableAnalytics"],
  ["dojo.customDomainReady", "associateCustomDomain"],
]) {
  assert.equal(root.variables.tags[tag], `[if(parameters('${parameter}'), 'true', 'false')]`,
    "Boolean ownership tags must remain lowercase strings after ARM evaluation.");
}
assert.equal(find("Microsoft.Authorization/roleAssignments").length, 0);
assert.equal(find("Microsoft.KeyVault/vaults/secrets").length, 0);
const pricing = only("Microsoft.Security/pricings");
assert.equal(pricing.resource.name, "CloudPosture");
assert.equal(pricing.resource.properties.pricingTier, "Standard");
assert.equal(pricing.parent.condition, "[parameters('enableDefenderCspm')]");
const app = only("Microsoft.Web/sites").resource;
assert.equal(app.properties.httpsOnly, true);
assert.equal(app.identity.type, "SystemAssigned");
const settings = app.properties.siteConfig;
assert.equal(settings.ipSecurityRestrictionsDefaultAction, "Deny");
assert.equal(settings.ipSecurityRestrictions.length, 1);
assert.equal(settings.ipSecurityRestrictions[0].ipAddress, "AzureFrontDoor.Backend");
assert.equal(settings.ipSecurityRestrictions[0].tag, "ServiceTag");
assert.deepEqual(settings.ipSecurityRestrictions[0].headers["x-azure-fdid"], ["[parameters('frontDoorId')]"]);
assert.equal(settings.ftpsState, "Disabled");
assert.equal(settings.scmIpSecurityRestrictionsUseMain, false);
assert.equal(find("Microsoft.Web/sites/basicPublishingCredentialsPolicies").length, 2);
assert.ok(find("Microsoft.Web/sites/basicPublishingCredentialsPolicies").every(({ resource }) => resource.properties.allow === false));
const plan = only("Microsoft.Web/serverfarms").resource;
assert.equal(plan.sku.name, "B1");
assert.equal(plan.sku.capacity, 1);
assert.equal(plan.properties.reserved, true);
const profile = only("Microsoft.Cdn/profiles").resource;
assert.equal(profile.sku.name, "Premium_AzureFrontDoor");
const waf = only("Microsoft.Network/frontDoorWebApplicationFirewallPolicies");
assert.equal(waf.template.parameters.wafMode.defaultValue, "Detection");
assert.equal(waf.resource.properties.policySettings.enabledState, "Enabled");
assert.equal(waf.resource.properties.policySettings.mode, "[parameters('wafMode')]");
assert.equal(waf.resource.properties.managedRules.managedRuleSets[0].ruleSetType, "Microsoft_DefaultRuleSet");
assert.equal(waf.resource.properties.managedRules.managedRuleSets[0].ruleSetVersion, "2.1");
assert.match(waf.resource.properties.customRules.rules, /dojoProbe=waf-marker/);
const routeEntry = only("Microsoft.Cdn/profiles/afdEndpoints/routes");
const route = routeEntry.resource.properties;
assert.deepEqual(route.supportedProtocols, ["Https"]);
assert.equal(route.forwardingProtocol, "HttpsOnly");
assert.ok(!route.cacheConfiguration);
assert.match(route.customDomains, /associateCustomDomain|associatedCustomDomains/);
assert.equal(routeEntry.template.parameters.associateCustomDomain.defaultValue, false);
assert.match(routeEntry.template.variables.associatedCustomDomains, /parameters\('associateCustomDomain'\)/);
assert.match(routeEntry.template.variables.associatedCustomDomains, /not\(empty\(parameters\('customDomainName'\)\)\)/);
assert.ok(routeEntry.resource.dependsOn.some((dependency) => /securityPolic/.test(dependency)),
  "A custom-domain route must wait for its WAF security-policy association.");
const domain = only("Microsoft.Cdn/profiles/customDomains").resource;
assert.equal(domain.properties.hostName, "[parameters('customDomainName')]");
assert.equal(domain.properties.tlsSettings.certificateType, "ManagedCertificate");
assert.equal(domain.properties.tlsSettings.minimumTlsVersion, "TLS12");
assert.match(domain.condition, /customDomainName/);
const association = only("Microsoft.Cdn/profiles/securityPolicies").resource.properties.parameters.associations[0];
assert.match(association.domains, /associatedCustomDomains/);
const origin = only("Microsoft.Cdn/profiles/originGroups/origins").resource.properties;
assert.equal(origin.enforceCertificateNameCheck, true);
assert.equal(origin.httpsPort, 443);
const diagnostics = find("Microsoft.Insights/diagnosticSettings");
assert.equal(diagnostics.length, 2);
assert.deepEqual(diagnostics.flatMap(({ resource }) => resource.properties.logs.map((log) => log.category)).sort(),
  ["AppServiceConsoleLogs", "AppServiceHTTPLogs", "FrontDoorAccessLog", "FrontDoorHealthProbeLog", "FrontDoorWebApplicationFirewallLog"].sort());
assert.ok(diagnostics.every(({ resource }) => resource.properties.logs.every((log) => log.enabled === true)));
const workspace = only("Microsoft.OperationalInsights/workspaces");
assert.equal(workspace.template.parameters.dailyQuotaGb.defaultValue, 1);
assert.equal(workspace.template.parameters.retentionInDays.defaultValue, 30);
assert.equal(workspace.parent.properties.parameters.emitApplicationInsightsConnectionString.value, false);
assert.equal(workspace.template.parameters.emitApplicationInsightsConnectionString.defaultValue, true,
  "Existing Pawprint consumers must preserve their default output behavior.");
assert.match(workspace.template.outputs.applicationInsightsConnectionString.value, /if\(parameters\('emitApplicationInsightsConnectionString'\)/);
const sentinel = only("Microsoft.SecurityInsights/onboardingStates");
assert.equal(sentinel.parent.condition, "[parameters('enableSentinel')]");
const ruleEntry = only("Microsoft.SecurityInsights/alertRules");
const rule = ruleEntry.resource;
assert.equal(rule.properties.enabled, "[parameters('enableAnalytics')]");
assert.equal(rule.properties.severity, "Informational");
assert.equal(rule.properties.incidentConfiguration.createIncident, false);
assert.equal(rule.properties.displayName, SENTINEL_RULE_DISPLAY_NAME);
assert.equal(rule.properties.queryFrequency, "PT15M");
assert.equal(rule.properties.queryPeriod, "PT1H");
assert.equal(rule.properties.triggerOperator, "GreaterThan");
assert.equal(rule.properties.triggerThreshold, 0);
assert.equal(rule.properties.suppressionEnabled, false);
assert.equal(rule.properties.eventGroupingSettings.aggregationKind, "SingleAlert");
assert.deepEqual(rule.properties.customDetails, { RunId: "RunId", AppResourceId: "AppResourceId", EvidenceKind: "EvidenceKind" });
const queryVariable = /^\[replace\(variables\('([^']+)'\), '__APP_RESOURCE_ID__', parameters\('appResourceId'\)\)\]$/.exec(rule.properties.query);
assert.ok(queryVariable, "The embedded query must be scoped by the exact appResourceId parameter.");
assert.match(ruleEntry.template.variables[queryVariable[1]], /synthetic-training-correlation-not-compromise/);
for (const output of Object.keys(root.outputs)) assert.doesNotMatch(output, /secret|token|password|connectionstring/i);
console.log(`Verified ${resources.length} compiled resources: bounded scopes, opt-ins, cost defaults, HTTPS/WAF/origin isolation, logging, zero runtime grants, and synthetic analytics.`);
