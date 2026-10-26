import { responseFingerprint } from "../scripts/lib/response.mjs";

export const LIVE_WAF_API = "2025-03-01";
export const LIVE_PROBE_PATH = "/evidence/live-probe/";

export function operatorPolicyId(config) {
  return `${config.names.groupId}/providers/Microsoft.Network/frontDoorWebApplicationFirewallPolicies/p2pop${config.invocation.suffix}waf`;
}

export function liveProbeRule(config, action = "Log") {
  if (!config.liveWindow || !["Log", "Block"].includes(action)) throw new Error("A fresh private live window and fixed test-rule action are required.");
  return {
    name: `P2pLive${config.liveWindow.id.replaceAll("-", "").slice(0, 12)}`,
    priority: 197, enabledState: "Enabled", ruleType: "MatchRule", action,
    matchConditions: [
      { matchVariable: "RequestHeader", selector: "Host", operator: "Equal", negateCondition: false,
        transforms: ["Lowercase"], matchValue: [new URL(config.origin).hostname] },
      { matchVariable: "RequestUri", operator: "RegEx", negateCondition: false, transforms: ["Lowercase"],
        matchValue: ["^(?:https?://[^/]+)?/evidence/live-probe/[0-9a-f-]{36}$"] },
    ],
  };
}

export function livePolicyBody(config, policy) {
  const p = policy?.properties;
  if (typeof policy?.id !== "string" || policy.id.toLowerCase() !== operatorPolicyId(config).toLowerCase()
      || policy.tags?.["dojo.scenario"] !== "php2proof-operator"
      || policy.tags?.["dojo.suffix"] !== config.invocation.suffix
      || policy.tags?.["pawprint.expiresAt"] !== (config.originalExpiry ?? config.expiry)
      || p?.policySettings?.enabledState !== "Enabled" || p.policySettings.mode !== "Prevention"
      || !Array.isArray(p.customRules?.rules) || !Array.isArray(p.managedRules?.managedRuleSets)
      || typeof policy.location !== "string" || policy.sku?.name !== "Premium_AzureFrontDoor") {
    throw new Error("Only the original owned operator WAF in Prevention can be used for the scoped live transport test.");
  }
  const rules = p.customRules.rules;
  if (rules.some((rule) => typeof rule.name !== "string") || new Set(rules.map((rule) => rule.name.toLowerCase())).size !== rules.length) {
    throw new Error("Ambiguous operator WAF custom-rule inventory.");
  }
  return structuredClone({
    location: policy.location, sku: policy.sku, tags: policy.tags,
    ...(typeof policy.etag === "string" ? { etag: policy.etag } : {}),
    properties: { policySettings: p.policySettings, customRules: p.customRules, managedRules: p.managedRules },
  });
}

export function probeRuleState(config, policy) {
  const body = livePolicyBody(config, policy);
  const expected = liveProbeRule(config);
  const rules = body.properties.customRules.rules;
  const existing = rules.find((rule) => rule.name.toLowerCase() === expected.name.toLowerCase());
  if (rules.some((rule) => rule.name !== expected.name && rule.priority === expected.priority)) {
    throw new Error("Reserved live-test priority is occupied; no existing rule is adopted or overwritten.");
  }
  if (!existing) return { action: "absent", name: expected.name };
  const shape = ({ name, priority, enabledState, ruleType, matchConditions }) => ({ name, priority, enabledState, ruleType, matchConditions });
  if (!["Log", "Block"].includes(existing.action) || responseFingerprint(shape(existing)) !== responseFingerprint(shape(expected))) {
    throw new Error("Live-test rule scope or structure drifted; no foreign rule is adopted.");
  }
  return { action: existing.action, name: expected.name };
}

export function changeProbeRule(config, policy, action) {
  if (!["Log", "Block", "Remove"].includes(action)) throw new Error("Unknown fixed live WAF action.");
  const state = probeRuleState(config, policy);
  if (action === "Block" && state.action !== "Log") throw new Error("Review the live Log baseline before applying test-route blocking.");
  if (action === "Remove" && state.action === "absent") throw new Error("No owned test rule exists to remove.");
  const body = livePolicyBody(config, policy);
  const rules = body.properties.customRules.rules.filter((rule) => rule.name !== state.name);
  body.properties.customRules.rules = action === "Remove" ? rules : [...rules, liveProbeRule(config, action)];
  return body;
}

// Detection logs a Block match without enforcing it, so the edge still answers 200.
export function expectedTransportStatus(ruleAction, mode) {
  if (!["Log", "Block", "absent"].includes(ruleAction) || !["Detection", "Prevention"].includes(mode)) {
    throw new Error("Unknown WAF rule action or mode for transport expectation.");
  }
  return ruleAction === "Block" && mode === "Prevention" ? 403 : 200;
}

export function liveWafObservation(config, policy) {
  const rule = probeRuleState(config, policy);
  return {
    policyId: operatorPolicyId(config), mode: policy.properties.policySettings.mode, rule,
    fingerprint: responseFingerprint(livePolicyBody(config, policy)),
    note: "This rule controls only the operator-host benign transport-test route; it is not a PHP CVE signature.",
  };
}
