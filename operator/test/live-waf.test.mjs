import test from "node:test";
import assert from "node:assert/strict";
import { changeProbeRule, expectedTransportStatus, livePolicyBody, liveProbeRule, liveWafObservation, operatorPolicyId } from "../live-waf.mjs";

const config = {
  invocation: { suffix: "proof1023c" },
  names: { groupId: "/subscriptions/16037566-d4df-4c7c-b484-346d8472b4c4/resourceGroups/NP-PHPToProof-Dev-CentralUS" },
  originalExpiry: "2026-10-24T18:45:04.967Z", origin: "https://operator-unit.azurefd.net",
  liveWindow: { id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa" },
};
const policy = () => ({
  id: operatorPolicyId(config), location: "Global", sku: { name: "Premium_AzureFrontDoor" },
  tags: { "dojo.scenario": "php2proof-operator", "dojo.suffix": "proof1023c", "pawprint.expiresAt": config.originalExpiry },
  properties: {
    policySettings: { enabledState: "Enabled", mode: "Prevention", requestBodyCheck: "Enabled" },
    customRules: { rules: [{ name: "ExistingBusinessRule", priority: 10, action: "Block", ruleType: "MatchRule" }] },
    managedRules: { managedRuleSets: [{ ruleSetType: "Microsoft_DefaultRuleSet", ruleSetVersion: "2.1", ruleGroupOverrides: [] }] },
  },
});

test("live WAF staging, blocking and removal preserve Prevention, other controls and original expiry", () => {
  const before = policy();
  const staged = { ...before, ...changeProbeRule(config, before, "Log") };
  const blocked = { ...staged, ...changeProbeRule(config, staged, "Block") };
  assert.equal(liveWafObservation(config, blocked).rule.action, "Block");
  assert.equal(blocked.properties.policySettings.mode, "Prevention");
  assert.deepEqual(blocked.properties.managedRules, before.properties.managedRules);
  assert.deepEqual(blocked.properties.customRules.rules[0], before.properties.customRules.rules[0]);
  assert.deepEqual(blocked.tags, before.tags);
  const removed = { ...blocked, ...changeProbeRule(config, blocked, "Remove") };
  assert.deepEqual(livePolicyBody(config, removed), livePolicyBody(config, before));
  const rule = liveProbeRule(config);
  assert.equal(rule.matchConditions[0].selector, "Host");
  assert.deepEqual(rule.matchConditions[0].matchValue, ["operator-unit.azurefd.net"]);
  assert.ok(rule.matchConditions[1].matchValue[0].includes("/evidence/live-probe/"));
});

test("foreign policies, disabled protection, colliding or drifted test rules are rejected", () => {
  for (const mutate of [
    (p) => { p.id = p.id.replace("p2popproof1023cwaf", "p2sproof1023cwaf"); },
    (p) => { p.properties.policySettings.mode = "Detection"; },
    (p) => { p.tags["pawprint.expiresAt"] = "2099-01-01T00:00:00.000Z"; },
    (p) => { p.properties.customRules.rules.push({ name: "Foreign", priority: 197 }); },
    (p) => { const rule = liveProbeRule(config); rule.matchConditions[1].matchValue = ["/"]; p.properties.customRules.rules.push(rule); },
  ]) {
    const p = policy();
    mutate(p);
    assert.throws(() => changeProbeRule(config, p, "Log"));
  }
  assert.throws(() => changeProbeRule(config, policy(), "Block"), /Log baseline/);
  assert.throws(() => changeProbeRule(config, policy(), "Remove"), /No owned/);
  assert.throws(() => changeProbeRule(config, policy(), "arbitrary"), /Unknown/);
});

test("transport expectations and observations follow the policy mode, not a fixed label", () => {
  assert.equal(expectedTransportStatus("Block", "Prevention"), 403);
  assert.equal(expectedTransportStatus("Block", "Detection"), 200);
  assert.equal(expectedTransportStatus("Log", "Prevention"), 200);
  assert.equal(expectedTransportStatus("absent", "Prevention"), 200);
  assert.throws(() => expectedTransportStatus("Block", "Disabled"), /Unknown/);
  assert.equal(liveWafObservation(config, policy()).mode, "Prevention");
  const detection = policy();
  detection.properties.policySettings.mode = "Detection";
  assert.throws(() => liveWafObservation(config, detection), /Prevention/);
});
