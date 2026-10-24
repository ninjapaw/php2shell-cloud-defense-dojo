import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync } from "node:fs";
import { parseConfigJson, parseInvocation, validateConfig, names } from "../scripts/lib/config.mjs";
import {
  assertEndpointHost, assertOriginHost, assertOriginRestrictions, assertOwnedGroup,
  assertWhatIf, desiredState, hasPermission, redact, request,
} from "../scripts/lib/safety.mjs";
import { configuration, DEFAULT_CONFIG, FDID, ownedGroup, restrictedConfig, SUBSCRIPTION } from "./support/harness.mjs";
import { createAzureClient, readAzureCollection } from "../scripts/lib/azure.mjs";

test("public recorded evidence routes its stylesheet but never the private console", () => {
  const source = readFileSync(new URL("../infra/operator-routes.bicep", import.meta.url), "utf8");
  const match = /resource publicEvidenceRoute\b[\s\S]*?patternsToMatch:\s*(\[[^\]]*\])/.exec(source);
  assert.ok(match, "The reviewed public evidence route must be explicit.");
  assert.deepEqual(JSON.parse(match[1].replaceAll("'", '"')), ["/evidence/*", "/style.css"]);
});

test("configuration and CLI reject production, unknown keys, invalid types and arbitrary targets", () => {
  for (const environment of ["prod", "production", "test", "DEV", "", "dev; echo unsafe"]) {
    assert.throws(() => parseInvocation(["plan", "--environment", environment, "--suffix", "demo1234"], DEFAULT_CONFIG, {}));
    assert.throws(() => validateConfig({ ...DEFAULT_CONFIG, environment }));
  }
  for (const patch of [{ ttlHours: 0 }, { ttlHours: 73 }, { ttlHours: "24" }, { phpVersion: "7.4" }, { location: "east us" }, { secret: "do-not-store" }]) {
    assert.throws(() => validateConfig({ ...DEFAULT_CONFIG, ...patch }));
  }
  for (const flag of ["--target", "--url", "--host", "--resource-group", "--allow-production", "--config"]) {
    assert.throws(() => parseInvocation(["simulate", "--suffix", "demo1234", flag, "https://example.invalid"], DEFAULT_CONFIG, {}));
  }
  for (const suffix of ["abc", "a".repeat(13), "PROD", "../other", "demo;id", "demo-dev", "demo\nbad"]) {
    assert.throws(() => parseInvocation(["plan", "--suffix", suffix], DEFAULT_CONFIG, {}));
  }
  assert.throws(() => parseInvocation(["doctor", "--suffix", "demo1234"], DEFAULT_CONFIG, {}), /explicit subscription/);
  assert.throws(() => parseInvocation(["plan", "--suffix", "demo1234", "--subscription", "not-a-uuid"], DEFAULT_CONFIG, {}));
  assert.throws(() => parseInvocation(["plan", "deploy", "--suffix", "demo1234"], DEFAULT_CONFIG, {}));
  assert.throws(() => parseInvocation(["plan", "--suffix", "demo1234", "--waf-mode", "Off"], DEFAULT_CONFIG, {}));
  assert.equal(parseInvocation(["plan", "--suffix", "demo1234"], DEFAULT_CONFIG, {}).environment, "dev");
  assert.equal(parseInvocation(["doctor"], DEFAULT_CONFIG, { DOJO_SUFFIX: "demo1234", AZURE_SUBSCRIPTION_ID: SUBSCRIPTION }).subscription, SUBSCRIPTION);
  assert.throws(() => parseConfigJson('{"password":"accidental-secret",invalid}'), (error) =>
    error.message.includes("contents omitted") && !error.message.includes("accidental-secret"));
  assert.throws(() => parseInvocation(["validate", "--suffix", "demo1234", "--subscription", SUBSCRIPTION,
    "--enable-defender-cspm"], DEFAULT_CONFIG, {}), /opt-ins do not apply/);
  assert.throws(() => parseInvocation(["protect", "--suffix", "demo1234", "--subscription", SUBSCRIPTION,
    "--waf-mode", "Detection"], DEFAULT_CONFIG, {}), /explicitly enforce Prevention/);
});

test("JSON resourceGroup is required, bounded, and authoritative for every resource ID", () => {
  for (const resourceGroup of [undefined, null, 42, "", "a".repeat(91), "other/group", "group.", "group\n", " group", "group;id"]) {
    assert.throws(() => parseConfigJson(JSON.stringify({ ...DEFAULT_CONFIG, resourceGroup })), /resourceGroup/);
  }
  for (const resourceGroup of ["g", "a".repeat(90), "NP-PHPToProof-Dev-EastUS2-team42", "rg-p2s-demo1234-dev"]) {
    const settings = parseConfigJson(JSON.stringify({ ...DEFAULT_CONFIG, resourceGroup }));
    const config = parseInvocation(["plan", "--suffix", "demo1234", "--subscription", SUBSCRIPTION], settings, {});
    const n = names(config);
    assert.equal(n.group, resourceGroup);
    assert.equal(n.groupId, `/subscriptions/${SUBSCRIPTION}/resourceGroups/${resourceGroup}`);
    for (const [key, value] of Object.entries(n).filter(([key]) => key.endsWith("Id"))) {
      assert.ok(value === n.groupId || value.startsWith(`${n.groupId}/`), key);
    }
    assert.equal(names({ ...config, suffix: "next1234", location: "westus" }).group, resourceGroup);
    assert.equal(n.app, "p2s-demo1234-app");
  }
});

test("ownership requires exact group ID, scenario, suffix, dev tags and valid state metadata", () => {
  const config = configuration("uninstall");
  const group = ownedGroup(config);
  assert.equal(assertOwnedGroup(group, config), group);
  const normalized = structuredClone(group);
  normalized.name = normalized.name.toLowerCase();
  normalized.id = normalized.id.toUpperCase();
  assert.equal(assertOwnedGroup(normalized, config), normalized);
  for (const mutate of [
    (value) => { value.id += "-other"; },
    (value) => { value.name = "production"; },
    (value) => { value.location = "westus"; },
    (value) => { value.tags["pawprint.managed"] = "false"; },
    (value) => { value.tags["pawprint.environment"] = "prod"; },
    (value) => { value.tags["dojo.suffix"] = "someoneelse"; },
    (value) => { value.tags["dojo.scenario"] = "other"; },
    (value) => { value.tags["pawprint.expiresAt"] = "not-a-date"; },
    (value) => { value.tags["pawprint.ttlHours"] = "999"; },
    (value) => { value.tags["dojo.state"] = "vulnerable"; },
    (value) => { delete value.tags["dojo.sentinel"]; },
  ]) {
    const invalid = structuredClone(group);
    mutate(invalid);
    assert.throws(() => assertOwnedGroup(invalid, config));
  }
});

test("repair retains fixed/Prevention, original expiry and opt-ins without silently enabling CSPM", () => {
  const config = configuration("repair");
  const group = ownedGroup(config, {
    "dojo.state": "fixed", "dojo.wafMode": "Prevention",
    "dojo.defenderCspmExpected": "true", "dojo.sentinel": "true", "dojo.analytics": "true",
  });
  const state = desiredState(config, group, new Date("2026-10-22T00:00:00Z"));
  assert.equal(state.labState, "fixed");
  assert.equal(state.wafMode, "Prevention");
  assert.equal(state.expiresAt, group.tags["pawprint.expiresAt"]);
  assert.equal(state.defenderCspmExpected, true);
  assert.equal(config.enableDefenderCspm, false);
  assert.equal(state.enableSentinel, true);
  assert.equal(state.enableAnalytics, true);
  assert.throws(() => desiredState({ ...config, wafMode: "Detection" }, group), /Downgrading/);
  assert.throws(() => desiredState(config), /existing/);
  assert.throws(() => desiredState(configuration("deploy", { enableAnalytics: true })), /Sentinel/);
  assert.equal(desiredState(configuration("deploy")).wafMode, "Detection");
  assert.equal(desiredState(configuration("remediate"), ownedGroup()).wafMode, "Prevention");
});

test("endpoint validation accepts only independently read scenario Azure hostnames", () => {
  const n = names(configuration("simulate"));
  assert.equal(assertEndpointHost(`${n.endpoint}-hash.z01.azurefd.net`, n.endpoint),
    `https://${n.endpoint}-hash.z01.azurefd.net`);
  assert.equal(assertOriginHost(`${n.app}-hash.eastus2-01.azurewebsites.net`, n.app),
    `https://${n.app}-hash.eastus2-01.azurewebsites.net`);
  for (const host of [
    "localhost", "127.0.0.1", "169.254.169.254", "example.com",
    `${n.endpoint}.azurefd.net.evil.invalid`, `https://${n.endpoint}.azurefd.net`,
    `${n.endpoint}.azurefd.net:443`, `user@${n.endpoint}.azurefd.net`,
    `${n.endpoint}.azurefd.net/path`, "other-entry.azurefd.net", `${n.endpoint}.AZUREFD.NET`,
  ]) assert.throws(() => assertEndpointHost(host, n.endpoint));
  assert.throws(() => assertOriginHost("another-app.azurewebsites.net", n.app));
});

test("origin needs deny-by-default and both Front Door service tag and exact profile header", () => {
  assert.doesNotThrow(() => assertOriginRestrictions(restrictedConfig(), FDID));
  for (const mutate of [
    (value) => { value.ipSecurityRestrictionsDefaultAction = "Allow"; },
    (value) => { value.ipSecurityRestrictions[0].ipAddress = "0.0.0.0/0"; },
    (value) => { delete value.ipSecurityRestrictions[0].headers; },
    (value) => { value.ipSecurityRestrictions[0].headers["x-azure-fdid"].push(SUBSCRIPTION); },
    (value) => { value.ipSecurityRestrictions.push({ action: "Allow", ipAddress: "1.2.3.4/32" }); },
  ]) {
    const invalid = restrictedConfig();
    mutate(invalid);
    assert.throws(() => assertOriginRestrictions(invalid, FDID));
  }
});

test("what-if rejects scope escapes, unsafe changes, unapproved pricing and incomplete results", () => {
  const config = configuration("deploy");
  const groupId = names(config).groupId;
  assertWhatIf({ status: "Succeeded", changes: [{ resourceId: `${groupId}/providers/Microsoft.Web/sites/app`, changeType: "Create" }] }, config);
  for (const change of [
    { resourceId: `${groupId}-other/providers/Microsoft.Web/sites/app`, changeType: "Create" },
    { resourceId: `/subscriptions/${SUBSCRIPTION}`, changeType: "Modify" },
    { resourceId: groupId, changeType: "Delete" },
    { resourceId: groupId, changeType: "Ignore" },
    { resourceId: groupId, changeType: "Unsupported" },
    { resourceId: groupId, changeType: "UnknownStatus" },
    { resourceId: groupId },
    { resourceId: `/subscriptions/${SUBSCRIPTION}/providers/Microsoft.Security/pricings/CloudPosture`, changeType: "Modify" },
  ]) assert.throws(() => assertWhatIf({ status: "Succeeded", changes: [change] }, config));
  assert.throws(() => assertWhatIf({ status: "Failed", changes: [] }, config));
  assert.throws(() => assertWhatIf({ status: "Succeeded" }, config));
  assertWhatIf({ status: "Succeeded", changes: [{
    resourceId: `/subscriptions/${SUBSCRIPTION}/providers/Microsoft.Security/pricings/CloudPosture`, changeType: "Modify",
  }] }, { ...config, enableDefenderCspm: true });
});

test("effective permissions honor wildcards, role exclusions and additive grants", () => {
  const permission = [{ actions: ["Microsoft.Web/*"], notActions: ["Microsoft.Web/sites/delete"] }];
  assert.equal(hasPermission(permission, "Microsoft.Web/sites/write"), true);
  assert.equal(hasPermission(permission, "Microsoft.Web/sites/delete"), false);
  assert.equal(hasPermission(permission, "Microsoft.Security/pricings/write"), false);
  assert.equal(hasPermission([...permission, { actions: ["Microsoft.Web/sites/delete"], notActions: [] }], "Microsoft.Web/sites/delete"), true);
});

test("redaction covers quoted multiword secrets, escaped values, SAS, bearer and JWT tokens", () => {
  const secret = "very sensitive value";
  const examples = [
    `{"password":"${secret}"}`, `client_secret='${secret}'`,
    `{"connectionString":"Server=demo;Password=${secret};"}`,
    `accessToken="${secret}"`, "Authorization: Bearer raw-bearer-value",
    "https://example.invalid/?sig=raw-sas-value&sp=r",
    'password="escaped\\"private-value"', "token=unquoted private value",
    "eyJheader.eyJpayload.signature",
  ];
  for (const text of examples) {
    const safe = redact(text);
    assert.match(safe, /REDACTED/);
    for (const value of [secret, "raw-bearer-value", "raw-sas-value", "private-value", "unquoted private value", "eyJheader.eyJpayload.signature"]) {
      assert.ok(!safe.includes(value), `Secret leaked from ${text}`);
    }
  }
});

test("HTTP helper refuses redirects, bounds bodies, and sets a timeout", async () => {
  await assert.rejects(request("https://example.invalid", {
    fetchImpl: async (_url, options) => {
      assert.equal(options.redirect, "manual");
      assert.ok(options.signal instanceof AbortSignal);
      return new Response(null, { status: 302, headers: { Location: "http://169.254.169.254/" } });
    },
  }), /Redirects/);
  await assert.rejects(request("https://example.invalid", {
    fetchImpl: async () => new Response("x".repeat(65_537)),
  }), /64 KiB/);
  assert.deepEqual(await request("https://example.invalid", {
    fetchImpl: async () => new Response("ok"),
  }), { status: 200, text: "ok" });
});

test("Azure CLI uses an explicit subscription, refuses implicit extension installation and omits raw invalid JSON", () => {
  const calls = [];
  const client = createAzureClient(configuration("doctor"), (command, args, options) => {
    calls.push({ command, args, options });
    return "{}";
  });
  client(["provider", "show", "--namespace", "Microsoft.Web"]);
  client(["account", "show"]);
  client(["deployment", "sub", "what-if"]);
  client(["deployment", "group", "what-if", "--no-pretty-print"]);
  assert.equal(calls[0].command, "az");
  assert.ok(calls[0].args.includes(SUBSCRIPTION));
  assert.ok(!calls[1].args.includes("--subscription"), "Active account is checked, not silently replaced.");
  assert.equal(calls[2].args.filter((arg) => arg === "--no-pretty-print").length, 1);
  assert.equal(calls[3].args.filter((arg) => arg === "--no-pretty-print").length, 1);
  assert.ok(!calls[0].args.includes("--no-pretty-print"));
  for (const call of calls) {
    assert.equal(call.options.env.AZURE_EXTENSION_USE_DYNAMIC_INSTALL, "no");
    assert.equal(call.options.env.AZURE_CORE_COLLECT_TELEMETRY, "false");
  }
  const invalid = createAzureClient(configuration("doctor"), () => "not JSON: accidental-private-value");
  assert.throws(() => invalid(["provider", "show"]), (error) =>
    error.message.includes("invalid JSON") && !error.message.includes("accidental-private-value"));
  const failed = createAzureClient(configuration("doctor"), () => {
    throw new Error("The content for this response was already consumed; token=unit-test-sensitive-value");
  });
  assert.throws(() => failed(["deployment", "sub", "what-if", "--parameters", "private-parameter-value"]), (error) =>
    error.message.includes("Azure deployment sub what-if")
    && error.message.includes("already consumed")
    && !error.message.includes("unit-test-sensitive-value")
    && !error.message.includes("private-parameter-value"));
});

test("Azure webapp plan read-back normalizes CLI naming and rejects ambiguous identities", () => {
  const planId = `/subscriptions/${SUBSCRIPTION}/resourceGroups/group/providers/Microsoft.Web/serverfarms/plan`;
  for (const payload of [
    { appServicePlanId: planId },
    { appServicePlanId: planId, serverFarmId: null },
    { serverFarmId: planId },
    { appServicePlanId: planId, serverFarmId: planId.toUpperCase() },
  ]) {
    const client = createAzureClient(configuration("validate"), () => JSON.stringify(payload));
    assert.equal(client(["webapp", "show"]).serverFarmId, planId);
  }
  for (const payload of [
    { appServicePlanId: planId, serverFarmId: `${planId}-foreign` },
    { appServicePlanId: 123 },
    { appServicePlanId: "" },
  ]) {
    const client = createAzureClient(configuration("validate"), () => JSON.stringify(payload));
    assert.throws(() => client(["webapp", "show"]), /invalid or conflicting/);
  }
  const other = createAzureClient(configuration("validate"), () => JSON.stringify({ appServicePlanId: planId }));
  assert.deepEqual(other(["resource", "show"]), { appServicePlanId: planId });
});

test("Azure collection pagination is complete, bounded and restricted to the original management path", async () => {
  const url = `https://management.azure.com/subscriptions/${SUBSCRIPTION}/providers/Microsoft.Authorization/permissions?api-version=2022-04-01`;
  const calls = [];
  const result = await readAzureCollection(async (args) => {
    calls.push(args);
    return calls.length === 1 ? { value: [1], nextLink: `${url}&skiptoken=next` } : { value: [2] };
  }, url);
  assert.deepEqual(result, [1, 2]);
  assert.equal(calls.length, 2);
  for (const nextLink of [
    "https://example.invalid/permissions", `${url.split("?")[0]}/other`, 123, "",
    url.replace("https://", "https://unexpected:credential@"), `${url}#unexpected-fragment`,
  ]) {
    let requests = 0;
    await assert.rejects(() => readAzureCollection(() => {
      requests += 1;
      return { value: [], nextLink };
    }, url), /continuation/);
    assert.equal(requests, 1, "A foreign/invalid continuation must not be requested.");
  }
  await assert.rejects(() => readAzureCollection(() => ({}), url), /value array/);
  await assert.rejects(() => readAzureCollection(() => ({ value: [] }), "https://example.invalid/"), /management endpoint/);
  let pages = 0;
  await assert.rejects(() => readAzureCollection(() => {
    pages += 1;
    return { value: [], nextLink: `${url}&page=${pages}` };
  }, url), /10-page limit/);
  assert.equal(pages, 10);
});
