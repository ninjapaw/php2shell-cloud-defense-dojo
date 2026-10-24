import assert from "node:assert/strict";
import test from "node:test";
import { execute } from "../scripts/dojo.mjs";
import { names } from "../scripts/lib/config.mjs";
import { configuration, harness, ownedGroup, SUBSCRIPTION, syntheticRule } from "./support/harness.mjs";

test("offline plan never contacts Azure, packages code or makes requests", async () => {
  const config = configuration("plan", { subscription: undefined });
  const h = harness(config);
  const result = await execute(config, h.dependencies);
  assert.equal(result.environment, "dev");
  assert.equal(result.optional.subscriptionWideBillableCloudPosture, false);
  assert.equal(result.initialState.wafMode, "Detection");
  assert.equal(h.calls.length, 0);
  assert.equal(h.requests.length, 0);
  assert.equal(h.state.packaged, 0);
});

test("doctor performs a read-only preflight plus bounded what-if, with no deployment", async () => {
  const config = configuration("doctor", { enableSentinel: true });
  const h = harness(config);
  const result = await execute(config, h.dependencies);
  assert.equal(result.preflight, "passed");
  assert.equal(h.state.tools, 1);
  assert.ok(h.calls.some((args) => args.join(" ").startsWith("deployment sub what-if")));
  assert.ok(!h.calls.some((args) => args.includes("create") || args.includes("register") || args.includes("delete")));
  assert.equal(h.requests.length, 0);
});

test("first deploy runs what-if before create, packages only the app, cleans up, and validates live safety", async () => {
  const config = configuration("deploy", { yes: true });
  const h = harness(config, { absent: true });
  const result = await execute(config, h.dependencies);
  assert.equal(result.validated, true);
  assert.equal(result.directOriginBlocked, true);
  assert.equal(result.runtimeRoleAssignmentsAtAppScope, 0);
  assert.match(result.permissionBoundary, /group-based and out-of-scope grants require separate review/);
  const roles = h.calls.find((args) => args.slice(0, 3).join(" ") === "role assignment list");
  assert.equal(roles[roles.indexOf("--fill-principal-name") + 1], "false");
  const whatIfIndex = h.calls.findIndex((args) => args[0] === "deployment" && args[2] === "what-if");
  const createIndex = h.calls.findIndex((args) => args[0] === "deployment" && args[2] === "create");
  assert.ok(whatIfIndex >= 0 && createIndex > whatIfIndex);
  assert.ok(h.calls[createIndex].includes("enableDefenderCspm=false"));
  assert.ok(h.calls[createIndex].includes("wafMode=Detection"));
  assert.equal(h.state.packaged, 1);
  assert.equal(h.state.cleaned, 1);
  assert.equal(h.requests.length, 4);
});

test("configured and legacy group names scope deployment, repair and exact teardown consistently", async (t) => {
  for (const resourceGroup of ["NP-PHPToProof-Dev-EastUS2-team42", "rg-p2s-demo1234-dev"]) {
    await t.test(resourceGroup, async () => {
      const config = configuration("deploy", { resourceGroup, yes: true });
      const h = harness(config, { absent: true });
      await execute(config, h.dependencies);
      await execute({ ...config, command: "repair" }, h.dependencies);
      for (const args of h.calls) {
        if (args[0] === "deployment" && ["what-if", "create"].includes(args[2])) {
          assert.ok(args.includes(`groupName=${resourceGroup}`));
        }
        if (args.includes("--resource-group")) {
          assert.equal(args[args.indexOf("--resource-group") + 1], resourceGroup);
        }
        if (args[0] === "group") assert.equal(args[args.indexOf("--name") + 1], resourceGroup);
      }
      const result = await execute({ ...config, command: "uninstall", confirmation: resourceGroup }, h.dependencies);
      assert.equal(result.deleted, resourceGroup);
      assert.deepEqual(h.calls.filter((args) => args.includes("delete")),
        [["group", "delete", "--name", resourceGroup, "--yes"]]);
    });
  }
});

test("repair is idempotent and does not reopen fixed endpoints or extend expiry", async () => {
  const config = configuration("repair", { yes: true });
  const h = harness(config, { pricingTier: "Standard", tags: {
    "dojo.state": "fixed", "dojo.wafMode": "Prevention", "dojo.defenderCspmExpected": "true",
  } });
  const expectedExpiry = h.state.group.tags["pawprint.expiresAt"];
  for (let run = 0; run < 2; run += 1) {
    const result = await execute(config, h.dependencies);
    assert.equal(result.state, "fixed");
    assert.equal(result.wafMode, "Prevention");
    assert.equal(h.state.group.tags["pawprint.expiresAt"], expectedExpiry);
  }
  for (const create of h.calls.filter((args) => args[0] === "deployment" && args[2] === "create")) {
    assert.ok(create.includes("labState=fixed"));
    assert.ok(create.includes("wafMode=Prevention"));
    assert.ok(create.includes("enableDefenderCspm=false"));
    assert.ok(create.includes("defenderCspmExpected=true"));
    assert.ok(create.includes(`expiresAt=${expectedExpiry}`));
  }
});

test("protect is an explicit separate Prevention transition and remediation disables training surfaces", async () => {
  for (const command of ["protect", "remediate"]) {
    const config = configuration(command, { yes: true });
    const h = harness(config);
    const result = await execute(config, h.dependencies);
    assert.equal(result.wafMode, "Prevention");
    assert.equal(result.state, command === "remediate" ? "fixed" : "training");
  }
});

test("fixed-state closure checks the ordinary request surface, not only the blocked WAF marker", async () => {
  const config = configuration("validate");
  const h = harness(config, {
    tags: { "dojo.state": "fixed", "dojo.wafMode": "Prevention" },
    fetchOverride: (url) => {
      const parsed = new URL(url);
      if (parsed.searchParams.get("signal") === "request" && !parsed.searchParams.has("dojoProbe")) {
        return Response.json({ synthetic: true, signal: "request" });
      }
    },
  });
  await assert.rejects(execute(config, h.dependencies), /Remediated training endpoints remain accessible/);
  assert.ok(!h.logs.some((line) => line.includes('"validated": true')));
});

test("Sentinel validation refuses an onboarded workspace with a missing synthetic rule", async () => {
  const config = configuration("validate");
  const h = harness(config, {
    tags: { "dojo.sentinel": "true" },
    azOverride: (args) => args[0] === "rest" && args[4]?.includes("/alertRules?")
      ? { value: [] } : undefined,
  });
  await assert.rejects(execute(config, h.dependencies), /Sentinel synthetic/);
  assert.ok(!h.logs.some((line) => line.includes('"validated": true')));
});

test("Sentinel rule validation preserves disabled/enabled opt-ins and accepts equivalent resource-ID casing", async () => {
  for (const enabled of [false, true]) {
    const config = configuration("validate");
    const rule = syntheticRule(config, enabled);
    rule.properties.query = rule.properties.query.replaceAll(names(config).appId, names(config).appId.toUpperCase());
    const h = harness(config, {
      tags: { "dojo.sentinel": "true", "dojo.analytics": String(enabled) },
      sentinelRules: [rule],
    });
    const result = await execute(config, h.dependencies);
    assert.deepEqual(result.sentinel, { onboarded: true, syntheticRuleConfigured: true, analyticsEnabled: enabled });
    assert.equal(h.calls.filter((args) => args[0] === "rest" && args[4]?.includes("/alertRules?")).length, 1);
    assert.ok(!h.calls.some((args) => args.includes("create") || args.includes("delete")));
  }
});

test("Sentinel rule query, scope, schedule, incident and enablement drift cannot pass validation", async () => {
  const config = configuration("validate");
  for (const mutate of [
    (rule) => { rule.id = rule.id.replace(names(config).workspaceId, "/subscriptions/other/resourceGroups/other"); },
    (rule) => { rule.kind = "NRT"; },
    (rule) => { rule.properties.enabled = true; },
    (rule) => { rule.properties.severity = "High"; },
    (rule) => { rule.properties.queryFrequency = "PT1M"; },
    (rule) => { rule.properties.queryPeriod = "P1D"; },
    (rule) => { rule.properties.triggerThreshold = 10; },
    (rule) => { rule.properties.suppressionEnabled = true; },
    (rule) => { rule.properties.incidentConfiguration.createIncident = true; },
    (rule) => { rule.properties.eventGroupingSettings.aggregationKind = "AlertPerResult"; },
    (rule) => { delete rule.properties.customDetails.RunId; },
    (rule) => { rule.properties.query = rule.properties.query.replaceAll(names(config).appId, `${names(config).appId}-other`); },
    (rule) => { rule.properties.query += "\n| take 0"; },
  ]) {
    const rule = syntheticRule(config);
    mutate(rule);
    const h = harness(config, { tags: { "dojo.sentinel": "true" }, sentinelRules: [rule] });
    await assert.rejects(execute(config, h.dependencies), /Sentinel synthetic rule/);
    assert.ok(!h.logs.some((line) => line.includes('"validated": true')));
  }
  const rule = syntheticRule(config);
  const duplicate = harness(config, { tags: { "dojo.sentinel": "true" }, sentinelRules: [rule, structuredClone(rule)] });
  await assert.rejects(execute(config, duplicate.dependencies), /ambiguous/);
});

test("all write commands and simulation require acknowledgement before Azure is contacted", async () => {
  for (const command of ["deploy", "repair", "protect", "remediate", "simulate"]) {
    const config = configuration(command);
    const h = harness(config);
    await assert.rejects(execute(config, h.dependencies), /--yes/);
    assert.equal(h.calls.length, 0);
  }
});

test("teardown requires exact confirmation, checks ownership, deletes only the group and verifies absence", async () => {
  const config = configuration("uninstall");
  for (const confirmation of [undefined, "*", "production", `/subscriptions/${SUBSCRIPTION}`, `${names(config).group}-other`]) {
    const h = harness(config);
    await assert.rejects(execute({ ...config, confirmation, yes: true }, h.dependencies), /exact scenario group/);
    assert.equal(h.calls.length, 0);
  }
  const h = harness(config);
  const result = await execute({ ...config, confirmation: names(config).group }, h.dependencies);
  assert.equal(result.deleted, names(config).group);
  assert.equal(result.subscriptionPlansChanged, false);
  const deletions = h.calls.filter((args) => args.includes("delete"));
  assert.deepEqual(deletions, [["group", "delete", "--name", names(config).group, "--yes"]]);
  assert.equal(h.state.deleted, true);
  assert.ok(!h.calls.some((args) => args.includes("pricing")));
});

test("teardown refuses an unowned group and never reports deletion that has not completed", async () => {
  const config = configuration("uninstall");
  const h = harness(config, { tags: { "dojo.scenario": "someone-else" } });
  await assert.rejects(execute({ ...config, confirmation: names(config).group }, h.dependencies), /ownership/);
  assert.ok(!h.calls.some((args) => args.includes("delete")));
  const locked = harness(config, { azOverride: (args) => args[0] === "group" && args[1] === "exists" ? true : undefined });
  await assert.rejects(execute({ ...config, confirmation: names(config).group }, locked.dependencies), /still exists/);
});

test("simulation sends exactly five scenario requests, plus four safety checks, to verified endpoints only", async () => {
  for (const wafMode of ["Detection", "Prevention"]) {
    const config = configuration("simulate", { yes: true });
    const h = harness(config, { tags: { "dojo.wafMode": wafMode } });
    const result = await execute(config, h.dependencies);
    assert.equal(result.synthetic, true);
    assert.equal(result.requests.length, 5);
    assert.equal(result.requests[0].status, wafMode === "Detection" ? 200 : 403);
    assert.deepEqual(result.requests.slice(1).map((item) => item.status), [200, 200, 200, 200]);
    assert.equal(h.requests.length, 9);
    assert.equal(h.requests.filter((item) => new URL(item.url).searchParams.get("runId") === result.runId).length, 5);
    assert.deepEqual(h.state.slept, [250, 250, 250, 250]);
    assert.ok(!h.calls.some((args) => args.includes("create") || args.includes("delete")));
    assert.equal(h.requests.filter((item) => item.options.headers["X-Azure-FDID"]).length, 1);
  }
});

test("simulation refuses fixed state and a bypassed origin before generating scenario telemetry", async () => {
  const config = configuration("simulate", { yes: true });
  const fixed = harness(config, { tags: { "dojo.state": "fixed", "dojo.wafMode": "Prevention" } });
  await assert.rejects(execute(config, fixed.dependencies), /disabled after remediation/);
  const bypass = harness(config, { originStatus: 200 });
  await assert.rejects(execute(config, bypass.dependencies), /DIRECT ORIGIN BYPASS/);
  assert.ok(bypass.requests.every((item) => !item.url.includes("signal=")));
});

test("missing diagnostics, unexpected runtime grants, CSPM downgrade, and disabled basic publishing checks are hard failures", async () => {
  const config = configuration("validate");
  for (const options of [
    { azOverride: (args) => args.slice(0, 3).join(" ") === "monitor diagnostic-settings list" ? { value: [] } : undefined },
    { azOverride: (args) => args.slice(0, 3).join(" ") === "role assignment list" ? [{ id: "unexpected" }] : undefined },
    { tags: { "dojo.defenderCspmExpected": "true" }, pricingTier: "Free" },
    { azOverride: (args) => args[0] === "resource" && args[3]?.includes("/basicPublishingCredentialsPolicies/")
      ? { id: args[3], properties: { allow: true } } : undefined },
  ]) {
    const h = harness(config, options);
    await assert.rejects(execute(config, h.dependencies));
    assert.ok(!h.logs.some((line) => line.includes('"validated": true')));
  }
});

test("preflight errors stop deployment: wrong subscription, provider, region, runtime, permissions, and escaped what-if", async () => {
  const config = configuration("deploy", { yes: true });
  for (const azOverride of [
    (args) => args[0] === "account" ? { id: "wrong", state: "Enabled" } : undefined,
    (args) => args[0] === "provider" ? { registrationState: "NotRegistered" } : undefined,
    (args) => args[0] === "appservice" ? [] : undefined,
    (args) => args[0] === "webapp" && args[1] === "list-runtimes" ? ["PHP:7.4"] : undefined,
    (args) => args[0] === "rest" ? { value: [{ actions: ["*/read"], notActions: [] }] } : undefined,
    (args) => args[0] === "deployment" && args[2] === "what-if" ? { status: "Succeeded", changes: [{ resourceId: "/subscriptions/other", changeType: "Modify" }] } : undefined,
  ]) {
    const h = harness(config, { azOverride });
    await assert.rejects(execute(config, h.dependencies));
    assert.ok(!h.calls.some((args) => args.includes("create")));
    assert.equal(h.state.packaged, 0);
  }
});

test("code deployment failure cleans its temporary artifact and never reports success", async () => {
  const config = configuration("deploy", { yes: true });
  const h = harness(config, { deployError: true });
  await assert.rejects(execute(config, h.dependencies), /Code deployment failed/);
  assert.equal(h.state.cleaned, 1);
  assert.ok(!h.logs.some((line) => line.includes('"validated": true')));
});

test("a failed infrastructure result cannot proceed to packaging or shape a success report", async () => {
  const config = configuration("deploy", { yes: true });
  const h = harness(config, { azOverride: (args) =>
    args.slice(0, 3).join(" ") === "deployment sub create" ? { properties: { provisioningState: "Failed" } } : undefined });
  await assert.rejects(execute(config, h.dependencies), /did not reach Succeeded/);
  assert.equal(h.state.packaged, 0);
  assert.ok(!h.logs.some((line) => line.includes('"validated": true')));
});

test("investigation reports real matching records or explicit absence, not invented findings", async () => {
  const config = configuration("investigate");
  for (const assessments of [[], [{ AssessmentId: "observed-assessment", DisplayName: "PHP", Status: "Healthy" }]]) {
    const h = harness(config, { assessments });
    assert.deepEqual(await execute(config, h.dependencies), assessments);
    const graph = h.calls.find((args) => args[0] === "graph");
    assert.ok(graph.includes("--subscriptions"));
    for (const term of ["PHP", "CVE-2026-109618", "CVE-2026-109619", names(config).appId]) assert.ok(graph[3].includes(term));
    assert.ok(graph[3].includes(`id startswith '${names(config).groupId}/'`));
    assert.doesNotMatch(graph[3], /Details contains '\/subscriptions\//);
    const report = JSON.parse(h.logs[0]);
    assert.equal(report.hunting.coverage.length, 20);
    assert.equal(report.hunting.source.revision.length, 40);
    assert.ok(report.hunting.coverage.find((item) => item.id === "hunt-D1").queries.some((query) => query.path.endsWith("/appservice-http.kql")));
    assert.equal(h.calls.filter((args) => args[0] === "graph").length, 1, "The broader estate queries must not run automatically.");
    if (assessments.length === 0) assert.match(h.logs[0], /No matching PHP\/CVE assessments returned/);
  }
});

test("repair does not silently accept absent or unowned groups", async () => {
  const config = configuration("repair", { yes: true });
  for (const options of [{ absent: true }, { tags: { "pawprint.managed": "false" } }]) {
    const h = harness(config, options);
    await assert.rejects(execute(config, h.dependencies));
    assert.ok(!h.calls.some((args) => args.includes("create")));
  }
  assert.equal(ownedGroup(config).name, names(config).group);
});

test("live resource identity/hostname and routing drift cannot redirect validation or simulation", async () => {
  const config = configuration("simulate", { yes: true });
  const n = names(config);
  for (const azOverride of [
    (args) => args[0] === "resource" && args[3] === n.endpointId
      ? { id: n.endpointId, properties: { hostName: "example.invalid", enabledState: "Enabled" } } : undefined,
    (args) => args[0] === "resource" && args[3] === n.endpointId
      ? { id: `${n.endpointId}-other`, properties: {} } : undefined,
    (args) => args[0] === "resource" && args[3] === `${n.profileId}/securityPolicies/application-waf`
      ? { id: args[3], properties: { parameters: { type: "WebApplicationFirewall", wafPolicy: { id: "other" } } } } : undefined,
    (args) => args[0] === "resource" && args[3] === n.planId
      ? { id: n.planId, sku: { name: "P3v3", capacity: 5 }, properties: { reserved: true } } : undefined,
  ]) {
    const h = harness(config, { azOverride });
    await assert.rejects(execute(config, h.dependencies));
    assert.equal(h.requests.length, 0);
  }
});

test("health and marker HTTP 200 alone do not count as valid lab evidence", async () => {
  const config = configuration("validate");
  for (const fetchOverride of [
    (url) => url.endsWith("/health.php") ? Response.json(null) : undefined,
    (url) => url.includes("dojoProbe=") ? new Response("<html>not the app</html>") : undefined,
    (url) => url.endsWith("/health.php") ? Response.json({ scenario: "other" }) : undefined,
  ]) {
    const h = harness(config, { fetchOverride });
    await assert.rejects(execute(config, h.dependencies));
    assert.ok(!h.logs.some((line) => line.includes('"validated": true')));
  }
});

test("deployment readiness retries only bounded network failures and reports them explicitly", async () => {
  const config = configuration("deploy", { yes: true });
  let attempts = 0;
  const h = harness(config, { fetchOverride: (url) => {
    if (url.endsWith("/health.php") && attempts++ < 2) throw new TypeError("temporary DNS propagation");
    return undefined;
  } });
  const result = await execute(config, h.dependencies);
  assert.equal(result.validated, true);
  assert.deepEqual(h.state.slept, [10_000, 10_000]);
  assert.equal(h.logs.filter((line) => line.includes("No success asserted")).length, 2);
  const failed = harness(config, { fetchOverride: (url) => {
    if (url.endsWith("/health.php")) throw new TypeError("still unavailable");
    return undefined;
  } });
  await assert.rejects(execute(config, failed.dependencies), /NOT validated/);
  assert.equal(failed.requests.length, 12);
  assert.equal(failed.state.slept.length, 11);
  assert.ok(!failed.logs.some((line) => line.includes('"validated": true')));
});
