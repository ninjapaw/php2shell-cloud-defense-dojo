import test from "node:test";
import assert from "node:assert/strict";
import { ReadOnlyAzure, AzureReadError, boundedJson } from "../azure.mjs";
import { config } from "./support.mjs";

const credential = { getToken: async () => ({ token: "unit-test-token", expiresOnTimestamp: Date.now() + 60_000 }) };

test("managed identity adapter denies every write and all foreign targets before network access", async () => {
  const cfg = config();
  let reads = 0;
  const azure = new ReadOnlyAzure(cfg, credential, { fetchImpl: async () => { reads += 1; throw new Error("Unexpected network"); } });
  for (const args of [
    ["group", "delete", "--name", cfg.names.group],
    ["deployment", "sub", "create"], ["webapp", "deploy"], ["security", "pricing", "create"],
    ["resource", "show", "--ids", `${cfg.names.groupId}/other`, "--api-version", "2025-03-01"],
    ["resource", "show", "--ids", cfg.names.profileId, "--api-version", "different"],
    ["rest", "--method", "get", "--url", "https://attacker.invalid/"],
    ["graph", "query", "--graph-query", "Resources | take 100", "--subscriptions", cfg.invocation.subscription],
  ]) await assert.rejects(() => azure.az(args), /outside the fixed/);
  assert.equal(reads, 0);
});

test("Azure requests are bounded, explicit-token reads; redirects and bad/incomplete responses are failures", async () => {
  const cfg = config();
  let guards = 0;
  const azure = new ReadOnlyAzure(cfg, credential, {
    guard: async () => { guards += 1; },
    fetchImpl: async (url, options) => {
      assert.ok(url.startsWith("https://management.azure.com/subscriptions/"));
      assert.equal(options.method, "GET");
      assert.equal(options.redirect, "manual");
      assert.ok(options.signal instanceof AbortSignal);
      assert.equal(options.headers.Authorization, "Bearer unit-test-token");
      return Response.json({ subscriptionId: cfg.invocation.subscription, state: "Enabled" });
    },
  });
  assert.equal((await azure.az(["account", "show"])).id, cfg.invocation.subscription);
  assert.ok(guards >= 1);
  const redirect = new ReadOnlyAzure(cfg, credential, { fetchImpl: async () => new Response("", { status: 302 }) });
  await assert.rejects(() => redirect.az(["account", "show"]), /redirects/);
  await assert.rejects(() => boundedJson(new Response("not JSON")), /invalid JSON/);
  await assert.rejects(() => boundedJson(new Response("x".repeat(1_048_577))), /1 MiB/);
  await assert.rejects(() => boundedJson(Response.json({ error: { code: "Forbidden" } }, { status: 403 })), AzureReadError);
  const partial = new ReadOnlyAzure(cfg, credential, { fetchImpl: async () => Response.json({ data: [], resultTruncated: true }) });
  await assert.rejects(() => partial.graph("unit test bounded query"), /incomplete/);
});

test("role validation includes inherited scope but only returns the exact public application principal", async () => {
  const cfg = config();
  const principal = "22222222-2222-4222-8222-222222222222";
  const azure = new ReadOnlyAzure(cfg, credential, { fetchImpl: async (url) => {
    if (url.includes("/roleAssignments")) {
      assert.ok(new URL(url).searchParams.get("$filter") === "atScope()");
      return Response.json({ value: [
        { id: "owned", properties: { principalId: principal, roleDefinitionId: "role" } },
        { id: "other", properties: { principalId: "other", roleDefinitionId: "other-role" } },
      ] });
    }
    return Response.json({ id: cfg.names.appId, identity: { principalId: principal }, properties: { state: "Running" } });
  } });
  await azure.az(["webapp", "show", "--resource-group", cfg.names.group, "--name", cfg.names.app]);
  const result = await azure.az(["role", "assignment", "list", "--scope", cfg.names.appId, "--include-inherited",
    "--fill-principal-name", "false", "--query", `[?principalId=='${principal}'].{id:id,roleDefinitionId:roleDefinitionId}`]);
  assert.deepEqual(result, [{ id: "owned", roleDefinitionId: "role" }]);
});
