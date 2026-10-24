import test from "node:test";
import assert from "node:assert/strict";
import { loadHuntPack, assertHuntId, bindHuntQuery, runHunts, huntingPage,
  publicHuntingSnapshot, publicHuntingPage, initializeHuntCapture } from "../hunts.mjs";
import { setup, NOW, config, MemoryStore } from "./support.mjs";
import { ownedGroup } from "../../tests/support/harness.mjs";
import { AzureStore } from "../store.mjs";
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";

test("reviewed actual hunting recording retains true outcomes and matches every displayed query", () => {
  const snapshot = JSON.parse(readFileSync(new URL("../public-evidence/hunting.json", import.meta.url), "utf8"));
  const pack = loadHuntPack();
  assert.equal(snapshot.reviewed, true);
  assert.equal(snapshot.runId, "5c4df084-1156-4807-a989-701317fe68c8");
  assert.equal(snapshot.results.length, 27);
  assert.equal(snapshot.results.filter((item) => item.status === "queried").length, 3);
  assert.equal(snapshot.results.filter((item) => item.status === "unavailable").length, 18);
  assert.equal(snapshot.results.filter((item) => item.status === "not-applicable").length, 6);
  for (const item of snapshot.results) {
    const entry = pack.queries.find((query) => query.id === item.id);
    assert.equal(item.queryTemplateSha256, createHash("sha256").update(entry.template).digest("hex"));
    if (item.status !== "queried") {
      assert.equal(item.rows, null);
      assert.equal(item.rowCount, null);
    }
  }
  const html = publicHuntingPage(snapshot);
  assert.equal((html.match(/id="hunt-/g) ?? []).length, 27);
  assert.doesNotMatch(html, /<form|<script|16037566-d4df-4c7c-b484-346d8472b4c4/);
  assert.match(html, /1 MiB response bound/);
});

test("hunting records reuse only the existing private evidence/control key namespaces", () => {
  const store = new AzureStore({ getBlockBlobClient: (name) => name }, {});
  assert.equal(store.blob("evidence/hunting/lab-waf"), "evidence/hunting/lab-waf.json");
  assert.match(store.blob("control/hunting-bootstrap/11111111-1111-4111-8111-111111111111"), /^control\//);
  assert.throws(() => store.blob("hunting/lab-waf"), /Invalid private/);
  assert.throws(() => store.blob("evidence/../secrets"), /Invalid private/);
});

function azure(calls = []) {
  return {
    az: async () => ownedGroup(),
    tables: async () => ["AzureDiagnostics", "AppServiceConsoleLogs", "AppServiceHTTPLogs"],
    graph: async (query) => { calls.push(query); return { data: [{ Runtime: "PHP|8.4", Apps: 1, SampleResourceIds: ["private://asset"] }] }; },
    logs: async (query, timespan) => { calls.push(query); assert.ok(timespan.includes("/")); return [{ Signal: "request", Synthetic: true, Message: "<script>unsafe</script>", ClientIp: "private-ip" }]; },
    pricing: async () => ({ pricingTier: "Standard" }),
  };
}

test("pinned hunting catalogue covers all27 queries and20 value walkthroughs without arbitrary input", () => {
  const pack = loadHuntPack();
  assert.equal(pack.queries.length, 27);
  assert.equal(pack.coverage.length, 20);
  assert.equal(pack.source.revision, "41815ef397da1fb048925815ce7c77bfe4eca5e5");
  for (const id of ["../other", "all;take100", "DeviceProcessEvents | take 1", "unknown"]) assert.throws(() => assertHuntId(id), /fixed reviewed hunt/);
  const cfg = config();
  for (const entry of pack.queries.filter((item) => item.platform === "resource-graph")) {
    const query = bindHuntQuery(cfg, entry);
    assert.ok(query.includes(cfg.names.groupId.toLowerCase()));
    assert.match(query, /startswith/);
    assert.match(query, /\| take 50$/);
  }
  for (const entry of pack.queries.filter((item) => item.platform === "lab-workspace")) {
    assert.match(bindHuntQuery(cfg, entry), /\| take 100$/);
    assert.ok(bindHuntQuery(cfg, entry).includes(cfg.names.appId.toLowerCase())
      || bindHuntQuery(cfg, entry).includes(cfg.names.profileId.toLowerCase()));
  }
});

test("hunting executes only10 owned read-only adaptations and distinguishes absent sources from actual results", async () => {
  const calls = [];
  const result = await runHunts(config(), azure(calls), "all", { now: () => NOW });
  assert.equal(result.results.length, 27);
  assert.equal(calls.length, 10);
  assert.equal(result.results.filter((row) => row.status === "queried").length, 10);
  assert.equal(result.results.filter((row) => row.platform === "defender-xdr").every((row) =>
    row.status === "unavailable" && row.rows === null && row.rowCount === null), true);
  assert.equal(result.results.filter((row) => row.status === "not-applicable").length, 6);
  assert.equal(result.plans.AppServices.tier, "Standard");
  const missing = azure();
  missing.tables = async () => [];
  const empty = await runHunts(config(), missing, "lab-waf", { now: () => NOW });
  assert.equal(empty.results[0].status, "unavailable");
  assert.equal(empty.results[0].rowCount, null);
  const failed = azure();
  failed.logs = async () => { throw new Error("Source query failed"); };
  const errors = [];
  const failure = await runHunts(config(), failed, "lab-waf", { now: () => NOW, log: (line) => errors.push(line) });
  assert.equal(failure.results[0].status, "failed");
  assert.equal(failure.results[0].rows, null);
  assert.ok(errors.some((line) => line.includes("Source query failed")));
  const oversized = azure();
  oversized.tables = async () => { throw new Error("Metadata size bound"); };
  const observed = await runHunts(config(), oversized, "lab-waf", { now: () => NOW, log: () => {} });
  assert.equal(observed.results[0].status, "queried");
  assert.equal(observed.results[0].sourceReadinessWarning, "Metadata size bound");
  oversized.logs = async () => [];
  const uncertain = await runHunts(config(), oversized, "lab-waf", { now: () => NOW, log: () => {} });
  assert.equal(uncertain.results[0].status, "queried-with-source-gap");
  assert.equal(uncertain.results[0].rowCount, 0);
});

test("public hunting snapshots require review and omit private identifiers and query bindings", async () => {
  const result = await runHunts(config(), azure(), "all", { now: () => NOW });
  const candidate = publicHuntingSnapshot(result);
  assert.throws(() => publicHuntingPage(candidate), /not been approved/);
  assert.ok(!JSON.stringify(candidate).includes("private://"));
  assert.ok(!JSON.stringify(candidate).includes("private-ip"));
  assert.ok(!JSON.stringify(candidate).includes(config().names.groupId));
  const html = publicHuntingPage({ ...candidate, reviewed: true });
  assert.match(html, /Twenty additional-value walkthroughs/);
  assert.match(html, /Without optional protection/);
  assert.match(html, /Additional value/);
  assert.doesNotMatch(html, /<form|<script/);
  const h = await setup();
  const privateHtml = await huntingPage(h.cfg, h.store, { csrf: "x".repeat(43) });
  assert.equal((privateHtml.match(/id="hunt-/g) ?? []).length, 27);
  assert.match(privateHtml, /Evaluate all scenarios/);
  assert.match(privateHtml, /No recorded execution/);
});

test("deployment hunt capture is lease/audit/expiry gated, private and never automatically replayed", async () => {
  const cfg = config();
  const store = new MemoryStore();
  const lines = [];
  const id = "11111111-1111-4111-8111-111111111111";
  const result = await initializeHuntCapture(cfg, store, () => azure(), id, { now: () => NOW, log: (line) => lines.push(line) });
  assert.equal(result.reviewed, false);
  assert.equal((await store.read(`control/hunting-bootstrap/${id}`)).value.status, "captured");
  assert.equal((await store.read("evidence/hunting/lab-waf")).value.status, "queried");
  assert.equal(lines.filter((line) => line.startsWith("HUNT_REDACTED_RESULT ")).length, 27);
  await initializeHuntCapture(cfg, store, () => { throw new Error("Must not replay"); }, id, { now: () => NOW, log: (line) => lines.push(line) });
  assert.match(lines.at(-1), /REPLAY_DENIED/);
  await assert.rejects(initializeHuntCapture({ ...cfg, expiresAt: NOW }, store, () => azure(), id, { now: () => NOW }), /lifetime has ended/);
});
