import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { publicSnapshot, captureEvidence } from "../evidence.mjs";
import { config } from "./support.mjs";

const run = {
  runId: "12345678-1234-4234-8234-123456789abc", startedAt: "2026-10-24T14:00:00.000Z", endedAt: "2026-10-24T14:00:02.000Z",
  requests: ["request", "php-error", "process-synthetic", "outbound-synthetic", "canary"].map((signal) => ({ signal, status: 200, synthetic: true })),
};

test("actual source failures remain explicit and never become fabricated Defender alerts", async () => {
  const evidence = await captureEvidence(config(), run, {
    logs: async (query) => {
      assert.match(query, /12345678-1234-4234-8234-123456789abc/);
      assert.match(query, /_ResourceId =~/);
      return [];
    },
    graph: async () => ({ data: [{ Assessment: "HTTPS", Status: "Healthy" }] }),
    alerts: async () => { throw new Error("Defender alerts not authorized"); },
    pricing: async () => ({ pricingTier: "Standard" }),
  }, () => {});
  assert.equal(evidence.captures.defenderAlerts.status, "unavailable");
  assert.equal(evidence.captures.application.rows.length, 0);
  assert.match(evidence.comparison, /Not a Defender-disabled/);
  assert.equal(evidence.captures.posture.rows[0].Status, "Healthy");
});

test("manual public export is field-allowlisted, deduplicated and drops raw/private/error data", () => {
  const row = { Utc: "2026-10-24T14:00:00Z", Rule: "DojoBenignMarker", Action: "Block", WafMode: "detection", clientIp: "1.2.3.4", Raw: "password=private" };
  const source = {
    schemaVersion: 1, ...run, capturedAt: "2026-10-24T14:02:00Z",
    comparison: "password=do-not-copy", classifications: { secret: "do-not-copy" },
    scope: { tenant: "private" }, plans: { AppServices: { status: "queried", tier: "Standard", secret: "private" } },
    captures: {
      waf: { status: "queried", rows: [row, row] },
      application: { status: "queried", rows: [{ Signal: "request", Synthetic: true, EvidenceKind: "synthetic-application-log", Message: "do-not-copy", Raw: "clientIp:1.2.3.4" }] },
      posture: { status: "queried", rows: [{ Assessment: "HTTPS check", Status: "Healthy", tenantId: "private" }] },
      defenderAlerts: { status: "unavailable", error: "authorization token=private" },
    },
  };
  const result = publicSnapshot(source);
  const text = JSON.stringify(result);
  assert.equal(result.captures.waf.rows.length, 1);
  assert.equal(result.captures.waf.rows[0].Action, "Block");
  assert.equal(result.captures.waf.rows[0].WafMode, "detection");
  assert.ok(!text.includes("private"));
  assert.ok(!text.includes("1.2.3.4"));
  assert.ok(!text.includes("do-not-copy"));
  assert.ok(!text.includes("token="));
  assert.match(result.classifications.waf, /not enforced blocking/);
});

test("the reviewed actual capture contains all five ingested fixtures, observed plans and honest Defender results", () => {
  const record = JSON.parse(readFileSync(new URL("../public-evidence/92ad189c-9a88-4403-b773-52453963e4b8.json", import.meta.url), "utf8"));
  assert.deepEqual(publicSnapshot(record), record);
  assert.equal(record.requests.length, 5);
  assert.ok(record.requests.every((item) => item.status === 200 && item.synthetic === true));
  assert.deepEqual(record.captures.application.rows.map((item) => item.Signal), record.requests.map((item) => item.signal));
  assert.equal(record.captures.waf.rows[0].Action, "Block");
  assert.equal(record.captures.waf.rows[0].WafMode, "detection");
  assert.equal(record.captures.posture.rows.length, 4);
  assert.ok(record.captures.posture.rows.every((item) => item.Status === "Healthy"));
  assert.equal(record.captures.defenderAlerts.status, "queried");
  assert.deepEqual(record.captures.defenderAlerts.rows, []);
  assert.ok(Object.values(record.plans).every((plan) => plan.tier === "Standard"));
  assert.match(record.comparison, /Not a Defender-disabled control run/);
});
