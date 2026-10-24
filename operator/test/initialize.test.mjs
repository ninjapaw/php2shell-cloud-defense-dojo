import test from "node:test";
import assert from "node:assert/strict";
import { once } from "node:events";
import { randomUUID } from "node:crypto";
import { createOperatorServer } from "../server.mjs";
import { initialize } from "../initialize.mjs";
import { Authentication, validateVerifier } from "../auth.mjs";
import { ControlPlane } from "../control.mjs";
import { config, MemoryStore } from "./support.mjs";

test("one-time private bootstrap verifies actual HTTP login/CSRF and never automatically replays", async (t) => {
  const cfg = config();
  const store = new MemoryStore();
  const secrets = new Map();
  const vault = {
    getSecret: async (name) => {
      if (!secrets.has(name)) throw Object.assign(new Error("Not found"), { statusCode: 404 });
      return secrets.get(name);
    },
    setSecret: async (name, value, properties) => {
      const secret = { value, properties }; secrets.set(name, secret); return secret;
    },
  };
  const credentials = async () => validateVerifier(await vault.getSecret("operator-admin-verifier"), cfg);
  const auth = new Authentication(cfg, store, credentials);
  let simulations = 0;
  const signals = ["request", "php-error", "process-synthetic", "outbound-synthetic", "canary"];
  const control = new ControlPlane(cfg, store, credentials, () => ({
    az: async () => ({}),
    logs: async (query) => query.startsWith("AppServiceConsoleLogs")
      ? signals.map((Signal) => ({ Signal, Synthetic: true, EvidenceKind: "synthetic-application-log" }))
      : [{ Rule: "DojoBenignMarker", Action: "Block", WafMode: "detection" }],
    graph: async () => ({ data: [] }), alerts: async () => [], pricing: async () => ({ pricingTier: "Standard" }),
  }), {
    run: async () => {
      simulations += 1;
      return { runId: randomUUID(), startedAt: new Date().toISOString(), endedAt: new Date().toISOString(),
        requests: signals.map((signal) => ({ signal, status: 200, synthetic: true })) };
    }, log: () => {},
  });
  const serviceErrors = [];
  const server = createOperatorServer(cfg, { store, auth, control, log: (value) => serviceErrors.push(value) });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  cfg.origin = `http://127.0.0.1:${server.address().port}`;
  const originalFetch = globalThis.fetch;
  const originalLog = console.log;
  const logs = [];
  globalThis.fetch = (url, options) => originalFetch(url, { ...options, headers: { ...options.headers, "X-Azure-FDID": cfg.frontDoorId } });
  console.log = (message) => logs.push(message);
  let busy = false;
  const worker = setInterval(async () => {
    if (busy) return;
    busy = true;
    try { await control.workOnce(); } finally { busy = false; }
  }, 20);
  t.after(async () => {
    clearInterval(worker);
    globalThis.fetch = originalFetch;
    console.log = originalLog;
    await new Promise((resolve) => server.close(resolve));
  });
  const id = randomUUID();
  await initialize(cfg, { store, auth, control, vault }, id).catch((error) => {
    throw new Error(`${error.message}; service diagnostics: ${serviceErrors.join("; ")}`);
  });
  assert.equal(simulations, 1);
  assert.equal((await store.read(`control/initialize-${id}`)).value.status, "succeeded");
  assert.ok(logs.some((line) => line.startsWith("OPERATOR_VERIFIED_LOGIN")));
  assert.ok(logs.some((line) => line.startsWith("OPERATOR_REDACTED_EVIDENCE ")));
  assert.ok(!logs.some((line) => line.includes(secrets.get("operator-admin-password").value)));
  await initialize(cfg, { store, auth, control, vault }, id);
  assert.equal(simulations, 1);
});
