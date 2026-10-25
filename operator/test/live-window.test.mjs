import assert from "node:assert/strict";
import test from "node:test";
import { makeVerifier, passwordMatches, validateVerifier } from "../auth.mjs";
import { assertLive } from "../config.mjs";
import { parseLiveWindow } from "../live-config.mjs";
import { authorizeLiveWindow, ownerLiveSession } from "../live-authorize.mjs";

const subscription = "16037566-d4df-4c7c-b484-346d8472b4c4";
const id = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const originalExpiry = "2026-10-24T18:45:04.967Z";
const originalStart = Date.parse("2026-10-24T16:00:00.000Z");
const now = Date.parse("2026-10-25T00:00:00.000Z");
const document = {
  schemaVersion: 1, id, notBefore: new Date(now).toISOString(),
  expiresAt: new Date(now + 4 * 3_600_000).toISOString(), resourceGroup: "rg-p2sc-proof1023c-dev", autoTeardown: true,
};
const invocation = { subscription, suffix: "proof1023c" };
const window = parseLiveWindow({ OPERATOR_LIVE_ENABLED: "true", OPERATOR_LIVE_WINDOW: JSON.stringify(document) }, invocation);
const config = {
  invocation, liveWindow: window, originalExpiry, originalExpiresAt: Date.parse(originalExpiry),
  expiry: window.expiresAt, expiresAt: window.endsAt, verifierSecret: "operator-admin-verifier",
};
const password = "local-negative-test-password-not-live-credentials";
const original = await makeVerifier("dojo-admin", password, originalExpiry, originalStart);

function fixture() {
  const data = new Map();
  const audits = [];
  const calls = [];
  let secret = { value: JSON.stringify(original), properties: { enabled: true, notBefore: new Date(originalStart), expiresOn: new Date(originalExpiry) } };
  const store = {
    async read(key) { return data.has(key) ? { value: structuredClone(data.get(key)), etag: "known" } : undefined; },
    async write(key, value) { data.set(key, structuredClone(value)); },
    async audit(event, fields) { audits.push({ event, fields }); },
    async withLease(name, operation) { return operation({ assertLease() {} }); },
  };
  const vault = {
    async getSecret(name) {
      assert.equal(name, config.verifierSecret, "No username/password secret value may be retrieved.");
      calls.push("get-verifier");
      return structuredClone(secret);
    },
    async setSecret(name, value, properties) {
      assert.equal(name, config.verifierSecret);
      calls.push("set-verifier");
      secret = { value, properties };
      return structuredClone(secret);
    },
  };
  const group = {
    id: window.groupId,
    tags: { "dojo.liveWindowId": id, "dojo.liveScenario": "php2proof-private-live",
      "pawprint.environment": "dev", "pawprint.expiresAt": window.expiresAt },
  };
  return { store, vault, data, audits, calls, group, readGroup: async (target) => { assert.equal(target, window.groupId); return group; },
    now: () => now, wait: async () => {}, secret: () => secret };
}

test("live windows are explicit, exact-scope, short-lived and require private automatic teardown", () => {
  assert.equal(parseLiveWindow({}, invocation), undefined);
  for (const change of [
    { autoTeardown: false }, { resourceGroup: "NP-PHPToProof-Dev-CentralUS" }, { target: "https://foreign.invalid" },
    { expiresAt: new Date(now + 4 * 3_600_000 + 1).toISOString() }, { id: "not-a-window" },
    { notBefore: document.expiresAt }, { schemaVersion: 2 },
  ]) {
    assert.throws(() => parseLiveWindow({ OPERATOR_LIVE_ENABLED: "true", OPERATOR_LIVE_WINDOW: JSON.stringify({ ...document, ...change }) }, invocation));
  }
  assert.throws(() => parseLiveWindow({ OPERATOR_LIVE_WINDOW: JSON.stringify(document) }, invocation), /explicit/);
  assert.throws(() => parseLiveWindow({ OPERATOR_LIVE_ENABLED: "yes" }, invocation), /boolean/);
  assert.throws(() => parseLiveWindow({
    OPERATOR_LIVE_ENABLED: "true", OPERATOR_LIVE_WINDOW: JSON.stringify(document),
    OPERATOR_LIVE_CAPTURE_ID: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
  }, invocation), /exact approved/);
  assert.doesNotThrow(() => assertLive(config, now));
  assert.throws(() => assertLive(config, now - 1), /not active/);
  assert.throws(() => assertLive(config, config.expiresAt), /not active/);
});

test("owner reauthorization preserves original expiry/password and rotates only the verifier epoch", async () => {
  const f = fixture();
  const result = await authorizeLiveWindow(config, f, id);
  assert.equal(result.status, "completed");
  const credential = validateVerifier(f.secret(), config, now);
  assert.equal(credential.epoch, id);
  assert.equal(credential.salt, original.salt);
  assert.equal(credential.verifier, original.verifier);
  assert.equal(credential.expiresAt, window.expiresAt);
  assert.equal(config.originalExpiry, originalExpiry);
  assert.equal(await passwordMatches(credential, original.username, password), true);
  await authorizeLiveWindow(config, f, id);
  assert.equal(f.calls.filter((call) => call === "set-verifier").length, 1);
  assert.ok(f.audits.some((event) => event.event === "live-authorization-intent"));
  const session = await ownerLiveSession(config, f.store, async () => credential, () => now);
  assert.equal(session.epoch, id);
  assert.ok(session.expiresAt <= config.expiresAt);
  assert.equal(session.sessionToken, undefined);
  assert.ok(await f.store.read(`sessions/${session.hash}`));
});

test("foreign targets, active old credentials and unapproved owner IDs never produce a verifier write", async () => {
  const wrongId = fixture();
  await assert.rejects(authorizeLiveWindow(config, wrongId, "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"), /exact/);
  assert.deepEqual(wrongId.calls, []);
  const foreign = fixture();
  foreign.group.id = `/subscriptions/${subscription}/resourceGroups/NP-PHPToProof-Dev-CentralUS`;
  await assert.rejects(authorizeLiveWindow(config, foreign, id), /ownership/);
  assert.deepEqual(foreign.calls, []);
  const active = fixture();
  await assert.rejects(authorizeLiveWindow({ ...config, originalExpiresAt: now + 1000 }, active, id), /currently active/);
  assert.equal(active.calls.includes("set-verifier"), false);
});

test("ambiguous credential writes leave an intent and are never automatically replayed", async () => {
  const f = fixture();
  let writes = 0;
  f.vault.setSecret = async () => { writes += 1; throw new Error("transport failed"); };
  await assert.rejects(authorizeLiveWindow(config, f, id), /Reconcile/);
  await assert.rejects(authorizeLiveWindow(config, f, id), /reconciliation/);
  assert.equal(writes, 1);
  assert.equal((await f.store.read(`control/live-authorize/${id}`)).value.status, "starting");
  await assert.rejects(ownerLiveSession(config, f.store, async () => original, () => now), /completed explicit/);
});

test("explicit permission propagation retries do not retry ambiguous writes", async () => {
  const f = fixture();
  const set = f.vault.setSecret;
  let attempts = 0;
  f.vault.setSecret = async (...args) => {
    attempts += 1;
    if (attempts < 3) { const error = new Error("permission pending"); error.statusCode = 403; throw error; }
    return set(...args);
  };
  assert.equal((await authorizeLiveWindow(config, f, id)).status, "completed");
  assert.equal(attempts, 3);
});
