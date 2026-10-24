import test from "node:test";
import assert from "node:assert/strict";
import { validateVerifier, Authentication } from "../auth.mjs";
import { config, setup, verifier, NOW, PASSWORD, MemoryStore } from "./support.mjs";

test("Key Vault credentials fail closed for disabled, expired, invalid and out-of-lifetime metadata", () => {
  const cfg = config();
  const secret = () => ({ value: JSON.stringify(verifier), properties: { enabled: true, expiresOn: new Date(cfg.expiry) } });
  assert.equal(validateVerifier(secret(), cfg, NOW).epoch, verifier.epoch);
  for (const change of [
    (s) => { s.properties.enabled = false; },
    (s) => { s.properties.expiresOn = new Date(NOW - 1); },
    (s) => { s.properties.expiresOn = new Date("invalid"); },
    (s) => { s.properties.notBefore = new Date(NOW + 1000); },
    (s) => { s.properties.expiresOn = new Date(cfg.expiresAt + 1000); },
    (s) => { s.value = JSON.stringify({ ...verifier, verifier: "bad" }); },
    (s) => { s.value = "@Microsoft.KeyVault(unresolved)"; },
    (s) => { s.value = JSON.stringify({ ...verifier, unexpected: "field" }); },
  ]) {
    const invalid = secret(); change(invalid);
    assert.throws(() => validateVerifier(invalid, cfg, NOW));
  }
  const invalidJson = secret();
  invalidJson.value = "never-log-this-credential-value";
  assert.throws(() => validateVerifier(invalidJson, cfg, NOW), (error) => !error.message.includes(invalidJson.value));
});

test("opaque durable sessions require current Key Vault epoch and stop at logout/expiry", async () => {
  const h = await setup();
  assert.match(h.sessionToken, /^[A-Za-z0-9_-]{43}$/);
  assert.equal((await h.auth.session(h.sessionToken)).hash, h.session.hash);
  assert.ok(!JSON.stringify([...h.store.rows]).includes(h.sessionToken));
  h.rotate();
  await assert.rejects(() => h.auth.session(h.sessionToken), /sign-in/);
  const other = await setup();
  await other.auth.logout(other.session);
  await assert.rejects(() => other.auth.session(other.sessionToken), /sign-in/);
  const expired = new Authentication(other.cfg, other.store, other.credentials, () => other.cfg.expiresAt);
  await assert.rejects(() => expired.session(other.sessionToken), /lifetime/);
});

test("durable login throttling and unavailable secrets/audit deny sign-in instead of falling back", async () => {
  const cfg = config();
  const store = new MemoryStore();
  const auth = new Authentication(cfg, store, async () => verifier, () => NOW);
  for (let index = 0; index < 5; index += 1) await assert.rejects(() => auth.login("unit-admin", "incorrect"), /Invalid administrator/);
  await assert.rejects(() => auth.login("unit-admin", PASSWORD), /rate limited/);
  assert.equal(store.events.filter((row) => row.event === "login-denied").length, 5);
  const unavailable = new Authentication(cfg, new MemoryStore(), async () => { throw new Error("Key Vault unavailable"); }, () => NOW);
  await assert.rejects(() => unavailable.login("unit-admin", PASSWORD), /Key Vault unavailable/);
  const broken = new MemoryStore();
  broken.audit = async () => { throw new Error("Audit storage unavailable"); };
  const denied = new Authentication(cfg, broken, async () => verifier, () => NOW);
  await assert.rejects(() => denied.login("unit-admin", PASSWORD), /Audit storage unavailable/);
  assert.ok(![...broken.rows.keys()].some((key) => key.startsWith("sessions/")));
  const malformed = new MemoryStore();
  await malformed.write("control/auth", { attempts: null });
  await assert.rejects(() => new Authentication(cfg, malformed, async () => verifier, () => NOW).login("unit-admin", PASSWORD), /counter/);
});
