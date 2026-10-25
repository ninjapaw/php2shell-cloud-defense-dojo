import { setTimeout as delay } from "node:timers/promises";
import { assertLive, OperatorError } from "./config.mjs";
import { digest, token, validateVerifier } from "./auth.mjs";
import { assertLiveGroup } from "./live-config.mjs";

export async function authorizeLiveWindow(config, { store, vault, readGroup, now = Date.now, wait = delay }, authorizeId) {
  const window = config.liveWindow;
  if (!window || authorizeId !== window.id) throw new Error("Owner authorization requires the exact new live-window UUID.");
  assertLive(config, now());
  assertLiveGroup(config, await readGroup(window.groupId));
  return store.withLease("live-authorize", async ({ assertLease }) => {
    const key = `control/live-authorize/${window.id}`;
    const saved = await store.read(key);
    const secret = await vault.getSecret(config.verifierSecret);
    let previous;
    try { previous = JSON.parse(secret.value); }
    catch (error) {
      if (!(error instanceof SyntaxError)) throw error;
      throw new Error("Existing credential document is invalid; its value is omitted.");
    }
    if (previous.epoch === window.id) {
      validateVerifier(secret, config, now());
      if (!saved) throw new Error("An updated verifier has no durable owner-authorization intent.");
      if (saved.value.status !== "completed") {
        await store.write(key, { ...saved.value, status: "completed", completedAt: new Date(now()).toISOString() }, saved.etag);
        await store.audit("live-authorization-reconciled", { windowId: window.id });
      }
      return { windowId: window.id, expiresAt: window.expiresAt, status: "completed" };
    }
    if (saved) throw new OperatorError(409, "live-authorization-reconcile", "A previous owner authorization requires reconciliation; no credential write is replayed.");
    if (!Number.isFinite(config.originalExpiresAt) || config.originalExpiresAt > now()
        || previous.expiresAt !== config.originalExpiry) {
      throw new Error("A fresh private window may not silently extend a currently active or foreign credential scope.");
    }
    // Check the expired document's integrity without reusing its authorization.
    validateVerifier(secret, {
      ...config, liveWindow: undefined, expiry: config.originalExpiry, expiresAt: config.originalExpiresAt,
    }, config.originalExpiresAt - 1);
    const document = { ...previous, epoch: window.id, notBefore: new Date(now()).toISOString(), expiresAt: window.expiresAt };
    const properties = { enabled: true, notBefore: new Date(document.notBefore), expiresOn: new Date(document.expiresAt) };
    validateVerifier({ value: JSON.stringify(document), properties }, config, now());
    await store.audit("live-authorization-intent", {
      windowId: window.id, groupId: window.groupId, originalExpiry: config.originalExpiry, expiresAt: window.expiresAt,
    });
    await store.write(key, { status: "starting", windowId: window.id, requestedAt: new Date(now()).toISOString() });
    let updated;
    const permissionDeadline = Math.min(now() + 300_000, config.expiresAt);
    for (let attempt = 0; attempt < 31; attempt += 1) {
      assertLive(config, now());
      assertLease();
      try {
        updated = await vault.setSecret(config.verifierSecret, JSON.stringify(document), properties);
        break;
      } catch (error) {
        if (error.statusCode !== 403 || attempt === 30 || now() >= permissionDeadline) {
          await store.audit("live-authorization-failed", { windowId: window.id, status: Number.isInteger(error.statusCode) ? error.statusCode : "unavailable" });
          throw new Error("Key Vault verifier update failed; no successful authorization is asserted. Reconcile the durable intent before retrying.");
        }
        await store.audit("live-authorization-permission-pending", { windowId: window.id, attempt: attempt + 1 });
        await wait(Math.min(10_000, permissionDeadline - now()));
      }
    }
    validateVerifier(updated, config, now());
    const current = await store.read(key);
    await store.write(key, { ...current.value, status: "completed", completedAt: new Date(now()).toISOString() }, current.etag);
    await store.audit("live-authorization-completed", { windowId: window.id, expiresAt: window.expiresAt });
    return { windowId: window.id, expiresAt: window.expiresAt, status: "completed" };
  });
}

export async function ownerLiveSession(config, store, credentials, now = Date.now) {
  assertLive(config, now());
  const window = config.liveWindow;
  if (!window || (await store.read(`control/live-authorize/${window.id}`))?.value.status !== "completed") {
    throw new Error("A completed explicit owner authorization is required for the fixed live capture.");
  }
  const credential = await credentials();
  if (credential.epoch !== window.id) throw new Error("Live owner capture credential epoch mismatch.");
  const session = { hash: digest(token()), csrf: token(), epoch: credential.epoch, expiresAt: Math.min(now() + 30 * 60_000, config.expiresAt) };
  await store.write(`sessions/${session.hash}`, session);
  await store.audit("live-owner-session", { windowId: window.id, session: session.hash });
  return session;
}
