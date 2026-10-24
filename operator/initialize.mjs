import { randomBytes, randomUUID, createHash } from "node:crypto";
import { setTimeout as delay } from "node:timers/promises";
import { makeVerifier, validateVerifier } from "./auth.mjs";
import { publicSnapshot } from "./evidence.mjs";
import { assertLive } from "./config.mjs";
import { redact } from "../scripts/lib/safety.mjs";

export async function initialize(config, { store, auth, control, vault }, initializeId) {
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(initializeId)) {
    throw new Error("One-time initialization requires an explicit deployment UUID.");
  }
  assertLive(config);
  const deadline = Math.min(Date.now() + 900_000, config.expiresAt);
  const active = () => {
    assertLive(config);
    if (Date.now() >= deadline) throw new Error("One-time initialization observation deadline ended.");
  };
  async function portal(path, fields, cookie) {
    active();
    if (!["/", "/login", "/jobs"].includes(path)) throw new Error("Initialization escaped the fixed portal paths.");
    const response = await fetch(`${config.origin}${path}`, {
      method: fields ? "POST" : "GET", redirect: "manual",
      signal: AbortSignal.timeout(Math.max(1, Math.min(15_000, deadline - Date.now()))),
      headers: {
        ...(cookie ? { Cookie: cookie } : {}),
        ...(fields ? { Origin: config.origin, "Content-Type": "application/x-www-form-urlencoded" } : {}),
      },
      ...(fields ? { body: new URLSearchParams(fields) } : {}),
    });
    const reader = response.body.getReader();
    const chunks = [];
    let size = 0;
    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        size += value.byteLength;
        if (size > 65_536) throw new Error("Initialization portal response exceeded 64 KiB.");
        chunks.push(value);
      }
    } finally { await reader.cancel(); }
    return { response, text: Buffer.concat(chunks).toString("utf8") };
  }
  const csrf = (html) => {
    const value = /name="csrf" value="([A-Za-z0-9_-]{43})"/.exec(html)?.[1];
    if (!value) throw new Error("Actual portal CSRF form is missing.");
    return value;
  };
  const secureCookie = (response, name) => {
    const rows = response.headers.getSetCookie().filter((value) => value.startsWith(`${name}=`));
    if (rows.length !== 1 || !/; Secure; HttpOnly; SameSite=Strict/.test(rows[0])) throw new Error("Actual portal cookie security drifted.");
    return rows[0].split(";")[0];
  };
  return store.withLease("initialize", async () => {
    const key = `control/initialize-${initializeId}`;
    const existing = await store.read(key);
    if (existing) {
      console.log("Existing durable initialization claim retained; no credential rotation or automatic test replay.");
      return;
    }
    await store.audit("initialization-intent", { initializeId });
    await store.write(key, { status: "starting", timestamp: new Date().toISOString() });
    let session;
    try {
      let secret;
      try { secret = await vault.getSecret(config.verifierSecret); }
      catch (error) { if (error.statusCode !== 404) throw error; }
      if (!secret) {
        const username = "dojo-admin";
        const password = randomBytes(40).toString("base64url");
        const verifier = await makeVerifier(username, password, config.expiry);
        const properties = { enabled: true, notBefore: new Date(), expiresOn: new Date(config.expiry) };
        await vault.setSecret("operator-admin-username", username, properties);
        await vault.setSecret("operator-admin-password", password, properties);
        secret = await vault.setSecret(config.verifierSecret, JSON.stringify(verifier), properties);
      }
      validateVerifier(secret, config);
      console.log("OPERATOR_CREDENTIALS_READY: Key Vault credentials established; no credential value emitted.");
      const username = (await vault.getSecret("operator-admin-username")).value;
      const password = (await vault.getSecret("operator-admin-password")).value;
      let login;
      for (let attempt = 0; attempt < 24; attempt += 1) {
        login = await portal("/login");
        if (login.response.status === 200) break;
        if (![502, 503].includes(login.response.status) || attempt === 23) throw new Error(`Actual login page failed: HTTP ${login.response.status}.`);
        await delay(5000);
      }
      const signedIn = await portal("/login", { csrf: csrf(login.text), username, password },
        secureCookie(login.response, "__Host-php2proof_login"));
      if (signedIn.response.status !== 303 || signedIn.response.headers.get("location") !== "/") {
        throw new Error(`Actual Key Vault-backed HTTP login failed: HTTP ${signedIn.response.status}. Values omitted.`);
      }
      const sessionCookie = secureCookie(signedIn.response, "__Host-php2proof_operator");
      session = await auth.session(sessionCookie.slice(sessionCookie.indexOf("=") + 1));
      const dashboard = await portal("/", undefined, sessionCookie);
      if (dashboard.response.status !== 200) throw new Error("Actual authenticated dashboard is unavailable.");
      const actionToken = csrf(dashboard.text);
      async function start(operation, sourceJobId) {
        const id = randomUUID();
        const result = await portal("/jobs", {
          csrf: actionToken, operation, idempotencyKey: id, ...(sourceJobId ? { sourceJobId } : {}),
        }, sessionCookie);
        if (result.response.status !== 303 || result.response.headers.get("location") !== `/jobs/${id}`) {
          throw new Error(`Actual authenticated fixed-catalogue dispatch failed: HTTP ${result.response.status}.`);
        }
        return { id };
      }
      console.log("OPERATOR_VERIFIED_LOGIN: Actual Key Vault-backed HTTP login, secure session, CSRF and private dashboard verified. No values emitted.");
      const job = await start("simulate");
      let record;
      async function wait(id) {
        for (let attempt = 0; attempt < 100; attempt += 1) {
          active();
          const result = await store.read(`jobs/${id}`);
          if (["completed", "completed-with-evidence-gaps"].includes(result?.value.status)) return result.value;
          if (!["queued", "running"].includes(result?.value.status)) throw new Error(`Initial guarded job failed: ${redact(result?.value.error ?? "invalid state")}`);
          await delay(5000);
        }
        throw new Error("Initial guarded job exceeded its observation deadline.");
      }
      record = await wait(job.id);
      let candidate;
      for (let attempt = 0; attempt < 5; attempt += 1) {
        const evidence = record.evidenceKey ? await store.read(record.evidenceKey) : undefined;
        if (!evidence) throw new Error("No private evidence was captured.");
        candidate = publicSnapshot(evidence.value);
        if (candidate.captures.application.status === "queried"
            && new Set(candidate.captures.application.rows.map((row) => row.Signal)).size === 5
            && candidate.captures.waf.status === "queried" && candidate.captures.waf.rows.length > 0) break;
        if (attempt === 4) throw new Error("Real five-signal/WAF ingestion did not converge; no complete public candidate is asserted.");
        await delay(65_000);
        record = await wait((await start("collect-evidence", job.id)).id);
      }
      const snapshot = JSON.stringify(candidate);
      await store.audit("initialization-candidate-ready", { initializeId, jobId: job.id, runId: candidate.runId });
      const current = await store.read(key);
      await store.write(key, {
        status: "succeeded", timestamp: new Date().toISOString(), jobId: job.id, runId: candidate.runId,
        candidateSha256: createHash("sha256").update(snapshot).digest("hex"), publication: "manual-review-required",
      }, current.etag);
      console.log(`OPERATOR_REDACTED_EVIDENCE ${snapshot}`);
    } catch (error) {
      const current = await store.read(key);
      await store.audit("initialization-failed", { initializeId, reason: redact(error.message) });
      await store.write(key, { ...current.value, status: "failed", error: redact(error.message) }, current.etag);
      throw error;
    } finally {
      if (session) await auth.logout(session);
    }
  });
}
