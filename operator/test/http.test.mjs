import test from "node:test";
import assert from "node:assert/strict";
import { once } from "node:events";
import { createOperatorServer } from "../server.mjs";
import { ControlPlane } from "../control.mjs";
import { setup, NOW, PASSWORD } from "./support.mjs";

test("HTTP boundary requires the edge, login, exact Origin and CSRF; no anonymous execution or secret response", async (t) => {
  const h = await setup();
  const control = new ControlPlane(h.cfg, h.store, h.credentials, () => ({}), { now: () => NOW });
  const server = createOperatorServer(h.cfg, { ...h, control, log: () => {} });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const base = `http://127.0.0.1:${server.address().port}`;
  const edge = { "X-Azure-FDID": h.cfg.frontDoorId };
  const post = (path, fields, cookie = "", origin = h.cfg.origin) => fetch(`${base}${path}`, {
    method: "POST", redirect: "manual",
    headers: { ...edge, Origin: origin, Cookie: cookie, "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams(fields),
  });
  assert.equal((await fetch(`${base}/`)).status, 403);
  assert.equal((await fetch(`${base}/`, { headers: edge })).status, 401);
  const publicHunts = await fetch(`${base}/evidence/hunting`, { headers: edge });
  assert.equal(publicHunts.status, 200);
  assert.match(await publicHunts.text(), /HISTORICAL REVIEWED CAPTURE/);
  const stylesheet = await fetch(`${base}/style.css`, { headers: edge });
  assert.equal(stylesheet.status, 200);
  assert.match(stylesheet.headers.get("content-type"), /^text\/css/);
  assert.equal((await post("/jobs", { operation: "simulate" })).status, 401);
  assert.equal((await post("/login", { username: "unit-admin", password: PASSWORD }, "", "https://attacker.invalid")).status, 403);
  const loginPage = await fetch(`${base}/login`, { headers: edge });
  const html = await loginPage.text();
  assert.ok(!html.includes(PASSWORD));
  assert.ok(!html.includes(h.sessionToken));
  const nonce = /name="csrf" value="([^"]+)"/.exec(html)[1];
  const loginCookie = loginPage.headers.getSetCookie()[0].split(";")[0];
  assert.match(loginPage.headers.get("set-cookie"), /Secure; HttpOnly; SameSite=Strict/);
  assert.equal(loginPage.headers.get("referrer-policy"), "same-origin",
    "Native browser form POSTs must retain their same-origin Origin without leaking cross-site referrers.");
  assert.equal((await post("/login", { csrf: nonce, username: "unit-admin", password: PASSWORD }, loginCookie, "null")).status, 403);
  const invalid = await post("/login", { csrf: "x".repeat(43), username: "unit-admin", password: PASSWORD }, loginCookie);
  assert.equal(invalid.status, 403);
  const signedIn = await post("/login", { csrf: nonce, username: "unit-admin", password: PASSWORD }, loginCookie);
  assert.equal(signedIn.status, 303);
  const sessionCookie = signedIn.headers.getSetCookie()[0].split(";")[0];
  assert.match(sessionCookie, /^__Host-php2proof_operator=/);
  const home = await fetch(`${base}/`, { headers: { ...edge, Cookie: sessionCookie } });
  const dashboard = await home.text();
  assert.equal(home.status, 200);
  assert.match(dashboard, /GhostPaw test console/);
  assert.match(dashboard, /Not authorized/);
  const hunts = await fetch(`${base}/hunts`, { headers: { ...edge, Cookie: sessionCookie } });
  const huntsHtml = await hunts.text();
  assert.equal(hunts.status, 200);
  assert.equal((huntsHtml.match(/id="hunt-/g) ?? []).length, 27);
  assert.match(huntsHtml, /20 value\/evaluation walkthroughs/);
  assert.match(huntsHtml, /name="huntId" value="all"/);
  const csrf = /name="csrf" value="([^"]+)"/.exec(dashboard)[1];
  assert.equal((await post("/jobs", { csrf, operation: "hunt-pack", huntId: "lab-waf",
    idempotencyKey: "00000000-0000-4000-8000-000000000002", query: "arbitrary query" }, sessionCookie)).status, 400);
  assert.equal((await post("/jobs", { csrf: "wrong", operation: "simulate" }, sessionCookie)).status, 403);
  assert.equal((await post("/jobs", { csrf, operation: "simulate", idempotencyKey: "00000000-0000-4000-8000-000000000001", target: "https://other.invalid" }, sessionCookie)).status, 400);
  assert.equal((await post("/jobs", { csrf, operation: "remediate", idempotencyKey: "00000000-0000-4000-8000-000000000001" }, sessionCookie)).status, 400);
  assert.equal(h.store.queue.length, 0);
  const sent = await post("/jobs", { csrf, operation: "validate", idempotencyKey: "00000000-0000-4000-8000-000000000001" }, sessionCookie);
  assert.equal(sent.status, 303);
  assert.equal(h.store.queue.length, 1);
  const record = await h.store.read("jobs/00000000-0000-4000-8000-000000000001");
  await h.store.write("jobs/00000000-0000-4000-8000-000000000001", { ...record.value, error: "<script>alert(1)</script>" }, record.etag);
  const detail = await fetch(`${base}${sent.headers.get("location")}`, { headers: { ...edge, Cookie: sessionCookie } });
  assert.match(await detail.text(), /&lt;script&gt;/);
  assert.equal((await post("/logout", { csrf }, sessionCookie)).status, 303);
  assert.equal((await fetch(`${base}/`, { headers: { ...edge, Cookie: sessionCookie } })).status, 401);
});

test("dependency failure is HTTP 503, not a successful-looking empty dashboard", async (t) => {
  const h = await setup();
  h.store.recentJobs = async () => { throw new Error("Storage unavailable"); };
  const server = createOperatorServer(h.cfg, { ...h, control: {}, log: () => {} });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const response = await fetch(`http://127.0.0.1:${server.address().port}/`, {
    headers: { "X-Azure-FDID": h.cfg.frontDoorId, Cookie: `__Host-php2proof_operator=${h.sessionToken}` },
  });
  assert.equal(response.status, 503);
  assert.match(await response.text(), /No successful action/);
});
