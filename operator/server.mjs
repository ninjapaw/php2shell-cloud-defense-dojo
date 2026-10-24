import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { timingSafeEqual } from "node:crypto";
import { ManagedIdentityCredential } from "@azure/identity";
import { SecretClient } from "@azure/keyvault-secrets";
import { BlobServiceClient } from "@azure/storage-blob";
import { QueueClient } from "@azure/storage-queue";
import { redact } from "../scripts/lib/safety.mjs";
import { CATALOGUE, LIMITS, OperatorError, loadConfig } from "./config.mjs";
import { Authentication, keyVaultCredentials, token } from "./auth.mjs";
import { AzureStore } from "./store.mjs";
import { ReadOnlyAzure } from "./azure.mjs";
import { ControlPlane, newRequestId } from "./control.mjs";

const COOKIE = "__Host-php2proof_operator";
const escape = (value) => String(value).replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;").replaceAll('"', "&quot;").replaceAll("'", "&#39;");
const csrfEqual = (a, b) => typeof a === "string" && typeof b === "string"
  && /^[A-Za-z0-9_-]{43}$/.test(a) && /^[A-Za-z0-9_-]{43}$/.test(b)
  && timingSafeEqual(Buffer.from(a), Buffer.from(b));
const cookie = (request) => {
  const matches = (request.headers.cookie ?? "").split(";").map((part) => part.trim()).filter((part) => part.startsWith(`${COOKIE}=`));
  return matches.length === 1 ? matches[0].slice(COOKIE.length + 1) : undefined;
};
const hidden = (key, value) => `<input type="hidden" name="${key}" value="${escape(value)}">`;
const layout = (title, body, publicPage) => `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><link rel="stylesheet" href="/style.css"><title>${escape(title)} | PHP to Proof</title></head><body><header><a href="/">PHP to Proof / Operator</a><span>${publicPage ? "PUBLIC READ-ONLY" : "PRIVATE CONTROL PLANE"}</span></header><main><h1>${escape(title)}</h1>${body}</main><footer>Authorized defensive training only. No arbitrary commands or Defender downgrades.</footer></body></html>`;

async function form(request) {
  if (request.headers["content-type"]?.split(";")[0] !== "application/x-www-form-urlencoded") throw new OperatorError(415, "content-type", "Expected an encoded HTML form.");
  const chunks = [];
  let size = 0;
  for await (const chunk of request) {
    size += chunk.length;
    if (size > LIMITS.requestBytes) throw new OperatorError(413, "body-limit", "Operator request exceeds the fixed size limit.");
    chunks.push(chunk);
  }
  const parameters = new URLSearchParams(Buffer.concat(chunks).toString("utf8"));
  if ([...parameters.keys()].some((key) => parameters.getAll(key).length !== 1)) throw new OperatorError(400, "duplicate-field", "Duplicate form fields are not permitted.");
  return Object.fromEntries(parameters);
}

export function createOperatorServer(config, { store, auth, control, log = console.error }) {
  const server = createServer(async (request, response) => {
    const headers = {
      "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store",
      "Content-Security-Policy": "default-src 'none'; style-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
      "X-Content-Type-Options": "nosniff", "Referrer-Policy": "same-origin",
      "Strict-Transport-Security": "max-age=31536000",
    };
    const send = (status, title, body, extra = {}, publicPage = false) => {
      response.writeHead(status, { ...headers, ...extra });
      response.end(layout(title, body, publicPage));
    };
    try {
      if (request.headers["x-azure-fdid"] !== config.frontDoorId) throw new OperatorError(403, "edge-required", "The verified operator edge is required.");
      const url = new URL(request.url, config.origin);
      if (url.origin !== config.origin || url.search) throw new OperatorError(400, "invalid-url", "Unexpected operator URL.");
      if (request.method === "GET" && url.pathname === "/health") {
        response.writeHead(200, { ...headers, "Content-Type": "application/json" });
        response.end(JSON.stringify({
          service: "php-to-proof-operator", status: "running", nodeVersion: process.versions.node,
          privilegedActionsRequireLogin: true, dependencyReadinessAsserted: false,
        }));
        return;
      }
      if (request.method === "GET" && url.pathname === "/style.css") {
        const css = await readFile(new URL("./style.css", import.meta.url), "utf8");
        response.writeHead(200, { ...headers, "Content-Type": "text/css; charset=utf-8" });
        response.end(css);
        return;
      }
      if (request.method === "GET" && ["/evidence/deploy", "/evidence/deploy/source.zip", "/evidence/deploy/source.sha256"].includes(url.pathname)) {
        const deployment = await import("./deploy.mjs");
        if (url.pathname.endsWith("/source.zip")) {
          const zip = await deployment.deploymentDownload();
          response.writeHead(200, { ...headers, "Content-Type": "application/zip",
            "Content-Disposition": 'attachment; filename="php2proof-deploy.zip"' });
          response.end(zip);
        } else if (url.pathname.endsWith("/source.sha256")) {
          const manifest = await deployment.deploymentManifest();
          response.writeHead(200, { ...headers, "Content-Type": "text/plain; charset=utf-8" });
          response.end(`${manifest.sha256}  php2proof-deploy.zip\n`);
        } else send(200, "Deploy PHP to Proof to your Azure environment", await deployment.deploymentPage(), {}, true);
        return;
      }
      if (request.method === "GET" && ["/evidence/response", "/evidence/response/script"].includes(url.pathname)) {
        const guide = await import("./response.mjs");
        if (url.pathname.endsWith("/script")) {
          const source = await guide.responseDownload();
          response.writeHead(200, { ...headers, "Content-Type": "text/javascript; charset=utf-8",
            "Content-Disposition": 'attachment; filename="php2proof-response.mjs"' });
          response.end(source);
        } else send(200, "GhostPaw: detection, prevention, resolution and proof", guide.publicResponsePage(), {}, true);
        return;
      }
      if (request.method === "GET" && (url.pathname === "/evidence/hunting" || /^\/evidence\/[0-9a-f-]{36}$/.test(url.pathname))) {
        const name = url.pathname.slice("/evidence/".length);
        let snapshot;
        try { snapshot = await readFile(new URL(`./public-evidence/${name}.json`, import.meta.url), "utf8"); }
        catch (error) {
          if (error.code === "ENOENT") throw new OperatorError(404, "not-published", "No manually reviewed snapshot is published at this address.");
          throw error;
        }
        if (name === "hunting") {
          send(200, "PHP2Shell hunting: queries, results and additional value",
            (await import("./hunts.mjs")).publicHuntingPage(JSON.parse(snapshot)));
        } else send(200, "Recorded GhostPaw evidence", `<p>Static, manually reviewed and redacted evidence. No live query or privileged action is exposed. <a href="/evidence/hunting">Additional hunting queries and value walkthroughs</a>.</p><pre>${escape(snapshot)}</pre>`);
        return;
      }
      const nonce = token();
      if (request.method === "GET" && url.pathname === "/login") {
        send(200, "Administrator sign-in", `<p>Use the administrator credentials established in Key Vault. Never place passwords in URLs.</p><form action="/login" method="post">${hidden("csrf", nonce)}<p><label>Username <input name="username" autocomplete="username" required maxlength="64"></label></p><p><label>Password <input name="password" type="password" autocomplete="current-password" required maxlength="256"></label></p><button>Sign in</button></form>`,
          { "Set-Cookie": `__Host-php2proof_login=${nonce}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=300` });
        return;
      }
      if (request.method === "POST") {
        if (request.headers.origin !== config.origin) throw new OperatorError(403, "origin", "Cross-origin operator actions are forbidden.");
        const input = await form(request);
        if (url.pathname === "/login") {
          const loginNonce = (request.headers.cookie ?? "").split(";").map((part) => part.trim()).filter((part) => part.startsWith("__Host-php2proof_login="));
          if (loginNonce.length !== 1 || !csrfEqual(input.csrf, loginNonce[0].split("=")[1])) throw new OperatorError(403, "csrf", "Reload the sign-in form before submitting.");
          if (Object.keys(input).some((key) => !["csrf", "username", "password"].includes(key))) throw new OperatorError(400, "unknown-field", "Unexpected sign-in field.");
          const result = await auth.login(input.username, input.password);
          response.writeHead(303, { ...headers, Location: "/", "Set-Cookie": [
            `${COOKIE}=${result.sessionToken}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=${Math.floor((result.session.expiresAt - Date.now()) / 1000)}`,
            "__Host-php2proof_login=; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=0",
          ] });
          response.end();
          return;
        }
        const session = await auth.session(cookie(request));
        if (/^\/api\/jobs\/[0-9a-f-]{36}$/.test(url.pathname)) {
          const id = url.pathname.slice("/api/jobs/".length);
          const job = await store.read(`jobs/${id}`);
          if (!job) throw new OperatorError(404, "not-found", "Run not found.");
          const evidence = job.value.evidenceKey ? await store.read(job.value.evidenceKey) : undefined;
          response.writeHead(200, { ...headers, "Content-Type": "application/json; charset=utf-8" });
          response.end(JSON.stringify({ job: job.value, evidence: evidence?.value ?? null }));
          return;
        }
        if (!csrfEqual(input.csrf, session.csrf)) throw new OperatorError(403, "csrf", "The private action token is invalid.");
        if (url.pathname === "/logout") {
          if (Object.keys(input).some((key) => key !== "csrf")) throw new OperatorError(400, "unknown-field", "Unexpected logout field.");
          await auth.logout(session);
          response.writeHead(303, { ...headers, Location: "/login", "Set-Cookie": `${COOKIE}=; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=0` });
          response.end();
          return;
        }
        if (url.pathname === "/jobs") {
          if (Object.keys(input).some((key) => !["csrf", "operation", "idempotencyKey", "sourceJobId", "huntId", "responseId", "responsePlanJobId", "responseFingerprint", "responseConfirmation"].includes(key))) throw new OperatorError(400, "unknown-field", "Unexpected job field or target override.");
          const approval = Object.fromEntries([["id", input.responseId], ["planJobId", input.responsePlanJobId],
            ["fingerprint", input.responseFingerprint], ["confirmation", input.responseConfirmation]].filter(([, value]) => value !== undefined));
          const job = await control.start(session, input.operation, input.idempotencyKey, input.sourceJobId, input.huntId,
            Object.keys(approval).length ? approval : undefined);
          response.writeHead(303, { ...headers, Location: `/jobs/${job.id}` });
          response.end();
          return;
        }
        throw new OperatorError(404, "not-found", "Operator action not found.");
      }
      if (request.method !== "GET") throw new OperatorError(405, "method", "Only authenticated fixed HTML actions are supported.");
      const session = await auth.session(cookie(request));
      if (url.pathname === "/response") {
        send(200, "GhostPaw response scripts and approvals", await (await import("./response.mjs")).privateResponsePage(config, store, session));
        return;
      }
      if (url.pathname === "/hunts") {
        send(200, "PHP2Shell hunting scenarios", await (await import("./hunts.mjs")).huntingPage(config, store, session));
        return;
      }
      if (url.pathname === "/") {
        const jobs = await store.recentJobs();
        send(200, "GhostPaw test console", `<p><a href="/response">Official-response scripts: detection to prevention, resolution and validation</a> / <a href="/hunts">Hunting pack: scenarios, queries, actual results and additional value</a></p><p>Exact lab: ${escape(config.names.group)}. Original expiry: ${escape(config.expiry)}. Credentials, sessions, audit and queue storage are required before execution.</p><p>Baseline means actual source logs available independently of Defender—not an observed Defender-disabled environment. Enabled plans will never be switched off.</p>${CATALOGUE.filter((item) => !item.contextRequired).map((item) => item.enabled
          ? `<form action="/jobs" method="post">${hidden("csrf", session.csrf)}${hidden("operation", item.id)}${hidden("idempotencyKey", newRequestId())}<button>${escape(item.title)}</button></form>`
          : `<p><strong>${escape(item.title)}</strong>: disabled. ${escape(item.reason)}</p>`).join("")}<h2>Private run history</h2><ul>${jobs.map((job) => `<li><a href="/jobs/${escape(job.id)}">${escape(job.queuedAt)} / ${escape(job.operation)} / ${escape(job.status)}</a></li>`).join("")}</ul><form action="/logout" method="post">${hidden("csrf", session.csrf)}<button>Sign out</button></form>`);
        return;
      }
      if (/^\/jobs\/[0-9a-f-]{36}$/.test(url.pathname)) {
        const id = url.pathname.slice("/jobs/".length);
        const job = await store.read(`jobs/${id}`);
        if (!job) throw new OperatorError(404, "not-found", "Run not found.");
        const evidence = job.value.evidenceKey ? await store.read(job.value.evidenceKey) : undefined;
        const refresh = job.value.operation === "simulate" && job.value.result?.runId
          ? `<form action="/jobs" method="post">${hidden("csrf", session.csrf)}${hidden("operation", "collect-evidence")}${hidden("idempotencyKey", newRequestId())}${hidden("sourceJobId", job.value.id)}<button>Collect current logs for this existing run (no replay)</button></form>` : "";
        send(200, "Private run and actual evidence", `<p><a href="/">Return to console</a>. Refresh this page to read persisted progress; refresh does not execute a test.</p><pre>${escape(JSON.stringify(job.value, null, 2))}</pre>${refresh}${evidence ? `<h2>Actual captured sources</h2><pre>${escape(JSON.stringify(evidence.value, null, 2))}</pre>` : "<p>Evidence has not been captured for this run. No alert is inferred.</p>"}`);
        return;
      }
      throw new OperatorError(404, "not-found", "Operator page not found.");
    } catch (error) {
      const expected = error instanceof OperatorError;
      log(`ERROR: operator request denied/failed: ${expected ? error.code : "dependency-failure"} ${redact(error.message)}`);
      send(expected ? error.status : 503, expected ? error.message : "Operator dependencies unavailable", expected && error.status === 401
        ? '<p><a href="/login">Administrator sign-in</a></p>' : "<p>No successful action is asserted. Review the private audit and service logs.</p>");
    }
  });
  server.requestTimeout = 30_000;
  server.headersTimeout = 10_000;
  server.maxRequestsPerSocket = 100;
  return server;
}

export async function main() {
  const config = loadConfig();
  const credential = new ManagedIdentityCredential();
  const blobs = new BlobServiceClient(`https://${config.storageAccount}.blob.core.windows.net`, credential);
  const queue = new QueueClient(`https://${config.storageAccount}.queue.core.windows.net/${config.queueName}`, credential);
  const store = new AzureStore(blobs.getContainerClient(config.blobContainer), queue);
  const vault = new SecretClient(`https://${config.vaultName}.vault.azure.net`, credential);
  const credentials = keyVaultCredentials(vault, config);
  const auth = new Authentication(config, store, credentials);
  const control = new ControlPlane(config, store, credentials, (guard) => new ReadOnlyAzure(config, credential, { guard }));
  const server = createOperatorServer(config, { store, auth, control });
  let busy = false;
  const worker = setInterval(async () => {
    if (busy) return;
    busy = true;
    try { await control.workOnce(); }
    catch (error) {
      if (!(error instanceof OperatorError && error.code === "busy")) console.error(`ERROR: operator worker stopped this cycle: ${redact(error.message)}`);
    } finally { busy = false; }
  }, 2000);
  worker.unref();
  server.listen(config.port, "0.0.0.0", () => console.log("PHP to Proof operator listening; authenticated durable controls are required."));
  if (process.env.OPERATOR_HUNT_CAPTURE_ID) {
    const { initializeHuntCapture } = await import("./hunts.mjs");
    initializeHuntCapture(config, store, (guard) => new ReadOnlyAzure(config, credential, { guard }),
      process.env.OPERATOR_HUNT_CAPTURE_ID).catch((error) => console.error(`ERROR: bounded hunting capture failed: ${redact(error.message)}`));
  }
  if (process.env.OPERATOR_INITIALIZE === "true") {
    const { initialize } = await import("./initialize.mjs");
    initialize(config, { store, auth, control, vault }, process.env.OPERATOR_INITIALIZE_ID).catch((error) => {
      console.error(`ERROR: one-time operator initialization failed: ${redact(error.message)}`);
    });
  }
  return { server, stopWorker: () => clearInterval(worker) };
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  main().catch((error) => {
    console.error(`ERROR: operator startup failed: ${redact(error.message)}`);
    process.exitCode = 1;
  });
}
