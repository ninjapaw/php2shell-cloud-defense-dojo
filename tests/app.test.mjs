import assert from "node:assert/strict";
import test from "node:test";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { createServer } from "node:net";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { ROOT } from "../scripts/dojo.mjs";
import { SCENARIO, SENTINEL_RULE_DISPLAY_NAME } from "../scripts/lib/config.mjs";

const RUN_ID = "44444444-4444-4444-8444-444444444444";
const GITHUB_LINK = '<a href="https://github.com/ninjapaw/php2shell-cloud-defense-dojo">GitHub</a>';
const RECORDED_LINK = 'href="https://php2proof.ninjapaws.org/evidence/92ad189c-9a88-4403-b773-52453963e4b8"';
const DEPLOY_LINK = 'href="https://php2proof.ninjapaws.org/evidence/deploy">Deploy to Azure</a>';

async function startPhp(state, environment = "dev") {
  const server = createServer();
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const port = server.address().port;
  await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  const child = spawn("php", ["-S", `127.0.0.1:${port}`, "-t", join(ROOT, "app")], {
    env: { ...process.env, LAB_STATE: state, LAB_ENVIRONMENT: environment, LAB_RESOURCE_ID: "local://php2shell-test" },
    stdio: ["ignore", "pipe", "pipe"],
  });
  let error;
  let logs = "";
  child.on("error", (value) => { error = value; });
  child.stderr.on("data", (value) => { logs = `${logs}${value}`.slice(-65_536); });
  child.stdout.resume();
  let stopped = false;
  async function stop() {
    if (stopped || child.exitCode !== null) return;
    stopped = true;
    const ended = once(child, "exit");
    child.kill();
    await ended;
  }
  const base = `http://127.0.0.1:${port}`;
  let lastFailure;
  for (let attempt = 0; attempt < 50; attempt += 1) {
    if (error || child.exitCode !== null) break;
    try {
      await fetch(`${base}/health.php`, { signal: AbortSignal.timeout(1000) });
      return { base, stop, logs: () => logs };
    } catch (failure) {
      lastFailure = failure;
    }
    await delay(50);
  }
  await stop();
  throw new Error(`PHP test server did not become ready: ${error?.message ?? lastFailure?.message ?? logs}`);
}

test("real PHP training app is read-only, bounded and labels all synthetic signals", async (t) => {
  const app = await startPhp("training");
  t.after(app.stop);
  await t.test("dashboard, CSS and health are tangible and explicitly training-only", async () => {
    const page = await fetch(app.base);
    const html = await page.text();
    assert.equal(page.status, 200);
    assert.match(html, /<title>PHP to Proof \| Code-to-Cloud Defense Story<\/title>/);
    assert.match(html, /<h1>PHP to Proof\.<br>/);
    assert.match(html, /TRAINING ONLY/);
    assert.match(html, /class="badge">PUBLIC DEMO<\/span>/);
    assert.doesNotMatch(html, /class="badge">DEV ONLY<\/span>/);
    assert.match(html, /SYNTHETIC SIGNALS AVAILABLE/);
    assert.match(html, /No assessment, runtime alert, or attack path is fabricated/);
    assert.match(html, /href="\/walkthrough\.php"/);
    assert.ok(html.includes(GITHUB_LINK), "Story navigation must link to the exact project repository.");
    assert.ok(html.includes(DEPLOY_LINK), "Story top navigation must offer the actual deployment wizard guide.");
    assert.match(page.headers.get("content-security-policy"), /default-src 'none'/);
    assert.equal(page.headers.get("cache-control"), "no-store");
    assert.equal((await fetch(`${app.base}/assets/style.css`)).status, 200);
    const health = await (await fetch(`${app.base}/health.php`)).json();
    assert.equal(health.scenario, SCENARIO);
    assert.equal(health.state, "training");
    assert.equal(health.environment, "dev");
    assert.equal(health.syntheticEndpointsEnabled, true);
    assert.match(health.phpVersion, /^8\.[45]\./);
  });
  await t.test("guided walkthrough is complete, navigable and honest about unqueried plans", async () => {
    const response = await fetch(`${app.base}/walkthrough.php`);
    const html = await response.text();
    assert.equal(response.status, 200);
    assert.match(html, /<title>PHP to Proof \| Guided Walkthrough<\/title>/);
    assert.match(html, /class="badge">PUBLIC DEMO<\/span>/);
    assert.match(html, /TRAINING ONLY/);
    assert.doesNotMatch(html, /class="badge">DEV ONLY<\/span>/);
    assert.match(html, /Application state: training/);
    assert.ok(html.includes(GITHUB_LINK), "Walkthrough navigation must link to the exact project repository.");
    assert.ok(html.includes(DEPLOY_LINK), "Walkthrough top navigation must offer the same deployment entry.");
    assert.ok(html.includes(RECORDED_LINK), "Walkthrough must link to the reviewed actual run, not only illustrative examples.");
    assert.match(html, /not your new deployment's logs/);
    assert.match(html, /Defender and Sentinel status: not queried by this page/);
    assert.match(html, /Foundational CSPM/);
    assert.match(html, /Serverless protection/);
    assert.match(html, /With paid Defender CSPM/);
    assert.match(html, /Without paid Defender CSPM/);
    assert.match(html, /incident creation is disabled/);
    assert.match(html, /without the WAF marker/);
    assert.match(html, /at least two distinct synthetic app signals/);
    assert.doesNotMatch(html, /<script\b|<form\b|<iframe\b/i);
    assert.match(response.headers.get("content-security-policy"), /default-src 'none'/);
    assert.equal(response.headers.get("cache-control"), "no-store");
    assert.ok(Buffer.byteLength(html, "utf8") < 64 * 1024, "Guide must fit the bounded HTTP reader.");
    const ids = [...html.matchAll(/\bid="([^"]+)"/g)].map((match) => match[1]);
    assert.equal(new Set(ids).size, ids.length, "Guide IDs must be unique.");
    for (const match of html.matchAll(/href="#([^"]+)"/g)) assert.ok(ids.includes(match[1]), match[1]);
    for (const id of ["briefing", "components", "baseline", "request", "correlate", "posture",
      "sentinel", "protect", "remediate", "containers", "debrief", "glossary"]) {
      assert.ok(ids.includes(id), id);
    }
    assert.ok(!app.logs().includes("DOJO_EVENT "), "Reading the guide must not run a simulation.");
    for (const query of ["enable-defender=true", "target=https://example.invalid", "signal[]=request"]) {
      const rejected = await fetch(`${app.base}/walkthrough.php?${query}`);
      assert.equal(rejected.status, 400);
      assert.match((await rejected.json()).error, /accepts no training inputs/);
    }
  });
  await t.test("attack story pairs all five moves with captured logs and conditional alert references", async () => {
    const html = await (await fetch(`${app.base}/walkthrough.php`)).text();
    assert.match(html, /The request that wanted a shell/);
    assert.match(html, /Ghostpaw is fictional/);
    assert.match(html, /aria-label="Fictional attack chain"/);
    assert.match(html, /WITHOUT WORKLOAD DEFENDER \/ RAW CLUES/);
    assert.match(html, /WITH SUPPORTED DEFENDER \/ CONDITIONAL RESULT/);
    assert.equal((html.match(/DETECTION REFERENCE \/ NOT OBSERVED/g) ?? []).length, 5);
    assert.match(html, /Story order is not a detection or ingestion timetable/);
    assert.match(html, /Category reference, not a fired alert/);
    assert.match(html, /No guaranteed data-access alert/);
    assert.match(html, /alerts-azure-app-service/);
    assert.match(html, /id="alerts"/);
    assert.match(html, /CONFIGURED RULE \/ NOT AN OBSERVED ALERT/);
    assert.ok(html.includes(SENTINEL_RULE_DISPLAY_NAME));
    assert.match(html, /Severity: Informational/);
    assert.match(html, /Incident creation: disabled/);
    const signals = ["request", "php-error", "process-synthetic", "outbound-synthetic", "canary"];
    for (const signal of signals) assert.ok(html.includes(`id="move-${signal}"`), signal);
    assert.doesNotMatch(html, /data-example-signal=/);
    assert.doesNotMatch(html, /href="[^"]*[?&]signal=|<script\b|<form\b|<iframe\b/i);
    assert.ok(!app.logs().includes("DOJO_EVENT "), "Viewing attack examples must not generate any signals.");
  });
  await t.test("ten story cards use native ordered navigation, progress and a complete read-all fallback", async () => {
    const html = await (await fetch(`${app.base}/walkthrough.php`)).text();
    const steps = ["briefing", "move-request", "move-php-error", "move-process-synthetic",
      "move-outbound-synthetic", "move-canary", "recorded", "protect", "remediate", "debrief"];
    assert.deepEqual([...html.matchAll(/<section id="([^"]+)" class="walkthrough-chapter"/g)].map(([, id]) => id), steps);
    const controls = [...html.matchAll(/<nav class="walkthrough-controls"[^>]*>([\s\S]*?)<\/nav>/g)];
    assert.equal(controls.length, steps.length);
    for (const [index, [, navigation]] of controls.entries()) {
      const previous = navigation.match(/href="#([^"]+)" rel="prev"/);
      const next = navigation.match(/href="#([^"]+)" rel="next"/);
      assert.equal(previous?.[1], steps[index - 1]);
      assert.equal(next?.[1], steps[index + 1]);
      assert.ok(html.includes(`value="${index + 1}" max="10" aria-label="Story progress"`));
    }
    assert.match(controls[0][1], /aria-disabled="true">Previous step/);
    assert.match(controls.at(-1)[1], /href="#briefing">Restart story/);
    assert.match(html, /<summary>Jump to a step<\/summary>/);
    assert.match(html, /href="#all-steps">Read all steps<\/a>/);
    assert.match(html, /id="all-steps" tabindex="-1"/);
    assert.match(html, /<summary>Actual ingested log from the recorded run<\/summary>/);
    assert.equal((html.match(/<h3>What the analyst can see<\/h3>/g) ?? []).length, 5);
    assert.equal((html.match(/No provider alerts in this run\./g) ?? []).length, 5);
    assert.doesNotMatch(html, /<details open|<script\b|<form\b/i);
    assert.ok(!app.logs().includes("DOJO_EVENT "));
  });
  await t.test("each attack move shows the reviewed actual capture without inventing Defender alerts", async () => {
    const recorded = JSON.parse(readFileSync(join(ROOT, "operator", "public-evidence",
      "92ad189c-9a88-4403-b773-52453963e4b8.json"), "utf8"));
    const html = await (await fetch(`${app.base}/walkthrough.php`)).text();
    for (const value of [recorded.runId, recorded.startedAt, recorded.endedAt, recorded.capturedAt]) {
      assert.ok(html.includes(value), `Recorded provenance must match the reviewed snapshot: ${value}`);
    }
    assert.match(html, /HISTORICAL CAPTURE \/ NOT LIVE/);
    assert.match(html, /Not a Defender-disabled control run/);
    assert.match(html, /not enforced blocking/);
    assert.match(html, /direct provider alert query succeeded and returned <code>\[\]<\/code>/);
    assert.match(html, /not four detections/);
    assert.match(html, /not necessarily exclusive to paid CSPM/);
    assert.deepEqual(recorded.captures.defenderAlerts, { status: "queried", rows: [] });
    assert.equal(recorded.captures.posture.rows.length, 4);
    assert.ok(recorded.captures.posture.rows.every((row) => row.Status === "Healthy"));
    for (const plan of ["AppServices", "CloudPosture", "Containers"]) {
      assert.deepEqual(recorded.plans[plan], { status: "queried", tier: "Standard" });
    }
    const captures = [...html.matchAll(/<pre data-recorded-signal="([^"]+)"><code>([\s\S]*?)<\/code><\/pre>/g)];
    assert.deepEqual(captures.map(([, signal]) => signal), recorded.requests.map((request) => request.signal));
    assert.deepEqual(captures.map(([, , encoded]) => JSON.parse(encoded.replaceAll("&quot;", '"'))),
      recorded.captures.application.rows);
    assert.equal((html.match(/data-recorded-http="200"/g) ?? []).length, recorded.requests.length);
    assert.ok(recorded.requests.every((request) => request.status === 200 && request.synthetic === true));
    const waf = html.match(/<pre data-recorded-waf><code>([\s\S]*?)<\/code><\/pre>/);
    assert.ok(waf, "The actual WAF source record must be visible beside the first move.");
    assert.deepEqual(JSON.parse(waf[1].replaceAll("&quot;", '"')), recorded.captures.waf.rows[0]);
    assert.ok(!app.logs().includes("DOJO_EVENT "), "Reading historical captures must not run any tests.");
    assert.ok(Buffer.byteLength(html, "utf8") < 64 * 1024, "The expanded actual capture must preserve the HTTP bound.");
  });
  await t.test("all five signals return labelled fixtures and structured log events", async () => {
    for (const signal of ["request", "php-error", "process-synthetic", "outbound-synthetic", "canary"]) {
      const response = await fetch(`${app.base}/index.php?signal=${signal}&runId=${RUN_ID}&dojoProbe=waf-marker`);
      assert.equal(response.status, 200);
      const event = await response.json();
      assert.equal(event.scenario, SCENARIO);
      assert.equal(event.synthetic, true);
      assert.equal(event.signal, signal);
      assert.equal(event.runId, RUN_ID);
      assert.equal(event.resourceId, "local://php2shell-test");
      assert.equal(event.evidenceKind, "synthetic-application-log");
      if (signal === "canary") {
        assert.deepEqual(event.canary, { id: "synthetic://php2shell/ledger", classification: "fabricated-training-data", records: 3 });
      }
    }
    await delay(50);
    const events = app.logs().split("\n").filter((line) => line.includes("DOJO_EVENT "))
      .map((line) => JSON.parse(line.split("DOJO_EVENT ")[1]));
    assert.equal(events.length, 5);
    assert.ok(events.every((event) => event.synthetic === true && event.runId === RUN_ID));
    assert.match(events[2].message, /No process was started/);
    assert.match(events[3].message, /No network connection was made/);
  });
  await t.test("arbitrary targets, payload-shaped input, arrays and unknown signals are rejected", async () => {
    for (const query of [
      "target=https://example.invalid", "signal=canary&runId=not-a-uuid",
      `signal=command&runId=${RUN_ID}`, `signal=canary&runId=${RUN_ID}&target=http://169.254.169.254`,
      `signal[]=canary&runId=${RUN_ID}`, `signal=canary&runId[]=${RUN_ID}`,
      `signal=canary&runId=${RUN_ID}&dojoProbe=not-the-benign-marker`,
      "runId=unbound", "signal=%3Cscript%3E&runId=invalid",
    ]) {
      const response = await fetch(`${app.base}/index.php?${query}`);
      assert.equal(response.status, 400);
      assert.ok((await response.json()).error);
    }
  });
  await t.test("writes are rejected and HEAD is supported without a response body", async () => {
    for (const path of ["/index.php", "/health.php", "/walkthrough.php"]) {
      const rejected = await fetch(`${app.base}${path}`, { method: "POST" });
      assert.equal(rejected.status, 405);
      assert.equal(rejected.headers.get("allow"), "GET, HEAD");
      const head = await fetch(`${app.base}${path}`, { method: "HEAD" });
      assert.equal(head.status, 200);
      assert.equal(await head.text(), "");
    }
  });
});

test("real PHP fixed state removes every synthetic scenario surface", async (t) => {
  const app = await startPhp("fixed");
  t.after(app.stop);
  const html = await (await fetch(app.base)).text();
  assert.match(html, /<title>PHP to Proof \| Code-to-Cloud Defense Story<\/title>/);
  assert.match(html, /FIXED STATE \/ TRAINING SURFACES REMOVED/);
  const walkthrough = await (await fetch(`${app.base}/walkthrough.php`)).text();
  assert.match(walkthrough, /Application state: fixed/);
  assert.match(walkthrough, /Training endpoints have been removed/);
  assert.ok(html.includes(GITHUB_LINK), "Fixed story must retain its GitHub link.");
  assert.ok(walkthrough.includes(GITHUB_LINK), "Fixed walkthrough must retain its GitHub link.");
  assert.ok(walkthrough.includes(RECORDED_LINK), "Historical reviewed evidence remains available after remediation.");
  const health = await (await fetch(`${app.base}/health.php`)).json();
  assert.equal(health.state, "fixed");
  assert.equal(health.syntheticEndpointsEnabled, false);
  for (const signal of ["request", "php-error", "process-synthetic", "outbound-synthetic", "canary"]) {
    assert.equal((await fetch(`${app.base}/index.php?signal=${signal}&runId=${RUN_ID}`)).status, 404);
  }
  assert.ok(!app.logs().includes("DOJO_EVENT "));
});

test("PHP rejects production and unknown configuration with an explicit error", async (t) => {
  const app = await startPhp("training", "production");
  t.after(app.stop);
  const response = await fetch(`${app.base}/health.php`);
  assert.equal(response.status, 503);
  assert.match((await response.json()).error, /configuration is invalid/);
  assert.equal((await fetch(`${app.base}/walkthrough.php`)).status, 503);
  await delay(30);
  assert.match(app.logs(), /DOJO_CONFIGURATION_ERROR/);
});

test("PHP rejects explicitly empty and zero-like settings instead of reopening training defaults", async (t) => {
  for (const [state, environment] of [["", "dev"], ["0", "dev"], ["training", ""], ["training", "0"]]) {
    await t.test(`state=${JSON.stringify(state)}, environment=${JSON.stringify(environment)}`, async (t) => {
      const app = await startPhp(state, environment);
      t.after(app.stop);
      for (const path of ["/health.php", "/walkthrough.php", `/index.php?signal=request&runId=${RUN_ID}`]) {
        const response = await fetch(`${app.base}${path}`);
        assert.equal(response.status, 503);
        assert.match((await response.json()).error, /configuration is invalid/);
      }
      assert.ok(!app.logs().includes("DOJO_EVENT "));
    });
  }
});

test("PHP source contains no process, evaluation, egress or Azure token operations", () => {
  for (const file of ["index.php", "walkthrough.php", "health.php", "lab.php"]) {
    const source = readFileSync(join(ROOT, "app", file), "utf8");
    assert.doesNotMatch(source, /\b(?:shell_exec|exec|system|passthru|eval|assert|proc_open|popen|fsockopen|curl_exec|socket_connect)\s*\(/i);
    assert.doesNotMatch(source, /169\.254\.169\.254|IDENTITY_ENDPOINT|MSI_ENDPOINT/);
  }
});
