import assert from "node:assert/strict";
import test from "node:test";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { createServer } from "node:net";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { ROOT } from "../scripts/dojo.mjs";
import { SCENARIO } from "../scripts/lib/config.mjs";

const RUN_ID = "44444444-4444-4444-8444-444444444444";

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
    assert.match(html, /TRAINING ONLY/);
    assert.match(html, /SYNTHETIC SIGNALS AVAILABLE/);
    assert.match(html, /No assessment, runtime alert, or attack path is fabricated/);
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
    for (const path of ["/index.php", "/health.php"]) {
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
  assert.match(await (await fetch(app.base)).text(), /FIXED STATE \/ TRAINING SURFACES REMOVED/);
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
  await delay(30);
  assert.match(app.logs(), /DOJO_CONFIGURATION_ERROR/);
});

test("PHP rejects explicitly empty and zero-like settings instead of reopening training defaults", async (t) => {
  for (const [state, environment] of [["", "dev"], ["0", "dev"], ["training", ""], ["training", "0"]]) {
    await t.test(`state=${JSON.stringify(state)}, environment=${JSON.stringify(environment)}`, async (t) => {
      const app = await startPhp(state, environment);
      t.after(app.stop);
      for (const path of ["/health.php", `/index.php?signal=request&runId=${RUN_ID}`]) {
        const response = await fetch(`${app.base}${path}`);
        assert.equal(response.status, 503);
        assert.match((await response.json()).error, /configuration is invalid/);
      }
      assert.ok(!app.logs().includes("DOJO_EVENT "));
    });
  }
});

test("PHP source contains no process, evaluation, egress or Azure token operations", () => {
  for (const file of ["index.php", "health.php", "lab.php"]) {
    const source = readFileSync(join(ROOT, "app", file), "utf8");
    assert.doesNotMatch(source, /\b(?:shell_exec|exec|system|passthru|eval|assert|proc_open|popen|fsockopen|curl_exec|socket_connect)\s*\(/i);
    assert.doesNotMatch(source, /169\.254\.169\.254|IDENTITY_ENDPOINT|MSI_ENDPOINT/);
  }
});
