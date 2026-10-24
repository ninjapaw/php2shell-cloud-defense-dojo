import test from "node:test";
import assert from "node:assert/strict";
import { createHash, randomUUID } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { spawnSync } from "node:child_process";
import { gunzipSync, gzipSync } from "node:zlib";
import { SCENARIO } from "../../scripts/lib/config.mjs";
import { applyResponse, assessPhpVersion, buildResponsePlan, RESPONSE_ACTIONS, RESPONSE_GUIDANCE, responseRule, verifyResponse } from "../../scripts/lib/response.mjs";
import { responseArtifact, RESPONSE_FILES } from "../build-response.mjs";
import { publicResponsePage, responseIo, validateResponseDispatch } from "../response.mjs";
import { ControlPlane } from "../control.mjs";
import { config, NOW, setup } from "./support.mjs";
import { FDID } from "../../tests/support/harness.mjs";
import { buildHuntingArtifact } from "../build-hunts.mjs";

function fixture(cfg = config()) {
  const n = cfg.names;
  const group = {
    id: n.groupId, name: n.group, location: cfg.invocation.location, tags: {
      "dojo.scenario": SCENARIO, "dojo.suffix": cfg.invocation.suffix, "pawprint.managed": "true", "pawprint.environment": "dev",
      "pawprint.startedAt": new Date(NOW - 1000).toISOString(), "pawprint.expiresAt": cfg.expiry, "pawprint.ttlHours": "1",
      "dojo.state": "training", "dojo.wafMode": "Detection", "dojo.defenderCspmExpected": "false", "dojo.sentinel": "false", "dojo.analytics": "false",
    },
  };
  const policy = { id: n.policyId, location: "global", sku: { name: "Premium_AzureFrontDoor" }, etag: '"one"', tags: { preserve: "true" },
    properties: { provisioningState: "Succeeded", policySettings: { mode: "Detection", enabledState: "Enabled" },
      customRules: { rules: [{ name: "ExistingMarker", priority: 100, ruleType: "MatchRule", enabledState: "Enabled", action: "Block", matchConditions: [] }] },
      managedRules: { managedRuleSets: [] } } };
  const rows = new Map([
    [n.groupId, group], [n.policyId, policy],
    [n.profileId, { id: n.profileId, sku: { name: "Premium_AzureFrontDoor" }, properties: { frontDoorId: FDID } }],
    [n.endpointId, { id: n.endpointId, properties: { hostName: `${n.endpoint}-unit.b01.azurefd.net` } }],
    [n.appId, { id: n.appId, identity: { principalId: "11111111-1111-4111-8111-111111111111" },
      properties: { httpsOnly: true, serverFarmId: n.planId, defaultHostName: `${n.app}.azurewebsites.net` } }],
    [`${n.appId}/config/web`, { id: `${n.appId}/config/web`, properties: { linuxFxVersion: `PHP|${cfg.invocation.phpVersion}`,
      ipSecurityRestrictionsDefaultAction: "Deny", ipSecurityRestrictions: [
        { action: "Allow", tag: "ServiceTag", ipAddress: "AzureFrontDoor.Backend", headers: { "x-azure-fdid": [FDID] } },
      ] } }],
    [`${n.profileId}/securityPolicies/application-waf`, { id: `${n.profileId}/securityPolicies/application-waf`,
      properties: { parameters: { type: "WebApplicationFirewall", wafPolicy: { id: n.policyId },
        associations: [{ domains: [{ id: n.endpointId }], patternsToMatch: ["/*"] }] } } }],
  ]);
  const state = { rows, group, policy, writes: [], reads: [], catalog: [], settings: { LAB_ENVIRONMENT: "dev", LAB_RESOURCE_ID: n.appId,
    LAB_STATE: "training", PRIVATE_SETTING: "unit-private-setting-never-expose" }, php: `${cfg.invocation.phpVersion}.26`, requests: [], grants: [] };
  const io = {
    read: async (id) => { state.reads.push(id); if (!rows.has(id)) throw new Error("Unlisted fixture read"); return structuredClone(rows.get(id)); },
    catalog: async () => structuredClone(state.catalog),
    settings: async () => structuredClone(state.settings),
    roles: async () => structuredClone(state.grants),
    write: async (id, method, api, body) => {
      state.writes.push({ id, method, api, body: structuredClone(body) });
      if (id === n.policyId) {
        Object.assign(policy, structuredClone(body), { id: n.policyId, etag: `"${state.writes.length}"` });
        policy.properties.provisioningState = "Succeeded";
      } else if (id === `${n.groupId}/providers/Microsoft.Resources/tags/default`) Object.assign(group.tags, body.properties.tags);
      else if (id === `${n.appId}/config/appsettings`) state.settings = structuredClone(body.properties);
      else throw new Error("Unexpected fixture write");
    },
    fetchImpl: async (url, options) => {
      state.requests.push({ url, headers: options.headers });
      const parsed = new URL(url);
      if (parsed.hostname.endsWith(".azurewebsites.net")) return new Response("", { status: 403 });
      if (parsed.pathname === "/health.php") return Response.json({ scenario: SCENARIO, environment: "dev", resourceId: n.appId,
        state: state.settings.LAB_STATE, syntheticEndpointsEnabled: state.settings.LAB_STATE === "training", phpVersion: state.php });
      return new Response("harmless fixture", { status: parsed.searchParams.has("dojoProbe") && group.tags["dojo.wafMode"] === "Prevention"
        ? 403 : state.settings.LAB_STATE === "fixed" ? 404 : 200 });
    },
  };
  const options = { now: () => NOW, audit: async () => {}, sleep: async () => {}, log: () => {} };
  const enable = async () => {
    cfg.responseWritesEnabled = true;
    const preview = await buildResponsePlan(cfg, io, options);
    return applyResponse(cfg, io, "prevention", preview, options);
  };
  return { cfg, io, state, options, enable };
}

function managedFixture(f) {
  return {
    arm: async (path) => f.io.read(new URL(`https://management.azure.com${path}`).pathname),
    collection: async (path) => {
      if (path.includes("/FrontDoorWebApplicationFirewallManagedRuleSets?")) return f.io.catalog();
      if (path.includes("/roleAssignments?")) return f.io.roles();
      throw new Error("Unlisted collection");
    },
    request: async (url) => {
      assert.equal(new URL(url).pathname, `${f.cfg.names.appId}/config/appsettings/list`);
      return { properties: await f.io.settings() };
    },
    credential: { getToken: async () => ({ token: "unit-token-not-a-live-secret", expiresOnTimestamp: Date.now() + 600000 }) },
    fetchImpl: async (url, options) => {
      const parsed = new URL(url);
      await f.io.write(parsed.pathname, options.method, parsed.searchParams.get("api-version"), JSON.parse(options.body));
      return Response.json({ accepted: true });
    },
  };
}

test("official response has precise fixed-version thresholds and no response-rule log promise", () => {
  for (const [branch, patch] of Object.entries(RESPONSE_GUIDANCE.fixed)) {
    assert.equal(assessPhpVersion(`${branch}.${patch - 1}`).status, "patch-review-required");
    assert.equal(assessPhpVersion(`${branch}.${patch}`).status, "meets-advisory-version");
    assert.equal(assessPhpVersion(`${branch}.${patch + 1}`).status, "meets-advisory-version");
  }
  for (const value of ["8.4", "8.4.27RC1", "8.6.0", "8.4.27-unsupported-vendor", null, "<script>"]) {
    assert.equal(assessPhpVersion(value).status, "unverified-version");
  }
  const page = publicResponsePage();
  assert.match(page, /generates no WAF log entries or hit counts/);
  assert.match(page, /No post-mitigation capture has been published here/);
  assert.match(page, /8\.4\.27/);
  assert.equal((page.match(/id="response-step-/g) ?? []).length, RESPONSE_ACTIONS.length);
  assert.equal((page.match(/<form\b/g) ?? []).length, 0);
  assert.ok(page.includes(RESPONSE_GUIDANCE.response));
  assert.ok(page.includes(RESPONSE_GUIDANCE.customRules));
});

test("independent request rules test exact20-level boundaries and default to Log on PHP-only routes", () => {
  for (const kind of ["session", "form", "multipart"]) {
    const rule = responseRule(kind, ["owned-unit.azurefd.net"]);
    assert.equal(rule.action, "Log");
    const host = new RegExp(rule.matchConditions[0].matchValue[0]);
    for (const value of ["owned-unit.azurefd.net", "owned-unit.azurefd.net:443", "owned-unit.azurefd.net."]) assert.equal(host.test(value), true);
    for (const value of ["owned-unit.azurefd.net.attacker.invalid", "other.azurefd.net", "owned-unit.azurefd.net:444"]) assert.equal(host.test(value), false);
    const uri = new RegExp(rule.matchConditions[1].matchValue[0]);
    assert.equal(uri.test("/"), true);
    assert.equal(uri.test("/index.php?benign=1"), true);
    assert.equal(uri.test("https://owned-unit.azurefd.net/health.php"), true);
    assert.equal(uri.test("/evidence/response"), false);
    assert.equal(uri.test("/login"), false);
  }
  for (const count of [19, 20, 21]) {
    const field = `field${"[part]".repeat(count)}`;
    const form = responseRule("form", ["owned-unit.azurefd.net"]).matchConditions.at(-1);
    const multipart = responseRule("multipart", ["owned-unit.azurefd.net"]).matchConditions.at(-1);
    assert.equal(new RegExp(form.matchValue[0]).test(decodeURIComponent(`${encodeURIComponent(field)}=benign`)), count >= 20);
    for (const name of [`"${field}"`, field, `"escaped\\\"${field}"`, `"escaped\\\\${field}"`]) {
      assert.equal(new RegExp(multipart.matchValue[0]).test(`content-disposition: form-data; name=${name}\r\n\r\nbenign`), count >= 20);
    }
  }
});

test("response preview is read-only, scoped and never exposes application settings or assumes rollout", async () => {
  const h = fixture();
  const preview = await buildResponsePlan(h.cfg, h.io, h.options);
  assert.equal(h.state.writes.length, 0);
  assert.equal(h.state.requests.length, 0);
  assert.equal(preview.actions.find((action) => action.id === "response-rule").available, false);
  assert.equal(preview.scope.appId, h.cfg.names.appId);
  assert.equal(JSON.stringify(preview).includes(h.state.settings.PRIVATE_SETTING), false);
  assert.equal(h.state.group.tags["pawprint.expiresAt"], h.cfg.expiry);
  await assert.rejects(() => applyResponse(h.cfg, h.io, "prevention", preview, h.options), /writes are disabled/);
  h.cfg.expiresAt = NOW;
  const reads = h.state.reads.length;
  await assert.rejects(() => buildResponsePlan(h.cfg, h.io, h.options), /window has ended/);
  assert.equal(h.state.reads.length, reads);
});

test("mutations require fresh unchanged previews, preserve controls and prohibit silent rule adoption/downgrades", async () => {
  const h = fixture();
  await h.enable();
  const originalMarker = structuredClone(h.state.policy.properties.customRules.rules[0]);
  let preview = await buildResponsePlan(h.cfg, h.io, h.options);
  await assert.rejects(() => applyResponse(h.cfg, h.io, "session-block", preview, h.options), /Stage and independently review/);
  await applyResponse(h.cfg, h.io, "session-log", preview, h.options);
  assert.deepEqual(h.state.policy.properties.customRules.rules[0], originalMarker);
  assert.equal(h.state.policy.properties.policySettings.mode, "Prevention");
  assert.equal(h.state.policy.properties.policySettings.requestBodyCheck, "Enabled");
  await assert.rejects(() => applyResponse(h.cfg, h.io, "form-log", preview, h.options), /changed after preview/);
  preview = await buildResponsePlan(h.cfg, h.io, h.options);
  await applyResponse(h.cfg, h.io, "session-block", preview, h.options);
  preview = await buildResponsePlan(h.cfg, h.io, h.options);
  await assert.rejects(() => applyResponse(h.cfg, h.io, "session-log", preview, h.options), /Downgrading/);
  await assert.rejects(() => applyResponse(h.cfg, h.io, "form-log", { ...preview, createdAt: new Date(NOW - 600001).toISOString() }, h.options), /fresh reviewed/);
  assert.equal(h.state.group.tags["pawprint.expiresAt"], h.cfg.expiry);
  assert.equal(h.state.group.tags["dojo.state"], "training");
  assert.ok(h.state.writes.every((entry) => entry.id === h.cfg.names.policyId || entry.id.endsWith("/providers/Microsoft.Resources/tags/default")));
});

test("response rule is enabled only when published in an existing reviewed DRS; unrelated overrides survive", async () => {
  const h = fixture();
  await h.enable();
  const set = { ruleSetType: "Microsoft_DefaultRuleSet", ruleSetVersion: "2.2", ruleSetAction: "Block",
    ruleGroupOverrides: [{ ruleGroupName: "SQLI", rules: [{ ruleId: "942100", enabledState: "Enabled", action: "AnomalyScoring" }] }] };
  h.state.policy.properties.managedRules.managedRuleSets = [set];
  let preview = await buildResponsePlan(h.cfg, h.io, h.options);
  assert.equal(preview.actions.find((action) => action.id === "response-rule").available, false);
  h.state.catalog = [{ properties: { ruleSetType: set.ruleSetType, ruleSetVersion: "2.2",
    ruleGroups: [{ ruleGroupName: RESPONSE_GUIDANCE.responseGroup, rules: [{ ruleId: "99006001" }] }] } }];
  preview = await buildResponsePlan(h.cfg, h.io, h.options);
  const result = await applyResponse(h.cfg, h.io, "response-rule", preview, h.options);
  assert.equal(result.responseRuleLogsExpected, false);
  const groups = h.state.policy.properties.managedRules.managedRuleSets[0].ruleGroupOverrides;
  assert.deepEqual(groups[0], set.ruleGroupOverrides[0]);
  assert.deepEqual(groups[1].rules, [{ ruleId: "99006001", enabledState: "Enabled", action: "AnomalyScoring" }]);
  assert.equal(result.runtimePatchedByThisAction, false);
});

test("fixture removal preserves private settings and is not called PHP remediation; verification measures real version/HTTP/roles", async () => {
  const h = fixture();
  await h.enable();
  const preview = await buildResponsePlan(h.cfg, h.io, h.options);
  const result = await applyResponse(h.cfg, h.io, "resolve-fixtures", preview, h.options);
  assert.equal(result.runtimePatchedByThisAction, false);
  assert.equal(h.state.settings.PRIVATE_SETTING, "unit-private-setting-never-expose");
  let actual = await verifyResponse(h.cfg, h.io, h.options);
  assert.equal(actual.fixturesClosed, true);
  assert.equal(actual.preventionObserved, true);
  assert.equal(actual.resolved, false);
  assert.equal(actual.runtime.status, "patch-review-required");
  h.state.php = `${h.cfg.invocation.phpVersion}.${RESPONSE_GUIDANCE.fixed[h.cfg.invocation.phpVersion]}`;
  h.state.requests.length = 0;
  actual = await verifyResponse(h.cfg, h.io, h.options);
  assert.equal(actual.resolved, true);
  assert.ok(h.state.requests.length <= 20);
  assert.ok(h.state.requests.every((entry) => /^[a-z0-9.-]+$/.test(new URL(entry.url).hostname)));
  h.state.grants = [{ properties: { principalId: h.state.rows.get(h.cfg.names.appId).identity.principalId } }];
  await assert.rejects(() => verifyResponse(h.cfg, h.io, h.options), /has Azure role grants/);
});

test("partial or ambiguous writes require reconciliation and never imply a rollback or completed resolution", async () => {
  const h = fixture();
  h.cfg.responseWritesEnabled = true;
  const preview = await buildResponsePlan(h.cfg, h.io, h.options);
  const write = h.io.write;
  h.io.write = async (...args) => {
    if (args[1] === "PATCH") throw Object.assign(new Error("tag permission rejected"), { status: 403 });
    return write(...args);
  };
  await assert.rejects(() => applyResponse(h.cfg, h.io, "prevention", preview, h.options), (error) => error.mutationMayHaveOccurred === true);
  assert.equal(h.state.policy.properties.policySettings.mode, "Prevention");
  assert.equal(h.state.group.tags["dojo.wafMode"], "Detection");
});

test("dispatch binds mutation approval to exact session/epoch/group/preview and refuses default-off writes", async () => {
  const h = await setup();
  const f = fixture(h.cfg);
  const preview = await buildResponsePlan(h.cfg, f.io, f.options);
  const control = new ControlPlane(h.cfg, h.store, h.credentials, () => ({}), { now: () => NOW });
  const sourceId = randomUUID();
  await h.store.write(`jobs/${sourceId}`, { id: sourceId, operation: "response", response: { id: "plan" }, status: "completed",
    target: h.cfg.names.appId, sessionHash: h.session.hash, credentialEpoch: h.session.epoch, result: preview });
  const approval = { id: "prevention", planJobId: sourceId, fingerprint: preview.fingerprint, confirmation: h.cfg.names.group };
  await assert.rejects(() => control.start(h.session, "response", randomUUID(), undefined, undefined, approval), /writes are disabled/);
  h.cfg.responseWritesEnabled = true;
  await assert.rejects(() => validateResponseDispatch(control, h.session, { ...approval, confirmation: "another-group" }), /exact resource-group/);
  await assert.rejects(() => validateResponseDispatch(control, { ...h.session, epoch: randomUUID() }, approval), /fresh available/);
  const job = await control.start(h.session, "response", randomUUID(), undefined, undefined, approval);
  assert.equal(job.response.fingerprint, preview.fingerprint);
  assert.deepEqual(await control.start(h.session, "response", job.id, undefined, undefined, approval), job);
  await assert.rejects(() => control.start(h.session, "response", job.id, undefined, undefined, { ...approval, id: "session-log" }), /another action/);
});

test("managed-identity response writer denies scope/API/method and settings access before obtaining tokens", async () => {
  const cfg = config();
  let tokens = 0;
  const azure = { credential: { getToken: async () => { tokens += 1; throw new Error("No token expected"); } } };
  const io = responseIo(cfg, azure, async () => {});
  await assert.rejects(() => io.write(cfg.names.policyId, "PUT", "2025-03-01", {}), /explicit opt-in/);
  await assert.rejects(() => io.settings(), /not authorized/);
  cfg.responseWritesEnabled = true;
  await assert.rejects(() => io.write(cfg.names.appId, "PUT", "2025-03-01", {}), /exact resource/);
  await assert.rejects(() => io.write(cfg.names.policyId, "DELETE", "2025-03-01", {}), /exact resource/);
  assert.equal(tokens, 0);
});

test("durable response worker consumes a preview once and never replays a mutation", async () => {
  const h = await setup();
  h.cfg.responseWritesEnabled = true;
  const f = fixture(h.cfg);
  let time = NOW;
  const control = new ControlPlane(h.cfg, h.store, h.credentials, () => managedFixture(f),
    { now: () => time, fetchImpl: f.io.fetchImpl, log: () => {} });
  const previewJob = await control.start(h.session, "response", randomUUID(), undefined, undefined, { id: "plan" });
  await control.workOnce();
  const preview = (await h.store.read(`jobs/${previewJob.id}`)).value.result;
  time += 61000;
  const approval = { id: "prevention", planJobId: previewJob.id, fingerprint: preview.fingerprint, confirmation: h.cfg.names.group };
  const change = await control.start(h.session, "response", randomUUID(), undefined, undefined, approval);
  await control.workOnce();
  assert.equal((await h.store.read(`jobs/${change.id}`)).value.status, "completed");
  assert.equal((await h.store.read(`control/response/${previewJob.id}`)).value.jobId, change.id);
  const writes = f.state.writes.length;
  await h.store.send(change.id);
  await control.workOnce();
  assert.equal(f.state.writes.length, writes);
  time += 61000;
  const replay = await control.start(h.session, "response", randomUUID(), undefined, undefined, approval);
  await control.workOnce();
  assert.match((await h.store.read(`jobs/${replay.id}`)).value.error, /already been consumed/);
  assert.equal(f.state.writes.length, writes);
  assert.ok(h.store.events.some((event) => event.event === "response-write-intent"));
});

test("uncertain response worker leaves a durable reconciliation latch and refuses subsequent execution", async () => {
  const h = await setup();
  h.cfg.responseWritesEnabled = true;
  const f = fixture(h.cfg);
  let time = NOW;
  const control = new ControlPlane(h.cfg, h.store, h.credentials, () => managedFixture(f),
    { now: () => time, log: () => {} });
  const previewJob = await control.start(h.session, "response", randomUUID(), undefined, undefined, { id: "plan" });
  await control.workOnce();
  const preview = (await h.store.read(`jobs/${previewJob.id}`)).value.result;
  const write = f.io.write;
  f.io.write = async (...args) => {
    if (args[1] === "PATCH") throw new Error("Uncertain connection interruption");
    return write(...args);
  };
  time += 61000;
  const change = await control.start(h.session, "response", randomUUID(), undefined, undefined,
    { id: "prevention", planJobId: previewJob.id, fingerprint: preview.fingerprint, confirmation: h.cfg.names.group });
  await control.workOnce();
  const record = (await h.store.read(`jobs/${change.id}`)).value;
  assert.equal(record.status, "reconciliation-required");
  assert.equal(record.automaticReplayForbidden, true);
  time += 61000;
  await assert.rejects(() => control.start(h.session, "validate", randomUUID()), /active or unresolved/);
});

test("downloadable response bundle is bounded, readable, attributed and does not run imported CLI guards", (t) => {
  const directory = mkdtempSync(join(tmpdir(), "php2proof-response-test-"));
  t.after(() => rmSync(directory, { recursive: true }));
  const output = join(directory, "artifact");
  const manifest = responseArtifact(output);
  assert.ok(manifest.combinedProtectedBytes <= 61440);
  const source = JSON.parse(gunzipSync(readFileSync(join(output, "response.json.gz"))));
  assert.deepEqual(Object.keys(source.files).sort(), [...RESPONSE_FILES].sort());
  const script = source.files["operator/public-scripts/response.mjs"];
  assert.equal(readFileSync(join(output, "php2proof-response.mjs"), "utf8"), script);
  assert.match(script, /Permission is hereby granted/);
  assert.match(script, /responseCli/);
  assert.match(script, /OPERATOR|responseWritesEnabled/);
  const path = join(directory, "response.mjs");
  writeFileSync(path, script);
  const result = spawnSync(process.execPath, [path, "plan", "--environment", "prod", "--subscription", "11111111-1111-4111-8111-111111111111", "--suffix", "unit"], { encoding: "utf8", timeout: 10000 });
  assert.equal(result.status, 1);
  assert.match(result.stderr, /Only --environment dev/);
  assert.equal(result.stdout, "");
  assert.doesNotMatch(result.stderr, /CLOUDFLARE|zone.*required|Unsupported.*command/);
});

test("actual embedded publisher permits closed response maintenance after expiry but rejects foreign files and expired full releases", (t) => {
  const directory = mkdtempSync(join(tmpdir(), "php2proof-response-publisher-test-"));
  t.after(() => rmSync(directory, { recursive: true }));
  const build = join(directory, "response");
  responseArtifact(build);
  const response = JSON.parse(gunzipSync(readFileSync(join(build, "response.json.gz"))));
  const shell = readFileSync(new URL("../publish-hunts.sh", import.meta.url), "utf8").replaceAll("\r\n", "\n");
  const python = /python3 - <<'PY'\n([\s\S]*?)\nPY/.exec(shell)[1];
  let sequence = 0;
  const validate = (source) => {
    const output = join(directory, `case-${sequence++}`);
    mkdirSync(output);
    const bytes = gzipSync(JSON.stringify(source));
    const encoded = bytes.toString("base64");
    const env = { ORIGINAL_EXPIRY: "2000-01-01T00:00:00.000Z", HUNT_PUBLICATION_ROOT: output,
      SOURCE_SHA256: createHash("sha256").update(bytes).digest("hex"), SOURCE_COUNT: String(Math.ceil(encoded.length / 4000)) };
    for (let index = 0; index < Number(env.SOURCE_COUNT); index += 1) env[`SOURCE_${index}`] = encoded.slice(index * 4000, (index + 1) * 4000);
    const program = `import ast,json,os,sys\nsource=${JSON.stringify(python)}\nast.parse(source)\nos.environ.update(json.loads(sys.stdin.read()))\nexec(compile(source,'reviewed-publisher-validation','exec'))`;
    const result = spawnSync(process.platform === "win32" ? "python" : "python3", ["-c", program],
      { input: JSON.stringify(env), encoding: "utf8", timeout: 10000, maxBuffer: 1048576 });
    if (result.error) throw result.error;
    return { ...result, output };
  };
  const accepted = validate(response);
  assert.equal(accepted.status, 0, accepted.stderr);
  assert.equal(JSON.parse(accepted.stdout).kind, "response-maintenance");
  assert.equal(existsSync(join(accepted.output, "hunting.zip")), true);
  const publicBuild = join(directory, "public");
  responseArtifact(publicBuild, "public-walkthrough-maintenance");
  const publicSource = JSON.parse(gunzipSync(readFileSync(join(publicBuild, "response.json.gz"))));
  const publicAccepted = validate(publicSource);
  assert.equal(publicAccepted.status, 0, publicAccepted.stderr);
  const listing = spawnSync(process.platform === "win32" ? "python" : "python3",
    ["-c", "import json,sys,zipfile;print(json.dumps(zipfile.ZipFile(sys.argv[1]).namelist()))", join(publicAccepted.output, "hunting.zip")],
    { encoding: "utf8", timeout: 10000 });
  assert.equal(listing.status, 0);
  assert.deepEqual(JSON.parse(listing.stdout), ["walkthrough.php"]);
  const rejected = validate({ ...response, files: { ...response.files, "operator/auth.mjs": "not allowed" } });
  assert.notEqual(rejected.status, 0);
  assert.match(rejected.stderr, /file allowlist rejected/);
  assert.equal(existsSync(join(rejected.output, "hunting.zip")), false);
  const hunting = join(directory, "hunting");
  buildHuntingArtifact(hunting, "release");
  const full = JSON.parse(gunzipSync(readFileSync(join(hunting, "hunting.json.gz"))));
  const expired = validate(full);
  assert.notEqual(expired.status, 0);
  assert.match(expired.stderr, /Original hunting lifetime ended/);
});
