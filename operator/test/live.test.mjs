import test from "node:test";
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { once } from "node:events";
import { ControlPlane } from "../control.mjs";
import { runLiveJob } from "../live.mjs";
import { livePublicCandidate, renderLiveWalkthrough, validateReviewedLive } from "../live-public.mjs";
import { liveEvidenceQueries, captureLiveEvidence } from "../live-evidence.mjs";
import { privateLivePage } from "../live-control.mjs";
import { createOperatorServer } from "../server.mjs";
import { operatorPolicyId } from "../live-waf.mjs";
import { liveIo, teardownId } from "../live-azure.mjs";
import { setup, NOW } from "./support.mjs";

async function fixture() {
  const h = await setup();
  const cfg = h.cfg;
  cfg.originalExpiresAt = NOW - 1000;
  cfg.originalExpiry = new Date(cfg.originalExpiresAt).toISOString();
  cfg.operatorGroupId = `/subscriptions/${cfg.invocation.subscription}/resourceGroups/unit-operator`;
  const window = { schemaVersion: 1, id: h.session.epoch, notBefore: new Date(NOW - 300_000).toISOString(),
    expiresAt: cfg.expiry, resourceGroup: `rg-p2sc-${cfg.invocation.suffix}-dev`, autoTeardown: true };
  const groupId = `/subscriptions/${cfg.invocation.subscription}/resourceGroups/${window.resourceGroup}`;
  cfg.liveWindow = { ...window, startsAt: Date.parse(window.notBefore), endsAt: cfg.expiresAt, groupId };
  cfg.liveTarget = {
    subscription: cfg.invocation.subscription, suffix: cfg.invocation.suffix, resourceGroupId: groupId,
    clusterId: `${groupId}/providers/Microsoft.ContainerService/managedClusters/p2sc-${cfg.invocation.suffix}-aks`,
    registryId: `${groupId}/providers/Microsoft.ContainerRegistry/registries/p2sc${cfg.invocation.suffix}`,
    window, marker: { windowId: window.id, expiresAt: window.expiresAt },
    images: Object.fromEntries([["affected", "8.4.26", "a"], ["fixed", "8.4.27", "b"]].map(([key, version, hex]) =>
      [key, { version, digest: `sha256:${hex.repeat(64)}`, observedAt: new Date(NOW - 60_000).toISOString() }])),
  };
  let clock = NOW;
  const snapshot = (version = "8.4.26") => ({
    observedAt: new Date(clock).toISOString(), namespaceUid: "namespace", deploymentUid: "deployment",
    deploymentResourceVersion: "100", podUid: "pod", imageId: `sha256:${(version === "8.4.27" ? "b" : "a").repeat(64)}`,
    image: `p2sc${cfg.invocation.suffix}.azurecr.io/php2shell@sha256:${(version === "8.4.27" ? "b" : "a").repeat(64)}`,
    healthStatus: 200, isolationVerified: true, health: { phpVersion: version },
  });
  const policy = {
    id: operatorPolicyId(cfg), location: "Global", sku: { name: "Premium_AzureFrontDoor" },
    tags: { "dojo.scenario": "php2proof-operator", "dojo.suffix": cfg.invocation.suffix, "pawprint.expiresAt": cfg.originalExpiry },
    properties: { policySettings: { enabledState: "Enabled", mode: "Prevention" },
      customRules: { rules: [] }, managedRules: { managedRuleSets: [] } },
  };
  const azure = { logs: async () => [], collection: async () => [], pricing: async () => ({ pricingTier: "Standard" }) };
  const control = new ControlPlane(cfg, h.store, h.credentials, () => azure, { now: () => clock, log: () => {} });
  const io = {
    target: async () => cfg.liveTarget,
    runtime: async (_target, input) => {
      if (input.operation === "run") assert.ok(await h.store.read(`control/live/${h.plan.id}`), "Audit/one-use latch precedes actual process dispatch.");
      return { command: "fixed-unit-command-not-executed", record: {
        runId: input.runId, startedAt: new Date(clock).toISOString(), finishedAt: new Date(clock).toISOString(),
        before: snapshot(), after: snapshot(),
        process: input.operation === "run" ? { command: "id", stdout: "uid=10001 gid=10001 groups=10001", exitCode: 0,
          startedAt: new Date(clock).toISOString(), finishedAt: new Date(clock).toISOString() } : null,
      } };
    },
    policy: async () => structuredClone(policy),
    transport: async (runId) => ({ runId, status: 200, startedAt: new Date(clock).toISOString(), endedAt: new Date(clock).toISOString() }),
  };
  const saveCompleted = async (job, result, evidence) => {
    const row = await h.store.read(`jobs/${job.id}`);
    const value = { ...job, status: "completed", result, ...(evidence ? { evidenceKey: `evidence/${job.id}` } : {}) };
    await h.store.write(`jobs/${job.id}`, value, row.etag);
    if (evidence) await h.store.write(`evidence/${job.id}`, evidence);
    return value;
  };
  return Object.assign(h, { cfg, control, io, azure, snapshot, saveCompleted, advance: () => { clock += 61_000; } });
}

test("AKS live adapter uses separate managed-AAD and ARM tokens and never follows a foreign accepted-command location", async () => {
  const h = await fixture();
  const scopes = [], requests = [];
  const azure = {
    credential: { getToken: async (scope) => {
      scopes.push(scope);
      return { token: scope.startsWith("6dae42f8-") ? "unit-cluster-token" : "unit-arm-token", expiresOnTimestamp: Date.now() + 60_000 };
    } },
    fetchImpl: async (url, options) => {
      requests.push({ url, options });
      return new Response(null, { status: 202, headers: { location: "https://foreign.invalid/commandResults/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa?api-version=2025-07-01" } });
    },
  };
  const io = liveIo(h.control, azure, async () => {}, fetch);
  await assert.rejects(io.runtime(h.cfg.liveTarget, {
    operation: "verify", operationId: randomUUID(), runId: randomUUID(), variant: "either",
  }, randomUUID()), (error) => /tracking location escaped/.test(error.message) && error.mutationMayHaveOccurred === true);
  assert.deepEqual(scopes, ["6dae42f8-4368-4678-94ff-3960e28e3630/.default", "https://management.azure.com/.default"]);
  assert.equal(requests.length, 1);
  assert.equal(requests[0].url, `https://management.azure.com${h.cfg.liveTarget.clusterId}/runCommand?api-version=2025-07-01`);
  assert.equal(requests[0].options.redirect, "manual");
  assert.equal(requests[0].options.headers.Authorization, "Bearer unit-arm-token");
  assert.equal(JSON.parse(requests[0].options.body).clusterToken, "unit-cluster-token");
  assert.equal(h.store.events.filter((event) => event.event === "private-command-intent").length, 1);
  assert.doesNotMatch(JSON.stringify(h.store.events), /unit-cluster-token|unit-arm-token/);
});

test("AKS live adapter preserves uncertain acceptance without replay and distinguishes explicit authorization rejection", async () => {
  const h = await fixture();
  let calls = 0;
  const azure = {
    credential: { getToken: async () => ({ token: "unit-access-token", expiresOnTimestamp: Date.now() + 60_000 }) },
    fetchImpl: async () => { calls += 1; return new Response(null, { status: 202 }); },
  };
  const io = liveIo(h.control, azure, async () => {}, fetch);
  const input = () => ({ operation: "verify", operationId: randomUUID(), runId: randomUUID(), variant: "either" });
  await assert.rejects(io.runtime(h.cfg.liveTarget, input(), randomUUID()),
    (error) => /no tracking location/.test(error.message) && error.mutationMayHaveOccurred === true);
  azure.fetchImpl = async () => { calls += 1; return new Response(null, { status: 200 }); };
  await assert.rejects(io.runtime(h.cfg.liveTarget, input(), randomUUID()),
    (error) => /documented asynchronous 202/.test(error.message) && error.mutationMayHaveOccurred === true);
  azure.fetchImpl = async () => {
    calls += 1;
    return Response.json({ error: { code: "AuthorizationFailed", message: "Unit authorization rejection." } }, { status: 403 });
  };
  await assert.rejects(io.runtime(h.cfg.liveTarget, input(), randomUUID()),
    (error) => error.status === 403 && !error.mutationMayHaveOccurred);
  assert.equal(calls, 3, "Each submission is attempted once; a missing result location is never replayed.");
});

test("private target readback requires actual group, cluster, registry and scheduled exact-group teardown", async () => {
  const h = await fixture();
  const group = { id: h.cfg.liveWindow.groupId, tags: {
    "dojo.liveWindowId": h.cfg.liveWindow.id, "dojo.liveWindowExpiresAt": h.cfg.expiry,
    "dojo.liveScenario": "php2proof-private-live", "pawprint.environment": "dev", "pawprint.expiresAt": h.cfg.expiry,
  } };
  const cluster = { id: h.cfg.liveTarget.clusterId, tags: { "dojo.liveWindowId": h.cfg.liveWindow.id }, properties: {
    apiServerAccessProfile: { enablePrivateCluster: true, enablePrivateClusterPublicFQDN: false, disableRunCommand: false },
    disableLocalAccounts: true, aadProfile: { enableAzureRBAC: true },
    agentPoolProfiles: [{ count: 1, enableNodePublicIP: false, securityProfile: { sshAccess: "Disabled" } }],
    securityProfile: { defender: { securityMonitoring: { enabled: true } } },
  } };
  const registry = { id: h.cfg.liveTarget.registryId, tags: { "dojo.liveWindowId": h.cfg.liveWindow.id },
    properties: { adminUserEnabled: false, anonymousPullEnabled: false } };
  const teardown = { id: teardownId(h.cfg), tags: { "dojo.liveWindowId": h.cfg.liveWindow.id }, properties: {
    state: "Enabled", definition: {
      triggers: { AtExpiry: { recurrence: { startTime: h.cfg.expiry } } },
      parameters: { privateGroupId: { defaultValue: h.cfg.liveWindow.groupId } },
      actions: { CheckBoundary: { actions: { DeleteOnlyAfterRevocation: { actions: { DeletePrivateGroup: {
        inputs: { method: "DELETE", uri: `https://management.azure.com${h.cfg.liveWindow.groupId}?api-version=2025-04-01` },
      } } } } } },
    },
  } };
  const rows = new Map([group, cluster, registry, teardown].map((value) => [value.id, value]));
  let tokenCalls = 0;
  const azure = {
    arm: async (url) => structuredClone(rows.get(url.split("?")[0])),
    credential: { getToken: async () => { tokenCalls += 1; throw new Error("No token should be requested by readback."); } },
  };
  const io = liveIo(h.control, azure, async () => {}, fetch);
  assert.equal((await io.target()).resourceGroupId, h.cfg.liveWindow.groupId);
  group.tags["dojo.liveWindowId"] = randomUUID();
  await assert.rejects(io.target(), /ownership/);
  group.tags["dojo.liveWindowId"] = h.cfg.liveWindow.id;
  cluster.properties.securityProfile.defender.securityMonitoring.enabled = false;
  await assert.rejects(io.target(), /cluster, node or Defender boundary/);
  cluster.properties.securityProfile.defender.securityMonitoring.enabled = true;
  teardown.properties.definition.parameters.privateGroupId.defaultValue = h.cfg.names.group;
  await assert.rejects(io.target(), /automatic teardown/);
  assert.equal(tokenCalls, 0);
});

test("live transport is only the fixed benign read-only marker and rejects redirects or fabricated success bodies", async () => {
  const h = await fixture();
  const runId = randomUUID();
  let response = new Response(null, { status: 302, headers: { location: "https://foreign.invalid" } });
  const requests = [];
  const io = liveIo(h.control, {}, async () => {}, async (url, options) => {
    requests.push({ url, options });
    return response;
  });
  await assert.rejects(io.transport("arbitrary-command"), /UUID/);
  assert.equal(requests.length, 0);
  await assert.rejects(io.transport(runId), /Unexpected live transport HTTP 302/);
  response = Response.json({ kind: "benign-read-only-transport-marker", runId, observedAt: new Date(NOW).toISOString(),
    executesCommands: true, testsPhpExploit: false });
  await assert.rejects(io.transport(runId), /actual fixed transport marker/);
  response = Response.json({ kind: "benign-read-only-transport-marker", runId, observedAt: new Date(NOW).toISOString(),
    executesCommands: false, testsPhpExploit: false });
  const result = await io.transport(runId);
  assert.equal(result.status, 200);
  assert.equal(result.evidenceKind, "actual-benign-edge-http-response-not-cve-exploitation");
  assert.equal(requests[2].url, `${h.cfg.origin}/evidence/live-probe/${runId}`);
  assert.equal(requests[2].options.redirect, "manual");
});

test("private execution is separately scoped, preview-bound, one-use and cannot renew legacy public actions", async () => {
  const h = await fixture();
  await assert.rejects(h.control.start(h.session, "simulate", randomUUID()), /original public-lab execution/);
  await assert.rejects(h.control.start(h.session, "live", randomUUID(), undefined, undefined, undefined,
    { id: "process-probe", command: "whoami" }), /Unknown private/);
  const planJob = await h.control.start(h.session, "live", randomUUID(), undefined, undefined, undefined, { id: "plan" });
  const preview = await runLiveJob(h.control, planJob, h.azure, async () => {}, fetch, { io: h.io });
  h.plan = await h.saveCompleted(planJob, preview.result);
  assert.equal(h.plan.target, h.cfg.liveWindow.groupId);
  assert.equal(h.plan.liveWindowId, h.cfg.liveWindow.id);
  const input = { id: "process-probe", planJobId: h.plan.id, fingerprint: h.plan.result.fingerprint, confirmation: h.cfg.liveWindow.resourceGroup };
  h.advance();
  await assert.rejects(h.control.start(h.session, "live", randomUUID(), undefined, undefined, undefined,
    { ...input, confirmation: h.cfg.names.group }), /exact private resource-group/);
  const action = await h.control.start(h.session, "live", randomUUID(), undefined, undefined, undefined, input);
  const result = await runLiveJob(h.control, action, h.azure, async () => {}, fetch, { io: h.io });
  await h.saveCompleted(action, result.result, result.evidence);
  assert.equal(result.result.runtime.process.command, "id");
  assert.equal(result.evidence.captures.defenderAlerts.status, "queried");
  assert.deepEqual(result.evidence.captures.defenderAlerts.rows, []);
  h.advance();
  await assert.rejects(h.control.start(h.session, "live", randomUUID(), undefined, undefined, undefined, input), /already been consumed/);
  const page = await privateLivePage(h.cfg, h.store, h.session, NOW + 122_000);
  assert.match(page, /Original public authorization/);
  assert.match(page, /button disabled/);
  assert.doesNotMatch(page, /whoami/);
});

test("only fresh read/reconciliation jobs can pass an indeterminate private latch; it is never silently cleared", async () => {
  const h = await fixture();
  const id = randomUUID();
  await h.store.write(`jobs/${id}`, { id, operation: "live", target: h.cfg.liveWindow.groupId,
    liveWindowId: h.cfg.liveWindow.id, status: "reconciliation-required" });
  await h.store.write("control/dispatch", { activeJob: id, starts: [] });
  await assert.rejects(h.control.start(h.session, "live", randomUUID(), undefined, undefined, undefined, { id: "process-probe" }), /fresh preview/);
  const plan = await h.control.start(h.session, "live", randomUUID(), undefined, undefined, undefined, { id: "plan" });
  const observed = await runLiveJob(h.control, plan, h.azure, async () => {}, fetch, { io: h.io });
  await h.saveCompleted(plan, observed.result);
  assert.equal(observed.result.unresolvedJobId, id);
  assert.equal((await h.store.read("control/dispatch")).value.activeJob, id);
  assert.equal(observed.result.actions.find((action) => action.id === "runtime-fix").available, false);
  assert.equal(observed.result.actions.find((action) => action.id === "reconcile").available, true);
  h.advance();
  const action = await h.control.start(h.session, "live", randomUUID(), undefined, undefined, undefined,
    { id: "reconcile", planJobId: plan.id, fingerprint: observed.result.fingerprint, confirmation: h.cfg.liveWindow.resourceGroup });
  const reconciled = await runLiveJob(h.control, action, h.azure, async () => {}, fetch, { io: h.io });
  assert.equal(reconciled.result.earlierExecutionConfirmed, false);
  assert.equal((await h.store.read(`jobs/${id}`)).value.status, "reconciled-current-state");
  assert.equal((await h.store.read(`jobs/${id}`)).value.automaticReplayForbidden, true);
});

test("real-evidence queries are namespace/time/resource bounded; missing sources are not empty successful detections", async () => {
  const h = await fixture();
  const run = { runId: randomUUID(), startedAt: new Date(NOW - 10_000).toISOString(), endedAt: new Date(NOW).toISOString() };
  const queries = liveEvidenceQueries(h.cfg, run, new Date(NOW).toISOString());
  assert.match(queries.audit, /command=id/);
  assert.match(queries.audit, /php2shell-isolated/);
  assert.ok(queries.audit.includes(h.cfg.liveTarget.clusterId));
  const evidence = await captureLiveEvidence(h.cfg, run, { ...h.azure,
    logs: async () => { throw new Error("Source table unavailable"); } }, { now: () => NOW, log: () => {} });
  assert.equal(evidence.captures.aksAudit.status, "unavailable");
  assert.equal(evidence.captures.defenderAlerts.status, "queried");
  assert.deepEqual(evidence.captures.defenderAlerts.rows, []);
  assert.match(evidence.comparison, /not a controlled Defender-off/);
  assert.throws(() => liveEvidenceQueries(h.cfg, { ...run, startedAt: "not-utc" }, new Date(NOW).toISOString()));
});

function recording(h) {
  const startedAt = new Date(NOW).toISOString();
  const steps = [];
  const actions = ["waf-log", "process-probe", "transport-probe", "waf-block", "runtime-fix", "verify", "runtime-reset", "verify", "runtime-fix", "verify", "waf-remove"];
  let fixed = false;
  for (const [index, action] of actions.entries()) {
    const before = fixed ? "8.4.27" : "8.4.26";
    if (action === "runtime-fix") fixed = true;
    if (action === "runtime-reset") fixed = false;
    const time = new Date(NOW + index * 1000).toISOString();
    const result = { runId: randomUUID(), startedAt: time, endedAt: time,
      ...(action === "process-probe" || action.startsWith("runtime-") || action === "verify" ? {
        runtime: { before: { ...h.snapshot(before), observedAt: time }, after: { ...h.snapshot(fixed ? "8.4.27" : "8.4.26"), observedAt: time },
          ...(action === "process-probe" ? { process: { command: "id", stdout: "uid=10001 gid=10001 groups=10001", exitCode: 0, startedAt: time, finishedAt: time } } : {}) },
      } : {}),
      ...(action.startsWith("waf-") || action === "transport-probe" ? {
        transport: { status: action === "waf-block" ? 403 : 200, startedAt: time, endedAt: time,
          evidenceKind: "actual-benign-edge-http-response-not-cve-exploitation" },
      } : {}),
      ...(action.startsWith("waf-") ? { waf: { mode: "Prevention", rule: { action: action === "waf-log" ? "Log" : action === "waf-block" ? "Block" : "absent" } } } : {}),
    };
    const captures = Object.fromEntries(["aksAudit", "waf", "defenderAlerts"].map((name) => [name, {
      status: "queried", rows: [], ...(name === "defenderAlerts" ? {} : { query: `Source | where Resource == '${h.cfg.liveTarget.clusterId}'` }),
    }]));
    steps.push({ job: { operation: "live", liveWindowId: h.cfg.liveWindow.id, live: { id: action }, status: "completed", result },
      evidence: { capturedAt: time, captures, plans: Object.fromEntries(["AppServices", "CloudPosture", "Containers"].map((name) => [name, { status: "queried", tier: "Standard" }])) } });
  }
  return { schemaVersion: 1, windowId: h.cfg.liveWindow.id, status: "completed", startedAt,
    finishedAt: new Date(NOW + 20_000).toISOString(), steps };
}

test("review candidates omit sensitive raw fields; public cards require a complete measured fix/reset/final-fix cycle and explicit review", async () => {
  const h = await fixture();
  const capture = recording(h);
  capture.steps[1].job.secret = "must-not-publish";
  const candidate = livePublicCandidate(h.cfg, capture);
  assert.doesNotMatch(JSON.stringify(candidate), /must-not-publish|resourceGroups/);
  assert.equal(candidate.reviewed, false);
  assert.throws(() => renderLiveWalkthrough(candidate, h.cfg.origin), /separately reviewed/);
  candidate.reviewed = true;
  assert.equal(validateReviewedLive(candidate), candidate);
  const html = renderLiveWalkthrough(candidate, h.cfg.origin);
  assert.equal((html.match(/class="live-card"/g) ?? []).length, 10);
  assert.match(html, /Deploy to Azure/);
  assert.match(html, /uid=10001/);
  assert.match(html, /Queried:<\/strong> 0/);
  assert.match(html, /not a PHP exploitation recording/);
  assert.match(html, /https:\/\/github.com\/ninjapaw\/php2shell-cloud-defense-dojo/);
  assert.doesNotMatch(html, /<form\b|<script\b/);
  const incomplete = structuredClone(candidate);
  incomplete.steps = incomplete.steps.filter((step) => step.action !== "runtime-reset");
  assert.throws(() => validateReviewedLive(incomplete), /required baseline/);
});

test("anonymous transport marker is bounded/read-only, while private live execution still needs edge, authentication, Origin and CSRF", async (t) => {
  const h = await fixture();
  const server = createOperatorServer(h.cfg, { ...h, control: h.control, log: () => {} });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const base = `http://127.0.0.1:${server.address().port}`;
  const headers = { "X-Azure-FDID": h.cfg.frontDoorId };
  const path = `/evidence/live-probe/${randomUUID()}`;
  assert.equal((await fetch(`${base}${path}`)).status, 403);
  const marker = await fetch(`${base}${path}`, { headers });
  assert.equal(marker.status, 200);
  assert.equal((await marker.json()).executesCommands, false);
  assert.equal((await fetch(`${base}/live`, { headers })).status, 401);
  assert.equal((await fetch(`${base}/jobs`, { method: "POST", headers: { ...headers, Origin: h.cfg.origin, "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ operation: "live", liveId: "process-probe" }) })).status, 401);
  assert.equal(h.store.queue.length, 0);
});
