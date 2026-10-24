import assert from "node:assert/strict";
import test from "node:test";
import { execute } from "../scripts/dojo.mjs";
import { names, parseInvocation } from "../scripts/lib/config.mjs";
import { configuration, DEFAULT_CONFIG, harness, SUBSCRIPTION } from "./support/harness.mjs";

function domainHarness(options = {}) {
  const config = configuration("domain", { yes: true, customDomain: "php2proof.example.org", ...options.config });
  const h = harness(config, options);
  const records = [];
  const writes = [];
  const cloudflareCalls = [];
  const zoneId = "b".repeat(32);
  const token = "test-token-never-log";
  const edgeHost = `${names(config).endpoint}-fingerprint.z01.azurefd.net`;
  const cloudflareFetch = async (url, request) => {
    assert.equal(new URL(url).origin, "https://api.cloudflare.com");
    assert.equal(request.headers.Authorization, `Bearer ${token}`);
    cloudflareCalls.push({ url, method: request.method });
    let result;
    if (!url.includes("/dns_records")) result = { id: zoneId, name: "example.org", status: "active" };
    else if (["POST", "PATCH"].includes(request.method)) {
      const body = JSON.parse(request.body);
      result = { ...body, id: (records.length + 1).toString(16).padStart(32, "0") };
      records.push(result);
      writes.push(result);
    } else result = records.filter((record) => record.name === new URL(url).searchParams.get("name"));
    return Response.json({ success: true, result, result_info: { total_pages: 1 } });
  };
  const resolver = {
    resolveTxt: async () => [["azure-validation-token"]],
    resolveCname: async () => [options.dnsTarget ?? edgeHost],
  };
  Object.assign(h.dependencies, {
    environment: { CLOUDFLARE_ZONE_ID: zoneId, CLOUDFLARE_API_TOKEN: token },
    cloudflareFetch, resolver,
  });
  return { ...h, config, records, writes, cloudflareCalls, edgeHost, token };
}

const creates = (h) => h.calls.filter((args) => args.slice(0, 3).join(" ") === "deployment sub create");

test("DNS is opt-in and custom-domain intent cannot override a simulator or normal deployment target", async () => {
  for (const command of ["simulate", "validate", "deploy", "repair", "uninstall"]) {
    assert.throws(() => parseInvocation([
      command, "--suffix", "demo1234", "--subscription", SUBSCRIPTION, "--custom-domain", "arbitrary.example.org",
    ], DEFAULT_CONFIG, {}), /simulation targets cannot be overridden/);
  }
  const plan = await execute(configuration("plan", { customDomain: "php2proof.example.org" }), { log() {} });
  assert.equal(plan.initialState.customDomainName, "");
  assert.equal(plan.initialState.associateCustomDomain, false);
  assert.equal(plan.dns.customDomain, "php2proof.example.org");
  assert.match(plan.dns.activation, /separate domain --yes/);
});

test("domain requires acknowledgement and scoped credentials before any Azure write", async () => {
  const unconfirmed = domainHarness({ config: { yes: false } });
  await assert.rejects(execute(unconfirmed.config, unconfirmed.dependencies), /--yes/);
  assert.equal(unconfirmed.calls.length, 0);
  const missing = domainHarness();
  missing.dependencies.environment.CLOUDFLARE_API_TOKEN = "";
  await assert.rejects(execute(missing.config, missing.dependencies), /CLOUDFLARE_API_TOKEN/);
  assert.equal(creates(missing).length, 0);
  assert.equal(missing.writes.length, 0);
  assert.equal(missing.requests.length, 0);
});

test("Front Door domain lifecycle validates DNS before route/WAF association and verifies both HTTPS surfaces", async () => {
  const h = domainHarness();
  const expiry = h.state.group.tags["pawprint.expiresAt"];
  const result = await execute(h.config, h.dependencies);
  assert.equal(result.validated, true);
  assert.equal(result.customDomain, "https://php2proof.example.org");
  assert.equal(result.directOriginBlocked, true);
  assert.equal(creates(h).length, 2);
  assert.ok(creates(h)[0].includes("associateCustomDomain=false"));
  assert.ok(creates(h)[1].includes("associateCustomDomain=true"));
  assert.equal(h.calls.filter((args) => args.slice(0, 3).join(" ") === "deployment sub what-if").length, 2);
  assert.equal(h.writes.length, 2);
  assert.equal(h.writes[1].content, h.edgeHost);
  assert.equal(h.writes[1].proxied, false);
  assert.equal(h.writes[1].comment, "pawprint:dns:ninjapaw/php2shell-cloud-defense-dojo:dev:demo1234");
  assert.equal(h.state.group.tags["pawprint.expiresAt"], expiry);
  assert.equal(h.state.packaged, 0);
  assert.equal(h.requests.length, 6);
  assert.ok(h.requests.some((request) => request.url === "https://php2proof.example.org/health.php"));
  assert.ok(h.logs.every((line) => !line.includes(h.token)));
});

test("repeat domain apply is DNS-idempotent; domain-check is read-only and requires no Cloudflare token", async () => {
  const h = domainHarness();
  await execute(h.config, h.dependencies);
  await execute(h.config, h.dependencies);
  assert.equal(h.writes.length, 2);
  const writeCount = creates(h).length;
  const cloudflareCount = h.cloudflareCalls.length;
  h.dependencies.environment = {};
  await execute({ ...h.config, command: "domain-check", yes: false }, h.dependencies);
  assert.equal(creates(h).length, writeCount);
  assert.equal(h.cloudflareCalls.length, cloudflareCount);
});

test("DNS propagation and Azure approval failures retain a pending domain without associating a new route", async () => {
  for (const options of [{ domainValidationState: "Pending" }, { dnsTarget: "proxy.example.org" }]) {
    const h = domainHarness(options);
    await assert.rejects(execute(h.config, h.dependencies), /not Approved|Public DNS is not ready/);
    assert.equal(creates(h).length, 1);
    assert.ok(creates(h)[0].includes("associateCustomDomain=false"));
    assert.equal(h.state.group.tags["dojo.customDomainReady"], "false");
    assert.equal(h.requests.length, 0);
  }
});

test("repair and remediation preserve the exact domain, original expiry, and Prevention without DNS credentials", async () => {
  const h = domainHarness({ tags: { "dojo.state": "fixed", "dojo.wafMode": "Prevention" } });
  await execute(h.config, h.dependencies);
  const expiry = h.state.group.tags["pawprint.expiresAt"];
  h.dependencies.environment = {};
  for (const command of ["repair", "remediate"]) {
    const result = await execute({ ...h.config, command, customDomain: "" }, h.dependencies);
    assert.equal(result.customDomain, "https://php2proof.example.org");
    assert.equal(result.state, "fixed");
    assert.equal(result.wafMode, "Prevention");
    assert.equal(h.state.group.tags["pawprint.expiresAt"], expiry);
    assert.ok(creates(h).at(-1).includes("customDomainName=php2proof.example.org"));
    assert.ok(creates(h).at(-1).includes("associateCustomDomain=true"));
  }
});

test("Azure hostname, WAF association, TLS deployment, and instance ownership drift fail closed", async () => {
  const tampered = domainHarness({ azOverride: (args) => {
    if (args[0] === "resource" && args[3]?.endsWith("/customDomains/application-domain")) {
      return { id: args[3], properties: { hostName: "other.example.org" } };
    }
  } });
  await assert.rejects(execute(tampered.config, tampered.dependencies), /exact managed-TLS/);
  assert.equal(tampered.writes.length, 0);
  const tls = domainHarness({ domainDeploymentStatus: "InProgress" });
  await assert.rejects(execute(tls.config, tls.dependencies), /managed HTTPS deployment is not ready/);
  assert.equal(tls.requests.length, 0);
  const foreign = domainHarness();
  foreign.records.push({
    id: "c".repeat(32), type: "CNAME", name: foreign.config.customDomain,
    content: "older.azurefd.net", ttl: 300, proxied: false,
    comment: "pawprint:dns:ninjapaw/php2shell-cloud-defense-dojo:dev:another",
  });
  await assert.rejects(execute(foreign.config, foreign.dependencies), /Conflicting DNS/);
  assert.equal(foreign.writes.length, 0);
});

test("domain-check refuses pending state and implicit renames; teardown reports retained records explicitly", async () => {
  const pending = domainHarness();
  await assert.rejects(execute({ ...pending.config, command: "domain-check" }, pending.dependencies), /not associated/);
  assert.equal(pending.cloudflareCalls.length, 0);
  const h = domainHarness();
  await execute(h.config, h.dependencies);
  await assert.rejects(execute({ ...h.config, customDomain: "another.example.org" }, h.dependencies), /cannot be renamed/);
  const writeCount = h.writes.length;
  const result = await execute({
    ...h.config, command: "uninstall", confirmation: names(h.config).group,
  }, h.dependencies);
  assert.equal(result.dnsRecordsRetained, true);
  assert.equal(h.writes.length, writeCount);
  assert.ok(h.logs.some((line) => line.startsWith("WARNING: Remove this run's Cloudflare CNAME")));
});
