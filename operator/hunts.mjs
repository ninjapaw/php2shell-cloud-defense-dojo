import { readFileSync } from "node:fs";
import { randomUUID } from "node:crypto";
import { OperatorError, assertLive } from "./config.mjs";
import { redact, assertOwnedGroup } from "../scripts/lib/safety.mjs";

const ROOT = new URL("../", import.meta.url);
const PLATFORMS = ["lab-workspace", "resource-graph", "defender-xdr", "sentinel-log-analytics"];
const RUNNABLE = new Set(["lab-waf", "lab-php-errors", "lab-child-process", "lab-outbound",
  "lab-canary", "lab-correlation", "php-assessments", "appservice-runtimes",
  "appservice-runtime-discovery", "appservice-http"]);
const escape = (value) => String(value).replaceAll("&", "&amp;").replaceAll("<", "&lt;")
  .replaceAll(">", "&gt;").replaceAll('"', "&quot;").replaceAll("'", "&#39;");
const json = (value) => escape(JSON.stringify(value, null, 2));
const VALUE = {
  "lab-workspace": {
    without: "Actual WAF/application logs can support manual investigation independently of optional Defender plans.",
    with: "Supported Defender detections and actual posture add investigation context. Synthetic process, egress and ledger fixtures do not demonstrate a workload detection.",
  },
  "resource-graph": {
    without: "ARM runtime configuration and foundational recommendations identify leads; major.minor stack strings are not patch evidence.",
    with: "Applicable Defender assessments and paid CSPM graph/attack-path context can prioritize actual affected assets. Empty findings and text matches never prove coverage or safety.",
  },
  "defender-xdr": {
    without: "Web/WAF logs do not reconstruct device software, process ancestry, disk writes or endpoint network activity.",
    with: "Onboarded, supported MDE/TVM sources add those device-level observations and published CVE findings. App Service is not an MDE device; this console has no tenant-wide XDR hunting consent.",
  },
  "sentinel-log-analytics": {
    without: "Collected source logs can be queried manually without enabling Microsoft Sentinel.",
    with: "Explicitly configured Sentinel analytics can correlate ingested sources. Missing DCRs/tables, disabled rules and late ingestion remain gaps; a query result is not an alert or incident.",
  },
};

export function loadHuntPack() {
  const catalog = JSON.parse(readFileSync(new URL("detections/catalog.json", ROOT), "utf8"));
  if (catalog.schemaVersion !== 1 || catalog.source?.repository !== "https://github.com/cseelhoff-ms/php2shell-hunting-pack"
      || !/^[a-f0-9]{40}$/.test(catalog.source.revision) || !Array.isArray(catalog.queries)
      || !Array.isArray(catalog.coverage)) throw new Error("The pinned hunting catalogue is unavailable or invalid.");
  const ids = new Set();
  const queries = catalog.queries.map((entry) => {
    if (!/^[a-z0-9-]{1,64}$/.test(entry.id) || ids.has(entry.id) || !PLATFORMS.includes(entry.platform)
        || !/^detections\/(?:[a-z0-9-]+\/)?[a-z0-9-]+\.kql$/.test(entry.path)
        || !Array.isArray(entry.requiredTables) || !Array.isArray(entry.optionalTables)) {
      throw new Error("Hunt identity, platform, path or source contract escaped its reviewed catalogue.");
    }
    ids.add(entry.id);
    const template = readFileSync(new URL(entry.path, ROOT), "utf8");
    if (!template.trim() || Buffer.byteLength(template) > 32_768 || /\bexternaldata\b|evaluate\s+(?:python|r)\b/i.test(template)) {
      throw new Error("Hunt source exceeds the reviewed local read-only contract.");
    }
    return { ...entry, template };
  });
  return { ...catalog, queries };
}

export function assertHuntId(id) {
  const pack = loadHuntPack();
  if (id !== "all" && !pack.queries.some((entry) => entry.id === id)) {
    throw new OperatorError(400, "unknown-hunt", "Select a fixed reviewed hunt; query text and targets are not accepted.");
  }
  return pack;
}

export function bindHuntQuery(config, entry) {
  let query = entry.template.replaceAll("__APP_RESOURCE_ID__", config.names.appId)
    .replaceAll("let Window = 1h;", "let Window = 24h;")
    .replaceAll("ago(1h)", "ago(24h)").replaceAll("ago(14d)", "ago(24h)")
    .replaceAll("LastIngested > ago(15m)", "LastIngested > ago(24h)");
  if (entry.platform === "resource-graph") {
    if (!/^(resources|securityresources)\s*$/im.test(query)) throw new Error("Reviewed Resource Graph source changed.");
    query = query.replace(/^(resources|securityresources)\s*$/im,
      (source) => `${source}\n| where tolower(id) startswith ${JSON.stringify(`${config.names.groupId.toLowerCase()}/`)}`);
    return `${query}\n| take 50`;
  }
  if (entry.platform === "lab-workspace") {
    const column = entry.id === "lab-correlation" ? "AppResourceId" : "ResourceId";
    const target = entry.id === "lab-waf" ? config.names.profileId : config.names.appId;
    return `${query}\n| where tolower(${column}) == ${JSON.stringify(target.toLowerCase())}\n| take 100`;
  }
  if (entry.id === "appservice-http") {
    const source = "let Requests = AppServiceHTTPLogs";
    if (!query.includes(source)) throw new Error("Reviewed App Service HTTP source changed.");
    return `${query.replace(source, `${source}\n    | where tolower(_ResourceId) == ${JSON.stringify(config.names.appId.toLowerCase())}`)}\n| take 100`;
  }
  return query;
}

function clean(value, key = "") {
  if (/^(?:password|token|authorization|cookie|secret)$/i.test(key)) return "[REDACTED]";
  if (typeof value === "string") return redact(value).slice(0, 4096);
  if (Array.isArray(value)) return value.map((item) => clean(item));
  if (value && typeof value === "object") return Object.fromEntries(Object.entries(value).map(([name, item]) => [name, clean(item, name)]));
  return value;
}

export async function runHunts(config, azure, id, { guard = async () => {}, log = console.error, now = Date.now } = {}) {
  const pack = assertHuntId(id);
  const startedAt = new Date(now()).toISOString();
  const ended = now();
  const timespan = `${new Date(ended - 86_400_000).toISOString()}/${new Date(ended).toISOString()}`;
  let tables;
  let metadataError;
  try { await guard(); tables = await azure.tables(); }
  catch (error) {
    metadataError = redact(error.message);
    log(`ERROR: hunting source readiness unavailable: ${metadataError}`);
  }
  const results = [];
  for (const entry of pack.queries.filter((item) => id === "all" || item.id === id)) {
    await guard();
    const query = bindHuntQuery(config, entry);
    const item = { id: entry.id, platform: entry.platform, path: entry.path,
      template: entry.template, query, collectedAt: new Date(now()).toISOString(),
      timespan, scope: config.names.groupId, rows: null, rowCount: null };
    if (entry.platform === "defender-xdr") {
      results.push({ ...item, status: "unavailable", reason: "No XDR hunting connector/tenant-wide consent is configured. App Service does not supply MDE device telemetry.", missingTables: entry.requiredTables });
      continue;
    }
    if (!RUNNABLE.has(entry.id)) {
      results.push({ ...item, status: "not-applicable", reason: "This hunt requires a separately authorized VM, registry/container, Application Gateway or custom-log scope; none is selected by this App Service console.", missingTables: entry.requiredTables });
      continue;
    }
    const available = tables && [...entry.requiredTables, ...entry.optionalTables].filter((table) => tables.includes(table));
    if (entry.platform !== "resource-graph" && tables && (!available.length
        || entry.requiredTables.some((table) => !tables.includes(table)))) {
      results.push({ ...item, status: "unavailable", reason: metadataError ?? "Required source tables are absent; no query result or clean hunt is asserted.",
        missingTables: entry.requiredTables.filter((table) => !tables?.includes(table)), availableTables: available ?? [] });
      continue;
    }
    try {
      const rows = entry.platform === "resource-graph" ? (await azure.graph(query, 50)).data : await azure.logs(query, timespan);
      if (!Array.isArray(rows) || rows.length > 100) throw new Error("Hunting result exceeded its fixed row contract.");
      results.push({ ...item, status: !tables && entry.platform !== "resource-graph" && !rows.length ? "queried-with-source-gap" : "queried",
        outcome: rows.length ? "matches-to-review" : "zero-matches-not-clearance",
        rowCount: rows.length, rows: clean(rows), availableTables: available ?? [],
        ...(metadataError && entry.platform !== "resource-graph" ? { sourceReadinessWarning: metadataError } : {}),
        missingOptionalTables: entry.optionalTables.filter((table) => !tables?.includes(table)) });
    } catch (error) {
      const reason = redact(error.message);
      log(`ERROR: hunt ${entry.id} failed: ${reason}`);
      results.push({ ...item, status: "failed", reason });
    }
  }
  const plans = {};
  for (const name of ["AppServices", "CloudPosture", "Containers"]) {
    await guard();
    try { plans[name] = { status: "queried", tier: (await azure.pricing(name)).pricingTier }; }
    catch (error) {
      log(`ERROR: hunt plan observation ${name} failed: ${redact(error.message)}`);
      plans[name] = { status: "unavailable", reason: redact(error.message) };
    }
  }
  return { schemaVersion: 2, kind: "hunting", runId: randomUUID(), source: pack.source,
    startedAt, finishedAt: new Date(now()).toISOString(), scope: config.names.groupId, timespan,
    sourceReadiness: { status: tables ? "queried" : "unavailable", tables: tables ?? null, ...(metadataError ? { reason: metadataError } : {}) },
    plans, results, comparison: "Independent source logs versus actual observations under existing enabled plans; not a Defender-disabled experiment.",
    boundary: "Read-only, exact lab, retrospective 24-hour queries. No scan, exploit, image execution, DCR/rule deployment, protection change or tenant-wide XDR query." };
}

function coverageHtml(pack) {
  return pack.coverage.map((item) => `<details><summary>${escape(item.id)} / ${escape(item.title)}</summary>
    <p><strong>Requires:</strong> ${escape(item.requires.join("; "))}</p>
    <ul>${item.evaluation.map((text) => `<li>${escape(text)}</li>`).join("")}</ul>
    <p>${item.manualOnly ? "Walkthrough only: separate authorization/evidence required; no scanner or mutation is executed." : item.queryIds.map((id) => `<a href="#hunt-${escape(id)}">${escape(id)}</a>`).join(" / ")}</p></details>`).join("");
}

function card(entry, result, session) {
  const value = VALUE[entry.platform];
  return `<article id="hunt-${escape(entry.id)}"><h2>${escape(entry.id)}</h2>
    <p>${escape(entry.platform)} / ${escape(entry.path)}</p>
    <p><strong>Without optional protection:</strong> ${escape(value.without)}</p>
    <p><strong>Additional value:</strong> ${escape(value.with)}</p>
    <p><strong>Telemetry:</strong> ${escape(entry.labTelemetry)}</p>
    <p><strong>Required:</strong> ${escape(entry.requiredTables.join(", ") || "At least one declared optional lab source")}.</p>
    ${session ? `<form action="/jobs" method="post"><input type="hidden" name="csrf" value="${escape(session.csrf)}"><input type="hidden" name="operation" value="hunt-pack"><input type="hidden" name="huntId" value="${escape(entry.id)}"><input type="hidden" name="idempotencyKey" value="${randomUUID()}"><button ${RUNNABLE.has(entry.id) ? "" : "disabled"}>Run this fixed read-only hunt</button></form>` : ""}
    <details><summary>Reviewed query template</summary><pre>${escape(entry.template)}</pre></details>
    ${result ? `<p><strong>Actual result:</strong> ${escape(result.status)} / ${escape(result.collectedAt)}; ${result.rowCount === null ? "not executed" : `${result.rowCount} rows`}.</p>
      ${result.reason ? `<p>${escape(result.reason)}</p>` : ""}
      <details><summary>${session ? "Exact bound query, scope and observation" : "Reviewed result and public fields"}</summary><pre>${json(result)}</pre></details>` : "<p>No recorded execution for this query. No empty result or successful detection is inferred.</p>"}
    </article>`;
}

export async function huntingPage(config, store, session) {
  const pack = loadHuntPack();
  const records = await Promise.all(pack.queries.map((entry) => store.read(`evidence/hunting/${entry.id}`)));
  return `<p><a href="/">Private console</a> / <a href="/evidence/hunting">Reviewed public hunting walkthrough</a></p>
    <p>Source: <a href="${escape(pack.source.repository)}/tree/${escape(pack.source.revision)}">${escape(pack.source.repository)} / ${escape(pack.source.revision)}</a>.
    Independently authored adaptations, not copied upstream code. All ${pack.queries.length} query scenarios and ${pack.coverage.length} value/evaluation walkthroughs are included.</p>
    <p>Only the owned App Service lab is executable here. Missing data, zero matches and failures are different states. Existing Defender plans are never switched off. Retrospective queries are limited to 24 hours and 100 rows (Resource Graph: 50).</p>
    <form action="/jobs" method="post"><input type="hidden" name="csrf" value="${escape(session.csrf)}"><input type="hidden" name="operation" value="hunt-pack"><input type="hidden" name="huntId" value="all"><input type="hidden" name="idempotencyKey" value="${randomUUID()}"><button>Evaluate all scenarios and run supported lab hunts</button></form>
    <h2>Additional-value walkthroughs and missed-coverage checks</h2>${coverageHtml(pack)}
    <p>Also verify source retention/freshness, vendor backports and immutable image digests, long-lived workers, false-positive baselines, alert latency, cookie privacy, and ownership. Upstream Hunt B has a syntax defect in the reviewed revision; this independent adaptation is compiled separately. No query failure is a clean result.</p>
    ${pack.queries.map((entry, index) => card(entry, records[index]?.value, session)).join("")}`;
}

export function publicHuntingSnapshot(result) {
  const allowed = /^(TimeGenerated|Utc|Signal|Synthetic|EvidenceKind|Action|RuleName|ReviewStatus|CandidateKind|Runtime|Status|Apps|SoftwareVersion|CveId|Priority|Classification|Events|Errors)$/;
  return {
    schemaVersion: 2, kind: "reviewed-hunting", reviewed: false, runId: result.runId, source: result.source,
    startedAt: result.startedAt, finishedAt: result.finishedAt, timespan: result.timespan,
    plans: result.plans, comparison: result.comparison, boundary: result.boundary,
    results: result.results.map((item) => ({ id: item.id, platform: item.platform,
      status: item.status, collectedAt: item.collectedAt, rowCount: item.rowCount,
      template: item.template, ...(item.reason ? { reason: item.reason } : {}),
      ...(item.missingTables ? { missingTables: item.missingTables } : {}),
      rows: item.rows?.map((row) => Object.fromEntries(Object.entries(row).filter(([key]) => allowed.test(key)))) ?? null })),
    publication: "Redacted candidate requiring separate manual review before static publication.",
  };
}

export function publicHuntingPage(snapshot) {
  if (snapshot.schemaVersion !== 2 || snapshot.kind !== "reviewed-hunting" || snapshot.reviewed !== true
      || !Array.isArray(snapshot.results)) throw new Error("Reviewed hunting snapshot is invalid or has not been approved.");
  const pack = loadHuntPack();
  if (snapshot.source?.revision !== pack.source.revision || snapshot.results.length !== pack.queries.length
      || new Set(snapshot.results.map((item) => item.id)).size !== pack.queries.length
      || snapshot.results.some((item) => !pack.queries.some((entry) => entry.id === item.id))) {
    throw new Error("Reviewed hunting snapshot does not match the pinned query catalogue.");
  }
  return `<p><a href="https://php2proof.ninjapaws.org/walkthrough.php">GhostPaw story</a> / <a href="${escape(pack.source.repository)}">Upstream hunting pack</a></p>
    <p>HISTORICAL REVIEWED CAPTURE / ${escape(snapshot.startedAt)} to ${escape(snapshot.finishedAt)}.
    ${escape(snapshot.comparison)} ${escape(snapshot.boundary)}</p>
    <p>Queries below are reviewed templates; actual resource identifiers and raw sensitive fields are not public. Row counts are actual; null means not executed, never zero matches.</p>
    <h2>Twenty additional-value walkthroughs</h2>${coverageHtml(pack)}
    ${pack.queries.map((entry) => card(entry, snapshot.results.find((item) => item.id === entry.id))).join("")}`;
}

export async function initializeHuntCapture(config, store, azureFactory, id, { now = Date.now, log = console.log } = {}) {
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(id)) throw new Error("Invalid out-of-band hunting capture UUID.");
  assertLive(config, now());
  return store.withLease("hunt-capture", async ({ assertLease }) => {
    const key = `control/hunting-bootstrap/${id}`;
    if (await store.read(key)) {
      log("HUNT_CAPTURE_REPLAY_DENIED: the deployment capture already has a durable claim.");
      return;
    }
    await store.audit("hunt-capture-intent", { deploymentId: id });
    await store.write(key, { status: "claimed", startedAt: new Date(now()).toISOString() });
    const deadline = Math.min(now() + 180_000, config.expiresAt);
    const guard = async () => {
      assertLease();
      assertLive(config, now());
      if (now() >= deadline) throw new Error("The three-minute deployment hunt capture deadline ended.");
    };
    try {
      const azure = azureFactory(guard);
      assertOwnedGroup(await azure.az(["group", "show", "--name", config.names.group]), config.invocation);
      const result = await runHunts(config, azure, "all", { guard, now, log });
      for (const item of result.results) {
        const previous = await store.read(`evidence/hunting/${item.id}`);
        await store.write(`evidence/hunting/${item.id}`, item, previous?.etag);
      }
      const saved = await store.read(key);
      await store.write(key, { status: "captured", runId: result.runId, finishedAt: result.finishedAt }, saved.etag);
      await store.audit("hunt-capture-completed", { deploymentId: id, runId: result.runId });
      const candidate = publicHuntingSnapshot(result);
      const { results, ...header } = candidate;
      log(`HUNT_REDACTED_HEADER ${JSON.stringify({ deploymentId: id, ...header })}`);
      for (const item of results) log(`HUNT_REDACTED_RESULT ${JSON.stringify({ deploymentId: id, runId: result.runId, result: item })}`);
      return candidate;
    } catch (error) {
      const saved = await store.read(key);
      await store.write(key, { status: "failed", reason: redact(error.message) }, saved.etag);
      await store.audit("hunt-capture-failed", { deploymentId: id, reason: redact(error.message) });
      throw error;
    }
  });
}
