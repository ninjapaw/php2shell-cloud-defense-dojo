import { UUID } from "../scripts/lib/config.mjs";
import { redact } from "../scripts/lib/safety.mjs";
import { isIP } from "node:net";

const selected = (row, keys) => Object.fromEntries(keys.filter((key) => row[key] !== undefined).map((key) => [key, row[key]]));
const comparison = "Actual app/WAF source evidence independently available without Defender, versus actual observations under the enabled Defender plans. Not a Defender-disabled control run.";
const classifications = Object.freeze({
  application: "Actual ingestion of explicitly synthetic fixtures, not process execution, outbound connections or compromise.",
  waf: "Actual custom-rule matches. Block with Detection and HTTP 200 is not enforced blocking or CVE protection.",
  posture: "Actual assessments, not workload alerts.",
  defenderAlerts: "Actual provider alerts only, exact-app/time-window correlation does not establish fixture causality.",
  missing: "Unavailable and not-yet-observed evidence are not successful detections or proof of safety.",
});

export async function captureEvidence(config, run, azure, log = console.error) {
  if (!UUID.test(run.runId) || !Number.isFinite(Date.parse(run.startedAt)) || !Number.isFinite(Date.parse(run.endedAt))) {
    throw new Error("Evidence capture requires an actual persisted simulator run and UTC window.");
  }
  const start = new Date(Date.parse(run.startedAt) - 60_000).toISOString();
  const end = new Date(Date.parse(run.endedAt) + 300_000).toISOString();
  const timespan = `${start}/${end}`;
  const scope = (table, id) => `${table} | where TimeGenerated between (datetime(${start}) .. datetime(${end})) | where _ResourceId =~ '${id}'`;
  const captures = {};
  async function capture(name, operation) {
    try { captures[name] = { status: "queried", rows: await operation() }; }
    catch (error) {
      const message = redact(error.message);
      log(`ERROR: evidence source ${name} unavailable: ${message}`);
      captures[name] = { status: "unavailable", error: message };
    }
  }
  await capture("waf", () => azure.logs(`${scope("AzureDiagnostics", config.names.profileId)}
| where Category == 'FrontDoorWebApplicationFirewallLog' and requestUri_s contains '${run.runId}'
| project Utc=tostring(TimeGenerated), Rule=ruleName_s, Action=action_s, WafMode=policyMode_s, TrackingReference=trackingReference_s, RequestUri=requestUri_s
| order by Utc asc | take 100`, timespan));
  await capture("application", () => azure.logs(`${scope("AppServiceConsoleLogs", config.names.appId)}
| where ResultDescription startswith 'NOTICE: PHP message: DOJO_EVENT ' and ResultDescription contains '${run.runId}'
| extend Event=parse_json(substring(ResultDescription,strlen('NOTICE: PHP message: DOJO_EVENT ')))
| where tostring(Event.runId) == '${run.runId}' and tostring(Event.scenario) == 'php2shell-cloud-defense-dojo'
| project Utc=tostring(TimeGenerated),SourceLevel=Level,Raw=substring(ResultDescription,0,4096),Signal=tostring(Event.signal),Synthetic=tobool(Event.synthetic),EvidenceKind=tostring(Event.evidenceKind),Message=tostring(Event.message)
| order by Utc asc | take 100`, timespan));
  await capture("posture", async () => (await azure.graph(`SecurityResources
| where type =~ 'microsoft.security/assessments'
| where tolower(id) startswith '${config.names.appId.toLowerCase()}/providers/microsoft.security/assessments/'
| project Assessment=tostring(properties.displayName),Status=tostring(properties.status.code),FirstEvaluationUtc=tostring(properties.status.firstEvaluationDate)
| take 50`)).data);
  await capture("defenderAlerts", async () => {
    const alerts = await azure.alerts();
    return alerts.filter((row) => {
      const timestamp = Date.parse(row.properties?.startTimeUtc);
      return Number.isFinite(timestamp) && timestamp >= Date.parse(start) && timestamp <= Date.parse(end);
    }).map((row) => ({
      AlertName: row.properties.alertDisplayName, StartUtc: row.properties.startTimeUtc,
      Severity: row.properties.severity, Status: row.properties.status, AlertId: row.name,
      EvidenceKind: "actual-provider-alert",
      Correlation: "Exact app and time window only; causality to the harmless fixture is not asserted.",
    }));
  });
  const plans = {};
  for (const name of ["AppServices", "CloudPosture", "Containers"]) {
    try { plans[name] = { status: "queried", tier: (await azure.pricing(name)).pricingTier }; }
    catch (error) {
      plans[name] = { status: "unavailable", error: redact(error.message) };
      log(`ERROR: Defender plan observation ${name} unavailable: ${redact(error.message)}`);
    }
  }
  return {
    schemaVersion: 1, runId: run.runId, startedAt: run.startedAt, endedAt: run.endedAt,
    capturedAt: new Date().toISOString(), scope: { app: config.names.appId, workspace: config.workspaceId },
    requests: run.requests, captures, plans,
    comparison, classifications,
  };
}

export function publicSnapshot(evidence) {
  const signals = ["request", "php-error", "process-synthetic", "outbound-synthetic", "canary"];
  const utc = (value) => typeof value === "string" && /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,7})?Z$/.test(value) && Number.isFinite(Date.parse(value));
  if (evidence?.schemaVersion !== 1 || !UUID.test(evidence.runId) || !Array.isArray(evidence.requests)
      || evidence.requests.length !== 5 || evidence.requests.some((row, index) => row.signal !== signals[index]
        || row.synthetic !== true || ![200, ...(index === 0 ? [403] : [])].includes(row.status))
      || !utc(evidence.startedAt) || !utc(evidence.endedAt) || !utc(evidence.capturedAt)
      || Date.parse(evidence.endedAt) < Date.parse(evidence.startedAt)
      || Date.parse(evidence.endedAt) - Date.parse(evidence.startedAt) > 600_000
      || !evidence.captures || !evidence.plans) {
    throw new Error("Invalid evidence capture for manual public review.");
  }
  const allowed = {
    waf: ["Utc", "Rule", "Action", "WafMode"],
    application: ["Utc", "Signal", "Synthetic", "EvidenceKind"],
    posture: ["Assessment", "Status", "FirstEvaluationUtc"],
    defenderAlerts: ["AlertName", "StartUtc", "Severity", "Status", "EvidenceKind", "Correlation"],
  };
  const captures = {};
  for (const [source, keys] of Object.entries(allowed)) {
    const capture = evidence.captures[source];
    if (!capture || !["queried", "unavailable"].includes(capture.status)) throw new Error("Missing explicit evidence source state.");
    if (capture.status === "unavailable") captures[source] = { status: "unavailable" };
    else {
      if (!Array.isArray(capture.rows) || capture.rows.length > 100) throw new Error("Invalid bounded source evidence.");
      if (source === "application" && capture.rows.some((row) => row.Synthetic !== true
          || !signals.includes(row.Signal) || row.EvidenceKind !== "synthetic-application-log")) {
        throw new Error("Application evidence is not the explicitly identified synthetic fixture.");
      }
      const rows = capture.rows.map((row) => Object.fromEntries(Object.entries(selected(row, keys)).map(([key, value]) => {
        if (typeof value === "boolean" || value === null) return [key, value];
        if (typeof value !== "string" || value.length > 1000) throw new Error("Unsupported public evidence field shape.");
        return [key, redact(value)
          .replace(/\/subscriptions\/[^\s"']+/gi, "[resource redacted]")
          .replace(/\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi, "[email redacted]")
          .replace(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g, "[IP redacted]")
          .replace(/[0-9a-f:.]+/gi, (part) => isIP(part) ? "[IP redacted]" : part)
          .replace(/\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/gi, "[identifier redacted]")
          .replace(/https?:\/\/[^\s"']+/gi, "[URL redacted]")];
      })));
      captures[source] = { status: "queried", rows: [...new Map(rows.map((row) => [JSON.stringify(row), row])).values()] };
    }
  }
  return {
    schemaVersion: 1, runId: evidence.runId, startedAt: evidence.startedAt, endedAt: evidence.endedAt,
    capturedAt: evidence.capturedAt,
    requests: evidence.requests.map((row) => selected(row, ["signal", "status", "synthetic"])),
    captures, plans: Object.fromEntries(Object.entries(evidence.plans).filter(([name]) => ["AppServices", "CloudPosture", "Containers"].includes(name))
      .map(([name, value]) => [name, selected(value, ["status", "tier"])])),
    comparison, classifications,
    publication: "Sanitized, static snapshot requiring manual review; no live workspace or privileged API is exposed.",
  };
}
