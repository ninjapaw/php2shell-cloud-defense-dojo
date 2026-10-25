import { UUID } from "../scripts/lib/config.mjs";
import { redact } from "../scripts/lib/safety.mjs";
import { liveProbeRule } from "./live-waf.mjs";

export const LIVE_COMPARISON = "Actual process/HTTP/audit/WAF evidence available independently of Defender, alongside actual observations under enabled Defender plans. Defender was not disabled and this is not a controlled Defender-off experiment.";

export function liveEvidenceQueries(config, run, capturedAt) {
  if (!config.liveWindow || !config.liveTarget || !UUID.test(run?.runId ?? "")
      || !Number.isFinite(Date.parse(run.startedAt)) || !Number.isFinite(Date.parse(run.endedAt))
      || !Number.isFinite(Date.parse(capturedAt)) || Date.parse(run.startedAt) > Date.parse(run.endedAt)
      || Date.parse(run.startedAt) < config.liveWindow.startsAt || Date.parse(run.endedAt) > config.expiresAt
      || Date.parse(capturedAt) < Date.parse(run.endedAt)) throw new Error("Actual bounded private run chronology is required for log collection.");
  const start = new Date(Math.max(config.liveWindow.startsAt, Date.parse(run.startedAt) - 60_000)).toISOString();
  const end = new Date(Math.min(Date.parse(capturedAt), config.expiresAt)).toISOString();
  const audit = `AKSAuditAdmin
| where TimeGenerated between (datetime(${start}) .. datetime(${end}))
| where _ResourceId =~ '${config.liveTarget.clusterId}'
| where RequestUri contains '/namespaces/php2shell-isolated/'
| where RequestUri contains 'command=id' or Verb in ('patch', 'update')
| project Utc=tostring(TimeGenerated), Verb, RequestUri, AuditId, ResponseStatus, User, Stage
| order by Utc asc | take 100`;
  const waf = `AzureDiagnostics
| where TimeGenerated between (datetime(${start}) .. datetime(${end}))
| where _ResourceId =~ '${config.names.profileId}' and Category == 'FrontDoorWebApplicationFirewallLog'
| where requestUri_s contains '${run.runId}' and ruleName_s contains '${liveProbeRule(config).name}'
| project Utc=tostring(TimeGenerated), Rule=ruleName_s, Action=action_s, WafMode=policyMode_s, RequestUri=requestUri_s
| order by Utc asc | take 100`;
  return { start, end, timespan: `${start}/${end}`, audit, waf };
}

export async function captureLiveEvidence(config, run, azure, { now = Date.now, log = console.error } = {}) {
  const capturedAt = new Date(now()).toISOString();
  const queries = liveEvidenceQueries(config, run, capturedAt);
  const captures = {};
  async function capture(name, operation, query) {
    try {
      const rows = await operation();
      if (!Array.isArray(rows) || rows.length > 100) throw new Error("Source exceeded the fixed 100-row evidence bound.");
      captures[name] = { status: "queried", rows, ...(query ? { query } : {}) };
    } catch (error) {
      const message = redact(error.message);
      log(`ERROR: private live evidence ${name} unavailable: ${message}`);
      captures[name] = { status: "unavailable", error: message, ...(query ? { query } : {}) };
    }
  }
  await capture("aksAudit", () => azure.logs(queries.audit, queries.timespan), queries.audit);
  await capture("waf", () => azure.logs(queries.waf, queries.timespan), queries.waf);
  await capture("defenderAlerts", async () => {
    const rows = await azure.collection(`${config.liveWindow.groupId}/providers/Microsoft.Security/alerts?api-version=2022-01-01`);
    if (rows.length > 1000) throw new Error("Private-group alert inventory exceeded the bounded read.");
    return rows.filter((row) => {
      const utc = Date.parse(row.properties?.startTimeUtc);
      return Number.isFinite(utc) && utc >= Date.parse(queries.start) && utc <= Date.parse(queries.end);
    }).map((row) => ({
      AlertName: row.properties.alertDisplayName, StartUtc: row.properties.startTimeUtc, Severity: row.properties.severity,
      Status: row.properties.status, AlertId: row.name, EvidenceKind: "actual-provider-alert",
      Correlation: "Exact isolated resource-group and UTC-window correlation only; probe causality is not asserted.",
    }));
  });
  const plans = {};
  for (const name of ["AppServices", "CloudPosture", "Containers"]) {
    try { plans[name] = { status: "queried", tier: (await azure.pricing(name)).pricingTier }; }
    catch (error) {
      const message = redact(error.message);
      log(`ERROR: private live Defender-plan observation ${name} unavailable: ${message}`);
      plans[name] = { status: "unavailable", error: message };
    }
  }
  return {
    schemaVersion: 1, kind: "private-live-evidence", runId: run.runId, windowId: config.liveWindow.id,
    startedAt: run.startedAt, endedAt: run.endedAt, capturedAt,
    scope: { group: config.liveWindow.groupId, cluster: config.liveTarget.clusterId, workspace: config.workspaceId },
    captures, plans, comparison: LIVE_COMPARISON,
    limitations: [
      "Read/query success with zero rows means no matching observation at capture time, not no attack, vulnerability or future alert.",
      "Kubernetes id is authorized administrative process activity, not a PHP exploit, shell payload or guaranteed Defender trigger.",
      "The harmless WAF marker proves only the test-route Log/Block behavior, not PHP CVE-signature coverage.",
      "Audit rows are a 100-row chronological sample of id-exec and patch/update operations in the private namespace/window, not an exhaustive stream or proof of causality.",
      "Provider alerts outside the exact private resource group, including separately managed node groups, are outside this query.",
      "Unavailable sources and ingestion delays remain explicit; no telemetry or alert is fabricated.",
    ],
  };
}
