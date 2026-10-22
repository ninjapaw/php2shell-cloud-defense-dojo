import catalog from "../../detections/catalog.json" with { type: "json" };

export const HUNTING_CATALOG = catalog;
export const COVERAGE_IDS = [
  ...Array.from({ length: 10 }, (_, index) => `row-${String(index + 1).padStart(2, "0")}`),
  "hunt-A", "hunt-B", "hunt-C", "hunt-D1", "hunt-D2", "hunt-E1", "hunt-E2", "hunt-F1", "hunt-F2", "hunt-G",
];
export const SOURCE_QUERY_FILES = [
  "queries/defender-xdr/row01-tvm-cve-exposure.kql",
  "queries/defender-xdr/row05-php-inventory-version-check.kql",
  "queries/defender-xdr/row08-php-binaries-on-disk.kql",
  "queries/defender-xdr/row08-ncsc-products-in-inventory.kql",
  "queries/defender-xdr/row09-running-php-vs-mod-php.kql",
  "queries/defender-xdr/huntB-web-worker-spawns-shell.kql",
  "queries/defender-xdr/huntE1-php-file-drops.kql",
  "queries/defender-xdr/huntE2-web-worker-network.kql",
  "queries/resource-graph/row03-appservice-php-runtimes.kql",
  "queries/resource-graph/row04a-acr-subassessments-cve.kql",
  "queries/resource-graph/row04b-acr-images-with-php-findings.kql",
  "queries/sentinel-log-analytics/huntC-syslog-crash-oom.kql",
  "queries/sentinel-log-analytics/huntD1-appservice-http.kql",
  "queries/sentinel-log-analytics/huntD2-appgw-waf.kql",
  "queries/sentinel-log-analytics/huntF1-aks-containerlogv2.kql",
  "queries/sentinel-log-analytics/huntF2-apache-nginx-textlogs.kql",
];

export function huntingGuide() {
  return {
    source: catalog.source,
    catalog: "detections/catalog.json",
    guide: "docs/hunting-pack.md",
    offlineEvaluation: "npm run evaluate (schema/coverage checks, not live query execution)",
    boundary: "No tenant-wide query, scan, product-feed download, telemetry onboarding or mitigation is performed by this guide.",
    coverage: catalog.coverage.map(({ id, title, queryIds, runbook, requires, evaluation }) => ({
      id, title, runbook, requires, evaluation,
      queries: queryIds.map((queryId) => {
        const query = catalog.queries.find((entry) => entry.id === queryId);
        if (!query) throw new Error(`Unknown hunting query in catalog: ${queryId}.`);
        return {
          path: query.path, platform: query.platform, requiredTables: query.requiredTables,
          labTelemetry: query.labTelemetry, ...(query.operatorInput ? { operatorInput: query.operatorInput } : {}),
        };
      }),
    })),
  };
}
