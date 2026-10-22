#!/usr/bin/env node
import { readFileSync, readdirSync } from "node:fs";
import { join, relative, resolve, sep } from "node:path";
import { pathToFileURL } from "node:url";
import { ROOT } from "./dojo.mjs";
import { COVERAGE_IDS, HUNTING_CATALOG, SOURCE_QUERY_FILES } from "./lib/hunting.mjs";
import { compileQuery, KQL_SCHEMAS } from "./lib/kql.mjs";
import { redact } from "./lib/safety.mjs";

const nonemptyStrings = (values) => Array.isArray(values) && values.length > 0
  && values.every((value) => typeof value === "string" && value.trim().length > 0);
const sameValues = (left, right) => JSON.stringify(left) === JSON.stringify(right);

function queryFiles(directory) {
  return readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) return queryFiles(path);
    return entry.name.endsWith(".kql") ? [relative(ROOT, path).split(sep).join("/")] : [];
  });
}

export function evaluateQuery(entry, query) {
  if (!Object.hasOwn(KQL_SCHEMAS, entry.platform)) throw new Error(`${entry.id}: unknown query platform.`);
  if (!Array.isArray(entry.requiredTables) || !Array.isArray(entry.optionalTables)
      || !nonemptyStrings(entry.columns) || !entry.columns.includes("EvidenceKind")) {
    throw new Error(`${entry.id}: missing table or output-column contract.`);
  }
  const tables = [...entry.requiredTables, ...entry.optionalTables];
  if (new Set(tables).size !== tables.length || new Set(entry.columns).size !== entry.columns.length) {
    throw new Error(`${entry.id}: duplicate table or output-column contract.`);
  }
  if (entry.platform !== "lab-workspace" && (!entry.requiredTables.length || entry.optionalTables.length)) {
    throw new Error(`${entry.id}: estate queries must require their telemetry explicitly.`);
  }
  if (/\bexternaldata\b|evaluate\s+(?:python|r)\b/i.test(query)) {
    throw new Error(`${entry.id}: remote data or embedded execution is not permitted.`);
  }
  const compiled = compileQuery(query, entry.platform, tables);
  if (compiled.syntax.length || compiled.errors.length) {
    throw new Error(`${entry.id}: Kusto compilation failed: ${JSON.stringify([...compiled.syntax, ...compiled.errors])}`);
  }
  if (!sameValues(compiled.columns, entry.columns)) {
    throw new Error(`${entry.id}: output-column contract changed: ${JSON.stringify(compiled.columns)}.`);
  }
  for (const missing of entry.requiredTables) {
    const result = compileQuery(query, entry.platform, tables.filter((table) => table !== missing));
    if (!result.errors.length) throw new Error(`${entry.id}: missing required table ${missing} was hidden.`);
  }
  if (entry.platform === "lab-workspace") {
    for (const available of [[], tables.filter((table) => table === "AppServiceConsoleLogs")]) {
      const result = compileQuery(query, entry.platform, available);
      if (result.syntax.length || result.errors.length || !sameValues(result.columns, entry.columns)) {
        throw new Error(`${entry.id}: optional/empty lab schema contract failed.`);
      }
    }
  }
  return {
    id: entry.id, path: entry.path, platform: entry.platform, offlineStatus: "passed",
    missingSourceBehavior: entry.requiredTables.length ? "explicit-query-error" : "warnings-and-empty-results-possible",
    ...(entry.operatorInput ? { operatorInput: entry.operatorInput } : {}),
  };
}

export function validateHuntingCatalog(catalog = HUNTING_CATALOG) {
  if (catalog?.schemaVersion !== 1 || !/^[a-f0-9]{40}$/.test(catalog.source?.revision ?? "")
      || catalog.source?.repository !== "https://github.com/cseelhoff-ms/php2shell-hunting-pack"
      || !Array.isArray(catalog.queries) || !Array.isArray(catalog.coverage)) {
    throw new Error("Invalid hunting catalog or unpinned upstream provenance.");
  }
  const ids = catalog.queries.map((entry) => entry.id);
  const paths = catalog.queries.map((entry) => entry.path);
  if (new Set(ids).size !== ids.length || new Set(paths).size !== paths.length) {
    throw new Error("Duplicate query ID or path in hunting catalog.");
  }
  for (const entry of catalog.queries) {
    if (typeof entry.id !== "string" || !/^[a-z0-9-]+$/.test(entry.id)
        || typeof entry.path !== "string" || !/^detections\/(?:[a-z0-9-]+\/)?[a-z0-9-]+\.kql$/.test(entry.path)
        || typeof entry.labTelemetry !== "string" || !entry.labTelemetry.trim()
        || !Array.isArray(entry.references)
        || (entry.platform !== "lab-workspace" && !entry.path.startsWith(`detections/${entry.platform}/`))) {
      throw new Error("Invalid query identity, platform directory, telemetry boundary or reference metadata.");
    }
  }
  if (!sameValues([...paths].sort(), queryFiles(join(ROOT, "detections")).sort())) {
    throw new Error("Every KQL file must be registered exactly once in the hunting catalog.");
  }
  if (!sameValues(catalog.coverage.map((item) => item.id).sort(), [...COVERAGE_IDS].sort())) {
    throw new Error("Coverage must include exactly rows 01-10 and hunts A, B, C, D1/D2, E1/E2, F1/F2, G.");
  }
  for (const reference of SOURCE_QUERY_FILES) {
    if (!catalog.queries.some((entry) => entry.references.includes(reference))) {
      throw new Error(`Missing upstream query coverage: ${reference}.`);
    }
  }
  const runbook = readFileSync(join(ROOT, "docs", "hunting-pack.md"), "utf8");
  const headings = new Set(runbook.split(/\r?\n/));
  for (const item of catalog.coverage) {
    if (!Array.isArray(item.queryIds) || new Set(item.queryIds).size !== item.queryIds.length
        || item.queryIds.some((id) => !ids.includes(id))
        || (item.queryIds.length === 0) !== (item.manualOnly === true)
        || !nonemptyStrings(item.requires) || !nonemptyStrings(item.evaluation)
        || item.runbook !== `docs/hunting-pack.md#${item.id.toLowerCase()}`) {
      throw new Error(`${item.id}: invalid query mapping, prerequisites, runbook or evidence criteria.`);
    }
    const heading = item.id.startsWith("row-") ? `Row ${item.id.slice(4)}` : `Hunt ${item.id.slice(5)}`;
    if (!headings.has(`## ${heading}`)) throw new Error(`${item.id}: runbook section is missing.`);
  }
  for (const entry of catalog.queries.filter((query) => query.platform !== "lab-workspace")) {
    if (!catalog.coverage.some((item) => item.queryIds.includes(entry.id))) {
      throw new Error(`${entry.id}: query is not connected to an evaluation item.`);
    }
  }
  return catalog;
}

export function evaluateHunts(catalog = HUNTING_CATALOG) {
  validateHuntingCatalog(catalog);
  const results = catalog.queries.map((entry) =>
    evaluateQuery(entry, readFileSync(join(ROOT, ...entry.path.split("/")), "utf8")));
  return {
    source: catalog.source,
    offlineEvaluation: {
      status: "passed", queries: results.length, assetMethods: 10, huntItems: 10,
      upstreamQueryFilesMapped: SOURCE_QUERY_FILES.length,
      boundary: "Kusto syntax/types, declared sources, output shapes and coverage only. Resource Graph service restrictions, query results, thresholds and live detection efficacy are not executed by this compiler.",
    },
    queries: results,
    liveEvaluation: {
      status: "not-run", reason: "Requires authorized telemetry and operator evidence; missing/empty sources never count as safe.",
      items: catalog.coverage.map(({ id, title, runbook, requires, evaluation }) => ({
        id, title, status: "operator-evidence-required", runbook, requires, criteria: evaluation,
      })),
    },
  };
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try {
    if (process.argv.length !== 2) throw new Error("Usage: npm run evaluate (offline; no arguments or Azure access).");
    console.log(JSON.stringify(evaluateHunts(), null, 2));
  } catch (error) {
    console.error(`ERROR: ${redact(error.message)}`);
    process.exitCode = 1;
  }
}
