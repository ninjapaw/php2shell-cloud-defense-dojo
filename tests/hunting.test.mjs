import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { ROOT } from "../scripts/dojo.mjs";
import { COVERAGE_IDS, HUNTING_CATALOG, huntingGuide, SOURCE_QUERY_FILES } from "../scripts/lib/hunting.mjs";
import { evaluateHunts, validateHuntingCatalog } from "../scripts/evaluate-hunts.mjs";

test("all upstream asset methods, hunts and query files have an executable or manual evidence path", () => {
  assert.equal(validateHuntingCatalog(), HUNTING_CATALOG);
  assert.equal(HUNTING_CATALOG.queries.length, 27);
  assert.equal(HUNTING_CATALOG.coverage.length, 20);
  assert.equal(SOURCE_QUERY_FILES.length, 16);
  assert.deepEqual(HUNTING_CATALOG.coverage.map((item) => item.id).sort(), [...COVERAGE_IDS].sort());
  const manual = HUNTING_CATALOG.coverage.filter((item) => item.manualOnly).map((item) => item.id);
  assert.deepEqual(manual, ["row-06", "row-07", "row-10", "hunt-A", "hunt-G"]);
  for (const item of huntingGuide().coverage) {
    assert.ok(item.requires.length && item.evaluation.length);
    for (const query of item.queries) assert.ok(query.platform && query.requiredTables.length && query.labTelemetry);
  }
});

test("catalog validation rejects missing coverage, unregistered queries, escaped paths and lost provenance", () => {
  for (const mutate of [
    (catalog) => { catalog.coverage.pop(); },
    (catalog) => { catalog.queries.pop(); },
    (catalog) => { catalog.queries[0].path = "../outside.kql"; },
    (catalog) => { catalog.source.revision = "main"; },
    (catalog) => { catalog.queries[6].references = []; },
    (catalog) => { catalog.coverage[0].queryIds = ["missing-query"]; },
    (catalog) => { catalog.coverage[5].evaluation = []; },
    (catalog) => { catalog.queries[6].platform = "sentinel-log-analytics"; },
  ]) {
    const catalog = structuredClone(HUNTING_CATALOG);
    mutate(catalog);
    assert.throws(() => validateHuntingCatalog(catalog));
  }
});

test("offline evaluation never reports live or manual evidence as passed", () => {
  const report = evaluateHunts();
  assert.deepEqual({
    status: report.offlineEvaluation.status, queries: report.offlineEvaluation.queries,
    assetMethods: report.offlineEvaluation.assetMethods, huntItems: report.offlineEvaluation.huntItems,
  }, { status: "passed", queries: 27, assetMethods: 10, huntItems: 10 });
  assert.equal(report.liveEvaluation.status, "not-run");
  assert.ok(report.liveEvaluation.items.every((item) => item.status === "operator-evidence-required"));
  assert.match(report.queries.find((query) => query.id === "bundled-products").operatorInput, /Reviewed local/);
});

test("fixed-version references and empty product-input boundaries are explicit", () => {
  const inventory = readFileSync(join(ROOT, "detections", "defender-xdr", "php-inventory.kql"), "utf8");
  for (const version of ["8.2.35", "8.3.36", "8.4.27", "8.5.12"]) assert.ok(inventory.includes(`"${version}"`));
  assert.ok(inventory.indexOf('VendorPackaged, "vendor-backport') < inventory.indexOf('parse_version(RuntimeVersion) < parse_version(FixedVersion)'));
  const guide = readFileSync(join(ROOT, "docs", "hunting-pack.md"), "utf8");
  for (const text of ["EUPL-1.2", "zero-finding", "RLIMIT_AS", "RLIMIT_DATA", "operator-evidence-required", "not a live KQL execution"]) {
    assert.ok(guide.includes(text), text);
  }
  const workflow = readFileSync(join(ROOT, ".github", "workflows", "validate.yml"), "utf8");
  assert.match(workflow, /npm run evaluate/);
});
