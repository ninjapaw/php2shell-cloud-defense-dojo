import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { ROOT } from "../scripts/dojo.mjs";
import { HUNTING_CATALOG } from "../scripts/lib/hunting.mjs";
import { compileQuery } from "../scripts/lib/kql.mjs";
import { evaluateQuery } from "../scripts/evaluate-hunts.mjs";

test("the Kusto validator detects actual syntax and schema errors", () => {
  assert.ok(compileQuery("datatable(x:long)[] | extend Broken = ;", "lab-workspace").syntax.length > 0);
  assert.ok(compileQuery("datatable(x:long)[] | project NotAColumn", "lab-workspace").errors.length > 0);
});

for (const entry of HUNTING_CATALOG.queries) {
  test(`${entry.id}: ${entry.platform} syntax, exact output shape and missing-source behavior`, () => {
    const query = readFileSync(join(ROOT, ...entry.path.split("/")), "utf8");
    assert.equal(evaluateQuery(entry, query).offlineStatus, "passed");
  });
}

test("XDR event timestamps and TVM snapshots are not confused with Log Analytics", () => {
  assert.ok(compileQuery("DeviceProcessEvents | project TimeGenerated", "defender-xdr").errors.length);
  assert.equal(compileQuery("DeviceProcessEvents | project Timestamp", "defender-xdr").errors.length, 0);
  assert.ok(compileQuery("DeviceTvmSoftwareInventory | project Timestamp", "defender-xdr").errors.length);
  assert.ok(compileQuery("DeviceTvmSoftwareInventory | project DeviceId", "sentinel-log-analytics").errors.length);
});

test("Resource Graph schema fixtures retain columns after a quoted keyword column", () => {
  const result = compileQuery("resources | project ['kind'], properties, subscriptionId, resourceGroup, location", "resource-graph");
  assert.equal(result.errors.length, 0);
  assert.deepEqual(result.columns, ["kind", "properties", "subscriptionId", "resourceGroup", "location"]);
});

test("the evaluator rejects changed output contracts, hidden required tables and remote feeds", () => {
  const entry = HUNTING_CATALOG.queries.find((query) => query.id === "worker-child-processes");
  const query = readFileSync(join(ROOT, ...entry.path.split("/")), "utf8");
  assert.throws(() => evaluateQuery({ ...entry, columns: [...entry.columns, "InventedColumn"] }, query), /output-column contract changed/);
  assert.throws(() => evaluateQuery({ ...entry, requiredTables: [], optionalTables: entry.requiredTables }, query), /must require/);
  const optional = { ...entry, platform: "lab-workspace", requiredTables: ["AppServiceConsoleLogs"], optionalTables: [], columns: ["EvidenceKind"] };
  assert.throws(() => evaluateQuery(optional, 'let Empty = datatable(TimeGenerated:datetime)[]; union isfuzzy=true Empty, AppServiceConsoleLogs | project EvidenceKind = "review-required"'), /was hidden/);
  assert.throws(() => evaluateQuery(entry, 'externaldata(x:string)["https://example.test/data.csv"]'), /remote data/);
});

test("standalone worker hunt patterns remain synchronized and include versioned SAPIs", () => {
  const ids = ["worker-baseline", "worker-child-processes", "php-file-drops", "worker-network"];
  const patterns = ids.map((id) => {
    const entry = HUNTING_CATALOG.queries.find((query) => query.id === id);
    return readFileSync(join(ROOT, ...entry.path.split("/")), "utf8").match(/let WorkerPattern = @"([^"]+)";/)[1];
  });
  assert.equal(new Set(patterns).size, 1);
  const regex = new RegExp(patterns[0].replace("(?i)", ""), "i");
  for (const name of ["php", "php.exe", "php-fpm", "php-fpm8.4", "php8.3-fpm", "lsphp83", "apache2", "httpd.exe", "w3wp.exe", "frankenphp", "nginx"]) {
    assert.ok(regex.test(name), name);
  }
  for (const name of ["notphp", "php-fpm-malicious-suffix", "myapache2", "git"]) assert.ok(!regex.test(name), name);
});
