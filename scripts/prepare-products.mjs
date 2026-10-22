#!/usr/bin/env node
import { readFileSync, statSync } from "node:fs";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { parseArgs } from "node:util";
import { ROOT } from "./dojo.mjs";
import { redact } from "./lib/safety.mjs";

const MAX_BYTES = 1024 * 1024;
const MAX_ROWS = 2000;
const STATUSES = ["Investigation", "Vulnerable", "Fix", "Workaround", "Not vuln"];
const FIELDS = { Keyword: 128, Product: 256, Status109618: 32, Status109619: 32, Source: 2048 };
const MARKER = "// REVIEWED_PRODUCT_ROWS";

export function prepareProducts(text) {
  if (Buffer.byteLength(text, "utf8") > MAX_BYTES) throw new Error("Product input exceeds the 1 MiB limit.");
  let rows;
  try {
    rows = JSON.parse(text.replace(/^\uFEFF/, ""));
  } catch (error) {
    if (error instanceof SyntaxError) throw new Error("Invalid product JSON; input contents are not printed.");
    throw error;
  }
  if (!Array.isArray(rows) || rows.length < 1 || rows.length > MAX_ROWS) {
    throw new Error(`Supply a nonempty reviewed product array of at most ${MAX_ROWS} rows.`);
  }
  for (const [index, row] of rows.entries()) {
    if (!row || typeof row !== "object" || Array.isArray(row)) throw new Error(`Product row ${index + 1} must be an object.`);
    for (const [field, maximum] of Object.entries(FIELDS)) {
      if (typeof row[field] !== "string" || !row[field].trim() || row[field].length > maximum
          || /[\u0000-\u001f\u007f]/.test(row[field])) {
        throw new Error(`Product row ${index + 1} has an invalid ${field} field; contents omitted.`);
      }
    }
    if (!STATUSES.includes(row.Status109618) || !STATUSES.includes(row.Status109619)) {
      throw new Error(`Product row ${index + 1} has an unknown advisory status; review the source schema.`);
    }
    for (const source of row.Source.trim().split(/\s+/)) {
      let url;
      try {
        url = new URL(source);
      } catch (error) {
        if (error instanceof TypeError) throw new Error(`Product row ${index + 1} requires HTTPS source URLs.`);
        throw error;
      }
      if (url.protocol !== "https:" || url.username || url.password) {
        throw new Error(`Product row ${index + 1} requires HTTPS source URLs without credentials.`);
      }
    }
  }
  const template = readFileSync(join(ROOT, "detections", "defender-xdr", "bundled-products.kql"), "utf8");
  if (template.split(MARKER).length !== 2) throw new Error("Product query template marker is missing or duplicated.");
  const values = rows.map((row) => Object.keys(FIELDS).map((field) => JSON.stringify(row[field])).join(", ")).join(",\n    ");
  return `// ${rows.length} reviewed local product rows; no network calls. Retain source dataset attribution/licensing.\n${template.replace(MARKER, values)}`;
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try {
    const { values } = parseArgs({ options: { input: { type: "string" } }, allowPositionals: false });
    if (!values.input) throw new Error("Usage: node scripts/prepare-products.mjs --input <reviewed-products.json>");
    const size = statSync(values.input).size;
    if (size > MAX_BYTES) throw new Error("Product input exceeds the 1 MiB limit.");
    process.stdout.write(prepareProducts(readFileSync(values.input, "utf8")));
  } catch (error) {
    console.error(`ERROR: ${redact(error.message)}`);
    process.exitCode = 1;
  }
}
