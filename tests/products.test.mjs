import assert from "node:assert/strict";
import test from "node:test";
import { prepareProducts } from "../scripts/prepare-products.mjs";
import { HUNTING_CATALOG } from "../scripts/lib/hunting.mjs";
import { evaluateQuery } from "../scripts/evaluate-hunts.mjs";

const product = {
  Keyword: "Example PHP Product", Product: "Example product",
  Status109618: "Investigation", Status109619: "Fix",
  Source: "https://vendor.example.test/advisory",
};

test("reviewed multiword products render as typed KQL without remote downloads or string injection", () => {
  const rows = [product, {
    ...product, Keyword: 'Acme "PHP" \\ bundle\'); project Injected = 1; //',
    Source: "https://vendor.example.test/advisory https://github.com/NCSC-NL/php2shell",
  }];
  const query = prepareProducts(JSON.stringify(rows));
  assert.doesNotMatch(query, /REVIEWED_PRODUCT_ROWS|\bexternaldata\b/);
  assert.match(query, /2 reviewed local product rows; no network calls/);
  assert.equal(evaluateQuery(HUNTING_CATALOG.queries.find((entry) => entry.id === "bundled-products"), query).offlineStatus, "passed");
  assert.equal(prepareProducts(`\uFEFF${JSON.stringify(rows)}`), query, "UTF-8 BOM exports must work on Windows.");
});

test("empty, oversized, malformed and unreviewed product inputs fail explicitly without leaking values", () => {
  for (const input of ["[]", "{}", "null", "not-json", JSON.stringify([null]), JSON.stringify(Array(2001).fill(product)),
    JSON.stringify([{ ...product, Keyword: "" }]), JSON.stringify([{ ...product, Keyword: "bad\ninput" }]),
    JSON.stringify([{ ...product, Status109618: "safe" }]), JSON.stringify([{ ...product, Source: "http://vendor.example.test" }]),
    JSON.stringify([{ ...product, Source: "https://secret-user:secret-password@vendor.example.test" }])]) {
    assert.throws(() => prepareProducts(input), (error) => {
      assert.doesNotMatch(error.message, /secret-user|secret-password|bad\ninput/);
      return true;
    });
  }
  assert.throws(() => prepareProducts(" ".repeat(1024 * 1024 + 1)), /1 MiB/);
});
