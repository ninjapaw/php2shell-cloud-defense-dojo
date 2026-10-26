import test from "node:test";
import assert from "node:assert/strict";
import { liveEvidenceQueries } from "../live-evidence.mjs";

const RUN = {
  runId: "11111111-1111-4111-8111-111111111111",
  startedAt: "2026-10-24T16:33:41.463Z",
  endedAt: "2026-10-24T16:33:43.454Z",
};
const CAPTURED_AT = "2026-10-24T16:36:07.232Z";

function config(windowStartsAt) {
  return {
    origin: "https://example.invalid",
    expiresAt: Date.parse("2026-10-24T18:00:00.000Z"),
    liveWindow: { id: "live-window-test", startsAt: Date.parse(windowStartsAt) },
    liveTarget: { clusterId: "example-cluster" },
    names: { profileId: "example-profile" },
  };
}

test("live log window keeps whole-second rows stamped in the window's opening second", () => {
  const queries = liveEvidenceQueries(config("2026-10-24T16:33:41.200Z"), RUN, CAPTURED_AT);
  assert.equal(queries.start, "2026-10-24T16:33:41.000Z");
  assert.equal(queries.end, CAPTURED_AT);
  assert.equal(queries.timespan, `2026-10-24T16:33:41.000Z/${CAPTURED_AT}`);
});

test("live log window keeps the 60-second pre-run margin when the window opened earlier", () => {
  const queries = liveEvidenceQueries(config("2026-10-24T16:30:00.000Z"), RUN, CAPTURED_AT);
  assert.equal(queries.start, "2026-10-24T16:32:41.463Z");
});
