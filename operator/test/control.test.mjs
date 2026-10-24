import test from "node:test";
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { ControlPlane } from "../control.mjs";
import { setup, NOW } from "./support.mjs";
import { execute } from "../../scripts/dojo.mjs";
import { configuration, harness } from "../../tests/support/harness.mjs";

test("the existing guarded lifecycle accepts async Azure reads without dropping any validation", async () => {
  const cfg = configuration("simulate", { yes: true });
  const h = harness(cfg);
  const result = await execute(cfg, { ...h.dependencies, az: async (args) => h.dependencies.az(args) });
  assert.equal(result.requests.length, 5);
  assert.equal(result.requests.every((item) => item.synthetic), true);
  assert.equal(h.requests.length, 9);
  assert.deepEqual(h.state.slept, [250, 250, 250, 250]);
});

test("dispatch is durable, idempotent, target-fixed and never accepts writes/arbitrary commands", async () => {
  const h = await setup();
  const control = new ControlPlane(h.cfg, h.store, h.credentials, () => ({}), { now: () => NOW });
  const id = randomUUID();
  const first = await control.start(h.session, "validate", id);
  assert.deepEqual(await control.start(h.session, "validate", id), first);
  assert.equal(h.store.queue.length, 1);
  assert.equal(h.store.events.filter((row) => row.event === "dispatch-intent").length, 1);
  for (const action of ["protect", "remediate", "uninstall", "deploy", "domain", "container-test", "id", "defender-validation"]) {
    await assert.rejects(() => control.start(h.session, action, randomUUID()), /fixed harmless/);
  }
  await assert.rejects(() => control.start(h.session, "validate", randomUUID()), /active/);
  await assert.rejects(() => control.start(h.session, "validate", id, "arbitrary-target"), /external run/);
});

test("worker persists intent before dispatch and duplicate delivery never replays a started job", async () => {
  const h = await setup();
  let calls = 0;
  const control = new ControlPlane(h.cfg, h.store, h.credentials, () => ({ az: async () => ({}) }), {
    now: () => NOW, run: async () => { calls += 1; return { validated: true }; }, log: () => {},
  });
  const job = await control.start(h.session, "validate", randomUUID());
  await control.workOnce();
  assert.equal(calls, 1);
  assert.equal((await h.store.read(`jobs/${job.id}`)).value.status, "completed");
  await h.store.send(job.id);
  await control.workOnce();
  assert.equal(calls, 1);
  const other = await setup();
  const blocked = new ControlPlane(other.cfg, other.store, other.credentials, () => ({}), {
    now: () => NOW, run: async () => { throw new Error("Must not execute after crash."); }, log: () => {},
  });
  const pending = await blocked.start(other.session, "validate", randomUUID());
  const record = await other.store.read(`jobs/${pending.id}`);
  await other.store.write(`jobs/${pending.id}`, { ...record.value, status: "running" }, record.etag);
  await blocked.workOnce();
  assert.equal((await other.store.read(`jobs/${pending.id}`)).value.status, "reconciliation-required");
  await assert.rejects(() => blocked.start(other.session, "validate", randomUUID()), /active or unresolved/);
});

test("revoked credentials and expired lifetime prevent queued execution", async () => {
  const h = await setup();
  let executed = false;
  const control = new ControlPlane(h.cfg, h.store, h.credentials, () => ({}), {
    now: () => NOW, run: async () => { executed = true; }, log: () => {},
  });
  const job = await control.start(h.session, "validate", randomUUID());
  h.rotate();
  await control.workOnce();
  assert.equal(executed, false);
  assert.equal((await h.store.read(`jobs/${job.id}`)).value.status, "failed");
  const other = await setup();
  const expired = new ControlPlane(other.cfg, other.store, other.credentials, () => ({}), { now: () => other.cfg.expiresAt });
  await assert.rejects(() => expired.start(other.session, "validate", randomUUID()), /lifetime/);
});

test("queue/audit failure cannot report a successful or unaudited dispatch", async () => {
  const h = await setup();
  const control = new ControlPlane(h.cfg, h.store, h.credentials, () => ({}), { now: () => NOW });
  h.store.send = async () => { throw new Error("Queue unavailable"); };
  const id = randomUUID();
  await assert.rejects(() => control.start(h.session, "validate", id), /Queue unavailable/);
  assert.equal((await h.store.read(`jobs/${id}`)).value.status, "enqueue-failed");
  const other = await setup();
  const denied = new ControlPlane(other.cfg, other.store, other.credentials, () => ({}), { now: () => NOW });
  other.store.audit = async () => { throw new Error("Audit unavailable"); };
  await assert.rejects(() => denied.start(other.session, "validate", randomUUID()), /Audit unavailable/);
  assert.equal(other.store.queue.length, 0);
});
