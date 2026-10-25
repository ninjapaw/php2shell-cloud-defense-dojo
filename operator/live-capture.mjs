import { randomUUID } from "node:crypto";
import { setTimeout as delay } from "node:timers/promises";
import { assertLive } from "./config.mjs";
import { ownerLiveSession } from "./live-authorize.mjs";
import { liveIo } from "./live-azure.mjs";
import { livePublicCandidate } from "./live-public.mjs";
import { redact } from "../scripts/lib/safety.mjs";

const PLAYBOOK = Object.freeze([
  "waf-log", "process-probe", "transport-probe", "waf-block", "runtime-fix", "verify",
  "runtime-reset", "verify", "runtime-fix", "verify", "waf-remove",
]);

export async function initializeLiveCapture(control, captureId, { wait = delay } = {}) {
  const { config, store, credentials, now } = control;
  if (!config.liveWindow || captureId !== config.liveWindow.id) throw new Error("Fixed owner capture requires the exact approved private-window UUID.");
  assertLive(config, now());
  return store.withLease("live-capture", async ({ assertLease }) => {
    const key = `control/live-capture/${captureId}`;
    const previous = await store.read(key);
    if (previous?.value.status === "completed") return previous.value;
    if (previous) throw new Error("A prior private capture requires reconciliation. Completed or uncertain tests are never automatically replayed.");
    const guard = async () => { assertLease(); assertLive(config, now()); };
    const azure = control.azureFactory(guard);
    const io = liveIo(control, azure, guard, control.fetchImpl, { wait });
    await io.target();
    let state = {
      schemaVersion: 1, windowId: captureId, status: "running", startedAt: new Date(now()).toISOString(),
      jobIds: [], steps: [], refreshes: [],
    };
    async function save() {
      const current = await store.read(key);
      await store.write(key, state, current?.etag);
    }
    async function progress() {
      await io.report({
        schemaVersion: 1, kind: "private-live-capture-progress", windowId: captureId, status: state.status,
        startedAt: state.startedAt, authorizationEndsAt: config.expiry, actualCompletedSteps: state.steps.length,
        queuedOrCompletedJobs: state.jobIds.length,
        ...(state.status === "failed" ? { note: "Execution stopped; use exact private audit/job records. No failed or uncertain action is claimed successful." } : {}),
      });
    }
    await store.audit("private-capture-intent", { windowId: captureId, catalogue: PLAYBOOK });
    await save();
    try {
      await progress();
      async function dispatch(session, input) {
        await guard();
        const counter = await store.read("control/dispatch");
        if (counter?.value.starts?.length) {
          const remaining = Math.max(...counter.value.starts) + 60_100 - now();
          if (remaining > 0) await wait(remaining);
        }
        await guard();
        const id = randomUUID();
        state = { ...state, jobIds: [...state.jobIds, id], lastIntent: { jobId: id, action: input.id, at: new Date(now()).toISOString() } };
        await save();
        const job = await control.start(session, "live", id, undefined, undefined, undefined, input);
        const deadline = Math.min(now() + 13 * 60_000, config.expiresAt);
        while (now() < deadline) {
          await guard();
          const saved = await store.read(`jobs/${job.id}`);
          if (!saved) throw new Error("A fixed capture job lost its durable state.");
          if (["completed", "completed-with-evidence-gaps"].includes(saved.value.status)) return saved.value;
          if (!["queued", "running"].includes(saved.value.status)) throw new Error(`Fixed capture stopped at ${input.id}: ${saved.value.status}. Reconcile without replay.`);
          await wait(2000);
        }
        throw new Error(`Fixed capture observation deadline ended at ${input.id}. Reconcile the existing job; do not rerun it.`);
      }
      for (const action of PLAYBOOK) {
        await guard();
        const session = await ownerLiveSession(config, store, credentials, now);
        let input = { id: action };
        if (!["verify", "transport-probe"].includes(action)) {
          const plan = await dispatch(session, { id: "plan" });
          if (!plan.result.actions.some((entry) => entry.id === action && entry.available)) throw new Error(`The real current state did not make ${action} available. No mutation is attempted.`);
          input = { id: action, planJobId: plan.id, fingerprint: plan.result.fingerprint, confirmation: config.liveWindow.resourceGroup };
        }
        const job = await dispatch(session, input);
        if (action === "process-probe" && job.result.runtime?.before.health.phpVersion !== "8.4.26") throw new Error("The actual process baseline is not the reviewed affected private image.");
        if (action === "runtime-fix" && job.result.runtime?.after.health.phpVersion !== "8.4.27") throw new Error("The actual fixed image was not observed.");
        if (action === "runtime-reset" && job.result.runtime?.after.health.phpVersion !== "8.4.26") throw new Error("The actual private reset image was not observed.");
        state = { ...state, steps: [...state.steps, { jobId: job.id, action }], lastCompletedAt: new Date(now()).toISOString() };
        await save();
        await progress();
      }
      const refresh = state.steps.filter((step) => ["waf-log", "process-probe", "waf-block", "runtime-fix", "runtime-reset"].includes(step.action));
      for (const step of refresh) {
        const session = await ownerLiveSession(config, store, credentials, now);
        const collected = await dispatch(session, { id: "collect", sourceJobId: step.jobId });
        state = { ...state, refreshes: [...state.refreshes, { sourceJobId: step.jobId, jobId: collected.id }] };
        await save();
      }
      const steps = [];
      for (const step of state.steps) {
        const job = (await store.read(`jobs/${step.jobId}`)).value;
        const refreshed = state.refreshes.find((item) => item.sourceJobId === step.jobId);
        const source = refreshed ? (await store.read(`jobs/${refreshed.jobId}`)).value : job;
        const evidence = await store.read(source.evidenceKey);
        if (!evidence) throw new Error("The fixed capture has no durable actual evidence for a completed step.");
        steps.push({ job, evidence: evidence.value });
      }
      const finishedAt = new Date(now()).toISOString();
      const candidate = livePublicCandidate(config, { ...state, status: "completed", finishedAt, steps });
      await store.audit("private-capture-completed", { windowId: captureId, actualSteps: steps.length });
      await store.write(`evidence/live-candidate/${captureId}`, candidate);
      state = { ...state, status: "completed", finishedAt, candidateKey: `evidence/live-candidate/${captureId}` };
      await save();
      await io.report({ schemaVersion: 1, kind: "private-live-capture-result", windowId: captureId,
        status: "completed", startedAt: state.startedAt, finishedAt, candidate,
        note: "An unreviewed redacted candidate only. Publication is a separate explicit source change; this report creates no public execution route." });
      return state;
    } catch (error) {
      state = { ...state, status: "failed", failedAt: new Date(now()).toISOString(), error: redact(error.message) };
      await store.audit("private-capture-failed", { windowId: captureId, reason: redact(error.message) });
      await save();
      try { await progress(); }
      catch (reportError) { control.log(`ERROR: failed private-capture report could not be persisted: ${redact(reportError.message)}`); }
      throw error;
    }
  });
}
