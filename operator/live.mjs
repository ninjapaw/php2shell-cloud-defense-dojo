import { privateRunCommand, privateTransitionConfirmation } from "../scripts/lib/private-live.mjs";
import { responseFingerprint } from "../scripts/lib/response.mjs";
import { UUID } from "../scripts/lib/config.mjs";
import { LIVE_ACTIONS, liveAction, validateLiveDispatch } from "./live-control.mjs";
import { liveIo } from "./live-azure.mjs";
import { livePolicyBody, liveWafObservation } from "./live-waf.mjs";
import { captureLiveEvidence } from "./live-evidence.mjs";

function runtimeIdentity(record) {
  const value = record.after;
  return {
    namespaceUid: value.namespaceUid, deploymentUid: value.deploymentUid,
    deploymentResourceVersion: value.deploymentResourceVersion, podUid: value.podUid,
    image: value.image, imageId: value.imageId, phpVersion: value.health.phpVersion,
  };
}

function basis(config, state) {
  return {
    windowId: config.liveWindow.id, expiresAt: config.expiry, target: state.target,
    runtime: runtimeIdentity(state.runtime), waf: livePolicyBody(config, state.policy),
    unresolvedJobId: state.unresolvedJobId,
  };
}

export async function inspectLive(control, job, io, unresolvedId) {
  const target = await io.target();
  const { record: runtime } = await io.runtime(target, {
    operation: "verify", operationId: job.id, runId: job.id, variant: "either",
  }, job.id);
  const policy = await io.policy();
  const dispatch = await control.store.read("control/dispatch");
  const candidate = unresolvedId ?? dispatch?.value.activeJob;
  const active = UUID.test(candidate ?? "") ? await control.store.read(`jobs/${candidate}`) : undefined;
  const unresolvedJobId = active?.value.status === "reconciliation-required"
    && active.value.target === control.config.liveWindow.groupId && active.value.liveWindowId === control.config.liveWindow.id
    ? candidate : null;
  return { target, runtime, policy, unresolvedJobId };
}

export function buildLivePreview(control, job, state) {
  const { config } = control;
  const rule = liveWafObservation(config, state.policy).rule.action;
  const fixed = state.runtime.after.health.phpVersion === state.target.images.fixed.version;
  const available = {
    "process-probe": true, "waf-log": rule !== "Log", "waf-block": rule === "Log", "waf-remove": rule !== "absent",
    "runtime-fix": !fixed, "runtime-reset": fixed, reconcile: Boolean(state.unresolvedJobId),
  };
  const actions = LIVE_ACTIONS.filter((action) => action.writes).map((action) => ({
    id: action.id, available: Boolean(available[action.id] && (!state.unresolvedJobId || action.id === "reconcile")),
  }));
  const commands = {};
  const requests = [
    ["process-probe", "run", fixed ? "fixed" : "affected"],
    ["runtime-fix", "fix"], ["runtime-reset", "reset"],
  ];
  for (const [id, operation, variant] of requests) {
    if (actions.find((action) => action.id === id).available) {
      const request = { operation, operationId: job.id, runId: job.id,
        ...(variant ? { variant } : { confirmation: privateTransitionConfirmation(state.target, operation, control.now()) }) };
      commands[id] = privateRunCommand(state.target, request, control.now());
    }
  }
  return {
    schemaVersion: 1, kind: "private-live-plan", runId: job.id,
    windowId: config.liveWindow.id, target: config.liveWindow.groupId, expiresAt: config.expiry,
    createdAt: new Date(control.now()).toISOString(), fingerprint: responseFingerprint(basis(config, state)),
    runtime: state.runtime, waf: liveWafObservation(config, state.policy), unresolvedJobId: state.unresolvedJobId,
    actions, commands, commandNote: "Fixed script preview; execution generates its own run UUID and persists the exact executed script privately.",
  };
}

export async function runLiveJob(control, job, azure, guard, fetchImpl, { io: suppliedIo } = {}) {
  const { config, store, now } = control;
  const approved = await validateLiveDispatch(control, { hash: job.sessionHash, epoch: job.credentialEpoch }, job.live);
  const io = suppliedIo ?? liveIo(control, azure, guard, fetchImpl);
  const action = liveAction(approved.id);
  const startedAt = new Date(now()).toISOString();
  if (approved.id === "collect") {
    await io.target();
    const source = (await store.read(`jobs/${approved.sourceJobId}`)).value;
    const evidence = await captureLiveEvidence(config, source.result, azure, { now, log: control.log });
    return { result: {
      schemaVersion: 1, kind: "private-live-evidence-refresh", runId: source.result.runId,
      startedAt: source.result.startedAt, endedAt: source.result.endedAt, capturedAt: evidence.capturedAt,
      sourceJobId: source.id, note: "Read-only collection for the original persisted run; no test or mutation was replayed.",
    }, evidence };
  }
  const planJob = approved.planJobId ? await store.read(`jobs/${approved.planJobId}`) : undefined;
  let state;
  if (approved.id !== "transport-probe") state = await inspectLive(control, job, io,
    approved.id === "reconcile" ? planJob.value.result.unresolvedJobId : undefined);
  else await io.target();
  if (approved.id === "plan") return { result: {
    ...buildLivePreview(control, job, state), startedAt, endedAt: new Date(now()).toISOString(),
  } };
  if (action.writes) {
    if (responseFingerprint(basis(config, state)) !== approved.fingerprint) throw new Error("Actual target/runtime/WAF state changed since the approved preview. No mutation was attempted.");
    const key = `control/live/${approved.planJobId}`;
    if (await store.read(key)) throw new Error("This private live preview has been consumed; no mutation is replayed.");
    await store.audit("private-live-apply-intent", { jobId: job.id, action: action.id, windowId: config.liveWindow.id });
    await store.write(key, { jobId: job.id, action: action.id, consumedAt: new Date(now()).toISOString() });
    await guard();
  }
  let result;
  if (["process-probe", "runtime-fix", "runtime-reset"].includes(approved.id)) {
    const operation = { "process-probe": "run", "runtime-fix": "fix", "runtime-reset": "reset" }[approved.id];
    const request = {
      operation, operationId: job.id, runId: job.id,
      ...(operation === "run" ? { variant: state.runtime.after.health.phpVersion === state.target.images.fixed.version ? "fixed" : "affected" }
        : { confirmation: privateTransitionConfirmation(state.target, operation, now()) }),
    };
    const executed = await io.runtime(state.target, request, job.id);
    result = {
      schemaVersion: 1, kind: "private-live-change", action: approved.id, runId: job.id,
      startedAt: executed.record.startedAt, endedAt: executed.record.finishedAt,
      runtime: executed.record, executedCommand: executed.command,
      note: operation === "run" ? "Actual authorized id process; not PHP exploitation or a guaranteed Defender trigger."
        : "Actual pinned private-runtime transition. Public PHP, original expiry and legacy CLI intent were not changed.",
    };
  } else if (approved.id.startsWith("waf-")) {
    const change = { "waf-log": "Log", "waf-block": "Block", "waf-remove": "Remove" }[approved.id];
    const observed = await io.changeWaf(state.target, change, state.policy, job.id);
    result = {
      schemaVersion: 1, kind: "private-live-change", action: approved.id, runId: job.id, startedAt,
      endedAt: new Date(now()).toISOString(), ...observed,
      note: "Actual test-route rule state and HTTP response only. Prevention mode/other rules stay unchanged; CVE-signature protection is not claimed.",
    };
  } else if (approved.id === "reconcile") {
    const unresolved = await store.read(`jobs/${state.unresolvedJobId}`);
    if (unresolved?.value.status !== "reconciliation-required") throw new Error("The indeterminate private run changed before acknowledgement.");
    await store.audit("private-live-reconciliation-intent", { jobId: job.id, sourceJobId: state.unresolvedJobId });
    await store.write(`jobs/${state.unresolvedJobId}`, {
      ...unresolved.value, status: "reconciled-current-state", automaticReplayForbidden: true,
      reconciliation: { observedByJobId: job.id, observedAt: new Date(now()).toISOString(),
        note: "Current pinned state was measured and acknowledged. The earlier execution remains indeterminate, not successful, and is not replayed." },
    }, unresolved.etag);
    result = { schemaVersion: 1, kind: "private-live-reconciliation", action: approved.id, runId: job.id, startedAt,
      endedAt: new Date(now()).toISOString(), sourceJobId: state.unresolvedJobId, runtime: state.runtime,
      waf: liveWafObservation(config, state.policy), earlierExecutionConfirmed: false };
  } else {
    result = { schemaVersion: 1, kind: "private-live-observation", action: approved.id, runId: job.id, startedAt,
      endedAt: new Date(now()).toISOString(), ...(state ? { runtime: state.runtime, waf: liveWafObservation(config, state.policy) } : {}) };
    result.transport = await io.transport(job.id);
    result.endedAt = new Date(now()).toISOString();
  }
  const evidence = await captureLiveEvidence(config, result, azure, { now, log: control.log });
  return { result, evidence };
}
