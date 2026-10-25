import { randomUUID } from "node:crypto";
import { UUID } from "../scripts/lib/config.mjs";
import { OperatorError } from "./config.mjs";

export const LIVE_ACTIONS = Object.freeze([
  { id: "plan", title: "Inspect the private target and preview the fixed playbook", writes: false },
  { id: "process-probe", title: "Run the bounded real administrative id probe", writes: true },
  { id: "transport-probe", title: "Capture an actual harmless edge HTTP request", writes: false },
  { id: "waf-log", title: "Stage only the owned test-route rule in Log", writes: true },
  { id: "waf-block", title: "Block only the owned test-route request", writes: true },
  { id: "waf-remove", title: "Remove only this window's test-route rule", writes: true },
  { id: "runtime-fix", title: "Apply the pinned fixed private PHP image", writes: true },
  { id: "runtime-reset", title: "Reset only the isolated private PHP training image", writes: true },
  { id: "verify", title: "Verify actual serving version, image and edge response", writes: false },
  { id: "reconcile", title: "Acknowledge an indeterminate run using its measured current state (no replay)", writes: true },
  { id: "collect", title: "Refresh actual log and Defender observations for a saved run", writes: false, sourceRequired: true },
]);

export function liveAction(id) {
  const action = LIVE_ACTIONS.find((entry) => entry.id === id);
  if (!action) throw new OperatorError(400, "live-action", "Only the closed private live playbook is accepted; no command, target or payload input is allowed.");
  return action;
}

export async function validateLiveDispatch(control, session, input) {
  const { config, store } = control;
  if (!config.liveWindow || !config.liveTarget) throw new OperatorError(403, "live-disabled", "A separately authorized private target and fresh live window are required.");
  if (!input || Object.keys(input).some((key) => !["id", "planJobId", "fingerprint", "confirmation", "sourceJobId"].includes(key))) {
    throw new OperatorError(400, "live-input", "Unknown private live input or target override.");
  }
  const action = liveAction(input.id);
  if (action.sourceRequired) {
    if (Object.keys(input).some((key) => !["id", "sourceJobId"].includes(key)) || !UUID.test(input.sourceJobId ?? "")) {
      throw new OperatorError(400, "live-source", "Select an actual persisted private live run for evidence collection.");
    }
    const source = await store.read(`jobs/${input.sourceJobId}`);
    if (!source || source.value.operation !== "live" || source.value.target !== config.liveWindow.groupId
        || source.value.liveWindowId !== config.liveWindow.id || !source.value.result?.runId
        || !["completed", "completed-with-evidence-gaps"].includes(source.value.status)) {
      throw new OperatorError(400, "live-source", "The source must be an actual completed run within this exact private window.");
    }
    return { id: action.id, sourceJobId: input.sourceJobId };
  }
  if (!action.writes) {
    if (Object.keys(input).some((key) => key !== "id")) throw new OperatorError(400, "live-approval", "Read-only live actions do not accept approvals or target overrides.");
    return { id: action.id };
  }
  if (!UUID.test(input.planJobId ?? "") || !/^[a-f0-9]{64}$/.test(input.fingerprint ?? "")
      || input.confirmation !== config.liveWindow.resourceGroup || input.sourceJobId !== undefined) {
    throw new OperatorError(400, "live-approval", "Review a fresh preview and type the exact private resource-group name.");
  }
  const source = await store.read(`jobs/${input.planJobId}`);
  const preview = source?.value;
  const createdAt = Date.parse(preview?.result?.createdAt);
  if (!preview || preview.operation !== "live" || preview.live?.id !== "plan"
      || !["completed", "completed-with-evidence-gaps"].includes(preview.status)
      || preview.sessionHash !== session.hash || preview.credentialEpoch !== session.epoch
      || preview.liveWindowId !== config.liveWindow.id || preview.target !== config.liveWindow.groupId
      || preview.result?.fingerprint !== input.fingerprint || preview.result?.expiresAt !== config.expiry
      || !Number.isFinite(createdAt) || createdAt > control.now() || control.now() - createdAt > 600_000
      || !preview.result?.actions?.some((entry) => entry.id === action.id && entry.available === true)) {
    throw new OperatorError(409, "live-preview", "The available preview must be fresh and owned by this exact session, credential epoch, target and live window.");
  }
  if (action.id === "reconcile") {
    const unresolved = UUID.test(preview.result?.unresolvedJobId ?? "") ? await store.read(`jobs/${preview.result.unresolvedJobId}`) : undefined;
    if (unresolved?.value.status !== "reconciliation-required" || unresolved.value.target !== config.liveWindow.groupId
        || unresolved.value.liveWindowId !== config.liveWindow.id) throw new OperatorError(409, "live-reconcile", "No exact-window indeterminate private run is available to acknowledge.");
  }
  if (await store.read(`control/live/${input.planJobId}`)) throw new OperatorError(409, "live-consumed", "This preview has already been consumed. Create a new preview; uncertain mutations are never replayed.");
  return { id: action.id, planJobId: input.planJobId, fingerprint: input.fingerprint, confirmation: input.confirmation };
}

const escape = (value) => String(value).replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;").replaceAll('"', "&quot;").replaceAll("'", "&#39;");
const hidden = (key, value) => `<input type="hidden" name="${key}" value="${escape(value)}">`;

export async function privateLivePage(config, store, session, now = Date.now()) {
  if (!config.liveWindow || !config.liveTarget) return "<p>Private real-execution controls are off. Historical public recordings remain read-only.</p>";
  const jobs = (await store.recentJobs()).filter((job) => job.operation === "live" && job.liveWindowId === config.liveWindow.id);
  const plans = jobs.filter((job) => job.live?.id === "plan" && job.sessionHash === session.hash
    && job.credentialEpoch === session.epoch && ["completed", "completed-with-evidence-gaps"].includes(job.status)
    && Number.isFinite(Date.parse(job.result?.createdAt)) && Date.parse(job.result.createdAt) <= now
    && now - Date.parse(job.result.createdAt) <= 600_000)
    .sort((a, b) => Date.parse(b.queuedAt) - Date.parse(a.queuedAt));
  let plan;
  for (const candidate of plans) if (!(await store.read(`control/live/${candidate.id}`))) { plan = candidate; break; }
  const form = (action, source) => {
    const available = !action.writes || plan?.result.actions?.some((entry) => entry.id === action.id && entry.available === true);
    const approval = action.writes && available
      ? `${hidden("livePlanJobId", plan.id)}${hidden("liveFingerprint", plan.result.fingerprint)}<p><label>Confirm private group <input name="liveConfirmation" required autocomplete="off" placeholder="${escape(config.liveWindow.resourceGroup)}"></label></p>` : "";
    return `<form action="/jobs" method="post">${hidden("csrf", session.csrf)}${hidden("operation", "live")}${hidden("idempotencyKey", randomUUID())}${hidden("liveId", action.id)}${source ? hidden("liveSourceJobId", source.id) : ""}${approval}<button${available ? "" : " disabled"}>${escape(action.title)}</button>${available ? "" : "<p>Create a fresh available preview first. A consumed or drifted preview cannot be reused.</p>"}</form>`;
  };
  return `<p><a href="/">Console</a> / <a href="/evidence/live">Reviewed public walkthrough</a> / <a href="/response">Official mitigation guidance</a></p>
<p class="evidence-label">REAL BOUNDED ADMINISTRATIVE ACTIVITY / PRIVATE TARGET / NOT PHP REMOTE EXPLOITATION</p>
<p>Exact target: <strong>${escape(config.liveWindow.resourceGroup)}</strong>. Separate authorization ends <strong>${escape(config.expiry)}</strong>. Original public authorization remains ${escape(config.originalExpiry)} and is not extended.</p>
<p>The process probe executes only <code>id</code> through the authorized Kubernetes control plane. The transport test is a harmless GET to a fixed marker route. Neither is proof of PHP exploitation or a guaranteed Defender alert. The public application stays fixed; Defender plans and WAF Prevention mode are never downgraded.</p>
<p>Each write requires an available inspection preview, the same session/epoch, exact typed group confirmation, and a one-use durable latch. Preview freshness is ten minutes. Reset affects only the isolated pinned training image; finish on the fixed image. The scoped teardown workflow owns the private group, not the public or operator resource groups.</p>
${LIVE_ACTIONS.filter((action) => !action.sourceRequired).map((action) => `<section><h2>${escape(action.title)}</h2>${form(action)}${plan?.result.commands?.[action.id] ? `<details><summary>Reviewed fixed script template (the executed script is saved with its actual run UUID)</summary><pre>${escape(plan.result.commands[action.id])}</pre></details>` : ""}</section>`).join("")}
${plan ? `<details><summary>Latest unused actual preview</summary><pre>${escape(JSON.stringify(plan.result, null, 2))}</pre></details>` : ""}
<h2>Actual private run history</h2><ul>${jobs.map((job) => `<li><a href="/jobs/${escape(job.id)}">${escape(job.queuedAt)} / ${escape(job.live?.id)} / ${escape(job.status)}</a>${job.result?.runId && ["completed", "completed-with-evidence-gaps"].includes(job.status) ? form(liveAction("collect"), job) : ""}</li>`).join("")}</ul>`;
}
