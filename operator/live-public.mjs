import { readFile } from "node:fs/promises";
import { isIP } from "node:net";
import { UUID } from "../scripts/lib/config.mjs";
import { redact } from "../scripts/lib/safety.mjs";
import { LIVE_COMPARISON } from "./live-evidence.mjs";

const escape = (value) => String(value).replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;").replaceAll('"', "&quot;").replaceAll("'", "&#39;");
const utc = (value) => typeof value === "string" && /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,7})?Z$/.test(value) && Number.isFinite(Date.parse(value));
const sourceKinds = ["aksAudit", "waf", "defenderAlerts"];
const actionIds = ["waf-log", "process-probe", "transport-probe", "waf-block", "runtime-fix", "runtime-reset", "verify", "waf-remove"];
const safeText = (value) => {
  if (typeof value !== "string" || value.length > 1000) throw new Error("Public evidence text must be a bounded actual string.");
  return redact(value).replace(/\/subscriptions\/[^\s"']+/gi, "[resource redacted]")
    .replace(/\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi, "[email redacted]")
    .replace(/https?:\/\/[^\s"']+/gi, "[URL redacted]")
    .replace(/[0-9a-f:.]+/gi, (part) => isIP(part) ? "[IP redacted]" : part)
    .replace(/\b[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\b/gi, "[identifier redacted]");
};

function runtimeSnapshot(value) {
  if (!value || !utc(value.observedAt) || !["8.4.26", "8.4.27"].includes(value.health?.phpVersion)
      || value.healthStatus !== 200 || value.isolationVerified !== true) throw new Error("Public runtime proof requires an actual verified snapshot.");
  const digest = /@(sha256:[a-f0-9]{64})$/.exec(value.image)?.[1];
  if (!digest) throw new Error("Public runtime proof requires the observed immutable derived image.");
  return { observedAt: value.observedAt, phpVersion: value.health.phpVersion, imageDigest: digest,
    healthStatus: value.healthStatus, isolationVerified: true };
}

function publicSource(name, source) {
  if (!source || !["queried", "unavailable"].includes(source.status)) throw new Error("Every public evidence source must have an explicit state.");
  if (source.status === "unavailable") return { status: "unavailable", rows: [], totalObservedRows: null, rowsShown: 0 };
  if (!Array.isArray(source.rows) || source.rows.length > 100) throw new Error("Invalid private source row bound.");
  const rows = source.rows.slice(0, 20).map((row) => {
    if (name === "aksAudit") {
      if (!utc(row.Utc)) throw new Error("Audit proof has no actual UTC.");
      let command = "scoped patch/update operation";
      if (typeof row.RequestUri === "string") {
        const uri = new URL(row.RequestUri, "https://audit.invalid");
        if (uri.searchParams.getAll("command").includes("id")) command = "id";
      }
      const status = typeof row.ResponseStatus === "string" ? JSON.parse(row.ResponseStatus) : row.ResponseStatus;
      return { Utc: row.Utc, Verb: safeText(row.Verb), CommandOrOperation: command,
        ...(Number.isInteger(status?.code) ? { ResponseCode: status.code } : {}) };
    }
    const fields = name === "waf" ? ["Utc", "Rule", "Action", "WafMode"]
      : ["AlertName", "StartUtc", "Severity", "Status", "EvidenceKind", "Correlation"];
    return Object.fromEntries(fields.filter((key) => row[key] !== undefined).map((key) => [key, safeText(row[key])]));
  });
  return { status: "queried", rows, totalObservedRows: source.rows.length, rowsShown: rows.length,
    sample: "At most 20 of the original bounded 100 source rows are shown; private evidence retains the queried projection." };
}

export function livePublicCandidate(config, capture) {
  if (capture?.schemaVersion !== 1 || capture.windowId !== config.liveWindow.id || capture.status !== "completed"
      || !utc(capture.startedAt) || !utc(capture.finishedAt) || !Array.isArray(capture.steps) || capture.steps.length > 24) {
    throw new Error("Only a completed actual owner capture can produce a public review candidate.");
  }
  const steps = capture.steps.map(({ job, evidence }) => {
    const result = job?.result;
    if (job.operation !== "live" || job.liveWindowId !== config.liveWindow.id || !UUID.test(result?.runId ?? "")
        || !actionIds.includes(job.live?.id) || !["completed", "completed-with-evidence-gaps"].includes(job.status)
        || !utc(result.startedAt) || !utc(result.endedAt)) throw new Error("Public live steps require actual completed catalogue results.");
    const sources = Object.fromEntries(sourceKinds.map((name) => [name, publicSource(name, evidence?.captures?.[name])]));
    const runtime = result.runtime ? { before: runtimeSnapshot(result.runtime.before), after: runtimeSnapshot(result.runtime.after) } : undefined;
    const process = result.runtime?.process;
    const plans = Object.fromEntries(["AppServices", "CloudPosture", "Containers"].map((name) => {
      const observed = evidence.plans?.[name];
      if (!observed || !["queried", "unavailable"].includes(observed.status)
          || (observed.status === "queried" && !["Free", "Standard"].includes(observed.tier))) throw new Error("Actual Defender-plan state is required.");
      return [name, observed.status === "queried" ? { status: "queried", tier: observed.tier } : { status: "unavailable" }];
    }));
    return {
      action: job.live.id, runId: result.runId, startedAt: result.startedAt, endedAt: result.endedAt,
      capturedAt: evidence.capturedAt, status: job.status, sources, plans,
      ...(runtime ? { runtime } : {}),
      ...(process ? { process: { command: "id", stdout: safeText(process.stdout), exitCode: process.exitCode,
        startedAt: process.startedAt, finishedAt: process.finishedAt } } : {}),
      ...(result.transport ? { transport: { status: result.transport.status, startedAt: result.transport.startedAt,
        endedAt: result.transport.endedAt, evidenceKind: result.transport.evidenceKind } } : {}),
      ...(result.waf ? { waf: { mode: result.waf.mode, ruleAction: result.waf.rule.action } } : {}),
      queries: Object.fromEntries(["aksAudit", "waf"].filter((name) => evidence.captures[name].query).map((name) => [name,
        evidence.captures[name].query.replaceAll(config.liveTarget.clusterId, "<PRIVATE_CLUSTER_RESOURCE_ID>")
          .replaceAll(config.names.profileId, "<FRONT_DOOR_PROFILE_RESOURCE_ID>")])),
    };
  });
  return {
    schemaVersion: 1, kind: "reviewed-private-live", reviewed: false,
    windowId: capture.windowId, startedAt: capture.startedAt, finishedAt: capture.finishedAt,
    authorizationEndsAt: config.expiry, comparison: LIVE_COMPARISON, steps,
    limitations: [
      "Real authorized administrative process activity and real HTTP/control-plane/image transitions, not PHP remote-code exploitation.",
      "The WAF marker rule proves test-route enforcement only, not a CVE detector or a public-app WAF policy change.",
      "No Defender plan was disabled, no alert was fabricated, and no causal relationship is inferred from a shared time window.",
      "Zero-row and unavailable observations are different; ingestion and provider detections may arrive later.",
      "The original public authorization, its expired tags and historical synthetic run remain unchanged.",
    ],
  };
}

export function validateReviewedLive(value) {
  if (value?.schemaVersion !== 1 || value.kind !== "reviewed-private-live" || value.reviewed !== true
      || !UUID.test(value.windowId ?? "") || !utc(value.startedAt) || !utc(value.finishedAt)
      || !utc(value.authorizationEndsAt) || !Array.isArray(value.steps) || value.steps.length < 8 || value.steps.length > 24
      || Date.parse(value.finishedAt) < Date.parse(value.startedAt)) throw new Error("No complete separately reviewed private live recording is published.");
  for (const step of value.steps) {
    if (!actionIds.includes(step.action) || !UUID.test(step.runId ?? "") || !utc(step.startedAt) || !utc(step.endedAt)
        || !utc(step.capturedAt) || Date.parse(step.endedAt) < Date.parse(step.startedAt)
        || Date.parse(step.capturedAt) < Date.parse(step.endedAt)) throw new Error("Invalid reviewed live step chronology or identity.");
    for (const name of sourceKinds) {
      const source = step.sources?.[name];
      if (!source || !["queried", "unavailable"].includes(source.status) || !Array.isArray(source.rows) || source.rows.length > 20) throw new Error("Invalid explicit reviewed source state.");
    }
    if (step.transport && ![200, 403].includes(step.transport.status)) throw new Error("Unreviewed transport response.");
    if (step.runtime) for (const snapshot of [step.runtime.before, step.runtime.after]) {
      if (!["8.4.26", "8.4.27"].includes(snapshot?.phpVersion) || !/^sha256:[a-f0-9]{64}$/.test(snapshot.imageDigest ?? "")
          || !utc(snapshot.observedAt) || snapshot.healthStatus !== 200 || snapshot.isolationVerified !== true) throw new Error("Invalid reviewed runtime proof.");
    }
  }
  const affected = value.steps.some((step) => step.action === "process-probe" && step.runtime?.before.phpVersion === "8.4.26" && step.process?.command === "id" && step.process.exitCode === 0);
  const fixed = value.steps.filter((step) => step.action === "runtime-fix" && step.runtime?.after.phpVersion === "8.4.27");
  const reset = value.steps.find((step) => step.action === "runtime-reset" && step.runtime?.before.phpVersion === "8.4.27" && step.runtime.after.phpVersion === "8.4.26");
  if (!affected || fixed.length < 2 || !reset
      || !value.steps.some((step) => step.action === "waf-log" && step.transport?.status === 200 && step.waf?.ruleAction === "Log")
      || !value.steps.some((step) => step.action === "waf-block" && step.transport?.status === 403 && step.waf?.ruleAction === "Block" && step.waf?.mode === "Prevention")
      || !value.steps.some((step) => step.action === "waf-remove" && step.transport?.status === 200 && step.waf?.ruleAction === "absent")
      || Date.parse(fixed.at(-1).startedAt) < Date.parse(reset.endedAt)) throw new Error("The reviewed recording does not prove the required baseline, block, fix, private reset, final fix and test-rule removal cycle.");
  return value;
}

const json = (value) => `<pre>${escape(JSON.stringify(value, null, 2))}</pre>`;
const source = (step, name) => {
  const value = step.sources[name];
  return value.status === "unavailable" ? "<p><strong>Unavailable.</strong> No successful query or detection is asserted.</p>"
    : `<p><strong>Queried:</strong> ${value.totalObservedRows} matching rows observed at ${escape(step.capturedAt)}.${value.totalObservedRows === 0 ? " None observed at capture time; this is not proof of no attack or later alert." : ` Showing ${value.rowsShown} source rows.`}</p>${value.rows.length ? json(value.rows) : ""}`;
};
const proof = (step) => `<p>Actual run <code>${escape(step.runId)}</code>: ${escape(step.startedAt)} &rarr; ${escape(step.endedAt)}.</p>${json({
  ...(step.runtime ? { runtime: step.runtime } : {}), ...(step.process ? { process: step.process } : {}),
  ...(step.transport ? { transport: step.transport } : {}), ...(step.waf ? { waf: step.waf } : {}),
})}`;

export function renderLiveWalkthrough(snapshot, operatorOrigin) {
  const recording = validateReviewedLive(snapshot);
  if (!/^https:\/\/[a-z0-9.-]+\.azurefd\.net$/.test(operatorOrigin)) throw new Error("Invalid fixed private operator link.");
  const first = (id) => recording.steps.find((step) => step.action === id);
  const fixes = recording.steps.filter((step) => step.action === "runtime-fix");
  const process = first("process-probe");
  const block = first("waf-block");
  const verify = recording.steps.filter((step) => step.action === "verify").at(-1);
  const cards = [
    { id: "step-brief", title: "Brief the team", aliases: ["baseline", "baseline-title"], body: `<p>GhostPaw's story now has a measured private exercise: inspect &rarr; run a bounded administrative probe &rarr; collect evidence &rarr; prevent a test-route request &rarr; patch &rarr; verify &rarr; reset only the private target &rarr; fix again.</p><p><strong>These are real process, HTTP, audit and image-transition observations. They are not a PHP exploitation recording.</strong> The public PHP app is not downgraded, and no Defender component is switched off.</p><p>Recorded ${escape(recording.startedAt)} &rarr; ${escape(recording.finishedAt)}. Separate authorization ends ${escape(recording.authorizationEndsAt)}; a historical recording remains read-only after teardown.</p>` },
    { id: "step-baseline", title: "Inspect the affected private image", aliases: ["request", "request-title"], body: `<p>The actual private PHP/Apache baseline is measured, not inferred from a training-mode flag. The two pinned derived image digests remain distinct. The namespace is restricted, the workload has no public service or Azure grant, and its ingress/egress are denied.</p>${json(process.runtime.before)}<p>The public app and the private comparison image are different workloads. An affected version is exposure evidence, not compromise.</p>` },
    { id: "step-run", title: "Run the real bounded process probe", aliases: ["attack", "attack-title"], body: `<p>One private console button runs one bounded probe: <code>kubectl -n php2shell-isolated exec pod/&lt;resolved php-runtime pod&gt; -c php -- id</code> through the authorized control plane. Before and after the probe it reads back the restricted namespace labels, deny-all policy, absence of services, deployment, pods and replicasets with owner references, image and imageID digests, pod security context, container readiness and the in-pod PHP health endpoint. No web shell, arbitrary command, sensitive-data read, outbound destination or PHP exploit is accepted.</p>${proof(process)}<details><summary>Actual independent audit source</summary>${source(process, "aksAudit")}</details>` },
    { id: "step-detect", title: "Compare source evidence with Defender observations", aliases: ["alerts", "alerts-title", "components", "components-title"], body: `<p>${escape(recording.comparison)}</p><div class="live-comparison"><section><h3>Baseline / source evidence</h3><p>Actual <code>id</code> stdout, HTTP status, pinned image and Kubernetes/WAF records can be investigated without Defender analytics. These logs are not automatically workload alerts.</p>${source(process, "aksAudit")}</section><section><h3>Defender-enabled observation</h3>${json(process.plans)}${source(process, "defenderAlerts")}<p>Additional value, when supported telemetry and detectors exist: runtime anomaly analysis, vulnerability context, exposure prioritization, alert enrichment and investigation pivots. None of that is fabricated for this probe.</p></section></div>` },
    { id: "step-prevent", title: "Prove a narrow prevention control", aliases: ["prevent", "prevent-title"], body: `<p>The real operator WAF stays in <strong>Prevention</strong>. Only a window-owned harmless marker-route rule changes from Log to Block. This is not a PHP CVE signature or a public-app policy change.</p><h3>Actual Log baseline</h3>${proof(first("waf-log"))}<h3>Actual Block observation</h3>${proof(block)}<details><summary>Actual WAF records and query result</summary>${source(block, "waf")}</details><p>For the real Microsoft PHP2Shell response rules, stage request controls in Log before a separately approved Block. Response sanitization rule 99006001 does not block/challenge traffic and supplies no WAF hit counts. <a href="/evidence/response">Official mitigation and upgrade walkthrough</a>.</p>` },
    { id: "step-fix", title: "Apply the real pinned PHP fix", aliases: ["resolve", "resolve-title", "containers"], body: `<p>Upgrading PHP is the complete vulnerability remediation. This private transition actually replaces the affected derived image with the reviewed fixed PHP 8.4.27 digest, waits for rollout and measures loopback Apache health plus the serving pod image.</p>${proof(fixes[0])}<details><summary>Resolution script and official version baselines</summary><pre>kubectl -n php2shell-isolated set image deployment/php-runtime php=&lt;REGISTRY&gt;/php2shell@&lt;REVIEWED_FIXED_DIGEST&gt;\nkubectl -n php2shell-isolated rollout status deployment/php-runtime --timeout=300s\n# The portal uses a stricter resourceVersion-preconditioned image/annotation patch,\n# checks isolation before/after and records the exact executed closed script privately.</pre><p>Reviewed fixed branches: 8.2.35, 8.3.36, 8.4.27 and 8.5.12. <a href="/evidence/response/script">Download the official-guidance response runner</a>. Fixture removal is not PHP patching.</p></details>` },
    { id: "step-reset", title: "Reset only the isolated private training image", aliases: ["reset", "reset-title"], body: `<p>A separately confirmed private reset requires an actually fixed predecessor. It touches only the reviewed private Deployment image/variant, with an optimistic resourceVersion guard. It does not downgrade the public app, disable Defender, loosen network isolation or silently undo legacy CLI fixed-intent safeguards.</p>${proof(first("runtime-reset"))}<p>The exact generated reset script is shown before approval and saved with the private run. Reset is an exercise step, not the final state.</p>` },
    { id: "step-verify", title: "Fix again and measure the final state", aliases: ["validate", "validate-title"], body: `<p>The final image is fixed again. Serving PHP version and actual image digest—not a successful deployment request—provide the proof.</p>${proof(fixes.at(-1))}${verify ? `<details><summary>Independent final verification run</summary>${proof(verify)}</details>` : ""}<p>The test-only WAF rule is then removed while all original protections remain.</p>${proof(first("waf-remove"))}` },
    { id: "step-hunt", title: "Hunt with actual queries and result states", aliases: ["correlate", "correlate-title", "posture", "posture-title", "sentinel", "sentinel-title"], body: `<p>Use the run UUID, private cluster and exact UTC window as pivots. Every source result below is an actual bounded query, or an explicit unavailable state—not an illustrative alert.</p>${Object.entries(process.queries).map(([name, query]) => `<details><summary>${escape(name)} query and actual result</summary><pre>${escape(query)}</pre>${source(process, name)}</details>`).join("")}<details><summary>Actual provider alert observation</summary>${source(process, "defenderAlerts")}</details><p>Sentinel correlation requires actual connectors, tables, analytics rules and incident observations. <a href="/evidence/hunting">27 hunting queries and 20 additional-value scenarios</a> include real source-readiness gaps; unavailable XDR telemetry is never replaced with made-up DeviceProcessEvents.</p>` },
    { id: "step-close", title: "Close with proof, limits and cleanup", aliases: ["glossary", "close", "close-title"], body: `<ul>${recording.limitations.map((text) => `<li>${escape(text)}</li>`).join("")}</ul><p>A four-hour private execution window and an exact-group managed-identity cleanup workflow bound this exercise. Expiry labels alone do not stop billing. Compute, registry/builds, disks, NAT/bandwidth, log ingestion and protected vCores can bill until resources are actually deleted; inspect the private cleanup run and Azure group readback.</p><p><a href="/evidence/92ad189c-9a88-4403-b773-52453963e4b8">Original October 24 synthetic recording (different evidence class)</a> / <a href="/evidence/response">Official prevention and resolution runbook</a> / <a href="#step-brief">Restart</a>.</p>` },
  ];
  return `<p class="evidence-label">HISTORICAL REVIEWED LIVE CAPTURE / PUBLIC READ-ONLY / NO EXECUTION CONTROLS</p><p><a class="live-button" href="/evidence/deploy">Deploy to Azure</a> <a href="https://github.com/ninjapaw/php2shell-cloud-defense-dojo">GitHub: source, scripts and deployment</a> / <a href="${escape(operatorOrigin)}/live">Private administrator console</a></p><p>One card at a time, like Pawton. Use Previous/Next, bookmark a step, or <a href="#live-read-all">read all steps</a>.</p><nav aria-label="Walkthrough steps"><details><summary>Jump to a step</summary><ol>${cards.map((card, index) => `<li><a href="#${card.id}">${index + 1}. ${escape(card.title)}</a></li>`).join("")}</ol></details></nav><div class="live-story"><span id="live-read-all" tabindex="-1"></span>${cards.map((card, index) => `<section class="live-card" id="${card.id}" tabindex="-1" aria-labelledby="${card.id}-title">${card.aliases.map((id) => `<span id="${id}"></span>`).join("")}<p class="live-progress">STEP ${index + 1} OF ${cards.length}</p><progress max="${cards.length}" value="${index + 1}" aria-label="Walkthrough progress"></progress><h2 id="${card.id}-title">${escape(card.title)}</h2>${card.body}<nav class="live-navigation" aria-label="Step navigation">${index ? `<a href="#${cards[index - 1].id}">Previous: ${escape(cards[index - 1].title)}</a>` : "<span>Start here</span>"}${index + 1 < cards.length ? `<a href="#${cards[index + 1].id}">Next: ${escape(cards[index + 1].title)}</a>` : '<a href="#step-brief">Restart</a>'}</nav></section>`).join("")}</div>`;
}

export async function publicLivePage(config) {
  let text;
  try { text = await readFile(new URL("./public-evidence/live.json", import.meta.url), "utf8"); }
  catch (error) {
    if (error.code !== "ENOENT") throw error;
    return '<p class="evidence-label">NO REVIEWED LIVE RECORDING PUBLISHED YET</p><p>The private live playbook is separately authorized. No actual run, fix, alert or reset is claimed until its reviewed recording is published. <a href="/evidence/hunting">Existing hunting evidence</a> / <a href="/evidence/response">Official response guide</a> / <a href="/evidence/deploy">Deploy to Azure</a> / <a href="https://github.com/ninjapaw/php2shell-cloud-defense-dojo">GitHub source</a>.</p>';
  }
  if (Buffer.byteLength(text) > 262_144) throw new Error("Reviewed live recording exceeds its fixed read bound.");
  return renderLiveWalkthrough(JSON.parse(text), config.origin);
}
