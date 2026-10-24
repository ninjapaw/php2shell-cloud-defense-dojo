import { randomUUID } from "node:crypto";
import { readFile } from "node:fs/promises";
import { applyResponse, buildResponsePlan, responseAction, RESPONSE_ACTIONS, RESPONSE_API, RESPONSE_GUIDANCE, responseRule, verifyResponse } from "../scripts/lib/response.mjs";
import { UUID } from "../scripts/lib/config.mjs";
import { OperatorError } from "./config.mjs";
import { boundedJson } from "./azure.mjs";

const ARM = "https://management.azure.com";
const escape = (value) => String(value).replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;").replaceAll('"', "&quot;").replaceAll("'", "&#39;");
const hidden = (key, value) => `<input type="hidden" name="${key}" value="${escape(value)}">`;
const fingerprint = /^[a-f0-9]{64}$/;

export async function validateResponseDispatch(control, session, input) {
  if (!input || Object.keys(input).some((key) => !["id", "planJobId", "fingerprint", "confirmation"].includes(key))) {
    throw new OperatorError(400, "response-input", "Only a fixed response action and its exact preview approval are accepted.");
  }
  let action;
  try { action = responseAction(input.id); }
  catch { throw new OperatorError(400, "response-action", "Unknown fixed response action; no command or script input is accepted."); }
  if (!action.writes) {
    if (Object.keys(input).some((key) => key !== "id")) throw new OperatorError(400, "response-approval", "Read-only response actions do not accept mutation approvals or targets.");
    return { id: action.id };
  }
  if (control.config.responseWritesEnabled !== true) {
    await control.store.audit("response-write-denied", { action: action.id, reason: "writes-disabled", session: session.hash });
    throw new OperatorError(403, "response-writes-disabled", "Response writes are disabled. A new approved window and exact scoped permissions must be authorized separately.");
  }
  if (!UUID.test(input.planJobId ?? "") || !fingerprint.test(input.fingerprint ?? "") || input.confirmation !== control.config.names.group) {
    throw new OperatorError(400, "response-approval", "Review a persisted preview and type the exact resource-group name before this response action.");
  }
  const source = await control.store.read(`jobs/${input.planJobId}`);
  if (!source || source.value.operation !== "response" || source.value.response?.id !== "plan"
      || !["completed", "completed-with-evidence-gaps"].includes(source.value.status)
      || source.value.sessionHash !== session.hash || source.value.credentialEpoch !== session.epoch
      || source.value.target !== control.config.names.appId || source.value.result?.fingerprint !== input.fingerprint
      || source.value.result?.expiresAt !== control.config.expiry
      || !Number.isFinite(Date.parse(source.value.result?.createdAt))
      || Date.parse(source.value.result.createdAt) > control.now()
      || control.now() - Date.parse(source.value.result.createdAt) > 600_000
      || !source.value.result.actions?.some((entry) => entry.id === action.id && entry.available === true)) {
    throw new OperatorError(409, "response-preview", "A fresh available response preview owned by this credential/session is required.");
  }
  return { id: action.id, planJobId: input.planJobId, fingerprint: input.fingerprint, confirmation: input.confirmation };
}

export function responseIo(config, azure, guard, fetchImpl) {
  const n = config.names;
  const reads = new Map([
    [n.groupId, RESPONSE_API.group], [n.profileId, RESPONSE_API.cdn], [n.endpointId, RESPONSE_API.cdn],
    [n.policyId, RESPONSE_API.waf], [n.appId, RESPONSE_API.web], [`${n.appId}/config/web`, RESPONSE_API.web],
    [`${n.profileId}/securityPolicies/application-waf`, RESPONSE_API.cdn], [n.customDomainId, RESPONSE_API.cdn],
  ]);
  const writes = new Map([
    [n.policyId, ["PUT", RESPONSE_API.waf]],
    [`${n.appId}/config/appsettings`, ["PUT", RESPONSE_API.web]],
    [`${n.groupId}/providers/Microsoft.Resources/tags/default`, ["PATCH", RESPONSE_API.tags]],
  ]);
  const url = (id, api) => `${ARM}${id}?api-version=${api}`;
  return {
    fetchImpl,
    read: async (id, api) => {
      await guard();
      if (reads.get(id) !== api) throw new Error("Response read escaped the exact owned-lab resource/API allowlist.");
      return azure.arm(`${id}?api-version=${api}`);
    },
    catalog: async () => {
      await guard();
      return azure.collection(`/subscriptions/${config.invocation.subscription}/providers/Microsoft.Network/FrontDoorWebApplicationFirewallManagedRuleSets?api-version=${RESPONSE_API.waf}`);
    },
    roles: async () => {
      await guard();
      return azure.collection(`${n.appId}/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01&$filter=atScope()`);
    },
    settings: async () => {
      await guard();
      if (config.responseWritesEnabled !== true) throw new Error("Public-app settings access for response is not authorized.");
      return (await azure.request(url(`${n.appId}/config/appsettings/list`, RESPONSE_API.web), `${ARM}/.default`, {})).properties;
    },
    write: async (id, method, api, body) => {
      await guard();
      if (config.responseWritesEnabled !== true || JSON.stringify(writes.get(id)) !== JSON.stringify([method, api])) {
        throw new Error("Response write escaped the explicit opt-in and exact resource/method/API allowlist.");
      }
      const token = await azure.credential.getToken(`${ARM}/.default`);
      if (!token?.token || !Number.isFinite(token.expiresOnTimestamp) || token.expiresOnTimestamp <= Date.now()) throw new Error("No valid managed-identity response token.");
      await guard();
      const result = await azure.fetchImpl(url(id, api), {
        method, redirect: "manual", signal: AbortSignal.timeout(30_000),
        headers: { Authorization: `Bearer ${token.token}`, "Content-Type": "application/json",
          ...(typeof body.etag === "string" && /^[^\r\n]{1,256}$/.test(body.etag) ? { "If-Match": body.etag } : {}) },
        body: JSON.stringify(body),
      });
      if (result.status >= 300 && result.status < 400) { await result.body?.cancel(); throw new Error("Response write redirects are forbidden; reconcile before retrying."); }
      if (result.status === 204) return { acceptedNoContent: true };
      return boundedJson(result);
    },
  };
}

export async function runResponseJob(control, job, azure, guard, fetchImpl) {
  const approved = await validateResponseDispatch(control, { hash: job.sessionHash, epoch: job.credentialEpoch }, job.response);
  const io = responseIo(control.config, azure, guard, fetchImpl);
  const options = { guard, now: control.now, log: control.log,
    audit: (event, fields) => control.store.audit(event, { jobId: job.id, ...fields }) };
  if (approved.id === "plan") return buildResponsePlan(control.config, io, options);
  if (approved.id === "verify") return verifyResponse(control.config, io, options);
  await guard();
  const key = `control/response/${approved.planJobId}`;
  if (await control.store.read(key)) throw new Error("This response preview has already been consumed; automatic or manual replay requires a new plan.");
  await control.store.write(key, { jobId: job.id, action: approved.id, consumedAt: new Date(control.now()).toISOString() });
  const source = await control.store.read(`jobs/${approved.planJobId}`);
  return applyResponse(control.config, io, approved.id, source.value.result, options);
}

function command(id) {
  const scope = "--environment dev --subscription <SUBSCRIPTION_UUID> --suffix <DOJO_SUFFIX>";
  const cli = "node php2proof-response.mjs";
  return responseAction(id).writes
    ? `${cli} plan ${scope} --out response-${id}.json\n${cli} ${id} ${scope} --plan response-${id}.json --confirm-group NP-PHPToProof-Dev-CentralUS --yes`
    : `${cli} ${id} ${scope}${id === "plan" ? " --out response-plan-01.json" : ""}`;
}

export function publicResponsePage() {
  const source = RESPONSE_GUIDANCE;
  return `<p class="evidence-label">OFFICIAL GUIDANCE / INDEPENDENT TRAINING IMPLEMENTATION / NOT A LIVE AFTER-STATE</p>
<p>GhostPaw's route is <strong>discover &rarr; detect &rarr; prevent &rarr; patch &rarr; verify</strong>. No exploit, shell, sensitive-data access or automatic response is introduced.</p>
<nav><a href="https://php2proof.ninjapaws.org/walkthrough.php#recorded">Actual GhostPaw recording</a> / <a href="/evidence/hunting">27 hunts and actual results</a> / <a href="#response-closure">Closure checks</a> / <a href="/evidence/response/script">Download the readable Node.js response script</a></nav>
<h2>1. Discover and detect: start with the actual evidence</h2>
<p>The recorded GhostPaw run <code>92ad189c-9a88-4403-b773-52453963e4b8</code> at 2026-10-24 16:33 UTC returned five HTTP200s and five ingested <strong>synthetic</strong> app records. The actual WAF marker was Block/Detection, not enforced blocking. The scoped provider-alert query succeeded with no matching alerts. Four Healthy assessments are not CVE patch evidence.</p>
<p>The separate 18:35 UTC hunting capture queried three scenarios, recorded 18 unavailable and six not applicable. Missing sources are not a clean bill of health. All observed AppServices, CloudPosture and Containers plans were Standard; there was no Defender-disabled control experiment.</p>
<h2>2. Apply the official response, not just a story-state switch</h2>
<p><a href="${source.response}">Microsoft's response</a> and <a href="${source.customRules}">request-rule guidance</a>, updated ${source.updatedAt}, were reviewed ${source.reviewedAt}. The PHP fixed-version baselines are <code>8.2.35</code>, <code>8.3.36</code>, <code>8.4.27</code> and <code>8.5.12</code>. <a href="${source.php}">PHP's security release</a> confirms the 8.4 update. Supported later patches on those branches meet the version threshold; unknown branches/backports require vendor evidence.</p>
<p><strong>Upgrading PHP is the complete vulnerability remediation. WAF is temporary supplementary mitigation.</strong> Prioritize internet-facing VMs, platform runtimes, containers and base images. Rebuild and redeploy container images; patching the host does not patch PHP inside them. Migrate unsupported branches. This portal does not run package managers, arbitrary scripts, scanners or container images.</p>
<h2>3. Prevent: three independent request-side policies</h2>
<p>Each custom rule is independently authored and restricted to the verified public PHP hosts and this lab's PHP routes, including <code>/</code>. Read-only Node evidence routes are excluded. The session-upload-progress token policy and both 20-level nesting policies are staged in <strong>Log</strong>; independently review legitimate matches and application impact before a separately confirmed Block action. Twenty levels is application policy, not a CVE-defined safety boundary.</p>
<p>Check terminal Allow-rule precedence, request-body inspection limits, encoded/quoted parameters and upload/session dependencies. Preserve existing rules, scrubbers, associations, private origin and pricing. No new DRS, gateway or security product is installed automatically. Request-rule matches can produce WAF logs; verify actual mode/action and HTTP behavior. A synthetic marker or heuristic match is not a PHP2Shell exploit or guaranteed CVE coverage.</p>
<h2>4. Front Door response-side mitigation has different evidence</h2>
<p>For an already-reviewed DRS2.0/2.1/2.2, inspect the <a href="${source.managedRules}">available managed-rule catalogue</a> for group <code>${source.responseGroup}</code>, rule <code>${source.responseRule}</code>. Microsoft says rollout is expected through ${source.rolloutExpectedBy}; presence is checked, never assumed. The rule is disabled by default. Its prescribed anomaly action is distinct from forcing an immediate request block.</p>
<p><strong>This rule sanitizes potentially malicious response elements; it does not block/challenge traffic and generates no WAF log entries or hit counts.</strong> Do not invent a matching alert or use missing logs to declare it ineffective. The action script requires a pre-existing reviewed DRS with Block anomaly policy, enables only this rule's AnomalyScoring override, and leaves every other rule/exclusion unchanged. Missing catalogue access or an absent rule is explicitly unavailable, not successful.</p>
<p><strong>Other platforms:</strong> Application Gateway v2 uses the official conditional Set-Cookie response-header rewrite with the October22 corrected expression; it must not strip all cookies. Associate and test the rewrite set on its actual routes. AGC currently has request rules but no regex-based response rewrite. These are referenced manual tracks, not executable against this App Service/Front Door lab.</p>
<h2>5. Resolution: close the fixture and prove the runtime separately</h2>
<p><code>resolve-fixtures</code> changes only the owned public application's <code>LAB_STATE</code> to <code>fixed</code>, preserves other settings and original expiry, and retains Prevention. It removes five harmless training inputs. <strong>It does not install PHP or resolve either CVE.</strong> No resolution action reopens training or downgrades WAF.</p>
<p>App Service's <code>PHP|8.4</code> setting names a branch, not a patched full version. Check the actual <code>PHP_VERSION</code> returned by the trusted lab health endpoint. A branch switch or app restart is not proof that 8.4.27 is deployed. If the built-in image is below the threshold, obtain the platform's patched runtime or use a separately reviewed patched deployment; this portal does not silently migrate architecture. For private container/VM estates, follow the corresponding rebuild/package-manager vendor procedure and recheck the running deployment, not just its build manifest.</p>
<h2>6. Scripts and protected administrator controls</h2>
<p>The download is readable Node.js source, bundled from this repository with its shared safety helpers and vendored attribution. Requires Node24, Linux/macOS or WSL2 Azure CLI, and an already authenticated authorized account. No credential is embedded. Only the configured dev group and independently discovered owned endpoints are accepted. No host, query, command, group or package override exists.</p>
<p>First create a new private preview file. Apply at most one selected action per preview with exact group confirmation; the preview expires after ten minutes and its <code>.used</code> marker forbids replay. Generate a fresh preview after every change. The portal also binds the approval to its session/credential epoch and durable job, exact config fingerprint, audit, queue, lease and immutable expiry. Writes default off and require separately approved narrow permissions. Errors after a possibly accepted write require manual reconciliation, never automatic replay or rollback to exposure.</p>
${RESPONSE_ACTIONS.map((action) => `<section id="response-step-${action.id}"><h3>${escape(action.title)}</h3><pre><code>${escape(command(action.id))}</code></pre></section>`).join("")}
<p><a href="/evidence/response/script">Download the exact script</a>. Review <code>node php2proof-response.mjs plan ...</code> before any mutation; no live post-mitigation result is claimed by this guide. The original window ended 2026-10-24 18:45:04.967 UTC. This publication grants no extension or execution authorization; obtain a current explicitly approved window.</p>
<h2 id="response-closure">7. Verify measurable closure, then investigate residual risk</h2>
<ul><li>Trusted public homepage/health remains HTTP200; actual full PHP version meets the selected advisory baseline.</li><li>With Prevention, the harmless marked request is HTTP403. That proves the marker control, not CVE exploit prevention.</li><li>All five <strong>unmarked</strong> synthetic inputs return HTTP404 after fixture removal. A marked403 alone is not resolution.</li><li>The origin returns403 with and without copied FDID; the public PHP identity still has zero grants.</li><li>Read back each real custom-rule config and review legitimate traffic/logs independently. Rule99006001 has no WAF hits/logs by design.</li><li>Refresh relevant vulnerability/asset assessments and applicable hunts after their actual ingestion/scan cycles. Preserve source gaps, scan time, image digest/asset identity, UTC and genuine finding IDs.</li><li>If there is real compromise evidence, preserve forensic evidence, isolate via your approved incident process, rotate exposed credentials and rebuild from trusted artifacts. This training portal does not perform incident containment or secret rotation.</li></ul>
<p><strong>Published evidence:</strong> the historical detection/baseline recordings above are actual. <strong>No post-mitigation capture has been published here</strong> for Prevention, official-rule enforcement, fixture resolution or PHP patch verification. Expected statuses are not recorded after-state results; this static guide neither queries private runs nor asserts their current status. With or without Defender, apply patches and validate controls; paid CSPM can add supported inventory/attack-path context, workload protection can add genuine detections, and Sentinel can correlate supported sources. No product guarantees a detection or removes the need for remediation.</p>`;
}

export async function privateResponsePage(config, store, session) {
  const jobs = (await store.recentJobs()).filter((job) => job.operation === "response")
    .toSorted((a, b) => Date.parse(b.queuedAt) - Date.parse(a.queuedAt));
  const preview = jobs.find((job) => job.response?.id === "plan" && job.sessionHash === session.hash
    && job.credentialEpoch === session.epoch && ["completed", "completed-with-evidence-gaps"].includes(job.status)
    && Date.now() - Date.parse(job.result?.createdAt) <= 600_000);
  const form = (action, plan) => `<form action="/jobs" method="post">${hidden("csrf", session.csrf)}${hidden("operation", "response")}${hidden("idempotencyKey", randomUUID())}${hidden("responseId", action.id)}${plan ? `${hidden("responsePlanJobId", plan.id)}${hidden("responseFingerprint", plan.result.fingerprint)}<p><label>Confirm exact group ${escape(config.names.group)} <input name="responseConfirmation" required autocomplete="off"></label></p>` : ""}<button>${escape(action.title)}</button></form>`;
  return `<p><a href="/">Console</a> / <a href="/evidence/response">Official-response walkthrough and scripts</a></p><p>Owned group: ${escape(config.names.group)}. Original expiry: ${escape(config.expiry)}. Write authorization: <strong>${config.responseWritesEnabled === true ? "explicitly enabled; scoped permissions still required" : "OFF; no live IAM/mitigation authorization was assumed"}</strong>.</p>
<p>Preview is metadata-only. Verification makes bounded harmless requests. Both require this active authorized session. PHP patching is not simulated by a training-state switch.</p>
${RESPONSE_ACTIONS.filter((action) => !action.writes).map((action) => form(action)).join("")}
${preview ? `<h2>Latest private preview</h2><p><a href="/jobs/${escape(preview.id)}">Read the entire persisted plan</a>. Review application impact, exact configuration and scope before approval. Each preview is one-use.</p>` : "<p>No fresh preview belongs to this session. Generate and inspect one before any mutation.</p>"}
${RESPONSE_ACTIONS.filter((action) => action.writes).map((action) => {
    const planned = preview?.result?.actions?.find((entry) => entry.id === action.id);
    return config.responseWritesEnabled === true && planned?.available
      ? form(action, preview) : `<p><button disabled>${escape(action.title)}</button> ${escape(planned?.reason ?? "Requires approved write enablement and a fresh session-bound preview.")}</p>`;
  }).join("")}
<h2>Persisted response runs</h2><ul>${jobs.map((job) => `<li><a href="/jobs/${escape(job.id)}">${escape(job.queuedAt)} / ${escape(job.response?.id)} / ${escape(job.status)}</a></li>`).join("")}</ul>
<details><summary>Independently authored request-rule examples (Log, not applied)</summary><pre>${escape(JSON.stringify(["session", "form", "multipart"].map((kind) => responseRule(kind, ["verified-owned-host.invalid"])), null, 2))}</pre></details>`;
}

export async function responseDownload() {
  const source = await readFile(new URL("./public-scripts/response.mjs", import.meta.url), "utf8");
  if (!source.includes("responseCli") || source.length > 262144) throw new Error("The reviewed bounded response script was not built correctly.");
  return source;
}
