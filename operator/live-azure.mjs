import { setTimeout as delay } from "node:timers/promises";
import { privateRunCommand, parsePrivateRunResult, validatePrivateTarget } from "../scripts/lib/private-live.mjs";
import { sameId } from "../scripts/lib/safety.mjs";
import { UUID } from "../scripts/lib/config.mjs";
import { responseFingerprint } from "../scripts/lib/response.mjs";
import { assertLiveGroup } from "./live-config.mjs";
import { AzureReadError, boundedJson } from "./azure.mjs";
import { changeProbeRule, livePolicyBody, liveWafObservation, operatorPolicyId, LIVE_WAF_API, LIVE_PROBE_PATH } from "./live-waf.mjs";

const ARM = "https://management.azure.com";
const AKS_AUDIENCE = "6dae42f8-4368-4678-94ff-3960e28e3630/.default";
const commandIdValid = (value) => UUID.test(value) || /^[a-f0-9]{32}$/.test(value);
export const liveReportId = (config) => `${config.operatorGroupId}/providers/Microsoft.Resources/deployments/private-live-capture-${config.liveWindow.id.slice(0, 8)}`;
export const teardownId = (config) => `${config.liveWindow.groupId}/providers/Microsoft.Logic/workflows/p2sc-${config.invocation.suffix}-expiry`;

export function liveIo(control, azure, guard, fetchImpl, { wait = delay } = {}) {
  const { config, store, now } = control;
  const policyUrl = `${operatorPolicyId(config)}?api-version=${LIVE_WAF_API}`;
  async function request(id, api, method = "GET", body) {
    await guard();
    const allowed = [
      ["POST", `${config.liveTarget.clusterId}/runCommand`, "2025-07-01"],
      ["PUT", operatorPolicyId(config), LIVE_WAF_API],
      ["PUT", liveReportId(config), "2025-04-01"],
    ];
    const resultPath = `${config.liveTarget.clusterId}/commandResults/`;
    const knownResult = method === "GET" && id.toLowerCase().startsWith(resultPath.toLowerCase()) && commandIdValid(id.slice(resultPath.length)) && api === "2025-07-01";
    if (!knownResult && !allowed.some(([m, resource, version]) => m === method && resource === id && version === api)) {
      throw new Error("Private live API escaped the exact resource/method/version allowlist.");
    }
    const token = await azure.credential.getToken(`${ARM}/.default`);
    if (!token?.token || !Number.isFinite(token.expiresOnTimestamp) || token.expiresOnTimestamp <= Date.now()) throw new Error("No valid private live managed-identity token.");
    await guard();
    return azure.fetchImpl(`${ARM}${id}?api-version=${api}`, {
      method, redirect: "manual", signal: AbortSignal.timeout(30_000),
      headers: { Authorization: `Bearer ${token.token}`, ...(body ? { "Content-Type": "application/json" } : {}),
        ...(typeof body?.etag === "string" && /^[^\r\n]{1,256}$/.test(body.etag) ? { "If-Match": body.etag } : {}) },
      ...(body ? { body: JSON.stringify(body) } : {}),
    });
  }
  async function target() {
    await guard();
    validatePrivateTarget(config.liveTarget, now());
    const group = await azure.arm(`${config.liveWindow.groupId}?api-version=2025-04-01`);
    assertLiveGroup(config, group);
    if (group.tags?.["dojo.liveWindowExpiresAt"] !== config.expiry) throw new Error("The independently read private-window expiry marker drifted.");
    const checked = { ...config.liveTarget, marker: {
      windowId: group.tags["dojo.liveWindowId"], expiresAt: group.tags["dojo.liveWindowExpiresAt"],
    } };
    validatePrivateTarget(checked, now());
    const cluster = await azure.arm(`${checked.clusterId}?api-version=2025-08-01`);
    const p = cluster.properties;
    if (!sameId(cluster.id, checked.clusterId) || cluster.tags?.["dojo.liveWindowId"] !== config.liveWindow.id
        || p?.apiServerAccessProfile?.enablePrivateCluster !== true || p.apiServerAccessProfile.enablePrivateClusterPublicFQDN === true
        || p.apiServerAccessProfile.disableRunCommand === true || p.disableLocalAccounts !== true || p.aadProfile?.enableAzureRBAC !== true
        || !Array.isArray(p.agentPoolProfiles) || p.agentPoolProfiles.length !== 1 || p.agentPoolProfiles[0].enableNodePublicIP === true
        || p.agentPoolProfiles[0].count !== 1 || p.agentPoolProfiles[0].securityProfile?.sshAccess !== "Disabled"
        || p.securityProfile?.defender?.securityMonitoring?.enabled !== true) throw new Error("The owned private-cluster, node or Defender boundary drifted.");
    const registry = await azure.arm(`${checked.registryId}?api-version=2025-04-01`);
    if (!sameId(registry.id, checked.registryId) || registry.tags?.["dojo.liveWindowId"] !== config.liveWindow.id
        || registry.properties?.adminUserEnabled !== false || registry.properties.anonymousPullEnabled !== false) {
      throw new Error("The pinned authenticated registry boundary drifted.");
    }
    const teardown = await azure.arm(`${teardownId(config)}?api-version=2019-05-01`);
    if (!sameId(teardown.id, teardownId(config)) || teardown.tags?.["dojo.liveWindowId"] !== config.liveWindow.id
        || teardown.properties?.state !== "Enabled"
        || teardown.properties.definition?.triggers?.AtExpiry?.recurrence?.startTime !== config.expiry
        || teardown.properties.definition?.parameters?.privateGroupId?.defaultValue !== config.liveWindow.groupId
        || teardown.properties.definition?.actions?.CheckBoundary?.actions?.DeleteOnlyAfterRevocation?.actions?.DeletePrivateGroup?.inputs?.method !== "DELETE"
        || teardown.properties.definition.actions.CheckBoundary.actions.DeleteOnlyAfterRevocation.actions.DeletePrivateGroup.inputs.uri !== `${ARM}${config.liveWindow.groupId}?api-version=2025-04-01`) {
      throw new Error("The exact private-group automatic teardown is not enabled for this window.");
    }
    return checked;
  }
  async function runtime(checked, input, jobId) {
    const command = privateRunCommand(checked, input, now());
    const clusterAccess = await azure.credential.getToken(AKS_AUDIENCE);
    if (!clusterAccess?.token || !Number.isFinite(clusterAccess.expiresOnTimestamp) || clusterAccess.expiresOnTimestamp <= Date.now()) throw new Error("No valid scoped managed-AAD AKS token.");
    await store.audit("private-command-intent", { jobId, operation: input.operation, runId: input.runId, windowId: config.liveWindow.id });
    let submitted = false;
    try {
      submitted = true;
      const response = await request(`${checked.clusterId}/runCommand`, "2025-07-01", "POST", { command, clusterToken: clusterAccess.token });
      if (response.status !== 202) {
        if (!response.ok) await boundedJson(response);
        await response.body?.cancel();
        throw new Error("AKS did not return the documented asynchronous 202 protocol; reconcile without replay.");
      }
      const location = response.headers.get("location");
      await response.body?.cancel();
      if (!location) throw new Error("Accepted AKS command has no tracking location; do not replay it.");
      const parsed = new URL(location, ARM);
      const prefix = `${checked.clusterId}/commandResults/`;
      const commandId = parsed.pathname.slice(prefix.length);
      if (parsed.origin !== ARM || parsed.username || parsed.password || parsed.hash || !parsed.pathname.toLowerCase().startsWith(prefix.toLowerCase())
          || !commandIdValid(commandId) || [...parsed.searchParams].length !== 1 || parsed.searchParams.get("api-version") !== "2025-07-01") {
        throw new Error("AKS tracking location escaped the exact accepted-command result boundary.");
      }
      await store.audit("private-command-accepted", { jobId, commandId, runId: input.runId });
      for (let attempt = 0; attempt < 126; attempt += 1) {
        await guard();
        const polled = await request(parsed.pathname, "2025-07-01");
        if (polled.status === 202 || (polled.status === 404 && attempt < 3)) {
          await polled.body?.cancel();
        } else {
          const body = await boundedJson(polled);
          const state = body.properties?.provisioningState;
          if (state === "Succeeded" || ["Failed", "Canceled", "Cancelled"].includes(state)) {
            const record = parsePrivateRunResult(body, checked, input, now());
            await store.audit("private-command-observed", { jobId, commandId, operation: input.operation, exitCode: record.exitCode });
            return { record, command };
          }
          if (!["Accepted", "Running", "Creating", "Updating", "InProgress"].includes(state)) throw new Error("AKS returned an unknown command-result state.");
        }
        await wait(5000);
      }
      throw new Error("Accepted AKS command exceeded the bounded observation deadline; do not replay.");
    } catch (error) {
      if (submitted && !(error instanceof AzureReadError && [400, 401, 403].includes(error.status))) error.mutationMayHaveOccurred = true;
      throw error;
    }
  }
  const policy = () => azure.arm(policyUrl);
  async function transport(runId) {
    if (!UUID.test(runId)) throw new Error("A real fixed transport run UUID is required.");
    const startedAt = new Date(now()).toISOString();
    const response = await fetchImpl(`${config.origin}${LIVE_PROBE_PATH}${runId}`, {
      method: "GET", redirect: "manual", signal: AbortSignal.timeout(20_000),
      headers: { "Cache-Control": "no-cache", "User-Agent": "PHPToProof-Bounded-Transport-Validation/1.0" },
    });
    if (![200, 403].includes(response.status)) { await response.body?.cancel(); throw new Error(`Unexpected live transport HTTP ${response.status}.`); }
    let marker;
    if (response.status === 200) {
      marker = await boundedJson(response);
      if (marker.kind !== "benign-read-only-transport-marker" || marker.runId !== runId || marker.executesCommands !== false
          || marker.testsPhpExploit !== false || !Number.isFinite(Date.parse(marker.observedAt))) {
        throw new Error("HTTP 200 did not contain the actual fixed transport marker.");
      }
    } else await response.body?.cancel();
    return { runId, startedAt, endedAt: new Date(now()).toISOString(), status: response.status,
      route: `${LIVE_PROBE_PATH}${runId}`, ...(marker ? { marker } : {}),
      evidenceKind: "actual-benign-edge-http-response-not-cve-exploitation" };
  }
  async function changeWaf(checked, action, before, jobId) {
    validatePrivateTarget(checked, now());
    const fresh = await policy();
    if (responseFingerprint(livePolicyBody(config, fresh)) !== responseFingerprint(livePolicyBody(config, before))) {
      throw new Error("Operator WAF changed after preview; no write was attempted.");
    }
    const desired = changeProbeRule(config, fresh, action);
    await store.audit("private-waf-write-intent", { jobId, action, policyId: operatorPolicyId(config) });
    try {
      const response = await request(operatorPolicyId(config), LIVE_WAF_API, "PUT", desired);
      await boundedJson(response);
      for (let attempt = 0; attempt < 18; attempt += 1) {
        await guard();
        const observed = await policy();
        const state = liveWafObservation(config, observed);
        const withoutProbe = (source) => {
          const body = livePolicyBody(config, source);
          delete body.etag;
          body.properties.customRules.rules = body.properties.customRules.rules.filter((rule) => rule.name !== state.rule.name);
          return responseFingerprint(body);
        };
        if (withoutProbe(observed) !== withoutProbe(before)) throw new Error("A non-test WAF control changed; reconciliation is required.");
        if (state.rule.action === (action === "Remove" ? "absent" : action)) {
          const expected = action === "Block" ? 403 : 200;
          const probe = await transport(jobId);
          if (probe.status === expected) return { waf: state, transport: probe };
        }
        await wait(15_000);
      }
      throw new Error("WAF change was accepted but edge propagation was not proved within the bounded observation window.");
    } catch (error) {
      if (!(error instanceof AzureReadError && [400, 401, 403, 412].includes(error.status))) error.mutationMayHaveOccurred = true;
      throw error;
    }
  }
  async function report(record) {
    await store.audit("private-capture-report-intent", { windowId: config.liveWindow.id, reportId: liveReportId(config) });
    const response = await request(liveReportId(config), "2025-04-01", "PUT", {
      properties: { mode: "Incremental", parameters: { record: { value: record } },
        template: { $schema: "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
          contentVersion: "1.0.0.0", parameters: { record: { type: "object" } }, resources: [],
          outputs: { result: { type: "object", value: "[parameters('record')]" } } } },
    });
    return boundedJson(response);
  }
  return { target, runtime, policy, transport, changeWaf, report };
}
