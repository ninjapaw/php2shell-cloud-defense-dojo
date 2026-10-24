import { readFileSync } from "node:fs";
import { parseConfigJson, parseInvocation, names, UUID } from "../scripts/lib/config.mjs";

export class OperatorError extends Error {
  constructor(status, code, message) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

export const CATALOGUE = Object.freeze([
  { id: "simulate", title: "GhostPaw: five harmless moves", enabled: true },
  { id: "validate", title: "Validate routing, WAF, origin and permissions", enabled: true },
  { id: "investigate", title: "Read actual matching posture assessments", enabled: true },
  { id: "domain-check", title: "Check the existing custom domain", enabled: true },
  { id: "collect-evidence", title: "Refresh evidence for a persisted run", enabled: true, contextRequired: true },
  { id: "hunt-pack", title: "Reviewed read-only hunting pack", enabled: true, contextRequired: true },
  { id: "defender-validation", title: "Microsoft App Service validation marker", enabled: false,
    reason: "Deferred: registration eligibility and a four-hour observation window must be verified before this test can be authorized." },
  ...["protect", "remediate", "deploy", "repair", "uninstall", "domain", "container-test"].map((id) => ({
    id, title: id, enabled: false, reason: "Not authorized through this read-only/harmless-test portal.",
  })),
]);
export const OPERATIONS = Object.freeze(CATALOGUE.filter((item) => item.enabled).map((item) => item.id));
export const LIMITS = Object.freeze({
  sessionMs: 30 * 60_000, jobMs: 10 * 60_000, requestBytes: 4096,
  jsonBytes: 524_288, startsPerHour: 10, startIntervalMs: 60_000,
  authAttempts: 5, authWindowMs: 15 * 60_000,
});

export function assertLive(config, now = Date.now()) {
  if (!Number.isFinite(config.expiresAt) || now >= config.expiresAt) {
    throw new OperatorError(410, "expired", "The original lab lifetime has ended. No new login or test is permitted.");
  }
}

export function loadConfig(environment = process.env) {
  const required = (key, pattern) => {
    const value = environment[key];
    if (typeof value !== "string" || !pattern.test(value)) {
      throw new Error(`Missing or invalid operator setting: ${key}. No insecure default is available.`);
    }
    return value;
  };
  const subscription = required("AZURE_SUBSCRIPTION_ID", UUID);
  const tenantId = required("AZURE_TENANT_ID", UUID);
  const suffix = required("DOJO_SUFFIX", /^[a-z0-9]{4,12}$/);
  const origin = required("OPERATOR_ORIGIN", /^https:\/\/[a-z0-9-]+(?:\.[a-z0-9-]+)*\.azurefd\.net$/);
  const frontDoorId = required("OPERATOR_FRONT_DOOR_ID", UUID);
  const storageAccount = required("OPERATOR_STORAGE_ACCOUNT", /^[a-z0-9]{3,24}$/);
  const vaultName = required("OPERATOR_VAULT_NAME", /^[a-z][a-z0-9-]{1,22}[a-z0-9]$/);
  const expiry = required("OPERATOR_EXPIRES_AT", /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/);
  const expiresAt = Date.parse(expiry);
  if (!Number.isFinite(expiresAt) || new Date(expiresAt).toISOString() !== expiry) throw new Error("Invalid operator expiry.");
  const lab = parseConfigJson(readFileSync(new URL("../config/dev.json", import.meta.url), "utf8"));
  const invocation = parseInvocation(["validate", "--subscription", subscription, "--suffix", suffix], lab, {});
  const workspaceId = required("OPERATOR_WORKSPACE_ID", UUID);
  const portText = environment.PORT ?? "8080";
  if (!/^\d{2,5}$/.test(portText) || Number(portText) > 65535) throw new Error("Invalid operator listening port.");
  return Object.freeze({
    invocation, tenantId, origin, frontDoorId, storageAccount, vaultName, workspaceId,
    expiresAt, expiry, port: Number(portText), names: names(invocation),
    verifierSecret: "operator-admin-verifier",
    blobContainer: "operator-private", queueName: "operator-jobs",
  });
}
