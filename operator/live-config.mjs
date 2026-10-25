import { UUID } from "../scripts/lib/config.mjs";

const keys = ["schemaVersion", "id", "notBefore", "expiresAt", "resourceGroup", "autoTeardown"];
const timestamp = (value) => typeof value === "string" && /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(value)
  && Number.isFinite(Date.parse(value)) && new Date(value).toISOString() === value;

export function parseLiveWindow(environment, invocation) {
  const enabled = environment.OPERATOR_LIVE_ENABLED;
  if (enabled !== undefined && !["true", "false"].includes(enabled)) throw new Error("OPERATOR_LIVE_ENABLED must be an explicit lowercase boolean.");
  if (enabled !== "true") {
    if (environment.OPERATOR_LIVE_WINDOW !== undefined || environment.OPERATOR_LIVE_AUTHORIZE_ID
        || environment.OPERATOR_LIVE_CAPTURE_ID || environment.OPERATOR_LIVE_TARGET) {
      throw new Error("Live scope settings require an explicit live-execution opt-in.");
    }
    return undefined;
  }
  const raw = environment.OPERATOR_LIVE_WINDOW;
  if (typeof raw !== "string" || Buffer.byteLength(raw) > 4096) throw new Error("An explicit bounded live-window document is required.");
  let value;
  try { value = JSON.parse(raw); }
  catch (error) {
    if (!(error instanceof SyntaxError)) throw error;
    throw new Error("The live-window document is invalid JSON.");
  }
  if (!value || Array.isArray(value) || Object.keys(value).length !== keys.length
      || Object.keys(value).some((key) => !keys.includes(key)) || value.schemaVersion !== 1
      || typeof value.id !== "string" || !UUID.test(value.id)
      || !timestamp(value.notBefore) || !timestamp(value.expiresAt)
      || Date.parse(value.expiresAt) - Date.parse(value.notBefore) < 60_000
      || Date.parse(value.expiresAt) - Date.parse(value.notBefore) > 4 * 3_600_000
      || value.resourceGroup !== `rg-p2sc-${invocation.suffix}-dev` || value.autoTeardown !== true) {
    throw new Error("Live authorization must be one exact private dev group, an explicit UUID, at most four hours and automatic teardown.");
  }
  for (const name of ["OPERATOR_LIVE_AUTHORIZE_ID", "OPERATOR_LIVE_CAPTURE_ID"]) {
    if (environment[name] !== undefined && (!UUID.test(environment[name]) || environment[name] !== value.id)) {
      throw new Error(`${name} must equal the exact approved live-window UUID.`);
    }
  }
  return Object.freeze({
    ...value,
    startsAt: Date.parse(value.notBefore),
    endsAt: Date.parse(value.expiresAt),
    groupId: `/subscriptions/${invocation.subscription}/resourceGroups/${value.resourceGroup}`,
  });
}

export function assertLiveGroup(config, group) {
  const window = config.liveWindow;
  if (!window || !group || typeof group.id !== "string" || group.id.toLowerCase() !== window.groupId.toLowerCase()
      || group.tags?.["dojo.liveWindowId"] !== window.id
      || group.tags?.["dojo.liveScenario"] !== "php2proof-private-live"
      || group.tags?.["pawprint.environment"] !== "dev"
      || group.tags?.["pawprint.expiresAt"] !== window.expiresAt) {
    throw new Error("Live target ownership, exact private scope or approved window drifted.");
  }
  return group;
}
