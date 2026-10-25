import { investigationQuery } from "../scripts/dojo.mjs";
import { readAzureCollection } from "../scripts/lib/azure.mjs";
import { sameId, assertResource } from "../scripts/lib/safety.mjs";
import { UUID } from "../scripts/lib/config.mjs";

const ARM = "https://management.azure.com";

export class AzureReadError extends Error {
  constructor(status, code) {
    super(`Azure evidence read failed: HTTP ${status}, code ${code}. No successful result is asserted.`);
    this.status = status;
    this.code = code;
  }
}

export async function boundedJson(response) {
  if (!response.body) throw new Error("Azure returned an empty JSON response.");
  const reader = response.body.getReader();
  const chunks = [];
  let length = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      length += value.byteLength;
      if (length > 1_048_576) throw new Error("Azure evidence exceeds the 1 MiB response bound.");
      chunks.push(value);
    }
  } finally {
    await reader.cancel();
  }
  let body;
  try { body = JSON.parse(Buffer.concat(chunks).toString("utf8")); }
  catch { throw new Error("Azure returned invalid JSON; raw content is not exposed."); }
  if (!response.ok) throw new AzureReadError(response.status, /^[A-Za-z0-9_.-]{1,100}$/.test(body?.error?.code) ? body.error.code : "unspecified");
  return body;
}

export class ReadOnlyAzure {
  constructor(config, credential, { fetchImpl = fetch, guard = async () => {} } = {}) {
    Object.assign(this, { config, credential, fetchImpl, guard });
    const n = config.names;
    this.resources = new Map([
      [n.profileId, "2025-04-15"], [n.endpointId, "2025-04-15"],
      [n.policyId, "2025-03-01"], [n.planId, "2025-03-01"], [n.workspaceId, "2025-07-01"],
      [n.customDomainId, "2025-04-15"],
      [`${n.profileId}/securityPolicies/application-waf`, "2025-04-15"],
      [`${n.endpointId}/routes/application`, "2025-04-15"],
      [`${n.profileId}/originGroups/application/origins/application`, "2025-04-15"],
      ...["ftp", "scm"].map((name) => [`${n.appId}/basicPublishingCredentialsPolicies/${name}`, "2025-03-01"]),
      [`${n.workspaceId}/providers/Microsoft.SecurityInsights/onboardingStates/default`, "2025-09-01"],
    ].map(([id, version]) => [id.toLowerCase(), version]));
    this.az = this.az.bind(this);
  }

  async request(url, scope, body) {
    const parsed = new URL(url);
    if (parsed.username || parsed.password || parsed.hash || ![ARM, "https://api.loganalytics.azure.com"].includes(parsed.origin)) {
      throw new Error("Azure read target escaped the fixed public-cloud API boundary.");
    }
    await this.guard();
    const access = await this.credential.getToken(scope);
    if (!access?.token || !Number.isFinite(access.expiresOnTimestamp) || access.expiresOnTimestamp <= Date.now()) {
      throw new Error("Managed identity did not return a valid Azure read token.");
    }
    await this.guard();
    const response = await this.fetchImpl(url, {
      method: body === undefined ? "GET" : "POST",
      headers: { Authorization: `Bearer ${access.token}`, ...(body === undefined ? {} : { "Content-Type": "application/json" }) },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
      redirect: "manual", signal: AbortSignal.timeout(30_000),
    });
    if (response.status >= 300 && response.status < 400) {
      await response.body?.cancel();
      throw new Error("Azure read redirects are forbidden.");
    }
    return boundedJson(response);
  }

  arm(path) {
    if (!path.startsWith("/subscriptions/") && !path.startsWith("/providers/")) throw new Error("Invalid Azure read path.");
    return this.request(`${ARM}${path}`, "https://management.azure.com/.default");
  }

  collection(path) {
    return readAzureCollection((args) => this.request(args[4], "https://management.azure.com/.default"), `${ARM}${path}`);
  }

  async graph(query, limit = 50) {
    const result = await this.request(`${ARM}/providers/Microsoft.ResourceGraph/resources?api-version=2024-04-01`,
      "https://management.azure.com/.default", {
        subscriptions: [this.config.invocation.subscription], query,
        options: { $top: limit, resultFormat: "objectArray" },
      });
    if (!Array.isArray(result.data) || result.data.length > limit || result.$skipToken
        || result.resultTruncated === "true" || result.resultTruncated === true) {
      throw new Error("Resource Graph returned incomplete or invalid bounded evidence.");
    }
    return result;
  }

  async logs(query, timespan) {
    const result = await this.request(`https://api.loganalytics.azure.com/v1/workspaces/${this.config.workspaceId}/query`,
      "https://api.loganalytics.io/.default", { query, timespan });
    if (result.error || result.partialError || !Array.isArray(result.tables) || result.tables.length !== 1) {
      throw new Error("Log Analytics returned partial or invalid evidence; no empty-success fallback is allowed.");
    }
    const table = result.tables[0];
    if (!Array.isArray(table.columns) || !Array.isArray(table.rows) || table.rows.length > 100) throw new Error("Log result exceeded the bounded evidence shape.");
    return table.rows.map((row) => Object.fromEntries(table.columns.map((column, index) => [column.name, row[index]])));
  }

  async tables() {
    const result = await this.request(`https://api.loganalytics.azure.com/v1/workspaces/${this.config.workspaceId}/metadata`,
      "https://api.loganalytics.io/.default");
    if (!Array.isArray(result.tables) || result.tables.some((table) => typeof table.name !== "string")) {
      throw new Error("Log Analytics returned invalid source-readiness metadata.");
    }
    return result.tables.map((table) => table.name);
  }

  async pricing(name) {
    if (!["CloudPosture", "AppServices", "Containers"].includes(name)) throw new Error("Unsupported read-only pricing observation.");
    const path = `/subscriptions/${this.config.invocation.subscription}/providers/Microsoft.Security/pricings/${name}`;
    const result = await this.arm(`${path}?api-version=2024-01-01`);
    assertResource(result, path);
    if (!["Free", "Standard"].includes(result.properties?.pricingTier)) throw new Error("Invalid Defender plan observation.");
    return result.properties;
  }

  async alerts() {
    const rows = await this.collection(`${this.config.names.groupId}/providers/Microsoft.Security/alerts?api-version=2022-01-01`);
    if (rows.length > 1000) throw new Error("Defender alert collection exceeded the private evidence bound.");
    return rows.filter((row) => row.properties?.resourceIdentifiers?.some((entry) => sameId(entry.azureResourceId, this.config.names.appId)));
  }

  async az(args) {
    await this.guard();
    if (!Array.isArray(args) || args.some((part) => typeof part !== "string")) throw new Error("Invalid guarded read invocation.");
    const n = this.config.names;
    const equal = (...expected) => JSON.stringify(args) === JSON.stringify(expected);
    if (equal("account", "show")) {
      const result = await this.arm(`/subscriptions/${this.config.invocation.subscription}?api-version=2022-12-01`);
      if (!sameId(result.subscriptionId, this.config.invocation.subscription)) throw new Error("Subscription read-back identity mismatch.");
      return { id: result.subscriptionId, state: result.state };
    }
    if (equal("cloud", "show")) return { name: "AzureCloud" };
    if (equal("group", "exists", "--name", n.group) || equal("group", "show", "--name", n.group)) {
      let result;
      try { result = await this.arm(`${n.groupId}?api-version=2025-04-01`); }
      catch (error) {
        if (error instanceof AzureReadError && error.status === 404 && args[1] === "exists") return false;
        throw error;
      }
      assertResource(result, n.groupId);
      if (result.tags?.["pawprint.expiresAt"] !== (this.config.originalExpiry ?? this.config.expiry)) throw new Error("Original lab expiry differs from the operator's immutable boundary.");
      return args[1] === "exists" ? true : result;
    }
    if (equal("webapp", "show", "--resource-group", n.group, "--name", n.app)) {
      const result = assertResource(await this.arm(`${n.appId}?api-version=2025-03-01`), n.appId);
      this.appPrincipal = result.identity?.principalId;
      return { id: result.id, ...result.properties, identity: result.identity };
    }
    if (equal("webapp", "config", "show", "--resource-group", n.group, "--name", n.app)) {
      const result = await this.arm(`${n.appId}/config/web?api-version=2025-03-01`);
      assertResource(result, `${n.appId}/config/web`);
      const keys = ["ipSecurityRestrictionsDefaultAction", "ipSecurityRestrictions", "linuxFxVersion", "ftpsState"];
      return Object.fromEntries(keys.map((key) => [key, result.properties?.[key]]));
    }
    if (args.length === 6 && args[0] === "resource" && args[1] === "show" && args[2] === "--ids"
        && args[4] === "--api-version" && this.resources.get(args[3].toLowerCase()) === args[5]) {
      return this.arm(`${args[3]}?api-version=${args[5]}`);
    }
    if (args.length === 5 && args.slice(0, 4).join(" ") === "monitor diagnostic-settings list --resource"
        && [n.appId, n.profileId].some((id) => sameId(args[4], id))) {
      return { value: await this.collection(`${args[4]}/providers/Microsoft.Insights/diagnosticSettings?api-version=2021-05-01-preview`) };
    }
    if (equal("role", "assignment", "list", "--scope", n.appId, "--include-inherited",
      "--fill-principal-name", "false", "--query", `[?principalId=='${this.appPrincipal}'].{id:id,roleDefinitionId:roleDefinitionId}`)
        && UUID.test(this.appPrincipal)) {
      const rows = await this.collection(`${n.appId}/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01&$filter=atScope()`);
      return rows.filter((row) => sameId(row.properties?.principalId, this.appPrincipal))
        .map((row) => ({ id: row.id, roleDefinitionId: row.properties.roleDefinitionId }));
    }
    if (equal("security", "pricing", "show", "--name", "CloudPosture")) return this.pricing("CloudPosture");
    if (equal("graph", "query", "--graph-query", investigationQuery(this.config.invocation), "--subscriptions", this.config.invocation.subscription)) {
      return this.graph(args[3]);
    }
    if (args.length === 5 && args.slice(0, 4).join(" ") === "rest --method get --url") {
      const initial = `${ARM}${n.workspaceId}/providers/Microsoft.SecurityInsights/alertRules`;
      const url = new URL(args[4]);
      if (url.origin === ARM && url.pathname.toLowerCase() === new URL(initial).pathname.toLowerCase()
          && url.searchParams.get("api-version") === "2025-09-01") {
        return this.request(url.href, "https://management.azure.com/.default");
      }
    }
    throw new Error("Operation is outside the fixed managed-identity read allowlist; no command was executed.");
  }
}
