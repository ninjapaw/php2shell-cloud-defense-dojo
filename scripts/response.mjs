#!/usr/bin/env node
import { parseArgs } from "node:util";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { tmpdir } from "node:os";
import { pathToFileURL } from "node:url";
import lab from "../config/dev.json" with { type: "json" };
import { names, parseInvocation } from "./lib/config.mjs";
import { createAzureClient, readAzureCollection } from "./lib/azure.mjs";
import { assertOwnedGroup, redact, sameId } from "./lib/safety.mjs";
import { applyResponse, assertResponseWindow, buildResponsePlan, responseAction, RESPONSE_API, verifyResponse } from "./lib/response.mjs";

export async function responseCli(args, { azFactory = createAzureClient, now = Date.now, log = console.log } = {}) {
  const { values, positionals } = parseArgs({ args, allowPositionals: true, options: {
    environment: { type: "string", default: "dev" }, subscription: { type: "string" }, suffix: { type: "string" },
    out: { type: "string" }, plan: { type: "string" }, "confirm-group": { type: "string" }, yes: { type: "boolean", default: false },
  } });
  if (positionals.length !== 1) throw new Error("Supply one fixed response action; see the response walkthrough.");
  const action = responseAction(positionals[0]);
  const invocation = parseInvocation(["validate", "--environment", values.environment, "--subscription", values.subscription ?? "", "--suffix", values.suffix ?? ""], lab, {});
  if (action.writes && (!values.yes || values["confirm-group"] !== invocation.resourceGroup || !values.plan)) {
    throw new Error("Writes require --yes, --confirm-group with the exact configured group, and a fresh --plan file.");
  }
  if ((!action.writes && (values.plan || values.yes || values["confirm-group"])) || (action.id !== "plan" && values.out)) {
    throw new Error("Approval/output flags do not apply to this response action.");
  }
  const az = azFactory(invocation);
  const n = names(invocation);
  const account = await az(["account", "show"]);
  if (!sameId(account?.id, invocation.subscription) || account.state !== "Enabled" || (await az(["cloud", "show"]))?.name !== "AzureCloud") {
    throw new Error("Select the exact enabled public-cloud subscription before response.");
  }
  const group = assertOwnedGroup(await az(["group", "show", "--name", n.group]), invocation);
  const config = { invocation, names: n, expiry: group.tags["pawprint.expiresAt"], expiresAt: Date.parse(group.tags["pawprint.expiresAt"]), responseWritesEnabled: action.writes };
  const guard = () => assertResponseWindow(config, now());
  const url = (id, api) => `https://management.azure.com${id}?api-version=${api}`;
  const io = {
    read: async (id, api) => { guard(); return az(["rest", "--method", "get", "--url", url(id, api)]); },
    catalog: async () => { guard(); return readAzureCollection(az, url(`/subscriptions/${invocation.subscription}/providers/Microsoft.Network/FrontDoorWebApplicationFirewallManagedRuleSets`, RESPONSE_API.waf)); },
    roles: async () => { guard(); return readAzureCollection(az, `${url(`${n.appId}/providers/Microsoft.Authorization/roleAssignments`, "2022-04-01")}&$filter=atScope()`); },
    settings: async () => { guard(); return (await az(["rest", "--method", "post", "--url", url(`${n.appId}/config/appsettings/list`, RESPONSE_API.web)])).properties; },
    write: async (id, method, api, body) => {
      guard();
      const directory = mkdtempSync(join(tmpdir(), "php2proof-response-"));
      const path = join(directory, "body.json");
      try {
        writeFileSync(path, JSON.stringify(body), { flag: "wx", mode: 0o600 });
        return await az(["rest", "--method", method.toLowerCase(), "--url", url(id, api), "--body", `@${path}`]);
      } finally { rmSync(directory, { recursive: true }); }
    },
  };
  let result;
  if (action.id === "plan") {
    result = await buildResponsePlan(config, io, { now, guard });
    if (values.out) writeFileSync(resolve(values.out), `${JSON.stringify(result, null, 2)}\n`, { flag: "wx", mode: 0o600 });
  } else if (action.id === "verify") result = await verifyResponse(config, io, { now, guard });
  else {
    const planPath = resolve(values.plan);
    const preview = JSON.parse(readFileSync(planPath, "utf8"));
    writeFileSync(`${planPath}.used`, `${action.id}\n`, { flag: "wx", mode: 0o600 });
    result = await applyResponse(config, io, action.id, preview, { now, guard,
      audit: async (event, fields) => console.error(JSON.stringify({ event, ...fields })) });
  }
  log(JSON.stringify(result, null, 2));
  return result;
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  responseCli(process.argv.slice(2)).then((result) => {
    if ((result.kind === "response-verification" && !result.resolved) || result.sourceGaps?.length) process.exitCode = 2;
  }).catch((error) => {
    console.error(`ERROR: response failed; do not replay an uncertain change: ${redact(error.message)}`);
    process.exitCode = 1;
  });
}
