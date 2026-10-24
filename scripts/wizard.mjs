#!/usr/bin/env node
import { createInterface } from "node:readline/promises";
import { stdin, stdout } from "node:process";
import { parseArgs } from "node:util";
import { randomBytes } from "node:crypto";
import { lstatSync, readFileSync, mkdirSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { execute, ROOT } from "./dojo.mjs";
import { runTool, createAzureClient } from "./lib/azure.mjs";
import { parseInvocation, validateConfig, UUID } from "./lib/config.mjs";
import { redact, sameId } from "./lib/safety.mjs";

export const WIZARD_ACTIONS = Object.freeze([
  ["plan", "Offline plan"], ["doctor", "Prerequisites, permissions and Azure what-if"],
  ["deploy", "Install a NEW core public training lab"], ["validate", "Validate the existing lab"],
  ["simulate", "Run five harmless GhostPaw moves"], ["investigate", "Inspect actual matching posture"],
  ["protect", "Enable WAF Prevention"], ["remediate", "Remove training fixtures (not a PHP update)"],
  ["repair", "Repair while preserving fixed/Prevention/expiry"], ["uninstall", "Delete only the exact owned main group"],
  ["exit", "Exit without another action"],
]);
const WRITES = new Set(["deploy", "simulate", "protect", "remediate", "repair", "uninstall"]);
const PREFLIGHT = new Set(["deploy", "protect", "remediate", "repair"]);
const INSTALL = "https://learn.microsoft.com/cli/azure/install-azure-cli";
const featureKeys = ["enableDefenderCspm", "enableSentinel", "enableAnalytics"];
const nodeOk = (version) => /^24\.(?:19|[2-9]\d|\d{3,})\.\d+$/.test(version.replace(/^v/, ""));
const cliOk = (version) => typeof version === "string" && /^2\.(?:6[1-9]|[7-9]\d|\d{3,})\.\d+$/.test(version);
const bicepOk = (text) => {
  const match = /\bBicep(?: CLI)? version\s+(\d+)\.(\d+)\.(\d+)/i.exec(text);
  return Boolean(match && (Number(match[1]) > 0 || Number(match[2]) > 48 || (Number(match[2]) === 48 && Number(match[3]) >= 1)));
};

export function validateProfile(value) {
  if (!value || value.schemaVersion !== 1 || Object.keys(value).some((key) => !["schemaVersion", "subscription", "suffix", "settings", "features"].includes(key))
      || !UUID.test(value.subscription ?? "") || !/^[a-z0-9]{4,12}$/.test(value.suffix ?? "")
      || !value.features || Object.keys(value.features).length !== featureKeys.length
      || featureKeys.some((key) => typeof value.features[key] !== "boolean")
      || (value.features.enableAnalytics && !value.features.enableSentinel)) {
    throw new Error("Invalid nonsecret wizard profile; only documented dev settings and boolean opt-ins are accepted.");
  }
  const settings = validateConfig(value.settings);
  if (settings.customDomain) throw new Error("The core wizard does not adopt a DNS name. Use the separately reviewed domain workflow.");
  return { schemaVersion: 1, subscription: value.subscription, suffix: value.suffix, settings, features: { ...value.features } };
}

export function loadProfile(path) {
  const file = resolve(path);
  if (!lstatSync(file).isFile() || lstatSync(file).isSymbolicLink() || lstatSync(file).size > 16384) throw new Error("Profile must be a bounded regular local JSON file.");
  let value;
  try { value = JSON.parse(readFileSync(file, "utf8")); }
  catch (error) {
    if (error instanceof SyntaxError) throw new Error("Profile is not valid JSON; contents omitted to protect accidental secrets.");
    throw error;
  }
  return validateProfile(value);
}

export function invocationFor(profile, command) {
  if (!WIZARD_ACTIONS.some(([id]) => id === command) || command === "exit") throw new Error("Unknown fixed wizard action.");
  const p = validateProfile(profile);
  const base = parseInvocation([command, "--subscription", p.subscription, "--suffix", p.suffix, "--environment", "dev"], p.settings, {});
  return { ...base, ...p.features, yes: false };
}

function parseJson(text, context) {
  try { return JSON.parse(text); } catch { throw new Error(`${context} did not return valid JSON; raw output is not displayed.`); }
}

export async function checkPrerequisites({ tool = runTool, version = process.versions.node, ask, print = console.log } = {}) {
  if (!nodeOk(version)) throw new Error(`Node24.19+ (below25) is required, not ${version}. Install the supported Node24 release; no runtime is bundled.`);
  let cli;
  try { cli = parseJson(tool("az", ["version", "--only-show-errors", "--output", "json"]), "Azure CLI"); }
  catch (error) { throw new Error(`Azure CLI prerequisite failed: ${redact(error.message)}. Install/reopen the terminal: ${INSTALL}`); }
  if (!cliOk(cli["azure-cli"])) throw new Error(`Azure CLI2.61+ is required. Update through Microsoft's installer: ${INSTALL}`);
  const bicep = () => {
    const text = tool("az", ["bicep", "version", "--only-show-errors"]);
    if (!bicepOk(text)) throw new Error("Bicep0.48.1 or newer is required.");
  };
  try { bicep(); }
  catch (error) {
    print(`Bicep check failed: ${redact(error.message)}`);
    if (!ask || !/^y(?:es)?$/i.test((await ask("Install the Azure CLI Bicep component locally? [y/N] ", "n")).trim())) {
      throw new Error("Bicep is required. Run az bicep install after reviewing local installation, then retry.");
    }
    tool("az", ["bicep", "install", "--version", "v0.48.1", "--only-show-errors"]);
    bicep();
  }
  try { tool("zip", ["-v"]); }
  catch (error) { throw new Error(`ZIP prerequisite failed: ${redact(error.message)}. Use zip on Linux/macOS or the built-in tar.exe on Windows; Azure Cloud Shell is an alternative.`); }
  const result = { node: version, azureCli: cli["azure-cli"], bicep: "checked", archive: "checked", azureResourcesChanged: false };
  print(JSON.stringify(result, null, 2));
  return result;
}

async function subscriptions(tool, ask, print) {
  let accounts = parseJson(tool("az", ["account", "list", "--all", "--only-show-errors", "--output", "json"]), "Azure subscriptions");
  if (!Array.isArray(accounts)) throw new Error("Azure subscriptions response is not an array.");
  if (!accounts.length) {
    print("No Azure CLI sign-in is available. Sign in using Microsoft's Azure CLI; this app never asks for passwords or tokens.");
    const mode = (await ask("Sign in: [1] browser/WAM [2] device code [0] cancel [1] ", "1")).trim() || "1";
    if (!["1", "2"].includes(mode)) throw new Error("Azure sign-in cancelled; no deployment was performed.");
    tool("az", ["login", ...(mode === "2" ? ["--use-device-code"] : []), "--output", "none"], { stdio: "inherit" });
    accounts = parseJson(tool("az", ["account", "list", "--all", "--only-show-errors", "--output", "json"]), "Azure subscriptions");
  }
  if (!Array.isArray(accounts) || accounts.length > 1000 || accounts.some((item) => !UUID.test(item.id ?? "") || typeof item.name !== "string")) {
    throw new Error("Azure returned invalid or excessive subscription choices.");
  }
  const enabled = accounts.filter((item) => item.state === "Enabled");
  if (!enabled.length) throw new Error("No enabled subscription is available to this Azure CLI identity. Review sign-in/RBAC; no permission is granted automatically.");
  enabled.forEach((item, index) => print(`${index + 1}. ${JSON.stringify(item.name)} (${item.id})`));
  return enabled;
}

export async function runWizard(args, { tool = runTool, run = execute, ask, print = console.log, profileDirectory = join(ROOT, ".azure", "profiles"), suffix = () => randomBytes(3).toString("hex") } = {}) {
  const { values, positionals } = parseArgs({ args, allowPositionals: true,
    options: { profile: { type: "string" }, check: { type: "boolean", default: false }, help: { type: "boolean", default: false } } });
  if (positionals.length) throw new Error("The wizard accepts no positional commands or targets; use its fixed action menu.");
  if (values.help) {
    print("node scripts/wizard.mjs [--check] [--profile <saved-nonsecret-profile.json>]\nCore dev lab only. Node24.19+, Azure CLI2.61+, Bicep and ZIP/tar. No custom app registration, bundled CLI or local web server.");
    return { help: true };
  }
  const tools = await checkPrerequisites({ tool, ask: values.check ? undefined : ask, print });
  if (values.check) return tools;
  if (!ask) throw new Error("Interactive questions require a terminal. Use --check for a noninteractive prerequisite-only check.");
  const answer = async (message, fallback, valid) => {
    for (let attempt = 0; attempt < 3; attempt += 1) {
      const value = (await ask(`${message}${fallback !== undefined ? ` [${fallback}]` : ""}: `, fallback)).trim() || fallback;
      if (valid(value)) return value;
      print("Invalid selection; use the documented value. No action was dispatched.");
    }
    throw new Error("Too many invalid selections; no action was dispatched.");
  };
  const yes = async (message) => (await answer(`${message} y/n`, "n", (value) => /^(?:y|yes|n|no)$/i.test(value))).toLowerCase().startsWith("y");
  let profile;
  let path = values.profile && resolve(values.profile);
  if (path) profile = loadProfile(path);
  const accounts = await subscriptions(tool, ask, print);
  if (!profile) {
    const choice = await answer("Subscription number", "1", (value) => /^\d+$/.test(value) && Number(value) >= 1 && Number(value) <= accounts.length);
    const subscription = accounts[Number(choice) - 1].id;
    const location = await answer("Azure region identifier", "centralus", (value) => /^[a-z][a-z0-9]{2,31}$/.test(value));
    const selectedSuffix = await answer("Unique run suffix (4-12 lowercase letters/digits)", suffix(), (value) => /^[a-z0-9]{4,12}$/.test(value));
    const resourceGroup = await answer("New owned resource group", `NP-PHPToProof-Dev-${location}-${selectedSuffix}`, (value) => {
      try { validateConfig({ environment: "dev", resourceGroup: value, location, ttlHours: 24, phpVersion: "8.4" }); return true; }
      catch { return false; }
    });
    const ttl = await answer("Lifetime hours (metadata, NOT automatic deletion)", "24", (value) => /^(?:[1-9]|[1-6]\d|7[0-2])$/.test(value));
    const phpVersion = await answer("PHP platform branch (full patch must be verified separately)", "8.4", (value) => ["8.4", "8.5"].includes(value));
    print("Front Door Premium/WAF, Linux B1 and monitoring are billable. Log caps/expiry are not spending limits. No prices are guessed.");
    const enableDefenderCspm = await yes("Explicitly opt into billable subscription-wide Defender CloudPosture Standard? Existing plans are never disabled");
    const enableSentinel = await yes("Explicitly opt into billable Sentinel on this lab workspace");
    const enableAnalytics = enableSentinel ? await yes("Also enable the informational SYNTHETIC analytics rule (incident creation stays off)") : false;
    profile = validateProfile({ schemaVersion: 1, subscription, suffix: selectedSuffix,
      settings: { environment: "dev", resourceGroup, location, ttlHours: Number(ttl), phpVersion, customDomain: "" },
      features: { enableDefenderCspm, enableSentinel, enableAnalytics } });
    path = join(profileDirectory, `${selectedSuffix}.json`);
    mkdirSync(dirname(path), { recursive: true });
    writeFileSync(path, `${JSON.stringify(profile, null, 2)}\n`, { flag: "wx", mode: 0o600 });
    print(`Saved nonsecret run profile: ${path}. Reuse --profile for every later action; do not edit expiry or reset fixed state.`);
  }
  if (!accounts.some((item) => sameId(item.id, profile.subscription))) throw new Error("The profile's enabled subscription is not available to this identity.");
  const current = parseJson(tool("az", ["account", "show", "--only-show-errors", "--output", "json"]), "Active subscription");
  if (!sameId(current.id, profile.subscription)) {
    if (!await yes(`Change this local Azure CLI's active subscription to ${profile.subscription}`)) throw new Error("Subscription switch declined; no deployment was performed.");
    tool("az", ["account", "set", "--subscription", profile.subscription, "--only-show-errors"]);
  }
  print(`Exact dev scope: ${profile.subscription} / ${profile.settings.resourceGroup} / ${profile.suffix}. No DNS/custom domain is adopted. Private admin portal is a separate advanced deployment.`);
  print(`Saved billable opt-ins: ${JSON.stringify(profile.features)}. CSPM is subscription-wide; Sentinel/analytics are workspace-scoped. Review costs; existing plans are never disabled.`);
  const az = createAzureClient(profile, tool);
  for (;;) {
    WIZARD_ACTIONS.forEach(([id, label], index) => print(`${index + 1}. ${label} (${id})`));
    const selected = await answer("Action number", "1", (value) => /^\d+$/.test(value) && Number(value) >= 1 && Number(value) <= WIZARD_ACTIONS.length);
    const command = WIZARD_ACTIONS[Number(selected) - 1][0];
    if (command === "exit") return { status: "cancelled", profile: path, azureActionDispatched: false };
    const invocation = invocationFor(profile, command);
    if (command === "deploy" && await az(["group", "exists", "--name", invocation.resourceGroup]) !== false) {
      throw new Error("Install requires a NEW group. Use Repair for the exact saved existing run, or choose a fresh group/suffix; no group is silently adopted.");
    }
    if (PREFLIGHT.has(command)) {
      await run({ ...invocation, command: "doctor" });
      print("Review the what-if and costs above. The actual command rechecks preflight before writing.");
    }
    if (WRITES.has(command)) {
      print(command === "uninstall"
        ? "Delete ONLY this exact tagged main group. Review/remove its CNAME first; separate operator/container groups and subscription Defender plans are retained."
        : command === "remediate" ? "This removes harmless fixtures and retains Prevention, not a PHP CVE patch."
          : "Only this reviewed dev lifecycle action is allowed. No arbitrary target, shell command or automatic simulation follows installation.");
      const typed = await ask(`Type the exact group ${profile.settings.resourceGroup} to approve ${command}: `);
      if (typed !== profile.settings.resourceGroup) throw new Error("Exact group confirmation did not match; action cancelled.");
      invocation.yes = true;
      if (command === "uninstall") invocation.confirmation = typed;
    }
    const result = await run(invocation);
    print(`Finished ${command}. Preserve the actual result/UTC; an empty or missing source is not a successful detection.`);
    if (!await yes("Return to this run's action menu")) return { status: "finished", command, profile: path, result };
  }
}

export async function main(args = process.argv.slice(2)) {
  let terminal;
  try {
    if (!stdin.isTTY && !args.includes("--check") && !args.includes("--help")) throw new Error("Use an interactive terminal for the wizard, or --check for prerequisite-only validation.");
    terminal = createInterface({ input: stdin, output: stdout });
    return await runWizard(args, { ask: (question) => terminal.question(question) });
  } finally { terminal?.close(); }
}
if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  main().catch((error) => { console.error(`ERROR: ${redact(error.message)}`); process.exitCode = 1; });
}
