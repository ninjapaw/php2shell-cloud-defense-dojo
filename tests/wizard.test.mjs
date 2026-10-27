import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { WIZARD_ACTIONS, checkPrerequisites, invocationFor, runWizard, validateProfile } from "../scripts/wizard.mjs";
import { parseInvocation } from "../scripts/lib/config.mjs";

const subscription = "11111111-1111-4111-8111-111111111111";
const profile = () => ({
  schemaVersion: 1, subscription, suffix: "wizard42",
  settings: { environment: "dev", resourceGroup: "NP-PHPToProof-Dev-centralus-wizard42", location: "centralus", ttlHours: 24, phpVersion: "8.4", customDomain: "" },
  features: { enableDefenderCspm: false, enableSentinel: false, enableAnalytics: false },
});
function harness(t, { exists = false, signedIn = true } = {}) {
  const directory = mkdtempSync(join(tmpdir(), "php2proof-wizard-"));
  t.after(() => rmSync(directory, { recursive: true }));
  const path = join(directory, "profile.json");
  writeFileSync(path, JSON.stringify(profile()));
  const calls = [];
  const runs = [];
  const logs = [];
  let signed = signedIn;
  const tool = (command, args, options) => {
    calls.push({ command, args, options });
    if (command === "zip") return "archive tool";
    if (command !== "az") throw new Error("Unexpected tool");
    if (args[0] === "version") return '{"azure-cli":"2.91.0"}';
    if (args[0] === "bicep") return "Bicep CLI version 0.48.1";
    if (args[0] === "login") { signed = true; return ""; }
    if (args[0] === "account" && args[1] === "list") return JSON.stringify(signed ? [{ id: subscription, state: "Enabled", name: "Unit-owned subscription" }] : []);
    if (args[0] === "account" && args[1] === "show") return JSON.stringify({ id: subscription });
    if (args[0] === "group" && args[1] === "exists") return JSON.stringify(exists);
    throw new Error(`Unlisted tool request: ${args.slice(0, 2).join(" ")}`);
  };
  const run = async (invocation) => { runs.push(structuredClone(invocation)); return { actualTestResult: true }; };
  const questions = [];
  const ask = (answers) => async (question) => {
    questions.push(question);
    assert.ok(answers.length, `Unexpected question: ${question}`);
    return answers.shift();
  };
  return { directory, path, calls, runs, logs, tool, run, questions, ask, print: (message) => logs.push(message) };
}

test("prerequisite-only check never signs in or dispatches Azure resources", async (t) => {
  const h = harness(t);
  const result = await runWizard(["--check"], h);
  assert.equal(result.azureResourcesChanged, false);
  assert.equal(h.runs.length, 0);
  assert.equal(h.calls.some((call) => call.args[0] === "account" || call.args[0] === "login"), false);
  await assert.rejects(() => checkPrerequisites({ version: "26.0.0", tool: h.tool, print: h.print }), /Node24/);
  await assert.rejects(() => checkPrerequisites({ tool: () => { throw new Error("missing tool"); }, print: h.print }), /Azure CLI prerequisite failed/);
});
test("profiles reject production, secrets, unknown keys, DNS adoption and invalid paid opt-ins", () => {
  assert.equal(validateProfile(profile()).settings.customDomain, "");
  for (const value of [
    { ...profile(), password: "not allowed" },
    { ...profile(), settings: { ...profile().settings, environment: "prod" } },
    { ...profile(), settings: { ...profile().settings, customDomain: "php2proof.ninjapaws.org" } },
    { ...profile(), features: { ...profile().features, enableAnalytics: true } },
    { ...profile(), suffix: "../bad" },
  ]) assert.throws(() => validateProfile(value));
  assert.throws(() => invocationFor(profile(), "arbitrary command"), /fixed wizard/);
});
test("wizard opt-ins reach only the commands the CLI allows", () => {
  const billable = { ...profile(), features: { enableDefenderCspm: true, enableSentinel: true, enableAnalytics: true } };
  const optIns = (invocation) => [invocation.enableDefenderCspm, invocation.enableSentinel, invocation.enableAnalytics];
  for (const command of ["plan", "doctor", "deploy", "repair", "protect", "remediate"]) {
    assert.deepEqual(optIns(invocationFor(billable, command)), [true, true, true], command);
  }
  for (const command of ["validate", "simulate", "investigate", "uninstall"]) {
    assert.deepEqual(optIns(invocationFor(billable, command)), [false, false, false], command);
  }
});
test("wizard billable opt-ins agree with the CLI guard for every action", () => {
  const billable = { ...profile(), features: { enableDefenderCspm: true, enableSentinel: true, enableAnalytics: true } };
  for (const [command] of WIZARD_ACTIONS.filter(([id]) => id !== "exit")) {
    let cliAccepts = true;
    try {
      parseInvocation([command, "--subscription", subscription, "--suffix", "wizard42", "--environment", "dev", "--enable-sentinel"], profile().settings, {});
    } catch (error) {
      if (!/Billable deployment opt-ins/.test(error.message)) throw error;
      cliAccepts = false;
    }
    assert.equal(invocationFor(billable, command).enableSentinel, cliAccepts, command);
  }
});
test("missing or old Bicep installs only after explicit local-component approval", async (t) => {
  const h = harness(t);
  let installed = false;
  const tool = (command, args, options) => {
    if (command === "az" && args[0] === "bicep") {
      if (args[1] === "install") {
        assert.deepEqual(args, ["bicep", "install", "--version", "v0.48.1", "--only-show-errors"]);
        installed = true;
        return "";
      }
      return installed ? "Bicep CLI version 0.48.1" : "Bicep CLI version 0.30.0";
    }
    return h.tool(command, args, options);
  };
  await assert.rejects(() => checkPrerequisites({ tool, print: h.print }), /Bicep is required/);
  assert.equal(installed, false);
  await checkPrerequisites({ tool, print: h.print, ask: async () => "yes" });
  assert.equal(installed, true);
});
test("new profile asks essential questions, defaults paid options off and runs only the selected plan", async (t) => {
  const h = harness(t);
  const answers = ["1", "", "", "", "", "", "", "", "1", "n"];
  const result = await runWizard([], { ...h, ask: h.ask(answers), profileDirectory: h.directory, suffix: () => "fresh42" });
  assert.equal(result.command, "plan");
  const saved = JSON.parse(readFileSync(join(h.directory, "fresh42.json"), "utf8"));
  assert.equal(saved.settings.resourceGroup, "NP-PHPToProof-Dev-centralus-fresh42");
  assert.equal(saved.settings.customDomain, "");
  assert.equal(Object.values(saved.features).some(Boolean), false);
  assert.equal(h.runs.length, 1);
  assert.equal(h.runs[0].yes, false);
  assert.equal(h.calls.some((call) => call.args.slice(0, 2).join(" ") === "group delete"), false);
  assert.doesNotMatch(JSON.stringify(saved), /password|secret|token|clientId/i);
});
test("install reviews doctor then requires exact group confirmation and never auto-simulates", async (t) => {
  const h = harness(t);
  await runWizard(["--profile", h.path], { ...h, ask: h.ask(["3", profile().settings.resourceGroup, "n"]) });
  assert.deepEqual(h.runs.map((run) => run.command), ["doctor", "deploy"]);
  assert.equal(h.runs[1].yes, true);
  assert.equal(h.runs[1].resourceGroup, profile().settings.resourceGroup);
  assert.equal(h.runs.some((run) => run.command === "simulate"), false);
});
test("wrong write confirmation and pre-existing install group stop before deployment", async (t) => {
  const h = harness(t);
  await assert.rejects(() => runWizard(["--profile", h.path], { ...h, ask: h.ask(["3", "wrong-group"]) }), /did not match/);
  assert.deepEqual(h.runs.map((run) => run.command), ["doctor"]);
  const existing = harness(t, { exists: true });
  await assert.rejects(() => runWizard(["--profile", existing.path], { ...existing, ask: existing.ask(["3"]) }), /NEW group/);
  assert.equal(existing.runs.length, 0);
});
test("repair and uninstall reuse the exact saved dev scope and keep paid defaults unchanged", async (t) => {
  for (const [selection, action] of [["9", "repair"], ["10", "uninstall"]]) {
    const h = harness(t, { exists: true });
    await runWizard(["--profile", h.path], { ...h, ask: h.ask([selection, profile().settings.resourceGroup, "n"]) });
    const actual = h.runs.at(-1);
    assert.equal(actual.command, action);
    assert.equal(actual.environment, "dev");
    assert.equal(actual.resourceGroup, profile().settings.resourceGroup);
    assert.equal(actual.enableDefenderCspm, false);
    if (action === "uninstall") assert.equal(actual.confirmation, actual.resourceGroup);
  }
});
test("Azure CLI login is explicitly selected and never takes passwords, secrets or custom app IDs", async (t) => {
  const h = harness(t, { signedIn: false });
  await runWizard(["--profile", h.path], { ...h, ask: h.ask(["2", "11"]) });
  const login = h.calls.find((call) => call.args[0] === "login");
  assert.deepEqual(login.args, ["login", "--use-device-code", "--output", "none"]);
  assert.equal(login.options.stdio, "inherit");
  assert.equal(h.runs.length, 0);
});
test("unknown command/target and invalid selections fail explicitly rather than dispatching", async (t) => {
  const h = harness(t);
  await assert.rejects(() => runWizard(["--target", "https://unowned.invalid"], h), /Unknown option/);
  assert.equal(h.calls.length, 0);
  await assert.rejects(() => runWizard(["--profile", h.path], { ...h, ask: h.ask(["bad", "0", "99"]) }), /invalid selections/);
  assert.equal(h.runs.length, 0);
  assert.equal(h.logs.filter((message) => message.includes("Invalid selection")).length, 3);
});
