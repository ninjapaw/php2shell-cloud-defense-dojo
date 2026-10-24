import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import { parseDocument } from "yaml";
import { ROOT } from "../scripts/dojo.mjs";
import { SCENARIO, SENTINEL_RULE_DISPLAY_NAME } from "../scripts/lib/config.mjs";
import { githubEnvironmentSubject } from "../vendor/pawprint/scripts/github-oidc-subject.mjs";

const workflowDirectory = join(ROOT, ".github", "workflows");
const workflows = readdirSync(workflowDirectory).filter((name) => name.endsWith(".yml"));

test("PHP to Proof branding is consistent while technical identities stay stable", () => {
  for (const file of [
    "README.md", "docs/investigation.md", "docs/operations.md",
    "docs/container-lab.md", "docs/hunting-pack.md", "docs/walkthrough.md", "detections/README.md",
  ]) {
    assert.match(readFileSync(join(ROOT, file), "utf8"), /^# PHP to Proof\b/, file);
  }
  const metadata = JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8"));
  assert.match(metadata.description, /^PHP to Proof:/);
  assert.equal(metadata.name, "php2shell-cloud-defense-dojo");
  assert.equal(SCENARIO, "php2shell-cloud-defense-dojo");
  assert.match(readFileSync(join(ROOT, "container-lab/index.php"), "utf8"),
    /<title>PHP to Proof \| Isolated runtime assessment<\/title>/);
  const sentinel = readFileSync(join(ROOT, "infra/modules/sentinel.bicep"), "utf8");
  assert.ok(sentinel.includes(`displayName: '${SENTINEL_RULE_DISPLAY_NAME}'`));
  assert.match(sentinel, /name: guid\(workspace\.id, 'php2shell-synthetic-correlation'\)/);
  const settings = JSON.parse(readFileSync(join(ROOT, "config/dev.json"), "utf8"));
  assert.equal(settings.customDomain, "php2proof.ninjapaws.org");
  assert.ok(readFileSync(join(ROOT, "README.md"), "utf8").includes(settings.customDomain));
});

test("Git preserves LF for every linted text type even on Windows checkouts", () => {
  const files = [
    "app/assets/style.css", "app/conf.d/dojo.ini", "config/dev.json",
    ".github/copilot-instructions.md", ".github/workflows/validate.yml",
    "scripts/dojo.sh", "scripts/dojo.mjs", "infra/main.bicep", "detections/correlation.kql",
  ];
  const result = spawnSync("git", ["-C", ROOT, "check-attr", "-z", "eol", "--", ...files], { encoding: "utf8" });
  assert.equal(result.status, 0, result.error?.message ?? result.stderr);
  const attributes = result.stdout.split("\0").slice(0, -1);
  assert.equal(attributes.length, files.length * 3);
  for (let index = 0; index < attributes.length; index += 3) {
    assert.equal(attributes[index + 1], "eol");
    assert.equal(attributes[index + 2], "lf", attributes[index]);
  }
});

test("all workflows are manual-only, dev-bound, pinned, and protect credentials", () => {
  assert.deepEqual(workflows.sort(), ["deploy.yml", "remediate.yml", "simulate.yml", "teardown.yml", "validate.yml"]);
  for (const name of workflows) {
    const document = parseDocument(readFileSync(join(workflowDirectory, name), "utf8"), { uniqueKeys: true });
    assert.equal(document.errors.length, 0, name);
    const workflow = document.toJS();
    assert.deepEqual(Object.keys(workflow.on), ["workflow_dispatch"], name);
    assert.deepEqual(workflow.on.workflow_dispatch.inputs.environment.options, ["dev"]);
    assert.equal(workflow.permissions.contents, "read");
    if (name !== "validate.yml") {
      assert.equal(workflow.concurrency.group, "php2shell-dev");
      assert.equal(workflow.concurrency["cancel-in-progress"], false);
    }
    for (const job of Object.values(workflow.jobs)) {
      assert.equal(job.environment, "dev");
      assert.equal(job["runs-on"], "ubuntu-24.04");
      const uses = job.steps.filter((step) => step.uses);
      assert.ok(uses.length >= 2);
      for (const step of uses) {
        assert.match(step.uses, /^[\w-]+\/[\w-]+@[a-f0-9]{40}$/, `${name}: ${step.uses}`);
        if (step.uses.startsWith("actions/checkout@")) assert.equal(step.with["persist-credentials"], false);
        if (step.uses.startsWith("azure/login@")) {
          assert.ok(!Object.hasOwn(step.with, "creds"));
          if (name === "deploy.yml") {
            assert.equal(step.with["client-id"],
              "${{ vars[inputs.action == 'domain-check' && 'AZURE_READ_CLIENT_ID' || 'AZURE_DEPLOY_CLIENT_ID'] }}",
              "A missing read identity must fail, never fall back to the deployment identity.");
          } else assert.match(step.with["client-id"], /vars\.AZURE_(DEPLOY|READ|TEARDOWN)_CLIENT_ID/);
          assert.equal(job.permissions["id-token"], "write");
          const setupIndex = job.steps.findIndex((candidate) => candidate.run?.includes("AZURE_CONFIG_DIR="));
          const loginIndex = job.steps.indexOf(step);
          assert.ok(setupIndex >= 0 && setupIndex < loginIndex, "Ephemeral config must be set before Azure login.");
          assert.match(job.steps[setupIndex].run, /"\$RUNNER_TEMP".*"\$GITHUB_ENV"/);
          assert.equal(job.env.AZURE_LOGIN_POST_CLEANUP, "true");
        }
      }
      for (const step of job.steps) {
        if (step.run) assert.doesNotMatch(step.run, /\$\{\{\s*inputs\./, "Untrusted workflow input must pass through quoted environment variables.");
      }
      if (name === "validate.yml") assert.ok(!job.permissions?.["id-token"]);
    }
  }
});

test("workflow protection checks cannot be skipped or run after Azure authentication", () => {
  for (const name of workflows) {
    const workflow = parseDocument(readFileSync(join(workflowDirectory, name), "utf8")).toJS();
    for (const job of Object.values(workflow.jobs)) {
      const guard = job.steps.findIndex((step) => step.run?.includes("scripts/check-github.mjs"));
      const node = job.steps.findIndex((step) => step.uses?.startsWith("actions/setup-node@"));
      assert.ok(guard > node && node >= 0, name);
      assert.equal(job.steps[guard].if, undefined, name);
      assert.equal(job.steps[guard].env.GITHUB_TOKEN, "${{ github.token }}");
      assert.match(job.steps[guard].run, /--environment "\$DOJO_ENV"/);
      const login = job.steps.findIndex((step) => step.uses?.startsWith("azure/login@"));
      assert.ok(login === -1 || guard < login, name);
      assert.ok(!Object.hasOwn(job.env, "GITHUB_TOKEN"), "The API token must remain step-scoped.");
    }
  }
});

test("validation explicitly covers both supported PHP branches with a pinned runtime setup", () => {
  const workflow = parseDocument(readFileSync(join(workflowDirectory, "validate.yml"), "utf8")).toJS();
  const job = workflow.jobs.validate;
  assert.deepEqual(job.strategy.matrix.php, ["8.4", "8.5"]);
  assert.equal(job.strategy["fail-fast"], false);
  const index = job.steps.findIndex((step) => step.uses?.startsWith("shivammathur/setup-php@"));
  assert.ok(index >= 0);
  assert.equal(job.steps[index].uses, "shivammathur/setup-php@eb7c497e18156a6bbabfef1d3a82760b9eda3962");
  assert.equal(job.steps[index].with["php-version"], "${{ matrix.php }}");
  assert.equal(job.steps[index].with.coverage, "none");
  assert.equal(job.steps[index].with.tools, "none");
  assert.ok(index > job.steps.findIndex((step) => step.run?.includes("scripts/check-github.mjs")));
  assert.ok(index < job.steps.findIndex((step) => step.run?.includes("npm test")));
});

test("simulation has no target input, and teardown passes typed confirmation without a bypass", () => {
  const simulation = parseDocument(readFileSync(join(workflowDirectory, "simulate.yml"), "utf8")).toJS();
  assert.deepEqual(Object.keys(simulation.on.workflow_dispatch.inputs), ["environment"]);
  const teardown = parseDocument(readFileSync(join(workflowDirectory, "teardown.yml"), "utf8")).toJS();
  assert.equal(teardown.on.workflow_dispatch.inputs.resource_group_confirmation.required, true);
  assert.match(teardown.jobs.teardown.steps.at(-1).run, /--confirm-resource-group "\$CONFIRMED_RG"/);
  assert.doesNotMatch(teardown.jobs.teardown.steps.at(-1).run, /--yes/);
});

test("hunting queries declare optional sources, typed empty fallback, labels, and investigation pivots", () => {
  const files = readdirSync(join(ROOT, "detections")).filter((name) => name.endsWith(".kql"));
  assert.equal(files.length, 6);
  for (const name of files) {
    const query = readFileSync(join(ROOT, "detections", name), "utf8");
    assert.match(query, /^\/\/ /);
    assert.match(query, /datatable\(TimeGenerated:datetime\)\[\]/);
    assert.match(query, /union isfuzzy=true/);
    assert.match(query, /RunId/);
    assert.match(query, /ResourceId/);
    assert.match(query, /TimeGenerated/);
    assert.match(query, /synthetic|benign-input/);
    assert.doesNotMatch(query, /\bexternaldata\b|evaluate\s+(?:python|r)\b/i);
  }
  const correlation = readFileSync(join(ROOT, "detections", "correlation.kql"), "utf8");
  assert.match(correlation, /__APP_RESOURCE_ID__/);
  assert.match(correlation, /array_length\(SyntheticSignals\) >= 2/);
  assert.match(correlation, /join kind=inner Waf on RunId/);
  assert.match(correlation, /not-compromise/);
});

test("OIDC subject uses Pawprint's exact ID-qualified environment convention", () => {
  assert.equal(githubEnvironmentSubject({
    owner: { login: "ninjapaw", id: 1234 }, name: "php2shell-cloud-defense-dojo", id: 5678,
  }, "dev"), "repo:ninjapaw@1234/php2shell-cloud-defense-dojo@5678:environment:dev");
  assert.throws(() => githubEnvironmentSubject({ owner: { login: "ninjapaw" } }, "dev"));
});

test("documentation preserves safety, costs, CVE caveats, teardown and the license placeholder", () => {
  const readme = readFileSync(join(ROOT, "README.md"), "utf8");
  for (const text of ["TRAINING ONLY", "Independent community", "CloudPosture", "billable", "CVE-2026-109618",
    "CVE-2026-109619", "No fixed completion time", "--confirm-resource-group", "no runtime role", "synthetic"]) {
    assert.ok(readme.toLowerCase().includes(text.toLowerCase()), text);
  }
  assert.match(readFileSync(join(ROOT, "LICENSE"), "utf8"), /PLACEHOLDER/);
  assert.match(readFileSync(join(ROOT, "vendor", "pawprint", "LICENSE"), "utf8"), /MIT License/);
  assert.match(readFileSync(join(ROOT, ".github", "copilot-instructions.md"), "utf8"), /Never invent CVE coverage/);
});
