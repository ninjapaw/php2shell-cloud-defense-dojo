import assert from "node:assert/strict";
import test from "node:test";
import { checkGitHubEnvironment } from "../scripts/check-github.mjs";

const repository = "ninjapaw/php2shell-cloud-defense-dojo";
const metadata = { id: 42, name: "php2shell-cloud-defense-dojo", owner: { login: "ninjapaw", id: 7 } };
const environment = {
  id: 11, name: "dev",
  protection_rules: [{
    type: "required_reviewers", prevent_self_review: true,
    reviewers: [{ type: "User", reviewer: { id: 19, login: "fixture-reviewer-not-for-output" } }],
  }],
  deployment_branch_policy: { protected_branches: true, custom_branch_policies: false },
};

function fixture({ repo = metadata, settings = environment, policies, status = 200, invalidJson = false } = {}) {
  const calls = [];
  return {
    calls,
    fetchImpl: async (url, options) => {
      calls.push({ url, options });
      const parsed = new URL(url);
      assert.equal(parsed.origin, "https://api.github.com");
      assert.ok(parsed.pathname.startsWith(`/repos/${repository}`));
      assert.equal(options.method, "GET");
      assert.equal(options.body, undefined);
      assert.equal(options.redirect, "manual");
      assert.ok(options.signal instanceof AbortSignal);
      if (status !== 200) return Response.json({ message: "private-response-never-print" }, { status });
      if (invalidJson) return new Response("private-invalid-json");
      if (parsed.pathname.endsWith("/deployment-branch-policies")) return Response.json(policies);
      if (parsed.pathname.endsWith("/environments/dev")) {
        return settings === null ? Response.json({ message: "missing-or-hidden" }, { status: 404 }) : Response.json(settings);
      }
      return Response.json(repo);
    },
  };
}

test("GitHub readiness is bounded/read-only and uses real IDs only for a labelled OIDC candidate", async () => {
  const h = fixture();
  const token = "fixture-token-never-print";
  const result = await checkGitHubEnvironment({ repository, token }, h);
  assert.equal(result.ready, true);
  assert.equal(result.oidcSubjectCandidate, "repo:ninjapaw@7/php2shell-cloud-defense-dojo@42:environment:dev");
  assert.ok(Number.isFinite(Date.parse(result.observedAt)));
  assert.ok(result.checks.every((check) => check.status === "configured"));
  assert.equal(h.calls.length, 2);
  assert.ok(h.calls.every((call) => call.options.headers.Authorization === `Bearer ${token}`));
  assert.doesNotMatch(JSON.stringify(result), /fixture-token|fixture-reviewer/);
  assert.match(result.boundary, /No settings, credentials or Azure resources were changed/);
  assert.match(result.boundary, /remain unverified/);
});

test("an unavailable dev environment is explicit non-readiness, never a fabricated setup success", async () => {
  const h = fixture({ settings: null });
  const result = await checkGitHubEnvironment({ repository }, h);
  assert.equal(result.ready, false);
  assert.equal(result.checks[0].status, "unavailable");
  assert.match(result.checks[0].detail, /not found or is not readable/);
  assert.equal(h.calls.length, 2);
  assert.ok(h.calls.every((call) => !Object.hasOwn(call.options.headers, "Authorization")));
});

test("missing, ambiguous or malformed reviewers and missing self-review prevention cannot pass", async () => {
  for (const mutate of [
    (value) => { value.protection_rules = []; },
    (value) => { value.protection_rules.push(structuredClone(value.protection_rules[0])); },
    (value) => { value.protection_rules[0].reviewers = []; },
    (value) => { value.protection_rules[0].reviewers = [{ type: "User", reviewer: {} }]; },
    (value) => { value.protection_rules[0].prevent_self_review = false; },
    (value) => { delete value.protection_rules[0].prevent_self_review; },
  ]) {
    const settings = structuredClone(environment);
    mutate(settings);
    assert.equal((await checkGitHubEnvironment({ repository }, fixture({ settings }))).ready, false);
  }
});

test("explicit custom deployment patterns are verified without implementing a different wildcard matcher", async () => {
  const settings = {
    ...environment, deployment_branch_policy: { protected_branches: false, custom_branch_policies: true },
  };
  for (const name of ["dev", "release/*"]) {
    const h = fixture({ settings, policies: { total_count: 1, branch_policies: [{ id: 1, name, type: "branch" }] } });
    assert.equal((await checkGitHubEnvironment({ repository }, h)).ready, true);
    assert.equal(h.calls.length, 3);
    assert.match(h.calls[2].url, /per_page=100$/);
  }
  const fullPage = Array.from({ length: 100 }, (_, index) => ({ name: `dev-${index}`, type: "branch" }));
  assert.equal((await checkGitHubEnvironment({ repository },
    fixture({ settings, policies: { total_count: 100, branch_policies: fullPage } }))).ready, true);
  assert.equal((await checkGitHubEnvironment({ repository },
    fixture({ settings, policies: { total_count: 101, branch_policies: [...fullPage, { name: "dev-extra", type: "branch" }] } }))).ready, false);
  for (const policies of [
    { total_count: 0, branch_policies: [] },
    { total_count: 1, branch_policies: [] },
    { total_count: 101, branch_policies: [{ name: "dev", type: "branch" }] },
    { total_count: 1, branch_policies: [{ name: "*", type: "branch" }] },
    { total_count: 1, branch_policies: [{ name: "**", type: "tag" }] },
  ]) {
    const result = await checkGitHubEnvironment({ repository }, fixture({ settings, policies }));
    assert.equal(result.ready, false);
    assert.equal(result.checks.find((check) => check.id === "deployment-branches").status, "not-configured");
  }
  const invalid = fixture({ settings, policies: { total_count: 1, branch_policies: [{ name: "dev", type: "unknown" }] } });
  await assert.rejects(checkGitHubEnvironment({ repository }, invalid), /metadata is invalid/);
});

test("unrestricted and contradictory deployment-branch settings are not ready", async () => {
  for (const policy of [null, { protected_branches: false, custom_branch_policies: false },
    { protected_branches: true, custom_branch_policies: true }, { custom_branch_policies: true }]) {
    const result = await checkGitHubEnvironment({ repository },
      fixture({ settings: { ...environment, deployment_branch_policy: policy } }));
    assert.equal(result.ready, false);
  }
});

test("GitHub errors, malformed metadata and invalid inputs fail without echoing credentials or responses", async () => {
  for (const status of [401, 403, 404, 429, 500]) {
    await assert.rejects(checkGitHubEnvironment({ repository }, fixture({ status })), (error) => {
      assert.match(error.message, new RegExp(`HTTP ${status}`));
      assert.doesNotMatch(error.message, /private-response/);
      return true;
    });
  }
  await assert.rejects(checkGitHubEnvironment({ repository }, fixture({ invalidJson: true })), /contents omitted/);
  for (const repo of [{ ...metadata, id: 0 }, { ...metadata, owner: { ...metadata.owner, login: "different-owner" } }]) {
    await assert.rejects(checkGitHubEnvironment({ repository }, fixture({ repo })), /identity/);
  }
  await assert.rejects(checkGitHubEnvironment({ repository }, fixture({ settings: { ...environment, name: "production" } })), /metadata is invalid/);
  for (const options of [
    { repository: "https://example.invalid" }, { repository: "../other" },
    { repository, environment: "prod" }, { repository, token: "private\nvalue" },
    { repository, token: "private\u0000value" },
  ]) {
    let calls = 0;
    await assert.rejects(checkGitHubEnvironment(options, { fetchImpl: async () => { calls += 1; } }));
    assert.equal(calls, 0);
  }
});
