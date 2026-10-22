#!/usr/bin/env node
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { parseArgs } from "node:util";
import { SCENARIO } from "./lib/config.mjs";
import { redact, request } from "./lib/safety.mjs";
import { githubEnvironmentSubject } from "../vendor/pawprint/scripts/github-oidc-subject.mjs";

export async function checkGitHubEnvironment({ repository, environment = "dev", token }, { fetchImpl = fetch } = {}) {
  if (typeof repository !== "string" || !/^[a-z0-9][a-z0-9-]{0,38}\/[a-z0-9][a-z0-9._-]{0,99}$/i.test(repository)) {
    throw new Error("Supply a GitHub owner/repository name, not a URL or arbitrary target.");
  }
  if (environment !== "dev") throw new Error("Only the dev GitHub Environment is supported.");
  if (token !== undefined && (typeof token !== "string" || token.length > 2048 || /[^\x21-\x7e]/.test(token))) {
    throw new Error("GITHUB_TOKEN must be an environment-provided token without whitespace; contents omitted.");
  }
  const headers = {
    Accept: "application/vnd.github+json",
    "X-GitHub-Api-Version": "2026-03-10",
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
  };
  async function get(path, allowUnavailable = false) {
    const response = await request(`https://api.github.com${path}`, { headers, fetchImpl });
    if (allowUnavailable && response.status === 404) return undefined;
    if (response.status !== 200) {
      throw new Error(`GitHub configuration read failed (HTTP ${response.status}). Verify repository/environment read access; response contents omitted.`);
    }
    try {
      return JSON.parse(response.text);
    } catch (error) {
      if (error instanceof SyntaxError) throw new Error("GitHub configuration response was not valid JSON; contents omitted.");
      throw error;
    }
  }
  const [owner, name] = repository.split("/");
  const metadata = await get(`/repos/${repository}`);
  if (!Number.isSafeInteger(metadata?.id) || metadata.id <= 0
      || !Number.isSafeInteger(metadata.owner?.id) || metadata.owner.id <= 0
      || typeof metadata.owner.login !== "string" || metadata.owner.login.toLowerCase() !== owner.toLowerCase()
      || typeof metadata.name !== "string" || metadata.name.toLowerCase() !== name.toLowerCase()) {
    throw new Error("GitHub repository identity does not match the requested repository.");
  }
  const report = {
    repository: `${metadata.owner.login}/${metadata.name}`, environment,
    observedAt: new Date().toISOString(), ready: false, checks: [],
    oidcSubjectCandidate: githubEnvironmentSubject(metadata, environment),
    boundary: "Read-only GitHub configuration check. No settings, credentials or Azure resources were changed; OIDC federation, Azure permissions and live telemetry remain unverified.",
    oidcNote: "The candidate uses Pawprint's ID-qualified convention. Verify the actual organization subject customization and Entra federation separately.",
  };
  const settings = await get(`/repos/${repository}/environments/${environment}`, true);
  if (!settings) {
    report.checks.push({
      id: "environment", status: "unavailable",
      detail: "The dev environment was not found or is not readable. Configure its required reviewers, self-review prevention and branch restrictions before dispatch.",
    });
    return report;
  }
  if (settings.name !== environment || !Number.isSafeInteger(settings.id) || settings.id <= 0
      || !Array.isArray(settings.protection_rules)) {
    throw new Error("GitHub environment identity/protection metadata is invalid or incomplete.");
  }
  report.checks.push({ id: "environment", status: "configured", detail: "The exact dev environment is readable." });
  const rules = settings.protection_rules.filter((rule) => rule?.type === "required_reviewers");
  const reviewers = rules.length === 1 ? rules[0].reviewers : undefined;
  const hasReviewers = Array.isArray(reviewers) && reviewers.length > 0
    && reviewers.every((entry) => ["User", "Team"].includes(entry?.type)
      && Number.isSafeInteger(entry.reviewer?.id) && entry.reviewer.id > 0);
  report.checks.push({
    id: "required-reviewers", status: hasReviewers ? "configured" : "not-configured",
    detail: hasReviewers ? `${reviewers.length} reviewer entries configured; identities are not printed.`
      : "Exactly one unambiguous required-reviewers rule with actual User/Team entries is required.",
  });
  const preventsSelfReview = rules.length === 1 && rules[0].prevent_self_review === true;
  report.checks.push({
    id: "prevent-self-review", status: preventsSelfReview ? "configured" : "not-configured",
    detail: preventsSelfReview ? "Self-review prevention is enabled." : "Self-review prevention must be explicitly enabled.",
  });
  const policy = settings.deployment_branch_policy;
  if (policy?.protected_branches === true && policy.custom_branch_policies === false) {
    report.checks.push({
      id: "deployment-branches", status: "configured",
      detail: "Deployments are restricted to protected branches; GitHub must enforce the selected ref's branch protection.",
    });
  } else if (policy?.protected_branches === false && policy.custom_branch_policies === true) {
    const response = await get(`/repos/${repository}/environments/${environment}/deployment-branch-policies?per_page=100`);
    if (!Number.isSafeInteger(response?.total_count) || response.total_count < 0 || !Array.isArray(response.branch_policies)
        || response.branch_policies.some((entry) => typeof entry?.name !== "string" || !entry.name.trim()
          || !["branch", "tag"].includes(entry.type))) {
      throw new Error("GitHub deployment-branch policy metadata is invalid.");
    }
    const complete = response.total_count <= 100 && response.total_count === response.branch_policies.length;
    const restricted = complete && response.total_count > 0
      && response.branch_policies.every((entry) => !["*", "**"].includes(entry.name));
    report.checks.push({
      id: "deployment-branches", status: restricted ? "configured" : "not-configured",
      detail: !complete ? "Branch-policy results exceed the bounded page or are incomplete; restrictions were not verified."
        : restricted ? `${response.total_count} explicit branch/tag patterns configured; GitHub enforces matching.`
          : "Configure explicit branch/tag restrictions; an empty list or blanket wildcard does not pass.",
    });
  } else {
    report.checks.push({
      id: "deployment-branches", status: "not-configured",
      detail: "Select protected branches or explicit custom deployment branches/tags; unrestricted or ambiguous settings do not pass.",
    });
  }
  report.ready = report.checks.every((check) => check.status === "configured");
  return report;
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try {
    const { values } = parseArgs({
      allowPositionals: false,
      options: { repository: { type: "string" }, environment: { type: "string", default: "dev" } },
    });
    const report = await checkGitHubEnvironment({
      repository: values.repository ?? process.env.GITHUB_REPOSITORY ?? `ninjapaw/${SCENARIO}`,
      environment: values.environment, token: process.env.GITHUB_TOKEN,
    });
    console.log(JSON.stringify(report, null, 2));
    process.exitCode = report.ready ? 0 : 1;
  } catch (error) {
    console.error(`ERROR: ${redact(error.message)}`);
    process.exitCode = 1;
  }
}
