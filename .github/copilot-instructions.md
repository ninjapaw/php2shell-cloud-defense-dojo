# PHP2Shell Cloud Defense Dojo

This is an independent, disposable **defensive training lab**, not an exploit
toolkit or a production deployment. Read [README.md](../README.md),
[DISCLAIMER.md](../DISCLAIMER.md), and [the safety boundaries](../docs/operations.md)
before changing the scenario.

## Non-negotiable boundaries

- Support only `--environment dev`; reject production and unknown environments.
- Never add command execution, an exploit, arbitrary-target simulation, real
  sensitive data, or unlabelled synthetic evidence.
- Keep the simulator bounded and derive its HTTPS endpoint from independently
  verified live Azure resources. Never accept a URL, host, or IP override.
- Only the exact tagged scenario resource group may be uninstalled, after exact
  typed confirmation. Never delete at subscription or tenant scope.
- Defender `CloudPosture` Standard is an explicit billable subscription-wide
  choice. Omission and teardown must not change an existing pricing plan.
- Keep Sentinel opt-in. No automatic simulation on push, PR, or schedule.
- Start WAF in Detection. Prevention is a separate explicit step. Test the
  origin directly, including a copied Front Door header; failure to receive
  HTTP 403 is a validation failure.
- No secrets in source, outputs, logs, or reports. The initial app needs none.
  Use managed identity and Key Vault references if secrets become necessary.
- Never invent CVE coverage, Defender findings, screenshots, runtime events,
  ingestion completion times, prices, or a successful deployment validation.

## Architecture and changes

Use small Bicep modules. Shared infrastructure belongs in Pawprint and is
vendored with provenance and drift checks, not edited under `vendor/`.
Preserve expiry metadata and fixed/Prevention state during repair. The app's
managed identity has no role grants; do not add broad permissions for a demo.

Use `plan -> doctor/what-if -> deploy -> validate -> simulate -> investigate ->
protect -> remediate -> validate -> uninstall`. Describe resource-group,
subscription-wide, security, and cost effects before implementation.

Use Bash with `set -euo pipefail` for wrappers and Node's existing shared helpers
for validation and lifecycle orchestration. Add Pester coverage if PowerShell
scripts are introduced. Keep errors explicit and redact Azure diagnostics.

## Verification and documentation

Run `npm ci`, `npm run lint`, `npm test`, `npm run vendor:check`, ShellCheck,
and `az bicep build`/lint as applicable. Add tests for configuration, target
validation, redirects, safety bounds, confirmation and deletion scope, redaction,
and preservation of remedied state. See the manual validation workflow.

Update the operator guides when behavior changes. Distinguish real WAF records,
synthetic application logs, optional workload telemetry, and actual Defender
assessments. Missing telemetry is not a finding or proof of safety.
