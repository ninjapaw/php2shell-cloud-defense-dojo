# Deploy PHP to Proof in your Azure environment

## Recommended approach

Use the **Deploy to Azure** link at the top of the story or walkthrough, then run
the reviewed **Node.js CLI wizard** locally or in Azure Cloud Shell. Bash and
PowerShell launchers call the same wizard. This is simpler to maintain and review
than signed Windows/macOS applications or an authenticated local web server.

Azure CLI already uses Microsoft's first-party application. `az login` supports
browser/WAM and device-code sign-in; no custom app registration, client secret,
username/password flag or copied token is needed. Tenant MFA/consent policy and
Azure RBAC still apply. Packaging Azure CLI inside another app does not remove
these requirements. We deliberately do not redistribute it or silently install
machine-wide software.

The hosted website only serves instructions/source. It cannot deploy into
visitors' subscriptions, never receives their Azure credentials and never lends
the demo's managed identity to a visitor.

## Scope

The simple wizard deploys the **core public dev training lab**: PHP story and
walkthrough, Front Door Premium/WAF, Linux B1, monitoring and explicitly selected
optional Defender CSPM/Sentinel settings. It is not a production deployment,
exploit or security assessment.

The private authenticated administrator portal, Key Vault/Storage/private
endpoints, raw evidence capture, tenant-wide XDR onboarding and private container
comparison remain separate advanced deployments. They have additional IAM,
networking, credential and cost requirements. They are **not** silently installed
by the core wizard. Use the full project's [operator guide](../operator/README.md)
and [container guide](container-lab.md), not a claim that these tracks ran.

Historical recordings link to the central, clearly labelled reference case,
not nonexistent or invented logs for a new customer's lab. The new deployment's
own simulator/validation results come from that deployment and its saved profile.
The central custom domain is never adopted by the wizard.

## Prerequisites

- Node **24.19 or newer on24.x**, matching this reviewed project's engine range.
  [Install Node24](https://nodejs.org/download/release/).
- [Microsoft Azure CLI](https://learn.microsoft.com/cli/azure/install-azure-cli)
  **2.61+** and an authorized user account.
- The Azure CLI Bicep component. The wizard checks it and asks before local
  `az bicep install`. Provider registration, permission grants and missing quota
  are not performed or bypassed automatically.
- `zip` on Linux/macOS, or the ZIP-capable built-in `tar.exe` on current Windows.
  No local PHP, Docker, Python, npm dependencies or Git is required to run the
  prepared core distribution.

Native Windows supports Microsoft's official MSI/ZIP CLI layout. The Node
adapter uses its bundled `python.exe -IBm azure.cli` directly, preserving
argument boundaries and avoiding `cmd.exe` string interpolation. Other CLI
layouts fail with an explicit supported-installer/WSL/Cloud Shell recommendation.
This invokes the installed CLI; it does **not** bundle or copy Azure CLI/Python.

Cloud Shell is an alternative to local tools, not a guarantee that its default
Node version matches24.x. Check prerequisites there too. Do not bypass execution
policy or private-network restrictions.

## Download and run

The deployment page offers a ZIP and its SHA-256 checksum. Verify the exact hash,
review the source, and extract to a **new** directory before executing. Never
pipe a network response into a shell. The distribution contains only reviewed
core files and licences, no `.env`, live subscription ID, credentials, private
captures, SDK `node_modules` or advanced private environment.

```powershell
Invoke-WebRequest https://php2proof.ninjapaws.org/evidence/deploy/source.zip -OutFile php2proof-deploy.zip
(Get-FileHash .\php2proof-deploy.zip -Algorithm SHA256).Hash.ToLowerInvariant()
# Compare to the published checksum before continuing:
Expand-Archive -LiteralPath .\php2proof-deploy.zip -DestinationPath .\php2proof-deploy
Set-Location .\php2proof-deploy
node .\scripts\wizard.mjs --check
node .\scripts\wizard.mjs
```

```bash
curl --fail --location --output php2proof-deploy.zip https://php2proof.ninjapaws.org/evidence/deploy/source.zip
shasum -a 256 php2proof-deploy.zip
# Compare to the published checksum before continuing:
unzip php2proof-deploy.zip -d php2proof-deploy
cd php2proof-deploy
bash scripts/start.sh --check
bash scripts/start.sh
```

Linux can use `sha256sum`. PowerShell can alternatively run
`.\scripts\start.ps1`; if policy disallows an unsigned launcher, use the direct
Node command or an approved environment rather than changing policy.
From a complete checkout the same Node command works without an npm install.

## Questions and profile

1. Check local components. `--check` never logs in or deploys.
2. Reuse Azure CLI sign-in, or explicitly select browser/WAM/device-code login.
3. Choose an enabled subscription and confirm a local active-subscription change
   if needed.
4. Choose Azure region, unique4–12-character suffix, a fresh group name,
  1–72-hour metadata lifetime and PHP8.4/8.5 branch.
5. Explicitly select any billable subscription-wide CSPM, workspace Sentinel and
   synthetic analytics opt-ins. Defaults are off; existing plans are never
   disabled. Pricing/flags alone are not proof of scanning or detection.
6. Retain the nonsecret `.azure/profiles/<suffix>.json` and reuse it:

```bash
node scripts/wizard.mjs --profile .azure/profiles/<your-suffix>.json
```

Profiles are strict validated JSON, created without overwriting existing files.
They contain no passwords, tokens, credential cache or arbitrary target. Do not
use raw default-config CLI examples for a different wizard-created group: use
the saved profile for **every** subsequent lifecycle action.

## Actions and safeguards

| Menu action | Behavior |
| --- | --- |
| Plan | Existing offline resource/cost/evidence plan |
| Doctor | Tool/provider/quota/permission checks and bounded what-if; no registration/grants |
| Install | New group only; review what-if/costs, type exact group, then guarded deployment and actual validation |
| Validate | Real routing, WAF, origin, diagnostics, identity and runtime checks |
| Simulate | Explicitly selected five harmless labelled moves; never automatic after install |
| Investigate | Actual scoped posture, not fabricated findings |
| Protect | Explicit Prevention, not a CVE patch or guaranteed detector |
| Remediate | Remove harmless fixtures, preserve Prevention; verify PHP patch separately |
| Repair | Preserve original expiry, fixed state and Prevention, no reset/downgrade |
| Uninstall | Exact tagged main group only, with exact typed confirmation |

The actual deployment rechecks preflight after approval; what-if is not a
guarantee of quota, policy, propagation or application readiness. Errors remain
errors. Review actual HTTPS output/readback, not just an ARM Succeeded status.
No arbitrary subscription/tenant deletion, URL, host, shell, query or production
override is supported.

Front Door Premium/WAF, B1, ingestion/traffic and selected optional services are
billable. No prices/free-tier guarantee are invented. The1-GB/day ingestion cap
is not a total budget. **Expiry is metadata, not automatic teardown or stopped
billing.** Uninstall before leaving the lab unused. Remove this run's CNAME
before releasing its hostname. Separate advanced groups and shared Defender
plans are retained and require their own reviewed cleanup.

## Packaging and future enhancements

`node operator/build-deploy.mjs <new-output-directory>` produces the fixed source
ZIP/manifest and four separately bounded publication overlays. The download's
two fixed transport parts are reassembled and SHA-256 verified before serving
one normal ZIP; the existing source-input limit is not raised. Existing
JavaScript core helpers are minified only in the distribution; the wizard stays
readable, file paths/entry guards remain separate, and vendored MIT attribution
is retained. The original sources are not rewritten. No Azure CLI executable or
credential is shipped.

If customer feedback later justifies a signed desktop installer/local web UI,
build it as a separate project with loopback authentication/CSRF, signing,
per-platform builds and an update process. Node SEA or other packaging still
does not remove Azure CLI/RBAC/MFA prerequisites. That is deliberately outside
this simple first version.
