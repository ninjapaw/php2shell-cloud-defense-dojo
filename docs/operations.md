# PHP to Proof: operations, permissions, and cost controls

## Deployment contract

Only `--environment dev` is accepted. The suffix is 4-12 lowercase letters/digits.
There is no production override, arbitrary target, CLI resource-group override,
or secret flag. Azure operations require the active subscription to exactly match
the explicit UUID and require the public `AzureCloud` cloud.

The required `resourceGroup` in [dev configuration](../config/dev.json) is the
authoritative main-lab group name: `NP-PHPToProof-Dev-CentralUS`. It follows
`NP-<Workload>-<Environment>-<Region>`, as in the other project configurations.
The CLI passes that exact name into Bicep and scopes resources, what-if,
validation, and teardown to it, apart from the explicit optional subscription
`CloudPosture` Standard pricing resource.
An existing group must already carry the exact scenario ownership tags; it is
never silently adopted. Do not precreate an untagged group with the same name.
Boolean ownership tags are emitted as literal lowercase `true`/`false` strings;
ARM's boolean-to-string casing must not make repair or teardown reject the group.

Changing `resourceGroup` does not migrate or rename Azure resources. Keep its
original value, location, subscription and suffix for repair or uninstall.
For a legacy deployment, explicitly set its original `rg-p2s-SUFFIX-dev` name
in JSON; there is no silent legacy fallback. To start a different isolated run,
select a separate group name and suffix together. A suffix alone no longer
selects another group. Update the region label when changing location.
The subscription deployment record is named `php2shell-SUFFIX-dev`. Azure pins
that name to its original metadata location, independently of the workload.
For a new regional run, use a fresh suffix as well as the matching group name;
reusing an old name at another location causes `InvalidDeploymentLocation`.
The separate private container comparison is not configured by this setting
and retains its existing `rg-p2sc-SUFFIX-dev` naming.

`plan` is offline. `doctor` only reads tools, Azure configuration, permissions,
provider registration, B1 region/runtime availability and subscription Bicep
what-if. It never registers providers, changes the active account, installs a
plan, or deploys. Workload capacity/quotas, policy, role propagation, DNS and WAF
propagation can still fail later and are never silently ignored.
A zero B1 VM quota requires a quota increase or an explicitly reviewed region
change with a matching group name; do not silently upgrade the SKU or widen roles.

### Optional Azure-hosted deployment runner

The [local wizard](deployment.md) supports native Windows with the official
MSI/ZIP Azure CLI layout, plus Linux/macOS. It never interpolates `az.cmd` through
a shell; the helper is loaded only on Windows. Azure-hosted Linux source bundles
need no Windows-only helper.

When supported local CLI access is unavailable, the reviewed
[runner stack](../infra/deploy-runner.bicep) can run the same guarded CLI in a
digest-pinned, outbound-only Azure container. It is an explicit billable
operator operation, not an application runtime or a bypass of doctor/what-if.

`npm run cloud:bundle -- <new-output-file>` creates a checksum-pinned, allowlisted
source bundle. `cloudContext()` supplies protected input chunks for the job's
secure-object `sourceBundle` parameter. Each chunk is at most 8,000 characters;
the encoded bundle must fit a 60 KiB budget and is never silently truncated.
ACI uses secure environment values and verifies the checksum before extraction.
No source storage endpoint, SAS, password, or copied CLI token is needed.
Clients with request-size limits can stage source data (never credentials)
through [protected module outputs](../infra/deploy-runner-source.bicep) and
consume them with ARM `listOutputsWithSecureValues`. Keep every staging record
in the invocation's helper group; ordinary plaintext outputs are not permitted.
An immutable baseline may carry separately checksummed, protected overlays for
`scripts/lib/azure.mjs`, `infra/main.bicep`, and `config/dev.json` only. At most one
overlay per allowed path is accepted. The combined protected inputs remain within
the 60 KiB budget.
Run `npm run cloud:verify -- <compiled-job.json>` before deployment; it rejects
stale embedded startup text, public ingress, unbounded compute, and unprotected
source inputs. CI performs this check against a freshly compiled job.

Prepare the stack with `startRunner=false` and an empty protected
`sourceBundle` object containing `chunks: []`, then run the reviewed job module.
`deploy` always runs doctor/what-if before writing workload resources.
If doctor identifies unregistered Front Door support, explicitly approve
`registerCdn=true` for the temporary operator and `registrationProvider=Microsoft.Cdn`
for the job. Omission never registers providers or changes security pricing.
The temporary identity has Contributor only at the
configured main group, narrowly enumerated subscription deployment/metadata
actions. There are no source-account data-role grants. The app identity still
has no role grants. Redacted, output-only deployment records preserve actual
success/failure results; a missing report is not success.
CLI failures identify the command family without printing its parameter values
or retaining an unredacted exception cause.
The CLI adapter maps `webapp show`'s `appServicePlanId` to the ARM
`serverFarmId` name used by lifecycle checks; invalid or conflicting IDs fail.

Use a dedicated temporary group. The main group must be an existing, correctly
tagged resource, never a stack-managed group. Before cleanup, verify the stack's
managed-resource inventory against its invocation and exact helper/role IDs.
Remove helper resources and assignments first, retaining the custom role and
empty helper group; then remove those two remaining resources. Never perform
unscoped deletion, use Complete deployment mode, or delete the main group.

### Optional external DNS boundary

The configured public story hostname is `php2proof.ninjapaws.org` in the
Cloudflare zone `ninjapaws.org`. See the [Cloudflare record reference](../README.md#optional-cloudflare-custom-domain)
for the CNAME/TXT records and the distinction between the safe public dashboard
and the private affected-runtime comparison.

`domain --yes` is the only command that activates custom-domain intent.
Use an explicitly authorized Cloudflare subdomain and keep DNS-only routing
with CNAME flattening off. `DOJO_CUSTOM_DOMAIN`, `--custom-domain` on
plan/domain/domain-check, or the optional `customDomain` configuration supplies
intent, never a simulation target.

The Cloudflare token stays in `CLOUDFLARE_API_TOKEN` with Zone Read and DNS Edit
for the exact active zone selected by `CLOUDFLARE_ZONE_NAME` or
`CLOUDFLARE_ZONE_ID`. If both identifiers are set, they must match. No token
argument, file, Bicep parameter, deployment output, or diagnostic body is used.
Zone-wide token capability is still broader than a record: protect the GitHub
Environment and do not grant unrelated repositories that credential.

The explicit domain action preserves the existing lab state, original expiry,
Defender expectation, and Sentinel opt-ins. It performs bounded what-if before
each Bicep phase: pending managed-TLS domain, then validated route/WAF
association. It never adds DNS to the restricted origin or changes Cloudflare
zone, account, proxy, mail, or shared records.

New records carry ownership for this repository, dev environment, and suffix.
Only that exact owner can update them; equivalent legacy records are preserved
without adoption. A rename of an existing run's domain is refused. Conflicts,
DNS propagation, expired validation, and incomplete Azure TLS deployment are
explicit failures. Review expired/rejected Azure validation before explicitly
regenerating its token; do not turn off ownership checks.

`domain-check` uses the read identity in GitHub Actions and needs no Cloudflare
credential. It verifies the exact managed-TLS domain resource, both WAF/route
associations, public TXT/CNAME, and live HTTPS app identity/marker behavior.
Normal validation also checks an established custom domain. Repair,
protection, and remediation retain pending/associated domain tags without
writing DNS or requiring its token.

Before uninstall, remove this run's routing CNAME and review retained
validation TXT to avoid a dangling hostname. Resource-group teardown warns
about DNS but intentionally never deletes external or shared records.

## First deployment and providers

An authorized operator must explicitly register the providers used by the
reviewed template if the isolated subscription has not used them before:

- Microsoft.Web, Microsoft.Cdn, Microsoft.Network
- Microsoft.OperationalInsights, Microsoft.Insights, Microsoft.Security
- Microsoft.SecurityInsights only if opting in to Sentinel

Example, after selecting and verifying the training subscription:

```bash
az provider register --namespace Microsoft.Cdn --wait
```

Repeat only for the required namespaces. This is a deliberate subscription-wide
setup action, not something `doctor` does on your behalf.

For the initial deployment, use an authorized operator with the ability to create
the isolated group and deploy its resources. Once it exists, automation should
have workload rights only at **that exact group**. Do not use permanent
subscription Contributor/Owner as a convenient pipeline default.

No Bicep role assignments are created. The app's identity starts and remains
unprivileged; it does not need data-plane access to log synthetic events.

## Minimum identity boundaries

| Identity | Scope / permission category |
| --- | --- |
| Deployment | Contributor or a reviewed resource-specific deployment role at the exact existing scenario group |
| Subscription deployment record | Custom subscription role allowing `Microsoft.Resources/deployments/read`, `write`, `validate/action`, `whatIf/action`, `operations/read`; subscription/permissions reads needed for preflight |
| First-time group creation | Operator-only resource-group creation permission at subscription scope; not needed by normal automation once the group exists |
| CSPM opt-in operator | Additional `Microsoft.Security/pricings/read` and `write` at subscription scope, only for the explicitly approved enablement |
| Simulator / validator | Reader at the exact group, plus pricing read at subscription scope; no deployment/delete permissions |
| Investigator | Above read rights, Resource Graph query access, and Log Analytics Reader for querying the lab workspace |
| Teardown | Resource-group read/delete at the exact scenario group; subscription/account reads for context checks |
| Optional domain provisioning | Deployment identity plus Front Door custom-domain, route, and security-policy writes within this exact group; separate zone-scoped Cloudflare token |

Custom roles also need permission-inspection reads
(`Microsoft.Authorization/permissions/read`) where doctor checks them. Group
Contributor permits writing the existing group's tags and nested resources.
Defender validation needs pricing read even when the lab did not enable the plan.
Directory/app management and role-assignment creation are bootstrap operator
tasks; the runtime and pipeline do not need them. Do not grant RBAC Administrator
or User Access Administrator merely to deploy this scaffold.

## GitHub OIDC and environment approvals

Before dispatching a workflow:

1. Create the GitHub Environment **dev**. Configure required reviewers, prevent
   self-review, restrict deployment branches, and protect changes under `.github/`.
   Environment protection cannot be declared solely by workflow YAML.
2. Create separate Entra applications/service principals for deployment,
   read/simulation, and teardown. Create **no client secret**.
3. Add GitHub OIDC federation with issuer
   `https://token.actions.githubusercontent.com`, audience `api://AzureADTokenExchange`,
   and the exact protected-environment subject emitted for this repository.
4. Follow Pawprint's ID-qualified subject convention when enabled for the
   organization:
   `repo:ninjapaw@OWNER_ID/php2shell-cloud-defense-dojo@REPOSITORY_ID:environment:dev`.
   The vendored `scripts/github-oidc-subject.mjs` exports
   `githubEnvironmentSubject(repositoryMetadata, "dev")` to build it from actual
   GitHub API repository metadata. Confirm the real token subject; an org using
   a different subject customization must configure the matching trust explicitly.
5. Assign only the scopes in the table above. Do not grant the read identity the
   deployment identity's roles. Add pricing-write permission only when explicitly
   approving a CSPM deployment, then review removing it afterward.
6. Set these **dev Environment variables**, not secrets:
   `LAB_SUFFIX`, `AZURE_SUBSCRIPTION_ID`, `AZURE_TENANT_ID`,
   `AZURE_DEPLOY_CLIENT_ID`, `AZURE_READ_CLIENT_ID`, `AZURE_TEARDOWN_CLIENT_ID`.
   These are identifiers, not credentials.
7. Only for the optional domain action, add `LAB_CUSTOM_DOMAIN` and
   `CLOUDFLARE_ZONE_NAME` or `CLOUDFLARE_ZONE_ID` as variables, and
   `CLOUDFLARE_API_TOKEN` as a secret. The workflow supplies that token only to
   `domain`, not simulation, ordinary deployment, or `domain-check`.

### Read-only GitHub readiness preflight

Before workflow dispatch, inspect the live protection configuration:

```bash
npm run github:check -- --repository ninjapaw/php2shell-cloud-defense-dojo --environment dev
```

The [checker](../scripts/check-github.mjs) uses bounded GET requests to GitHub,
not Azure. It supports native Windows. Public repository metadata can be read
without a token; private metadata needs an authorized read token supplied only
through `GITHUB_TOKEN`, never an argument. The checker receives the existing
Actions repository token in a step-scoped environment variable. Tokens, reviewer identities, secret values
and raw error responses are not printed or persisted.

Exit 0 means the checked GitHub configuration is readable and has an unambiguous
required-reviewers rule, self-review prevention, and restricted deployment
branches. Use protected branches or explicit custom branch/tag patterns such as
`dev`; empty policies and literal `*`/`**` selectors do not pass. GitHub, not this
script, matches the actual selected ref. Custom-policy inspection is bounded to
100 entries and fails if the returned list is incomplete.

Exit 1 means unavailable metadata, missing/incomplete protections, or an API/input
error. It never substitutes a weak default, creates settings, chooses reviewers,
disables approvals, or grants roles. Assigning approvers and reviewing admin
bypass, repository branch protection and workflow-change protection remain owner
decisions. A configured reviewer list is not proof an independent reviewer is
available to approve a particular run.

The JSON includes an **OIDC subject candidate** built from actual GitHub
repository/owner IDs using the existing Pawprint helper. This does not verify
the organization's subject customization, Entra federation or Azure permissions;
confirm them separately as described above. No live KQL or workload evidence is
collected by this preflight.

All five workflows invoke this check after checkout/Node setup and before Azure
login or other validation work. Their explicit Ubuntu 24.04 runners avoid image
label drift. The offline validation workflow installs PHP 8.4 and 8.5 explicitly
and tests both; neither CI runtime is inferred from the hosted image's default.
Do not dispatch a workflow merely to auto-create an unprotected `dev` environment.
Local plan/tests and locally authenticated lifecycle commands remain independent
of this GitHub metadata service. If GitHub is unavailable, the documented local
uninstall still requires exact subscription, ownership and typed group
confirmation; never disable workflow protections to bypass the readiness check.

All workflows are manual and the job environment is hardcoded to `dev`; the CLI
still rejects unknown input values. OIDC login uses a runner-temp Azure config
directory and the pinned login action's post-cleanup. Checkout does not persist
GitHub credentials. There is no credential cache or artifact upload.
Simulation, deployment, remediation and teardown share one non-cancelling
dev-wide concurrency group, even if the suffix changes, because the group is
now explicitly configured rather than suffix-derived.

Workflows do not bootstrap Entra, register providers, or grant permissions.
A missing variable/trust/role fails explicitly. Never bypass approval by
disabling an environment or substituting a client secret.

## State, repair, and validation

The resource group's ownership tags record intended training/fixed state, WAF
mode, opt-ins, original creation and expiry. Live endpoints and IDs are read
independently from Azure, not from an editable local URL file.
The local PHP preview defaults only when its environment/state settings are
absent. Explicitly empty, zero-like or unknown values fail with HTTP 503 instead
of silently reopening training surfaces.

- Repair preserves fixed state, Prevention mode, expiry and Sentinel opt-in.
- Missing resources inside the owned group can be recreated idempotently.
- It will not downgrade protection or reopen training surfaces.
- A missing whole group requires `deploy`, not `repair`, and a reviewed what-if.
- CSPM enablement is never implicit during repair. Previous expectation persists,
  and validation fails if Standard is missing.
- Remediation intentionally leaves security logging and the supported runtime in
  place, disables training surfaces, and checks the app has no role grants.
- Unexpected identity grants are an explicit validation failure, not deleted
  automatically. Review the exact assignment and its scope manually.

Validation checks actual HTTPS app health/state/runtime, edge marker behavior,
direct origin rejection with and without copied FDID, diagnostic destinations,
workspace health, basic publishing disabled, identity grants, CSPM expectation,
and optional Sentinel onboarding plus the exact synthetic rule's scope, query,
schedule, incident-disabled settings and stored analytics opt-in. Missing,
duplicate or drifted rules fail validation; the command does not change them.
Collection pagination stays within the original Azure management path and fails
explicitly after 10 pages. This is not an assertion that logs/assessments
have arrived. Deployment validation retries HTTP readiness at most 12 times with
10-second delays; each HTTP request has a 15-second timeout and 64 KiB body cap.
Redirects are refused, including redirects to a different allowed-looking host.

The RBAC check reads direct and scope-inherited assignments **to the app's
principal at the app scope**. Principal-name filling is disabled, so the read
identity needs no directory lookup permission. Group-based grants and grants at
unrelated resource scopes require separate privileged review, for example in
Cloud Security Explorer. The validator does not claim to prove their absence.
The template itself creates no role assignments anywhere.

Simulation performs four base validation requests in training state (plus two
custom-domain checks when associated), then **five**
scenario requests (one harmless marker plus four labelled log shapes) with a
250 ms interval. It does not run in fixed state. There are no process, shell,
outbound, or Azure canary data-plane operations. Console output contains a UUID,
UTC window and status summary; no Azure tokens or raw deployment outputs.
Fixed-state validation checks all five ordinary signal endpoints return 404,
including `request` without the WAF marker. A marker's 403 alone cannot prove
that the underlying request surface was removed.

## Cost and expiry reminders

Front Door Premium and B1 capacity continue billing while idle. The workspace
has a daily ingestion cap and retention setting, not a comprehensive cost cap.
The default expiry is 24 hours and is never extended silently by repair.

Use Azure Cost Management budget alerts and a calendar/automation reminder for
`pawprint.expiresAt`. No policy/reminder principal or automatic resource deletion
is installed by default. A separate organization-owned reminder may read the
tag, but must not sweep/delete other groups or security pricing plans.

## Teardown and residual items

1. Save only redacted, observed evidence if needed.
2. Keep the original JSON `resourceGroup`, location, subscription and suffix,
   then run uninstall with that exact confirmed group name.
3. The command waits for deletion and checks that the group no longer exists.
   Azure deletion failures/locks are errors, not success.
4. Confirm the workload, edge profile/policy, workspace, Insights and Sentinel
   resources disappeared with that group. Review Azure Cost Management.
5. **CloudPosture remains unchanged.** If you opted in, review ongoing
   subscription charges and dependencies with the subscription owner. Disable it
   only through a separate approved change if no other workloads rely on it.
6. Review manually bootstrapped Entra apps, federated credentials, custom roles,
   and subscription-level role assignments. Remove only lab-specific objects by
   their reviewed IDs if no longer needed; these are outside uninstall's scope.
7. Subscription deployment history is non-billable metadata and is retained.
   It must not be mistaken for a surviving workload. No secrets are output there.
8. Stop any local PHP preview server. The scaffold stores no Azure credentials
   or local deployment state. Clear a manual Azure CLI session according to your
   organization's workstation policy.

If your organization later adds Key Vault, managed certificates, private
publishing, or shared log destinations, update teardown, cost, permission and
validation boundaries before calling the environment disposable.
