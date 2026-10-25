# PHP to Proof: isolated affected-runtime comparison

This is a **separate, explicitly opted-in dev deployment**. The original App
Service/WAF lab and its synthetic events remain unchanged. This comparison
deliberately packages a real affected PHP release, but supplies no exploit,
webshell endpoint, command-injection surface, sensitive data, or proof of
compromise.

## Verified image boundary

[Reviewed image references](../container-lab/images.json) pin official Linux
amd64 PHP/Apache manifests by digest: PHP **8.4.26**, and the **8.4.27** upstream
security-fix comparison. The primary
[OOM advisory](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w)
and [request-state advisory](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp)
describe the actual affected runtime conditions. No exploitability or scanner
coverage is inferred merely from a tag.

ACR imports the reviewed base manifests, builds both comparisons from a small
allowlisted source context, and deploys only an independently read image digest.
The root `.dockerignore` applies the same default-deny source boundary to direct
Docker builds, excluding local credentials, registry configuration, Git data,
dependencies, and reports.
`/health.php` reports the actual Apache PHP SAPI and exact version; mismatches
return HTTP 503. The fixed comparison addresses these upstream advisories,
not every OS/package vulnerability an image scanner might find.

## Isolation, permissions, and billable effects

- Dedicated `rg-p2sc-SUFFIX-dev`; the normal lab never adopts this group.
- Private AKS control plane; one Azure Linux 3 D2s_v6 node; no public node IP,
  SSH, public application, Service, Ingress, or real application data.
- Restricted namespace, a non-root pod, dropped capabilities, read-only root,
  bounded memory/CPU, memory-backed temporary storage, and deny-all ingress and
  egress. The application receives no Kubernetes token or Azure role.
- ACR Basic has anonymous access and admin credentials disabled. Its HTTPS API
  remains publicly routable for authenticated builds, pulls and assessment.
- The orchestration identity has Contributor only on this exact registry and
  cluster, and Kubernetes RBAC Cluster Admin only on this isolated cluster for
  namespace bootstrap and validation. Contributor is a control-plane role and
  does not supply Kubernetes data-plane authorization. This is privileged
  **operator** access, not workload access. The
  kubelet has AcrPull only on this registry. No subscription role is granted.
- The AKS-managed `p2sc-SUFFIX-nodes-dev` group contains the node, disk,
  outbound-only NAT and egress IP. It is removed by AKS deletion.
- Existing Defender Containers and CSPM Standard with registry assessments are
  required. Deployment enables this cluster's Defender monitoring/sensor; it
  does not alter any subscription pricing plan or unrelated extension.
- Deployment can explicitly register missing required Azure providers.
- Compute/disks, ACR/storage/builds, NAT/egress IP, protected vCores, logs, and
  keyless container-job compute can bill. A 1 GB/day log cap is not a
  total budget; 24-hour expiry is metadata, **not automatic teardown**.

The lab-specific [foundation](../infra/container-lab.bicep) and
[operation](../infra/container-lab-action.bicep) use explicit resources rather
than adding another vendored platform contract. This keeps the isolated
permission scopes and private-cluster settings visible. No shared files under
`vendor/` are changed.

## Run

Offline planning and tests work on native Windows. Cloud lifecycle commands
follow the existing repository contract: use Linux/macOS or WSL2 with Linux
Node, Azure CLI, Bicep, and an explicitly selected authorized subscription.
The Azure VS Code tools use separate authentication from Azure CLI; being
signed into the extension does not sign the CLI in.

```bash
az login
az account set --subscription '<authorized-training-subscription-uuid>'
export AZURE_SUBSCRIPTION_ID="$(az account show --query id -o tsv)"
export DOJO_SUFFIX=your1234
npm run container:lab -- plan
npm run container:lab -- deploy --yes
npm run container:lab -- validate --yes
npm run container:lab -- investigate
```

The authenticated Azure deployment tools can execute the same compiled ARM
templates and parameter objects when CLI authentication is unavailable. Use
Incremental mode, inspect bounded what-if, and independently verify readback.
Do not copy tokens between tools, enable registry admin credentials, or bypass
a registry authentication failure.

Operations run in a digest-pinned Azure CLI Container Instance using the
operator's managed identity. It exposes no ports, uses no Azure Files share or
storage account key, and exits after its bounded task. The CLI lifecycle waits
for its actual exit code and deletes the exact successful runner. Completed
comparison digests and serving-runtime observations are also recorded as
non-secret tags on the exact registry/cluster for independent readback. These
tags are observations, not Defender findings or proof of compromise.
Validation also runs in the scoped managed-identity job and therefore requires
`--yes` for its short-lived compute. The human caller does not need additional
Kubernetes data-plane permissions. The CLI accepts only one structured result
from that exact invocation, verifies the independent ACR digest and cluster
configuration, and then removes the successful runner. It does not substitute
old tag values or a configuration-only success for live runtime evidence.

## Private portal window

The optional [operator console](../operator/README.md#private-live-exercises-fixes-and-reset)
adds a **different, maximum four-hour window** to the comparison above. It uses
[the private orchestration template](../infra/private-live.bicep), not a public
attack endpoint. Existing public PHP, original expiry tags, DNS, Defender plans
and WAF mode are preserved.

1. Review the exact new private group, window UUID, expiry, paid resources and
   native template what-if. Do not adopt an unrelated or still-active group.
2. Deploy the private foundation and
   [expiry workflow](../infra/private-live-cleanup.bicep), the exact scoped grants,
   and AKS audit diagnostics to the owned workspace. Compare the template's
   expected and actual external grant-ID outputs before authorization.
3. Use the existing allowlisted build/deploy operation to build both pinned
   comparisons. Read actual derived ACR digests, serving PHP and sensor readiness;
   a configured image, zero-digest placeholder or enabled plan is insufficient.
4. Install the foundation/runtime operator overlays with live execution off.
   Separately authorize the exact observed target and verifier epoch; never
   retrieve the password in deployment outputs or extend the original public
   lab expiry.
5. Sign in and open `/live`. Preview, inspect the displayed closed script, type
   the exact private resource-group name and approve one action. Run the
   administrative `id` and benign HTTP tests, compare real raw-source evidence
   with actual Defender query outcomes, then Fix, Verify, Reset, Verify and Fix
   again. Reset changes **only this private deployment** and requires a measured
   fixed predecessor.
6. Collect the original run's sources after ingestion, rather than replaying
   activity. Review the redacted complete-cycle candidate before separately
   publishing its read-only card walkthrough.
7. Verify the final fixed PHP/digest and removal of the marker-only WAF rule.
   Revoke temporary verifier/publication grants. Check actual expiry workflow
   history, removal of its external scoped grants, private-group absence and
   AKS-managed node-group absence.

### First-deployment preflight and interrupted windows

AKS provider validation can return `GetLogAnalyticsWorkspaceError` when it
queries a workspace that the same foundation template has not created yet.
After verifying the exact private group's ownership and active window, create
only the workspace from the reviewed
[foundation definition](../infra/container-lab.bicep): the same name, location
and ownership/window tags, `PerGB2018`, 30-day retention, 1 GB/day ingestion cap
and local authentication disabled. Wait for actual provisioning success, then
repeat the unchanged full what-if before deploying the private foundation.
Do not retrieve workspace keys, enable local authentication or skip provider
validation to conceal the dependency.

Leave enough authorized time for provisioning, image builds, the entire paced
capture and evidence collection. Installing source with execution disabled is
not a live run. If the remaining window is insufficient, do not start a partial
cycle, reuse historical timestamps or silently extend credentials. Record the
unused or interrupted window, reconcile any jobs and temporary grants, and
obtain a fresh bounded authorization before continuing. An uncertain mutation
must be reconciled before another attempt; a fresh window is not permission to
replay it.

The process probe is actual privileged **operator** execution of a fixed command
inside a non-root pod, not PHP2Shell exploitation. The HTTP test is actual edge
enforcement of a benign marker, not validation that every CVE payload is blocked.
Raw AKS audit/WAF records, an empty completed alert query, missing permissions,
missing source tables and delayed inventory are distinct observations. The
portal never disables Defender to manufacture an unprotected comparison.

Unlike the normal 24-hour metadata-only CLI track, this feature schedules
managed-identity deletion at the explicit four-hour expiry. It first checks exact
window/group tags, removes each window-owned external worker grant and its
cleanup grant, then deletes only the private group. A stateful, at-most-one-hour
retry loop retains completed-pair progress instead of revisiting a scope after
its own cleanup permission was revoked. Failed or ambiguous cleanup remains
visible and needs owner reconciliation; a schedule is **not proof of deletion
or stopped billing**. For early
manual uninstall, an authorized owner must first revoke the exact external
grant IDs from the orchestration outputs and then delete the owned private
group. Do not delete the cleanup workflow first and leave its external grants
behind. Unassigned subscription custom-role definitions can remain as metadata;
remove them only after independently proving no assignment still uses them.

The four-hour node-compute estimate excludes disk, NAT and IP, ACR builds/storage,
protected vCores, logs, publisher jobs and workflow actions. The live window and
daily log cap are not a spending cap. Retained groups continue billing until
actual removal, even when portal buttons and credentials have expired.

## Actual evidence versus test telemetry

The [Defender support matrix](https://learn.microsoft.com/azure/defender-for-cloud/support-matrix-defender-for-containers)
and [AKS integration](https://learn.microsoft.com/azure/defender-for-cloud/defender-for-containers-enable)
are the basis for using AKS rather than assuming App Service emits MDE tables.
Validation checks the serving runtime, actual pod image, and ready Defender
daemonsets. Configuration alone is not evidence of a completed assessment.

Run the existing [ACR/CVE hunts](../detections/resource-graph/) against the
dedicated lab scope. `investigate` also reads actual, correctly cased Defender
alert properties. Missing subassessments, source-built PHP coverage, permissions,
inventory delay, and a completed scan with no matching CVE are different states.
An empty query is never a clearance.

Some current MDVM image findings are **primary assessments** under an ACR
`securityentitydata/...-images-sha256:...` resource, with a JSON
`additionalData.CvesDetails` array. They are not legacy subassessments. The two
container hunts accept both formats and retain the actual digest from this
image identity. A missing repository name still needs manual enrichment; the
query does not guess how encoded resource names map to repository paths.
Inspect `SoftwareName`, `DetectedSoftwareVersions`, `FixedVersion`, and the
individual `CveId`/`Severity` entries. Count unique CVEs separately from affected
images: the same package finding on base and derived images is not four
different vulnerabilities. A PHP-fixed comparison can retain independent OS
findings, and a reported OS finding is not a PHP2Shell detection.

```bash
npm run container:lab -- test-detection --yes
npm run container:lab -- investigate
```

`test-detection` executes only `id` through the authorized Kubernetes control
plane. It exercises actual audit/process telemetry without an application
exploit. **It is not a guaranteed Defender detection trigger.** The official
[Microsoft simulator](https://learn.microsoft.com/azure/defender-for-cloud/alerts-containers#kubernetes-alerts-simulation-tool)
uses a webshell even for other scenarios; this lab does not automatically
install it or represent ordinary administrative execution as compromise.
Neither an informational marker nor a sample alert proves exploitation.

## Remediation and teardown

```bash
npm run container:lab -- remediate --yes
npm run container:lab -- validate --yes
npm run container:lab -- uninstall --confirm-resource-group rg-p2sc-your1234-dev
```

Remediation records fixed intent before deployment, replaces the workload with
the fixed digest, and preserves ownership/expiry. A retry cannot silently
restore the affected runtime. Prior registry images remain as assessment
evidence until the lab is explicitly deleted.

Uninstall requires the exact owned group name; `--yes` cannot replace typed
confirmation. It deletes only that group and AKS-managed child resources,
never unrelated groups, DNS, or subscription Defender pricing.
