# PHP2Shell hunting coverage and evaluation

This dojo incorporates the investigation coverage of
[cseelhoff-ms/php2shell-hunting-pack](https://github.com/cseelhoff-ms/php2shell-hunting-pack/tree/15baae8d25e631ac2223f904f4d0a0f4cf08d703),
reviewed on 2026-10-22 at commit
`15baae8d25e631ac2223f904f4d0a0f4cf08d703`. The local queries are independently
authored; upstream code, scripts and product datasets are **not vendored**.
The mapping covers all 10 asset-discovery rows, Hunts A-G including D1/D2,
E1/E2 and F1/F2, all 16 upstream query files, their discovery/baseline variants,
and manual evidence paths for the non-KQL methods.

The [catalog](../detections/catalog.json) is the machine-readable query and
evaluation contract. [Schema fixtures](../detections/schemas.json) are offline
compiler inputs, **not collected telemetry**. See the
[query index](../detections/README.md) for the six original lab queries.

## Boundaries and platforms

- **Defender XDR Advanced Hunting:** use [defender-xdr/](../detections/defender-xdr/).
  Event tables use `Timestamp`; TVM inventory snapshots do not have it.
  `DeviceTvm*` data is not ingested into Sentinel, even if autocomplete accepts
  the table. The unified portal does not remove this engine/data distinction.
- **Azure Resource Graph Explorer:** use
  [resource-graph/](../detections/resource-graph/). Select only an explicitly
  authorized subscription/resource-group scope. Resource Graph is a KQL subset;
  the offline Kusto compiler does not verify service-side operator restrictions.
- **Log Analytics / connected Sentinel workspace:** use
  [sentinel-log-analytics/](../detections/sentinel-log-analytics/).
  These use `TimeGenerated` and require the named resource-specific/custom tables.
- The broader estate queries **fail explicitly** if a required table is missing.
  Only the six original lab queries use fuzzy optional-table resolution.
  An empty table, missing permission, stale inventory or no matching row is
  **not a successful security assessment**.
- This change provisions no extra resources, Defender plans, agents, DCRs,
  registries or scanners and grants no permissions. Such collection can be
  billable and needs separate design and approval. It does not alter the
  synthetic Sentinel rule or generate exploitation-shaped requests.

## Run and evaluate

```bash
npm run evaluate
node --test tests/kql.test.mjs tests/hunting.test.mjs tests/products.test.mjs
```

`evaluate` is offline and supported on native Windows. It verifies catalog
completeness, pinned provenance, every KQL file's registration, platform-specific
syntax/types, exact projected column names/order, missing-source behavior,
and runbook/evidence mappings. **It is not a live KQL execution**, threshold
execution test, ARG service acceptance test or detection-efficacy score.
CI runs it explicitly. No Azure login or network connection is used.

The report distinguishes `offlineEvaluation.status = passed` from
`liveEvaluation.status = not-run`. Every live/manual item remains
`operator-evidence-required`, including the product query's unpopulated input.
Do not turn 20 registered checklist items into 20 passed live detections.

For each authorized live evaluation, record: item/query ID and revision,
platform, exact resource/device/image scope, UTC event and collection windows,
table/column availability and permissions, observed rows, corroborating evidence,
alternative explanations, owner and disposition. Use **observed lead**,
**collection gap**, **not applicable with justification**, or **reviewed with
evidence** rather than deriving "safe" from an empty result.
Compare positive and negative controls in an isolated test workspace before
operationalizing a hunt; never use an exploit or production request generator.

`investigate --environment dev` still runs **only one bounded, lab-scoped**
assessment query. It also prints the full catalog guide, prerequisites and
evidence criteria. It does not run the wider queries or download product feeds.
Use the original simulator run ID only for the original lab queries; estate
hunts have no synthetic `RunId` requirement.

## Row 01

Run [TVM exposure](../detections/defender-xdr/tvm-exposure.kql) in Defender XDR.
Review actual CVE, software and device rows. Catalog publication is not assumed.
If no rows appear, continue Rows 05, 08 and 09 and verify onboarding/coverage.

## Row 02

Use [PHP assessments](../detections/resource-graph/php-assessments.kql) and actual
Defender for Cloud recommendations for VMs and running containers. Inspect
assessment status, exact resource, affected package and vendor advisory.
Follow [Cloud Security Explorer pivots](investigation.md#cloud-security-explorer-pivots)
only where supported relationships actually exist. No finding, attack path or
Defender workload-protection alert is guaranteed by this App Service lab.

## Row 03

Run [App Service candidates](../detections/resource-graph/appservice-runtimes.kql)
and [all-runtime discovery](../detections/resource-graph/appservice-runtime-discovery.kql).
Review Functions, slots, WordPress, custom containers and missing configuration.
For an approved app with empty ARG fields, inspect its actual configuration in
the portal or use read-only `az webapp config show --ids '<exact-app-resource-id>'`.
Do not assume a missing field means no PHP. Managed stacks expose major.minor;
verify the effective web-SAPI build/platform patch independently. Route custom
container digests to Row 04.

## Row 04

Run [container CVE findings](../detections/resource-graph/container-cve-findings.kql)
and [PHP-related finding inventory](../detections/resource-graph/container-php-findings.kql).
These filter to ACR resource identities, preserving repository/digest fields from
legacy and newer assessment shapes when present. Missing digest fields need
manual enrichment, not a guessed image identity.

For **zero-finding** images, separately inventory the approved registry and
actually deployed workload digests, including init containers where applicable.
Use an approved SBOM tool such as Syft on those immutable digests and inspect both
OS packages and source-built PHP binaries. A tag or OS package scan alone can miss
source-built PHP. Preserve tool version, digest, collection time and errors.
Do not execute untrusted images or suppress failed pulls/catalogs.
This manual step is part of evaluation, not replaced by the findings queries.

## Row 05

Run [PHP inventory](../detections/defender-xdr/php-inventory.kql) and
[distinct-software discovery](../detections/defender-xdr/software-discovery.kql).
Both primary PHP advisories identify upstream fixes **8.2.35, 8.3.36, 8.4.27
and 8.5.12**. These are branch-specific comparison references, not findings about
the dojo's effective runtime. Recheck current vendor advisories before action.

The query routes package suffixes/epochs/prereleases to manual vendor review
**before** comparing upstream thresholds. A distro backport can retain an older
upstream number. PHP application versions (for example phpMyAdmin) are not runtime
versions; the example application-name list is not exhaustive. Review unsupported
and unparsed versions and all software on observed web hosts for other PHP stacks.
An upstream threshold match still requires deployment and serving-runtime proof.

## Row 06

In an authorized Defender EASM workspace export approved, live assets in passes:
PHP framework; web-server technologies; PHP-dependent web components; IP banners.
Also export and review **distinct** framework, component and server values without
the fixed PHP keyword filters. Preserve external asset identity, scope and time.
EASM does not inventory internal-only assets; stripped headers conceal PHP.
No EASM workspace or external scan is created by this project.

## Row 07

Use organization-scoped code search for PHP base images, PHP package installation,
Compose/Kubernetes image references and `composer.json`. For example, in GitHub
code search replace the organization placeholder in `org:YOURORG "FROM php"
path:Dockerfile` and `org:YOURORG path:composer.json`.
Use equivalent explicitly scoped Azure DevOps Code Search when available.
Review distinct returned repositories and record truncation/access gaps.
Then map approved image digests to repository, build pipeline and owner using
available Defender for DevOps/code-to-cloud evidence. That mapping service is not
a replacement for free-text code search. Do not upload private code to public tools.

## Row 08

Run [binary evidence](../detections/defender-xdr/php-binary-evidence.kql).
`DeviceTvmSoftwareEvidenceBeta` only covers recognized software and may change
schema. Disk evidence does not prove a module is loaded or discover every appliance.

For [bundled-product leads](../detections/defender-xdr/bundled-products.kql),
obtain and review the upstream NCSC-derived CSV through an approved process.
Preserve its source commit/download time and vendor evidence. The NCSC dataset is
**EUPL-1.2**; retain its attribution/license if redistributing derived data.
It is not bundled, automatically fetched, complete or guaranteed accurate here.
Convert the reviewed records to a UTF-8 JSON **array**, retaining at least
`Keyword`, `Product`, `Status109618`, `Status109619` and `Source`.
`Source` may contain space-separated HTTPS URLs. Statuses must be `Investigation`,
`Vulnerable`, `Fix`, `Workaround` or `Not vuln`; they describe the source entry,
not the installed device's verified patch state.

Generate KQL locally without a cloud login or network request:

```bash
node scripts/prepare-products.mjs --input reviewed-products.json > generated-products.kql
```

Use a private scratch location for both files; do not commit inventory exports.
The helper rejects empty/malformed input, unknown statuses, credential-bearing
URLs, inputs above 1 MiB and more than 2000 rows. It quotes all values as KQL
string literals. Extra CSV metadata such as Notes/Supplier is not projected.
Scope the inventory to approved devices before a large keyword join.
The checked-in empty template is intentional: **no product rows means input
missing**, not completed NCSC coverage. Confirm a matched product's actual
serving PHP version and advisory. Custom applications may not be in any feed.

## Row 09

Run [worker classification](../detections/defender-xdr/worker-classification.kql)
and [worker discovery](../detections/defender-xdr/worker-discovery.kql).
Apache plus an installed mod_php package is a prioritization proxy, not evidence
the module is enabled/loaded. Installed-but-quiet hosts are retained. Process
events record starts; a worker older than the retention window can be missed.
Review distinct PHP-related launchers and inbound web-port processes, then update
the standalone baseline/B/E1/E2 worker patterns consistently. The tests check
their synchronization. Inbound network coverage varies by OS.

## Row 10

This dojo intentionally adds **no scanner or arbitrary-target option**.
Only for separately approved gaps, have the network owner arrange an authorized
fingerprint assessment with written targets, scanner identity, per-zone routing,
rate limits, change approval and SOC coordination. Review existing approved
fingerprints and distinct technologies/server values; corroborate with runtime
inventory. Hidden PHP headers are not clearance. Never run a public PoC.

## Hunt A

Cross-match Row 09 priority 1/2 candidates with Row 06 approved/live exposure.
Use stable asset IDs and owner-confirmed hostname/IP mappings at the same time;
NAT, shared hosting and aliases make naive string joins unreliable.
Keep unmatched/uncertain mappings visible. This is a manual triage evaluation,
not an automated claim that two unrelated datasets describe the same asset.

## Hunt B

Run [worker baseline](../detections/defender-xdr/worker-baseline.kql), then
[child-process hunt](../detections/defender-xdr/worker-child-processes.kql).
Review shells, interpreters, download/network tools and discovery commands.
Composer, git, image conversion, mail and deployment activity can be legitimate.
Do not automatically allow-list a frequently observed child.
Corroborate account, command, device, report ID, time and change owner.
Avoid exporting secrets embedded in command lines. In-worker execution has no
child event; the App Service simulator does not generate these records.

## Hunt C

Run [Syslog failures](../detections/sentinel-log-analytics/syslog-worker-failures.kql)
only after confirming AMA/DCR coverage by host, facility, severity and recent time.
Kernel/daemon and the relevant application facilities must be collected at the
needed severity. PHP/FPM/Apache error files do not automatically enter Syslog;
configure approved routing or use Hunt F2. Review segfault/OOM, timeout and worker
exit/churn signals, including bins with at least five events in 10 minutes.
Fixed bins can split bursts. No fixed ingestion completion time is promised.

## Hunt D1

Run [App Service HTTP](../detections/sentinel-log-analytics/appservice-http.kql).
It returns three lead types, grouped by resource, host and client: five 5xx POSTs
plus a maximum request over 100000 bytes within five minutes; two POSTs including
a session-cookie request and a 5xx within a 10-second bin; request-cookie length
over 1000. These are heuristic boundaries, not signatures.
Test both sides of size/count/time boundaries before tuning; fixed bins can split
nearby requests. Custom session names need separate review.
This table has no Content-Type, body or response cookie; the query never outputs
request-cookie contents. The lab's benign GETs should not be forced to match.

## Hunt D2

Run [Application Gateway WAF](../detections/sentinel-log-analytics/appgateway-waf.kql)
only with resource-specific `AGWAccessLogs` and `AGWFirewallLogs`.
Legacy AzureDiagnostics is a different schema; this lab's Front Door logs are
also a different source. Review POST/backend-5xx bursts and body/multipart
parsing leads. Rule IDs 200002/200003 need confirmation in the deployed ruleset;
they are not verified dedicated PHP2Shell coverage.
The join uses gateway resource identity and nonempty transaction IDs, not client
IP alone. A missing joined access record leaves backend status unknown.

## Hunt E1

Run [PHP file lifecycle](../detections/defender-xdr/php-file-drops.kql).
Review PHP-family writes by observed workers or into temp paths and a following
delete within the inclusive 0-10 minute window. Corroborate full path, device,
hash, report ID and timestamps. Reused paths, CMS/plugin updates, caches and
maintenance can match; a create/delete pair does not prove file execution.

## Hunt E2

Run [worker network](../detections/defender-xdr/worker-network.kql).
It includes direct workers on unusual public ports and child tools on **any**
public port, including 80/443. Direct worker common API/DNS/mail ports are
excluded; private, unknown-IP-type and excluded-port destinations need separate
review. Public IPv4/IPv6 classification comes from the observed MDE field.
The simulator performs no outbound connection or network-event generation.

## Hunt F1

Run [container worker errors](../detections/sentinel-log-analytics/container-worker-errors.kql)
only when Container Insights uses `ContainerLogV2`. Confirm actual PHP/Apache
stderr/stdout routing; FPM may need approved `catch_workers_output` and error-log
configuration. Review namespace, pod, container, resource and collection window.
Dynamic log messages are converted to strings. AKS is not deployed by this lab.

## Hunt F2

Run [custom web logs](../detections/sentinel-log-analytics/web-text-logs.kql)
after separately approving AMA/custom-text DCR collection. Create
`WebErrorLog_CL` and `WebAccessLog_CL` **before** the DCR. Both contracts require
`TimeGenerated:datetime`, `RawData:string`, `Computer:string` and the standard
`_ResourceId:string`; verify host/resource identity is actually populated.
Collect only approved append-only UTF-8 error/access files.

Access records must contain nine pipe-separated fields:
`timestamp|client-ip|method|uri|status|request-bytes|content-type|transfer-encoding|response-cookie-size-flag`.
Use URI path, not query-string/session content. The final flag is `1` when an
approved server-side response-cookie size threshold is exceeded, `0` when measured
below it, or `-` when unavailable (for example a server without that measurement).
Choose/document the flag's byte threshold in the approved logging configuration;
never log actual Cookie/Set-Cookie values or expose a public phpinfo page.

The hunt returns three multipart 5xx errors per 10-minute bin, any chunked
multipart POST, any large-response-cookie flag, and worker/memory error leads.
Malformed numeric/flag/field records produce explicit parse-error rows instead of
quietly disappearing. `UnknownResponseCookie` counts unobserved flags in returned
access-signal bins. Evaluate malformed and negative controls as well as positives.

## Hunt G

Use the two [primary PHP advisories](#primary-references), not WAF markers, for
real remediation. Only an update containing the fixes is complete mitigation.
Verify the effective web-SAPI build/vendor backport or immutable image digest,
restart **all** workers and preserve closure evidence.

For approved temporary mitigations review session upload-progress disabling,
invalid startup INI diagnostics, PHP 8.5 `fatal_error_backtraces`, decoded body
size/part/header/nesting limits and routes that need no multipart uploads.
Startup/admin configuration and the actual FPM/Apache worker matter; a CLI INI
check, `.user.ini` or application `ini_set` is not equivalent.

The OOM advisory discusses administratively enforcing `memory_limit=-1` as a
**partial** mitigation. Removing a per-request limit changes availability and
denial-of-service risk and still cannot prevent every allocator failure.
Do not apply it blindly to this shared environment or automate it in the dojo.
Container/cgroup limits also have availability trade-offs; **RLIMIT_AS** and
**RLIMIT_DATA** are explicitly unsuitable because they can induce allocator
failure on the vulnerable path. WAF coverage must be verified independently.
The lab's synthetic fixed state does not close a real CVE.

## Primary references

- [PHP OOM advisory, CVE-2026-109618](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w)
- [PHP stale-state advisory, CVE-2026-109619](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp)
- [TVM software evidence and Sentinel data boundary](https://learn.microsoft.com/defender-xdr/advanced-hunting-devicetvmsoftwareevidencebeta-table)
- [AppServiceHTTPLogs schema](https://learn.microsoft.com/azure/azure-monitor/reference/tables/appservicehttplogs)
- [AGWAccessLogs schema](https://learn.microsoft.com/azure/azure-monitor/reference/tables/agwaccesslogs)
- [AGWFirewallLogs schema](https://learn.microsoft.com/azure/azure-monitor/reference/tables/agwfirewalllogs)
- [Container registry Resource Graph samples](https://learn.microsoft.com/azure/container-registry/resource-graph-samples)
- [NCSC-NL PHP2Shell inventory](https://github.com/NCSC-NL/php2shell)
