# PHP to Proof: the investigation story

For the complete guided sequence, component comparison, and expected results,
start with [the walkthrough](walkthrough.md). The public dashboard also exposes
the read-only story at `/walkthrough.php`; this guide supplies deeper evidence
and product-specific pivots.

Use the simulator's run ID, UTC start/end, exact app resource ID, edge profile
and lab workspace. **PHP to Proof: A Code-to-Cloud Defense Story** follows:

**Discover -> inspect exposure -> review available attack paths -> observe bounded
activity -> correlate -> validate WAF Prevention -> remove training surfaces ->
verify no unnecessary grants -> validate closure.**

Do not turn an expected demo narrative into fabricated evidence.

## Defender CSPM

Enable only through an approved explicit `--enable-defender-cspm` deployment.
Validation checks the `CloudPosture` plan reports **Standard**. It does not enable
Defender for App Service, Servers, Containers, or unrelated subscription plans.
Those are separate billable designs and are not required for synthetic logs.

Run `investigate --environment dev` after deployment. It queries available
`microsoft.security/assessments` and `assessments/subassessments` in Resource Graph,
scoped to the exact lab group/app, for **PHP**, **CVE-2026-109618**, and
**CVE-2026-109619**. It prints observed assessment identifiers/names/status or
explicitly says no matching assessments were returned. At most 50 matching rows
are printed; review a broader scoped query if results reach that limit.

The CVE identifiers refer to published PHP advisories, but are not a claim that
Microsoft's current assessment catalog detects them, that the deployed stack is
affected, that App Service has been assessed, or that this WAF protects against
them. Confirm vendor build/affected-version evidence before making such a claim.
The [wider hunting guide](hunting-pack.md) records primary references and
branch-specific upstream fixes without asserting a finding about this app.

`investigate` also prints the [hunting catalog](../detections/catalog.json),
platform/table prerequisites and evidence criteria for all 10 asset methods and
Hunts A-G. Only its original bounded lab assessment query is executed; it does
not sweep the subscription/tenant or enable additional data collection.
Run `npm run evaluate` separately for offline catalog/schema checks.

### Cloud Security Explorer pivots

Use the actual discovered lab app resource as the starting entity and the
available query-builder relationships in your tenant. Product schema and
supported asset types change; do not paste invented relationship names.

1. Filter the asset by exact resource ID, subscription and resource group.
2. Explore available vulnerability/software assessments for PHP and the supplied
   CVE terms. Review actual affected-version and assessment status details.
3. Review internet exposure. Front Door is public, but the App Service route
   should be restricted to the specific edge profile. Verify the origin test.
4. Explore data classification/sensitive-data relationships if available.
   The fixture contains no real sensitive data; an absent relationship is normal.
5. Inspect the system-assigned identity and permissions. This app needs no grants.
6. Review attack paths only if the product actually returns them. Explain which
   exposure, permission or data precondition is supported by observed evidence.

Discovery and assessment are asynchronous and coverage-dependent; no fixed
completion time is promised. A new asset, no attack path, or no CVE record is not
proof of safety. Optional screenshots may be captured from your own run, with
identifiers redacted. There are no fabricated screenshots in this scaffold.

## Azure WAF

The ingress is **Front Door Premium** with **Microsoft Default Rule Set 2.1**.
It starts in **Detection**. The only custom rule is `DojoBenignMarker`, which
matches the query string fragment `dojoProbe=waf-marker` and has Block action.
In Detection mode it logs the benign match without enforcing the block; in
Prevention the expected response is HTTP 403.

This rule is a correlation/learning marker, **not a CVE signature**. Managed
rules remain enabled, but no coverage against the supplied CVEs is asserted.
To assert coverage, independently confirm the deployed managed rule ID/version,
its enabled state and vendor mapping, and observe relevant authorized test logs.
This repository does not supply an exploit payload for that purpose.

Diagnostics send `FrontDoorAccessLog`, `FrontDoorHealthProbeLog`, and
`FrontDoorWebApplicationFirewallLog` to the lab workspace's `AzureDiagnostics`.
Use [waf-requests.kql](../detections/waf-requests.kql); set `RunIdFilter`.
Review action, rule name, request URI, tracking reference, client IP, hostname,
resource ID and time window. Rule evaluation/log delivery can be delayed.

Before Prevention:

- Check a normal app/health request succeeds over HTTPS.
- Check the benign marker is associated with this exact profile/endpoint.
- Confirm logs identify the custom rule, not an assumed managed-rule CVE hit.
- Confirm legitimate traffic is not unexpectedly blocked.
- Confirm the origin returns **403** both directly and with a copied FDID header.

Run `protect --environment dev --yes`, then validate and repeat the bounded
simulation. A spoofed FDID from outside Front Door must still fail because both
the service tag and profile header are required. HTTP errors from an unrelated
endpoint, a DNS failure, or a redirect do not count as proof of origin isolation.

## Microsoft Sentinel

Sentinel is optional and scoped to the lab workspace. Hunting works directly in
Log Analytics without Sentinel. `--enable-sentinel` onboards the workspace and
installs one disabled Informational scheduled rule.
`--enable-analytics` additionally enables it. It is explicitly titled
**SYNTHETIC multi-signal training correlation** and does not create incidents.
Live validation checks the rule exists exactly once, retains the intended query
and app scope, uses the documented schedule and incident-disabled configuration,
and matches the recorded enabled/disabled opt-in. This is a configuration check,
not evidence that the query ran or produced an alert.

The six original lab queries at the root of [detections/](../detections/) provide:

- Real WAF requests with the shared run ID.
- Unusual PHP log errors, separating actual messages from synthetic examples.
- Optional supported process and network telemetry, separately labelled.
- Synthetic canary fixture access and sequence pivots.
- Correlation of real WAF activity with multiple synthetic application signals,
  optionally enriched with exported posture assessment rows.

Replace `__APP_RESOURCE_ID__` in the correlation hunting file. Bicep substitutes
the exact value for the scheduled rule. Use the UTC window, run ID, asset,
IP, host, identity and any device ID as pivots. Investigate delayed records
and health-probe/retry activity before drawing conclusions.

### What is not collected

App Service here does not expose the MDE `DeviceProcessEvents` or
`DeviceNetworkEvents` tables. The simulator **does not** create processes or
connections to make those tables appear. A supported, genuinely onboarded
workload would be a different scenario.

Defender continuous export to `SecurityRecommendation` is not configured.
That optional query source may be missing, and its assessment counts are
matching rows to review, not a verdict of public exposure or vulnerability.
The actual assessment query in `investigate` is the starting posture evidence.

Queries include an empty typed union branch and fuzzy table resolution so
optional missing tables yield warnings rather than fabricated results.
Warnings are meaningful: distinguish an uncreated table, ingestion delay,
missing permissions, unsupported telemetry, and no matching data.

The additional [platform-specific estate hunts](hunting-pack.md) do not use
optional-table fallbacks. They require their declared telemetry, and TVM queries
must run against Defender XDR data, not Sentinel's schema-only TVM visibility.
App Service HTTP diagnostics are configured here, but the benign GET simulator
does not create suspicious POSTs, large cookies, MDE records, Syslog, Application
Gateway, AKS or custom-text events. An absent hit is not a failed simulator or a
security clearance. The offline evaluator leaves every live/manual evidence
item pending operator review.

### Closure

After remediation, validate Prevention, 404 from training signal endpoints,
including an ordinary `request` without the benign WAF marker,
403 from direct origin (including copied header), workspace diagnostics,
disabled basic publishing and zero runtime role grants. Review real assessment
refreshes independently if you had an actual finding. Never mark a real CVE
closed solely because this synthetic scaffold changed state.

References:

- [Front Door origin security](https://learn.microsoft.com/azure/frontdoor/origin-security)
- [Front Door WAF policy](https://learn.microsoft.com/azure/web-application-firewall/afds/waf-front-door-create-portal)
- [Diagnostic logs](https://learn.microsoft.com/azure/frontdoor/standard-premium/how-to-logs)
- [Cloud Security Explorer](https://learn.microsoft.com/azure/defender-for-cloud/how-to-manage-cloud-security-explorer)
- [Attack paths](https://learn.microsoft.com/azure/defender-for-cloud/how-to-manage-attack-path)
- [PHP on App Service](https://learn.microsoft.com/azure/app-service/configure-language-php)
