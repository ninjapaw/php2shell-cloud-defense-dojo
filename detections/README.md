# Defensive investigation content

The six original lab queries below are self-contained. They include an empty typed source with
`union isfuzzy=true`; a missing optional table produces a Kusto warning and no
records from that table, not invented results. `column_ifexists` accommodates
missing optional columns. Warnings and empty results must be investigated.

| Query | Evidence |
| --- | --- |
| `waf-requests.kql` | Real Front Door WAF records, correlated by benign run marker |
| `php-errors.kql` | Actual PHP log messages or clearly labelled synthetic errors |
| `unexpected-child-process.kql` | Optional supported MDE process records, separate from synthetic examples |
| `unexpected-outbound.kql` | Optional supported MDE network records, separate from synthetic examples |
| `canary-access.kql` | In-code fabricated fixture access; no cloud secret or data-plane read |
| `correlation.kql` | Real WAF + multiple synthetic app signals, optionally enriched with exported assessment rows |

Set `RunIdFilter` and review the UTC window. For correlation, replace
`__APP_RESOURCE_ID__` with the exact deployed App Service resource ID. Resource
IDs, hostnames, client IPs, identities, device IDs, and timestamps are pivots,
not independent evidence of compromise. A single event never establishes it.

The App Service architecture does not produce MDE `DeviceProcessEvents` or
`DeviceNetworkEvents`. Do not enable a rule claiming that it does. A supported
VM/container workload and actual onboarding would be a separate scenario.
Defender continuous export to `SecurityRecommendation` is **not** configured;
the optional counts are matching assessment rows, not validated findings.
Investigate real posture directly through Resource Graph/Cloud Security Explorer.

`--enable-sentinel` explicitly onboards only the lab workspace and installs one
**disabled**, Informational scheduled correlation rule. `--enable-analytics`
additionally enables that labelled synthetic rule. Its 15-minute schedule reads
one hour, gates on recent ingestion, and does not create incidents. Late or
separately ingested events may be incomplete or repeated. No simulation runs
automatically. See [the investigation guide](../docs/investigation.md).

## Wider PHP2Shell hunting pack

The [catalog](catalog.json) adds **21 estate queries** to the six lab queries:

| Directory | Engine and coverage |
| --- | --- |
| [defender-xdr/](defender-xdr/) | TVM CVEs, PHP/version and distinct software inventory, bundled binaries/products, installed/observed worker classification, worker/listener discovery, child baseline, process/file/network hunts |
| [resource-graph/](resource-graph/) | Real posture assessments, App Service/Function/slot configuration and all-runtime discovery, registry CVE/PHP findings |
| [sentinel-log-analytics/](sentinel-log-analytics/) | Syslog crash/OOM/churn, App Service HTTP/session/cookie leads, Application Gateway WAF/access correlation, ContainerLogV2 and custom web logs |

These queries require their declared sources and do **not** hide missing tables.
XDR uses `Timestamp` for events; TVM inventory has no event timestamp.
TVM data is not ingested into Sentinel merely because the portal shows its schema.
They do not require the lab's synthetic run ID and are never automatically run
or added to the synthetic analytics rule.

[The coverage/evaluation guide](../docs/hunting-pack.md) maps all 10 upstream
asset methods and Hunts A-G, including EASM, repository/owner discovery, SBOM
review for zero-finding images, NCSC product input, exposure triage and patch
verification. It pins the reviewed source revision and distinguishes optional
telemetry from what this App Service lab actually collects.

Run `npm run evaluate` for offline syntax/type, exact output-shape,
missing-source and coverage checks. This does not execute live queries or prove
detection efficacy. All live/manual evidence remains explicitly unevaluated.
For reviewed local product input use
[`prepare-products.mjs`](../scripts/prepare-products.mjs); the empty checked-in
product table is not completed inventory coverage and no remote feed is fetched.
