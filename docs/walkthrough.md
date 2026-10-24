# PHP to Proof: the complete walkthrough

**A Code-to-Cloud Defense Story: observe, label, corroborate, and verify.**

Use this alongside the public site's **Walkthrough** page at `/walkthrough.php`.
The site is a read-only presentation: it does not run requests, enable products,
query Azure plans, or create alerts. Current status is limited to its own
training/fixed app state; the clearly dated recording is historical, not a live
plan or alert badge. All operator commands below require your separately
authorized terminal or the isolated [operator console](../operator/README.md).

The structure follows Pawton's briefing -> chapters -> with/without comparison
-> debrief pattern. The evidence contract is different: this public PHP lab
does **not** exercise a vulnerability or promise real workload-detector alerts.
Do not turn a simulated process, connection, or canary event into an attack claim.

## Recorded live walkthrough

The public chapters now show the actual redacted application record for **each
of the five moves**, with the actual WAF match beside the first move. The
[reviewed snapshot](../operator/public-evidence/92ad189c-9a88-4403-b773-52453963e4b8.json)
is the source of truth; tests cross-check the rendered timestamps, fields and
outcomes against it. The complete public recording is linked from the guide at
`/evidence/92ad189c-9a88-4403-b773-52453963e4b8`.

- Run: `92ad189c-9a88-4403-b773-52453963e4b8`.
- Requests: **2026-10-24 16:33:41.463–16:33:43.454 UTC**.
- Collection: **2026-10-24 16:36:07.232 UTC**.
- Measured: five HTTP **200** responses, five ingested **synthetic** application
  records, and the actual `DojoBenignMarker` WAF match. `Block` with `detection`
  mode and HTTP 200 is **not enforced blocking**.
- Defender: AppServices, CloudPosture and Containers were observed **Standard**.
  Four existing posture assessments were **Healthy**; these are not alerts or
  necessarily paid-CSPM-exclusive benefits. The exact-app/time-window provider
  workload-alert query succeeded and returned **no records**.

This is **not a Defender-disabled experiment**. The side-by-side view compares
source logs available independently of Defender with the actual observations
under the existing enabled plans. Conditional detection references remain
explicitly separate from the recorded results. No shell, real outbound
connection, secret access or compromise occurred, and no missing alert is
replaced with a demonstration alert.

## 0. Mission briefing

**The story:** a request reaches a PHP application with three fabricated ledger
records. Your job is to establish which asset was involved, what the edge did,
what the application actually recorded, which risk context is available, and
whether the controls and closure checks work.

**The base architecture:** Front Door Premium/WAF -> restricted Linux PHP App
Service B1 -> lab Log Analytics workspace. Linked Application Insights is
provisioned; it is not a promise of application traces or Defender detections.
The application identity needs zero Azure role grants. There is no real ledger,
secret canary, child process, or outbound connection in the public scenario.

Before presenting:

1. Read [the README](../README.md), [operations](operations.md), and
   [the safety disclaimer](../DISCLAIMER.md). Use only an isolated, authorized
   training subscription with approved costs.
2. Use the documented Node/PHP and Linux/macOS or WSL2 cloud toolchain.
   Native Windows supports offline planning and local tests, not the Azure
   lifecycle adapter. Sign in and explicitly select the correct subscription
   as described in the README.
3. Set `AZURE_SUBSCRIPTION_ID` and `DOJO_SUFFIX` to the actual run. Keep the
   original JSON `resourceGroup`, region, subscription, and suffix for an
   existing lab. Changing a suffix alone does not select a new group.
4. For a fresh deployment, follow the README's
   [plan/deploy sequence](../README.md#plan---investigate---close-the-loop).
   Do not try to adopt an unowned group or reuse an existing run under a new
   suffix. Do not deploy the optional private AKS track just to view the guide.
5. Capture current application state, WAF mode, workspace, resource IDs, and
   actual Defender/Sentinel plan/component settings. `validate` reports the
   observed `defenderCspm` pricing tier; an omitted CSPM flag is not evidence
   that an existing subscription plan is off.

**Presenter opening:** "We will generate harmless HTTP requests and inspect real
edge behavior. Some application messages describe attack-shaped activity, but
they are synthetic fixtures. Any actual Defender assessment or alert must be
independently observed and labelled."

**Stop conditions:** wrong asset/ownership, failed normal HTTPS, direct-origin
access, unexpected runtime grants, or unexplained blocking. Never weaken
restrictions, add broad permissions, or disable shared plans to force the demo.
There is no guaranteed completion time for discovery, logs, or detections.

## Present the attack: five moves, two investigation views

The public walkthrough now tells **The request that wanted a shell**. Like
Pawton, it pairs a fictional attacker's move with the analyst's raw clues,
the additional detection context a supported Defender plan could provide,
and the control that breaks the chain. Unlike Pawton's bounded SQL tests,
these PHP chapters do not execute the attack or promise detector triggers.

**Ghostpaw is fictional.** The sequence is narrative order, not an ingestion or
detection timetable. The recorded rows carry actual UTC timestamps; a new
simulator run has its own UUID and must not be confused with this recording.

| Move | Attacker's intent | What this replay actually does | Conditional Defender reference |
| --- | --- | --- | --- |
| `request` | Find an exposed PHP entry point | Benign request; real WAF evaluation and labelled app fixture | Injection attempts: supported cloud-native request-pattern detection, not a CVE signature |
| `php-error` | Turn parsing input into execution | Logs a simulated error; no crash or exploitation | Remote code execution: investigate real suspicious request patterns, not a fixture string |
| `process-synthetic` | Start a child process or shell | Logs a process-shaped fixture; no process starts | Web shell activity: supported runtime detection needs real relevant activity |
| `outbound-synthetic` | Contact an external destination | Logs a connection-shaped fixture; no egress occurs | Compromise indicators: no promise of a network alert from this replay |
| `canary` | Reach valuable data or credentials | Returns three fabricated in-code records | No guaranteed data-access/canary detector; no real sensitive-data relationship is created |

The first four labels are **categories**, based on Microsoft's current
[App Service alert reference](https://learn.microsoft.com/azure/defender-for-cloud/alerts-azure-app-service).
They are not asserted exact alert titles, detector IDs, severity values, or
coverage for a particular Linux workload or CVE. Verify current platform and
detector support. The reference cards are educational summaries, not product
screenshots or records returned by Defender.

### Show the evidence, then the queue

1. Read Ghostpaw's intent. Explain that it is the proposed attack, not a claim
   that this application performed it.
2. Read **Actual ingested log from the recorded run**. Each redacted row shows
   the actual UTC, signal, `Synthetic: true`, and
   `EvidenceKind: synthetic-application-log`. These are source-query
   projections of ingested `DOJO_EVENT` fixtures, not full raw console lines
   or illustrations. The run ID and collection window appear above the moves.
3. Compare **Without workload Defender / raw clues** with **With supported
   Defender / conditional result**. WAF and logs remain useful without optional
   plans. A supported workload detector adds its own investigation context only
   when it observes relevant real activity; reading the guide does nothing.
4. Read **Break the chain**. Distinguish prevention, patching, least privilege,
   and verified removal from alerting or simply closing an alert.
5. Use the public **Alerts and expected results** matrix. An empty queue is a
   legitimate result, not a reason to present a reference card as a live alert.

### What should appear with each profile?

| Profile | Expected from this safe replay | Not established |
| --- | --- | --- |
| Base lab, no optional Defender/Sentinel | Delivered WAF records and synthetic app logs; manual KQL | A native Defender alert, scheduled Sentinel alert, or incident |
| Paid Defender CSPM | Actual supported posture/graph results if available | Shell/process detections, a guaranteed CVE assessment, or an attack path |
| Defender for App Service | Same harmless replay; any real supported detection needs independent evidence | A promised alert from the process, outbound, or canary fixture |
| Sentinel only | Disabled Informational rule configuration | Scheduled evaluation or incident creation |
| Sentinel plus analytics | Possible Informational **synthetic** correlation alert when the query matches | A Defender detection or automatic incident |

For a real alert, open **Defender for Cloud -> Security alerts**, filter the exact
resource and UTC window, and retain only returned ID/title/severity/evidence/status.
Keep assessments/recommendations separate. For the optional Sentinel rule, use
its actual configuration and query/health results; the illustrated rule card is
not proof of evaluation. Do not publish tenant alert data or screenshots without
review and appropriate redaction.

## Component map: what changes with and without Defender?

This is a capability comparison, **not a live plan report**. Check the correct
subscription in **Defender for Cloud -> Environment settings**, including
component settings and support. Do not disable an existing shared plan merely
to create a "without" screenshot.

| Layer | Without the optional component | With it | What this repository actually does |
| --- | --- | --- | --- |
| Front Door WAF + diagnostics | Not a supported removal mode; they are the base lesson | Real request evaluation and delivered edge/app logs | Always provisions these for the public lab; paid Defender plans are not required for them |
| Foundational CSPM | Absence of paid CSPM does not remove all posture capabilities | Free supported inventory, recommendations, and posture information can still exist | Does not claim that Free means "no security" |
| Paid Defender CSPM | Use actual Azure configuration, available foundational recommendations, and manual log correlation | Supported security graph, risk prioritization, Cloud Security Explorer, and attack paths | Explicit `--enable-defender-cspm` requests subscription-wide `CloudPosture` Standard; no other Defender plan is enabled |
| CSPM Serverless protection | Standard pricing alone is not proof of enabled coverage or a completed Web App scan | Supported Web App/Function discovery and posture with the component enabled | Does not validate this component's setting, assessment completion, or specific CVE coverage; verify them separately |
| Defender for App Service | No expectation of App Service workload-protection alerts from a disabled plan | Separate plan-specific detections and context for supported features/platforms | Not enabled by the lab's CSPM flag; safe fixture requests are not guaranteed triggers; no MDE process tables are supplied |
| Defender for Servers / MDE | No real process/network endpoint telemetry in this PaaS design | Real telemetry from a supported, actually onboarded machine | No VM in the base lab; enabling a plan does not make App Service an MDE device |
| Defender for Containers | Public App Service lesson unchanged | Supported private AKS/registry assessments and workload telemetry in the separate track | Separate lab requires existing plans and validates its actual cluster/image/sensors; no public exploit endpoint |
| Microsoft Sentinel | Hunt directly in Log Analytics; no Sentinel incident or rule expected | Workspace investigation and optional scheduled analytics | `--enable-sentinel` installs one disabled Informational synthetic rule |
| Enabled synthetic analytics | Rule remains disabled; queries are manual | Matching ingested evidence can produce a synthetic correlation alert | Requires Sentinel plus `--enable-analytics`; `createIncident: false`, no playbook or Defender connector |

Paid CSPM posture, workload-protection alerts, WAF blocking, and SIEM correlation
are different capabilities. A paid plan does not guarantee a particular CVE,
attack path, runtime alert, or ingestion result. Product support and relevant
components must also be present.

### Choosing an explicit profile

For the base public lesson, use ordinary reviewed deployment without opt-ins.
Existing subscription plans are left alone. To add optional capabilities, first
review `plan` with the **same flags** you will use for `deploy`:

```bash
# Optional subscription-wide paid CSPM; not App Service/Servers/Containers
bash scripts/dojo.sh plan --environment dev --enable-defender-cspm
bash scripts/dojo.sh deploy --environment dev --yes --enable-defender-cspm

# Optional Sentinel workspace onboarding; rule remains disabled
bash scripts/dojo.sh plan --environment dev --enable-sentinel
bash scripts/dojo.sh deploy --environment dev --yes --enable-sentinel

# Optional enabled synthetic analytics; incident creation remains off
bash scripts/dojo.sh plan --environment dev --enable-sentinel --enable-analytics
bash scripts/dojo.sh deploy --environment dev --yes --enable-sentinel --enable-analytics
```

Combine approved flags if you need both CSPM and Sentinel. These are real writes
with applicable charges, not browser demo toggles. No subscription plan is
disabled by omitting a flag or uninstalling the lab. Serverless protection and
other workload plans need separate owner review; this guide does not silently
enable them. Existing fixed/Prevention state and original expiry are preserved.

## 1. Discover and validate the exact asset

**Operator:**

```bash
bash scripts/dojo.sh plan --environment dev
bash scripts/dojo.sh doctor --environment dev
bash scripts/dojo.sh validate --environment dev
```

Open the host's `/health.php`. Record `scenario`, `environment`, `state`,
`resourceId`, `phpVersion`, and `syntheticEndpointsEnabled`. Compare the asset
against independently read Azure resources, not just a URL or screenshot.

**Expected:** normal HTTPS succeeds; the configured app/edge/WAF/workspace
identities match; the plan remains Linux B1, capacity one; diagnostic routing
and disabled FTP/SCM basic publishing are verified; no app-scope runtime grants
exist. The direct origin must return **403**, including with a copied Front
Door ID header. A DNS failure or redirect is not this validation.

- **Without paid CSPM:** Azure resource configuration, health, logs, and available
  foundational recommendations are enough to begin the lesson.
- **With paid CSPM:** also start from the exact resource in Cloud Security
  Explorer and review the relationships actually supported and returned.

**Ask the audience:** "Which route is public, and which control keeps clients
from bypassing the edge?" The answer needs the service tag **and** profile
header restriction plus the observed origin-denial tests.

## 2. Generate one bounded run

```bash
bash scripts/dojo.sh simulate --environment dev --yes
```

The simulator first validates the live resource context, derives its Azure
endpoint, and sends at most five benign requests sharing a UUIDv4 run ID.
Only the first carries `dojoProbe=waf-marker`. It does not accept an arbitrary
URL/host/IP override. Save its run ID and UTC start/end.

**Expected in training + Detection:** all five requests return **200** and
identify this scenario/run. The custom rule has Block action, but Detection
does not enforce the block. Real WAF records must be checked after delivery.
There is no guarantee of exactly five log rows: validation has its own run and
health checks/retries can add unrelated records.

| Signal | What actually happens | What must not be claimed |
| --- | --- | --- |
| `request` | Benign HTTP request, real edge evaluation, synthetic app event if it reaches PHP | Exploitation or managed-rule CVE protection |
| `php-error` | A simulated unusual error string is logged | A real exception, crash, or vulnerable build |
| `process-synthetic` | A labelled process-shaped app event is logged | A child process, shell, or MDE process event |
| `outbound-synthetic` | A labelled connection-shaped app event is logged | Actual egress or command-and-control traffic |
| `canary` | A constant fabricated fixture with three records is returned | Secret access, an Azure data-plane read, or exfiltration |

- **Without workload protection:** the real WAF behavior and labelled app logs
  still exist; investigate them manually.
- **With workload protection:** the same safe run happens. Any supported detector
  output is additional, independently observed evidence, not a promised result.

**Presenter line:** "A real log about a simulated process is still a simulated
process. We have not run the behavior the message describes."

### Running through the authenticated operator console

Use the separately deployed [operator console](../operator/README.md) when a
credentialed, auditable interface is required. Its deployment outputs the operator
URL; the public PHP application does not receive privileged routes or Azure grants.
Retrieve the generated credentials through an authorized private-network Key
Vault client, not from a public page or deployment log.

Start **GhostPaw: five harmless moves**. The console persists intent, validates
the exact lab and original lifetime, then reuses the guarded simulator. Keep the
resulting run ID, UTC window and individual HTTP outcomes. Refreshing the status
page does not replay requests. **Collect current logs** re-queries that persisted
run when ingestion lags, without generating another attack-shaped fixture.

Raw evidence is private. A public capture is a separately reviewed, field-allowlisted
snapshot with its own capture time and source availability. Match the five request
signals to actual ingested application records; show the WAF policy mode beside
the recorded action and observed HTTP outcome. Duplicate WAF rows are not multiple
incidents. Show actual Defender plan/assessment/alert observations separately.

Do not call this a Defender-off experiment when plans were enabled. The left-hand
baseline is actual app/WAF evidence available independently of Defender; the
Defender side contains only additional observed records, or an explicit
not-observed/unavailable result. Four Healthy posture recommendations are not
four attack detections, and an error-channel synthetic event is not compromise.

## 3. Build the evidence timeline

Open **Logs** on the exact lab workspace. Set `RunIdFilter` in the
[six lab queries](../detections/README.md), review the UTC window, and replace
`__APP_RESOURCE_ID__` in [correlation](../detections/correlation.kql).

1. [WAF requests](../detections/waf-requests.kql): inspect the real rule, action,
   request URI, resource ID, tracking reference, host, client IP, and time.
2. [PHP errors](../detections/php-errors.kql): distinguish observed PHP messages
   from the synthetic `php-error` fixture.
3. [Child process](../detections/unexpected-child-process.kql) and
   [outbound](../detections/unexpected-outbound.kql): keep synthetic app examples
   separate from optional, supported endpoint telemetry.
4. [Canary access](../detections/canary-access.kql): explicitly label the constant
   fabricated fixture; no real data source is accessed.
5. [Correlation](../detections/correlation.kql): same run ID, exact app, multiple
   synthetic signals, and the real WAF marker. Preserve the evidence-kind label.

**Expected when delivered:** WAF logs in `AzureDiagnostics` and app console
records in `AppServiceConsoleLogs`. Diagnostic configuration is not proof of
ingestion. Investigate missing tables, permissions, destinations, limits,
query windows, and delivery before drawing a conclusion.

- **Without additional Defender telemetry:** the defensible outcome is real
  benign WAF activity correlated with synthetic application signals.
- **With genuine supported telemetry elsewhere:** review those source records
  separately, including actual device/resource identities and timestamps.
  The App Service lab itself does not emit `DeviceProcessEvents` or
  `DeviceNetworkEvents`. No flag here makes those tables appear.

Defender continuous export to `SecurityRecommendation` is not configured.
The query's optional posture counts are rows to review, not a vulnerability or
public-exposure verdict. Optional-table warnings are not successful detections.
The [wider hunting pack](hunting-pack.md) has separate prerequisites and does
not run automatically.

## 4. Review actual Defender posture

```bash
bash scripts/dojo.sh investigate --environment dev
```

This queries actual Resource Graph assessments, scoped to the lab group/app,
using PHP and CVE-2026-109618/CVE-2026-109619 as search terms. It prints at most
50 matches and the wider catalog; it does not scan the estate or invent data.
If the limit is reached, review a broader appropriately scoped query.

- **Without paid CSPM features:** use available foundational recommendations,
  actual configuration, runtime evidence, and the vendor advisory.
- **With paid CSPM features:** pivot in Cloud Security Explorer through actual
  asset/exposure/identity/data relationships. Review attack paths only if the
  product returns them. For Web App serverless posture, verify that component,
  current resource support, and actual assessment independently.

**Expected alternatives:** real matching assessments; an explicit empty result;
or a meaningful permissions/coverage/readiness error. An empty query is not a
clearance. The lab has no real sensitive data or intentionally excessive
identity grants, so an absent sensitive-data relationship or attack path can
be entirely normal.

**Do not claim:** a matching search term proves this runtime is affected,
Standard pricing proves a completed scan, or the synthetic run triggered a
Defender alert. Inspect the actual assessment, advisory, affected version,
resource/digest, and evidence first. See [the investigation guide](investigation.md).

## 5. Compare manual hunting, Sentinel, and enabled analytics

**Without Sentinel:** run the same KQL in Log Analytics. Manual investigation
does not require Sentinel.

**With `--enable-sentinel` only:** the lab workspace is onboarded and one
Informational scheduled rule is installed **disabled**. No automatic evaluation
is expected while it remains disabled.

**With `--enable-sentinel --enable-analytics`:**

- Rule: **PHP to Proof - SYNTHETIC multi-signal training correlation**.
- Schedule: every **15 minutes**, looking back **one hour**.
- Match: a WAF marker and **at least two distinct synthetic app signals** for
  the same run, exact app scope, and a recent-ingestion gate.
- Possible outcome: a synthetic correlation alert when the query matches,
  not a Defender workload-protection alert or proof of compromise.
- **No Sentinel incident is expected:** `createIncident: false`.
- No Defender alert connector, continuous export, automation/playbook, or
  estate hunt is enabled by these flags.

Ingestion and evaluation are asynchronous; late/separate delivery can miss a
match, and repeated matches are possible. Configuration validation does not
prove that the rule executed. Inspect query results and actual rule health.
Do not invent an alert, incident, or completion time for the narrative.

## 6. Prove WAF Prevention

Continue into the [official PHP2Shell response workflow](response.md) for the
downloadable/portal scripts, three independently staged Log-to-Block request
policies, response rule99006001 availability and its deliberately absent logs,
and actual PHP patch verification. The linked Microsoft guidance is the source;
the harmless marker below is not a CVE signature. The response controls default
off and do not renew an expired window or grant IAM permissions.

Before changing mode, review legitimate traffic, the actual custom-rule match,
and origin isolation. Then explicitly run:

```bash
bash scripts/dojo.sh protect --environment dev --yes
bash scripts/dojo.sh simulate --environment dev --yes
```

| Check | Training + Detection | Training + Prevention | Fixed + Prevention |
| --- | --- | --- | --- |
| Normal homepage and health | 200 | 200 | 200; health reports fixed |
| Benign marker request | 200 | 403 at WAF | 403 at WAF |
| Other four unmarked simulator signals | 200 | 200 | 404 at PHP; simulator deliberately refuses a fixed lab |
| Ordinary unmarked `request` signal | 200 | 200 | 404 at PHP |
| Direct origin, with/without copied FDID | 403 | 403 | 403 |

In Prevention the blocked marker does not reach PHP, so its synthetic app event
is absent; the four other benign simulator requests still reach PHP. Match the
actual run IDs, not exact global row counts.

This control works **with or without paid Defender plans**. CSPM does not perform
the inline block. The custom rule is a learning marker, not a CVE signature.
Managed-rule CVE coverage requires independent vendor mapping and authorized
evidence; no exploit payload is supplied.

## 7. Remove training surfaces and verify closure

**Fixture closure is not PHP remediation.** Microsoft's reviewed baselines are
8.2.35, 8.3.36, 8.4.27 and 8.5.12. A managed App Service branch setting is not a
full patch version; verify the running runtime and actual asset findings.
The [resolution/verification scripts](response.md#5-resolve-the-runtime-and-close-the-training-surface)
keep those results separate and return incomplete status when PHP still needs
updating. Request mitigation and response sanitization never replace patching.

```bash
bash scripts/dojo.sh remediate --environment dev --yes
bash scripts/dojo.sh validate --environment dev
```

**Expected:** fixed app state, `syntheticEndpointsEnabled: false`, Prevention,
normal homepage/health still working, and **404 for all five unmarked training
signals**. A marked request can still receive WAF 403; that response alone
does not establish application removal. Validation also checks origin isolation,
diagnostics, basic publishing, runtime plan, and app-scope permission boundaries.

The simulator refuses fixed state. `repair` preserves fixed/Prevention state,
opt-ins, and original expiry; it is not a reset button. Replay requires a newly
planned isolated lab, not silently reopening a remediated one.

- **Without actual Defender findings:** retain the verified configuration and
  HTTP evidence and describe the limited closure honestly.
- **With actual findings:** additionally verify the real affected component,
  patch/build or image digest, and later assessment refresh for the same asset.
  Changing this synthetic state or closing an alert is not CVE remediation.

## 8. Debrief and cleanup

Save a small evidence record: run IDs, UTC windows, resource/workspace identities,
observed runtime/state/WAF mode, actual query results with source labels, actual
assessment/alert IDs if any, origin-denial checks, and before/after responses.
Redact identifiers appropriately before sharing. Do not capture secrets.

**Presenter closing questions:**

1. Which evidence was real activity, and which was synthetic content?
2. What could we demonstrate without paid Defender components?
3. Which extra context actually appeared with supported components enabled?
4. Did we prove a detector fired, or only that its configuration exists?
5. Did we remove a synthetic surface, patch a verified component, or both?
6. What remains billable, and who owns its cleanup?

When teardown is approved:

```bash
bash scripts/dojo.sh uninstall --environment dev \
  --confirm-resource-group '<exact-owned-resource-group>'
```

Replace the placeholder only with the reviewed group from configuration,
ownership tags, and plan. `--yes` cannot bypass exact confirmation. Remove this
run's Cloudflare routing CNAME **before** releasing its Azure hostname; uninstall
does not delete shared or run DNS records. The original expiry is metadata, not
automatic teardown, and a 1 GB/day ingestion cap is not a total cost ceiling.

The exact lab group is deleted; unrelated groups and subscription Defender
pricing are not. Review remaining plans separately with the subscription owner;
do not disable protection used by other workloads.

## Optional advanced track: private affected-versus-fixed containers

Use [the separate container guide](container-lab.md) only after reviewing its
additional prerequisites, isolation, permission, and cost boundaries.

- Digest-pinned PHP **8.4.26** and upstream-fixed **8.4.27** comparison on private
  AKS; no public ingress, exploit endpoint, real sensitive data, or app grants.
- Existing Defender Containers and CSPM Standard with relevant registry
  assessments are required. The deployment enables this cluster's monitoring,
  not subscription pricing. Do not proceed without the approved prerequisites.
- Separate group/suffix and lifecycle; never use the private workload as the
  public site's Cloudflare target. Do not change another existing private run.
- Validate actual serving versions, image digests, ready sensors, and observed
  assessment evidence. A configured sensor is not a completed scan.
- `test-detection` runs only `id` through the authorized Kubernetes control
  plane. It is real administrative activity, not exploitation and **not a
  guaranteed Defender alert**.
- Inspect actual CVE/package/version/digest details. OS findings are not
  automatically PHP2Shell findings; absent CVEs are not a clearance. Remediation
  changes the serving digest, while prior images remain until explicit teardown.

This is the appropriate separate story for real image/version comparison.
It does not transform the public App Service's synthetic events into runtime
detections. Its own guarded teardown is required.

## Troubleshooting: what an empty or unexpected result means

| Observation | First checks / honest interpretation |
| --- | --- |
| Public walkthrough says status is not queried | Intentional: no browser Azure credentials or runtime management roles. Use operator validation and the correct portal subscription/component settings |
| Plan omitted but validation reports Standard | A pre-existing subscription plan may already be enabled; omission does not turn it off |
| No PHP/CVE assessment or attack path | Verify exact asset, component support/settings, advisory/build evidence, permissions, and discovery status; no result is not proof of safety |
| No WAF/app log table or matching rows | Verify diagnostic destinations/categories, resource IDs, run ID, UTC range, ingestion limits, permissions, and delivery; do not invent timing or records |
| No MDE process/network rows | Expected from this App Service design; synthetic events do not create endpoint telemetry |
| No Defender alert | Harmless simulator inputs are not promised triggers; verify actual plan/resource support and detector evidence separately |
| Sentinel present but no evaluation | `--enable-sentinel` installs the rule disabled; check explicit analytics opt-in and rule health |
| Analytics enabled but no incident | Expected: incident creation is disabled; even a synthetic alert needs the query's ingested evidence to match |
| Marker is 403 but ordinary requests work | Expected in Prevention; inspect the actual WAF rule/action |
| Simulator refuses after remediation | Expected fixed-state safety; repair does not reopen training |
| Custom hostname is not ready | Base Azure endpoint remains usable. Verify DNS-only CNAME, ownership TXT, Azure approval, WAF/route binding, and managed TLS; a CNAME alone is not activation |
| Direct origin succeeds or normal HTTPS fails | Stop; investigate the actual resource/routing/ACLs. Never loosen restrictions or count a redirect/unrelated denial as validation |

## Plain-language glossary

- **Posture / CSPM:** configuration and risk context, not inline HTTP prevention.
- **Workload protection:** product-specific detection on a supported resource
  with actual relevant telemetry.
- **Log:** a record; **alert:** a detector's conclusion to investigate;
  **incident:** grouped investigation work. They are not interchangeable.
- **Assessment:** an actual security evaluation, not a CVE keyword match.
- **Attack path:** a product-returned supported chain of preconditions; it is
  not inferred from a public URL alone.
- **Synthetic:** fabricated and labelled training content. Its real ingestion
  does not make the described process or connection happen.
- **Run ID / UTC window:** the experiment's shared UUID and time range, used to
  separate the run from validation, retries, and health probes.

## Primary references

Product boundaries checked against current first-party documentation:

- [Foundational and paid CSPM](https://learn.microsoft.com/azure/defender-for-cloud/concept-cloud-security-posture-management)
- [CSPM Serverless protection and component requirements](https://learn.microsoft.com/azure/defender-for-cloud/serverless-protection)
- [Defender for App Service and investigation diagnostics](https://learn.microsoft.com/azure/defender-for-cloud/defender-for-app-service-introduction)
- [App Service detection categories and alert reference](https://learn.microsoft.com/azure/defender-for-cloud/alerts-azure-app-service)
- [Sentinel scheduled analytics and incident settings](https://learn.microsoft.com/azure/sentinel/create-analytics-rules)
- [Current Defender feature support](https://learn.microsoft.com/azure/defender-for-cloud/support-matrix-defender-for-cloud)
- [Defender for Containers support](https://learn.microsoft.com/azure/defender-for-cloud/support-matrix-defender-for-containers)
- [Front Door origin security](https://learn.microsoft.com/azure/frontdoor/origin-security)
- [Front Door diagnostic logs](https://learn.microsoft.com/azure/frontdoor/standard-premium/how-to-logs)
- [Defender pricing](https://azure.microsoft.com/pricing/details/defender-for-cloud/)

See also [the detailed investigation guide](investigation.md), [hunting
prerequisites/evaluation](hunting-pack.md), and [operations](operations.md).
