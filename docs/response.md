# GhostPaw: detection, prevention, resolution and proof

This independent training implementation follows Microsoft's
[official PHP2Shell response](https://techcommunity.microsoft.com/blog/azurenetworksecurityblog/addressing-php2shell-cve-2026-109618-and-cve-2026-109619-upgrade-guidance-and-az/4566623)
and [three request-side WAF policies](https://techcommunity.microsoft.com/blog/azurenetworksecurityblog/azure-waf-custom-rules-for-php2shell-mitigation/4566684),
updated October 22 and reviewed October 24, 2026. It is not a Microsoft product,
an exploit, an incident-response service or a promise of CVE detection.

**Complete vulnerability remediation requires upgrading PHP. WAF is temporary,
supplementary mitigation.** `LAB_STATE=fixed` removes harmless fixtures only.

## Evidence contract and execution authorization

Start with the existing [recording](https://php2proof.ninjapaws.org/walkthrough.php#recorded)
and [hunting results](https://php2proof.ninjapaws.org/evidence/hunting). The real
16:33 UTC GhostPaw baseline has five HTTP200s, five ingested synthetic app records,
a Block/Detection WAF marker and no returned scoped provider alerts. The 18:35
hunting capture has three queried, 18 unavailable and six not-applicable cases.
Healthy assessments and an empty alert query are not patch or compromise clearance.
All observed Defender plans were Standard; no disabled-Defender experiment occurred.

The original deadline is **2026-10-24T18:45:04.967Z**. The authorization question
for a new live response window could not be answered, so it was not renewed.
No new prevention, patch, mitigation/IAM change or after-state capture is claimed.
Installing source does not authorize execution. Do not edit timestamps or weaken
expiry checks to make an old demo run. Expiry does not automatically delete
resources or stop billing.

With the response overlay installed:

- Authenticated `/response`: scripts, private previews, explicit approvals and
  persisted job results.
- Public `/evidence/response`: start-to-end guidance, scripts, source citations,
  real historical baseline and clearly labelled expected/not-run after-state.
- Public `/evidence/response/script`: readable standalone `php2proof-response.mjs`,
  bundled with shared safety helpers, embedded nonsecret dev configuration and
  Pawprint MIT attribution. No credential or live subscription ID is embedded.

## 1. Discover and detect

Retain the exact asset, runtime, exposure, run UUID, UTC window and source status.
Use the 27 hunting scenarios where their connectors and scope apply. Distinguish
raw app/WAF logs, synthetic fixtures, actual findings, genuine workload alerts
and optional Sentinel correlations. Empty/missing sources are not clearance.

Without paid components, validate PHP versions and scope, patch, inspect
independent service logs and verify prevention manually. Supported Defender CSPM
can add actual inventory/risk/attack-path context; workload protection can add
genuine detections; Sentinel can correlate supported ingested sources. No component
guarantees an alert, automatically patches PHP, or substitutes for forensic work.

## 2. Preview and confirm one scoped action

Use Node24 with Azure CLI on Linux/macOS or WSL2. Authenticate using an already
authorized identity and explicitly select the exact public-cloud subscription.
The same commands work with `node scripts/response.mjs` in this checkout, or
`node php2proof-response.mjs` after downloading the bundle.

```bash
node scripts/response.mjs plan --environment dev \
  --subscription "$AZURE_SUBSCRIPTION_ID" --suffix "$DOJO_SUFFIX" \
  --out response-prevention.json
```

Review the private JSON before separately executing:

```bash
node scripts/response.mjs prevention --environment dev \
  --subscription "$AZURE_SUBSCRIPTION_ID" --suffix "$DOJO_SUFFIX" \
  --plan response-prevention.json \
  --confirm-group NP-PHPToProof-Dev-CentralUS --yes
```

Each preview is valid for ten minutes, tied to the owned app/policy/group,
guidance revision, original expiry and exact configuration fingerprint. An
existing output file is never overwritten. A `.used` marker atomically consumes
the CLI preview; generate a **new filename and preview for every next action**.
No URL, group, command, query, package or production override is supported.
Private app settings are preserved internally, never printed or put in CLI
argument values. Temporary request bodies use private files and are cleaned.

Portal approvals additionally bind to the authenticated session and verifier
epoch, durable source job, CSRF, exact Origin, queue, lease, rate limit and
one-use private `control/response/<plan-job-id>` claim. Any scope/API/method
outside the fixed target list is denied before token acquisition.

### Write opt-in and permissions

`OPERATOR_RESPONSE_WRITES=false` is the default; Bicep's
`responseWritesEnabled=false` emits the same lowercase setting. This feature flag
is **not permission provisioning or lifetime renewal**. The source update does
not grant live write access. Separately authorize and review only:

| Permission | Exact scope |
| --- | --- |
| Front Door WAF policy read/write | Owned public WAF policy, never the operator policy |
| `Microsoft.Web/sites/config/list/action` and `Microsoft.Web/sites/config/write` | Owned public application's app-settings resource only; never operator configuration |
| `Microsoft.Resources/tags/read` / `write` | Owned main lab group, for merge-only intended WAF/state tags |
| `Microsoft.Network/frontDoorWebApplicationFirewallManagedRuleSets/read` | Subscription metadata only; included in the source metadata role |

No Contributor, pricing write, role-assignment write, deployment, DNS, deletion,
Key Vault password access or public PHP runtime grant is required by the scripts.
Do not enable the flag until the exact assignments and active authorization have
been reviewed. Missing grants fail explicitly. Credentials and private network
boundaries remain unchanged.

## 3. Prevention and three independently reviewed request rules

`prevention` is a separate explicit action. It retains existing custom/managed
rules, settings, scrubbers and associations, then merges only `dojo.wafMode`.
It never turns an existing Prevention policy back to Detection.

Request policies are restricted to the verified PHP hosts and current PHP routes,
including `/`; unrelated Node evidence routes are excluded:

| Stage action | Enforcement action | Meaning and limitation |
| --- | --- | --- |
| `session-log` | `session-block` | Multipart body contains PHP session-upload-progress token. Do not block if the application needs that feature without reviewing impact. |
| `form-log` | `form-block` | URL-decoded form field has at least20 bracket levels. This is application policy, not a vulnerability-defined threshold. |
| `multipart-log` | `multipart-block` | Inspected multipart field name has at least20 bracket levels. Quoting, encodings and WAF inspection boundaries affect coverage. |

All start in **Log**, including the session policy as a conservative lab staging
choice. Test each independently, inspect legitimate traffic and false positives,
then explicitly confirm its Block action using a new preview. Existing enforced
rules cannot be downgraded to Log. Priority collisions, changed reserved rules
and earlier terminal Allow rules are refused, not silently overwritten.

These independently authored adaptations are not verbatim vendor script copies.
They are heuristics for the selected paths, not universal exploit signatures.
New PHP routes require a separately reviewed scope update. Unit fixtures test
19/20/21-level boundaries; they are not evidence of live Azure WAF enforcement.

Prove the existing benign marker becomes403 while normal health stays200 and
origin access remains403. Actual request-rule validation must inspect matching
real WAF events and legitimate application behavior, not just configuration.

## 4. Response-side mitigation and its deliberately absent logs

`response-rule` checks the subscription's
[available managed-rule catalogue](https://learn.microsoft.com/en-us/rest/api/frontdoorservice/webapplicationfirewall/managed-rule-sets/list?view=rest-frontdoorservice-webapplicationfirewall-2025-03-01).
It requires an **already reviewed** DRS2.0/2.1/2.2 with Block anomaly policy. It
does not install a DRS or change other managed-rule actions/exclusions.

The exact group is `MS-ThreatIntel-Response-CVEs`, rule **99006001**. The rule is
disabled by default, and Microsoft expects rollout through October28. Absence or
catalogue-read failure is explicit unavailable state, not successful enablement.
The action enables this override with `AnomalyScoring`, corresponding to the
prescribed anomaly action, without forcing a conventional immediate request block.

**The response rule removes potentially malicious response elements; it does not
block/challenge traffic and produces no WAF log entries or hit counts.** Do not
invent an alert, screenshot or hit counter, and do not use their absence as a
negative test. Configuration/availability evidence and supported validation are
separate from actual compromise detection. PHP still needs updating.

Other platforms are referenced, not selected as portal execution targets:

- **Application Gateway v2:** apply the official conditional Set-Cookie rewrite,
  using the October22 corrected expression and actual route association. Do not
  delete every Set-Cookie header. Test non-production compatibility.
- **Application Gateway for Containers:** request custom rules; no regex-based
  response rewrite today. No new gateway or container environment is provisioned.

## 5. Resolve the runtime and close the training surface

Microsoft's fixed baselines are **8.2.35, 8.3.36, 8.4.27 and 8.5.12**. Upgrade all
affected deployments and supported branches. Containers require rebuilding and
redeploying the runtime-bearing image, then checking the running digest/version;
host patching alone is insufficient. VM package/backport evidence must come from
the applicable vendor.

For this managed App Service, `PHP|8.4` selects a branch, not a full patch. Check
the actual trusted health `phpVersion`. A restart or reselecting that branch is
not proof that8.4.27 is deployed. If Microsoft's managed runtime is below the
baseline, obtain the platform update or separately review a patched deployment
option. The portal does not claim a nonexistent customer-controlled exact-patch
API or silently convert the lab to a container/VM.

`resolve-fixtures` only merges `LAB_STATE=fixed` into the exact public app
settings and merges the intended state tag. It requires Prevention, preserves
other settings/expiry and never reopens the training fixture. **It performs no
PHP update.** Run it only with its own reviewed preview and confirmation.

## 6. Verify closure and handle uncertainty

```bash
node scripts/response.mjs verify --environment dev \
  --subscription "$AZURE_SUBSCRIPTION_ID" --suffix "$DOJO_SUFFIX"
```

The verification returns actual runtime, HTTP, identity and UTC evidence:

1. Trusted public health200 identifies the exact app/runtime/state.
2. All five **unmarked** fixture inputs are404.
3. The harmless marked request is403 under Prevention.
4. Origin403 is required both without and with copied FDID.
5. Public PHP identity has zero direct/inherited grants.
6. Actual full PHP version meets the reviewed branch threshold.

`resolved=true` requires all these. It remains scoped version/control evidence,
not incident clearance or replica-wide attestation. CLI exit2 reports incomplete
verification or source gaps; exit1 reports failure. Fixture closure with an old
PHP version is explicitly unresolved. Update/refresh actual vulnerability
assessments and applicable hunts on their real ingestion/scan cycles.

Writes are never automatically retried. Bounded provider-readback polling does
not replay a PUT and does not prove worldwide Front Door propagation. A network
error, partial write, audit failure or readback mismatch after a possible change
requires `reconciliation-required`. The portal stops new jobs; inspect Azure and
the durable audit as an authorized operator. Reconcile intended tags to actual
Prevention/fixed state without downgrading protection, then explicitly review
and clear the unresolved dispatch record using the approved operator process.
Do not delete audit/one-use claims or replay the old request.

Real compromise needs the organization's forensic preservation, isolation,
credential rotation and trusted rebuild procedures. These actions are not
simulated by the fixture or performed automatically by this portal.

## Packaging

```bash
node operator/build-response.mjs <new-artifact-directory>
```

The deterministic gzip overlay contains only seven fixed runtime/script paths,
is checksummed and must fit the unchanged61,440-byte protected-input cap. Its
readable standalone script keeps vendored MIT attribution and suppresses imported
libraries' CLI entry guards. Do not minify it into an opaque downloader.

The overlay must be installed after a full core deployment, alongside the
separate hunting overlay. Preserve SDK dependencies and reviewed evidence
(`clean=false`). It does not set app settings, grant roles, initialize credentials,
extend expiry, execute a response or automatically publish private results.
The existing bounded operator publisher accepts only the exact seven paths for
the `response-maintenance` kind. Its original full-release expiry rejection is
unchanged; code maintenance does not authorize new jobs or make an expired
login succeed. Publication still needs an independently authorized publisher;
no new live publishing/IAM grant was assumed when the owner was unavailable.
