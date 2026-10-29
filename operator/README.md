# PHP to Proof operator console

A separate Node.js operator application runs the existing guarded, harmless
GhostPaw scenarios and captures actual Azure evidence. It never adds Azure grants
to the public PHP application's identity.

## Access and credentials

The deployment outputs `operatorUrl`. This is a separate HTTPS Front Door origin,
not an administrator route in the public PHP app. Both origins reject direct
access, including requests with a copied Front Door ID. The operator endpoint has
its own Prevention policy; the public lab's existing WAF mode is preserved.

Credentials are generated inside Azure and stored in the private Key Vault:

| Secret | Purpose |
| --- | --- |
| `operator-admin-username` | Administrator username |
| `operator-admin-password` | Generated administrator password |
| `operator-admin-verifier` | Salted scrypt verifier, epoch and validity metadata |

The running operator identity can read **only the verifier secret**, not the
password secret. Passwords, Azure tokens and session cookies are never displayed
by an application endpoint or written to deployment outputs. Obtain credentials
through an authorized, VNet-connected Key Vault client. Azure control-plane
ownership alone does not grant secret-value access, and a browser outside the
private network cannot retrieve private vault values merely by opening Portal.

This is the requested local-credential login, not Entra/MFA sign-in. Restrict who
can retrieve the password. Disable/rotate the verifier epoch to revoke sessions.
There is no public password-reset or credential-display endpoint.

For the recorded deployment, use
[administrator sign-in](https://p2p-proof1023c-operator-dacubycsdbh4etck.b01.azurefd.net/login).
The vault is `p2p-proof1023c-operator`; retrieve `operator-admin-username` and
`operator-admin-password` through authorized private-network access. No password
is included in this repository or the public recording. The original fixture
execution ended at **2026-10-24 18:45:04.967 UTC**. The separately authorized
private window below does not renew those public-lab actions.

Missing, disabled, expired, malformed or inaccessible credentials fail closed.
Authentication, session storage, audit, queue and lease failures deny execution;
they do not produce empty successful dashboards.

## Available operations

| Console action | Actual behavior |
| --- | --- |
| GhostPaw simulation | Existing `execute()` validation, then five bounded harmless requests |
| Validate | Exact ownership, live routing, WAF configuration, HTTPS, origin isolation, diagnostics and runtime-role checks |
| Investigate | Guarded validation followed by exact-lab matching posture observations |
| Domain check | Existing read-only custom-domain checks |
| Collect evidence | Re-query an existing persisted simulation window; never replay its requests |
| Private live exercises (`/live`) | Separately opted-in, short-lived private process/transport tests, measured fixes, verification and isolated reset |

The full CLI hunting catalogue remains in [the hunting guide](../docs/hunting-pack.md).
There is no arbitrary command, query or target input.

### Hunting scenarios, queries and additional value

Open `/hunts` after sign-in. All 27 reviewed query scenarios and 20 discovery,
detection and closure walkthroughs are included. Run an individually allowlisted
lab hunt or evaluate the whole catalogue. The actual bound query, UTC window,
result rows and source gaps are saved privately. Unsupported XDR/estate methods
show their requirements, never invented rows or a successful empty hunt.

The deployment-only `OPERATOR_HUNT_CAPTURE_ID` UUID can authorize one audited,
lease/deadline/expiry-bounded read-only capture without reading the administrator
password. Its durable claim prevents automatic replay. It is not an HTTP route
or public execution bypass. Disable the setting after collecting the candidate;
manual review and a separate static publication are still mandatory.

`protect`, `remediate`, deployment/repair, DNS writes, teardown, container execution
and security-plan changes remain unavailable as generic lifecycle commands.
The separate [official-response workflow](../docs/response.md) exposes reviewed
scripts and fixed, independently approved response actions at `/response`.
`OPERATOR_RESPONSE_WRITES` defaults off; source installation does not add write
grants or renew the lab. An administrator must separately authorize the window,
feature opt-in and exact WAF/app-settings/tag permissions before mutation controls
can run. Public PHP identity grants remain zero. No generic lifecycle deploy,
command, target, package upgrade or DRS installation is exposed.

The `/evidence/response` public guide and `/evidence/response/script` download
are read-only. The bundled script includes the shared ownership/expiry guards,
requires already authorized Azure CLI access, and consumes a private preview file
once per selected action. Run the first preview command, inspect its JSON, then
independently approve the mutation; do not blindly pipe the examples together.
Neither script nor UI equates fixture removal with a PHP security update.
Failed/uncertain writes stop as `reconciliation-required`, never auto-replay or
restore exposure. Consult the response guide before manually reconciling.

The console must not disable Defender, reopen the fixed public app, weaken its
WAF, or turn the intentionally harmless public site into an RCE workload.
The private reset described below is restricted to a different, disposable AKS
deployment and never changes the public PHP version.

The Microsoft App Service `/This_Will_Generate_ASC_Alert` validation marker is
also deferred until registration eligibility and its observation deadline are
verified. Microsoft documents a possible 24-hour registration wait and roughly
1.5 hours or 2-4 hours for an alert. No request or alert is claimed when the
prerequisites do not fit the original lifetime.

## Private live exercises, fixes and reset

The `/live` catalogue is a separate authorization boundary, not an extension of
the original simulator. See the [private comparison guide](../docs/container-lab.md#private-portal-window).
Its closed actions are:

| Action | Measured behavior |
| --- | --- |
| Preview | Read the actual private target, PHP/digest and operator test-rule state; produce a session-bound ten-minute approval |
| Process probe | Run only administrative `id` in the exact isolated, non-root PHP pod; retain actual stdout and AKS command-result metadata |
| Transport probe | Send a benign UUID marker to the read-only operator edge route; retain the real HTTP response |
| WAF Log / Block / Remove | Change only this window's marker rule; preserve Prevention, managed rules and all other controls; verify edge propagation |
| Fix | Move the private deployment from the reviewed affected digest to the reviewed fixed digest; measure actual serving PHP before and after |
| Reset | Separately confirm a fixed predecessor before restoring only the reviewed affected private digest |
| Verify / Collect | Inspect actual runtime state or re-query an existing run without replaying it |
| Reconcile | Record current measured state after an uncertain job; never relabel an unobserved earlier action successful |

These are **real administrative activity and enforcement tests**, not a PHP
exploit, webshell, arbitrary command interface or proof of compromise. Every
write consumes one fresh preview tied to the same session, verifier epoch,
window, target and exact typed resource-group confirmation. Scripts are shown
before approval. An unknown or partially observed write stops with a durable
reconciliation requirement; it is not automatically retried or rolled back.

The reviewed owner capture runs Log, process probe, baseline HTTP, Block, Fix,
Verify, Reset, Verify, final Fix, Verify, and Remove. It leaves the private
runtime fixed and removes its test-only WAF rule. The real timestamps, query
outcomes, source gaps and before/after versions remain private until a complete
redacted candidate is explicitly reviewed.

Activation is out of band and requires all of the following:

- `OPERATOR_LIVE_WINDOW`: an exact six-field JSON document containing
  `schemaVersion=1`, a fresh UUID `id`, UTC `notBefore`/`expiresAt`, exact
  `resourceGroup=rg-p2sc-SUFFIX-dev`, and `autoTeardown=true`. Maximum four hours.
- `OPERATOR_LIVE_TARGET`: independently observed exact cluster/registry IDs,
  matching live-group markers, and distinct pinned affected/fixed derived image
  digests with observation timestamps inside that window.
- A deployed, enabled exact-group expiry workflow, private-cluster isolation,
  authenticated ACR, and ready Defender monitoring.
- Only the scoped private runner/Kubernetes permissions, exact operator test-WAF
  permission, and exact capture-report permission. The owner renewal additionally
  needs a temporary write grant on **only the verifier secret**.

`OPERATOR_LIVE_AUTHORIZE_ID` and optional `OPERATOR_LIVE_CAPTURE_ID` must equal
the approved window UUID. Durable owner intents prevent automatic reauthorization
or capture replay after an ambiguous restart. Renewal preserves the stored
username and scrypt password verifier, changes the verifier epoch and validity
only, and never reads the live password. Remove the temporary verifier-write
grant once renewal is proved. Keep original expiry, credential initialization,
legacy capture and public response-write settings unchanged.

The public `/evidence/live` recording and optional `/walkthrough.php` route are
read-only. Missing or incomplete reviewed evidence is explicitly unavailable;
fixture/unit-test results cannot become a live recording. The comparison shows
actual baseline sources independently available without Defender alongside
actual Defender observations while plans remain enabled. It does **not** claim
an observed Defender-off run or a guaranteed alert.

## GhostPaw and evidence

The simulator sends `request`, `php-error`, `process-synthetic`,
`outbound-synthetic` and `canary`, with the benign WAF marker on the first request.
It reuses [the existing guarded lifecycle](../scripts/dojo.mjs), including exact
resource ownership, independent endpoint checks, origin rejection, redirects
refused, 15-second/64-KiB responses and 250-ms scenario pacing.

The original simulator's application events are real ingested records containing **synthetic
fixtures**. No shell, process, real egress, sensitive data read or compromise is
performed.

Private run pages retain the run ID, UTC window, HTTP outcomes, collection time,
queried sources, observed plan tiers and explicit unavailable/not-observed states.
Collection may lag ingestion: use **Collect current logs** on the original run.

Keep these facts separate:

- WAF `Action=Block` with `WafMode=detection` and HTTP 200 is not enforced blocking.
- Duplicate WAF records do not represent multiple incidents.
- PHP/FastCGI error-channel transport does not make a fixture a real PHP exception.
- Healthy Defender recommendations are posture assessments, not workload alerts.
- Actual provider alerts are filtered to the exact app and time window. Temporal
  overlap alone does not prove that a harmless fixture caused an alert.
- Empty or unavailable evidence is not proof of safety or a successful detection.

The comparison is **raw WAF/app-source evidence available independently of
Defender** versus **actual observations under the enabled Defender plans**.
It is not an observed Defender-disabled control run. Existing subscription plans
remain enabled; Sentinel/analytics are not enabled implicitly.

## Durable execution boundaries

- Opaque server-side sessions with Secure, HttpOnly, SameSite=Strict cookies.
- Exact Origin and CSRF checks on private POST actions.
- Same-origin referrer policy preserves the browser's Origin on native form
  submissions while suppressing cross-site referrers. Opaque (`null`) and foreign
  Origins remain forbidden; the server never relaxes the Origin check.
- Persistent login throttling and one start per minute; ten starts per hour for
  the original catalogue and 36 for the separately scoped private workflow.
- One active lab execution, persistent leases, intent audit and idempotency.
- Ten-minute legacy job deadline and a maximum of twenty bounded lab HTTP
  requests; private live jobs use twelve minutes and 780-second queue visibility.
- Authorization, credential epoch, lease and expiry rechecked during execution.
- At-least-once queue delivery never automatically replays a potentially started
  simulation. A crashed/ambiguous job blocks new dispatch until reconciliation.
- Sessions and new starts cannot outlive their separately authorized scope;
  a new private epoch never renews expired original public-lab actions.

Blob versions and application append-only audit entries aid investigation; this
is not a claim of immutable or tamper-proof forensic storage.

## Private networking and least privilege

Storage and Key Vault public access stay disabled. A dedicated VNet, delegated
App Service integration subnet, three private endpoints and private DNS connect
the operator app to Blob, Queue and Key Vault. No peering, NAT gateway or new
App Service plan is required. The existing Linux B1 is reused without upgrading
its SKU.

Runtime grants are limited to the owned lab's read operations, its exact workspace,
the private operator Blob container/queue, subscription identity/pricing reads,
and the exact verifier secret. It has no workload deployment, WAF, DNS, pricing
write or public-site publishing permission by default. The explicit private
feature adds only the exact scoped permissions described above, not subscription
administration or grants to the public PHP identity.

One-time initialization is explicitly enabled out of band with a deployment UUID.
It uses a temporary vault-scoped Secrets Officer grant to establish credentials,
verifies real HTTP login/CSRF, starts the fixed simulation and emits only a
redacted evidence **candidate**. Its durable claim prevents automatic replay.
After verification, disable initialization and remove the temporary grant.

## Build and deployment

```powershell
npm --prefix operator ci --ignore-scripts
npm --prefix operator test
npm --prefix operator run build:runtime -- C:\path\to\new-session-artifact-directory
```

The build uses a pinned, build-only minifier and a production-only locked manifest.
Its pinned, build-only Zopfli compressor produces standard gzip and keeps source
ahead of package metadata to fit the existing transport budget without removing
runtime files or dependency integrity records. Neither build tool ships in the
production dependency manifest. `npm test` builds the actual runtime offline and
checks the complete file set, production dependency versions, SHA-256, chunk
sizes and combined protected-input limit.
The resulting runtime is independently SHA-256 verified and tested. Its allowlist,
sixteen-chunk maximum and combined 60-KiB protected-input bound are not expanded.
No `.env`, tests, credentials, arbitrary files or private container lab are shipped.
The optional private feature uses two separately bounded overlays, installed in
order while live execution remains disabled:

```powershell
az bicep build --file infra\private-live.bicep --outfile C:\path\to\private-live.json
node operator\build-live.mjs C:\path\to\new-live-foundation private-live-foundation C:\path\to\private-live.json
node operator\build-live.mjs C:\path\to\new-live-runtime private-live-runtime
```

Each keeps the same protected-source cap and exact file allowlist. Activation
checks hashes for all 21 runtime/helper assets to reject mixed overlays. A
reviewed recording is a third, static-only `private-live-recording` build; it
does not reactivate execution. The native private template exposed for download
is metadata, not a deployment triggered by visiting the site.

Hunting assets are a separate bounded overlay so the original 60-KiB protected
input limit is not widened:

```powershell
node operator\build-hunts.mjs C:\path\to\new-hunting-release release
node operator\build-hunts.mjs C:\path\to\new-reviewed-recording recording
```

Deploy the **release overlay after every full core runtime deployment**; the
core archive deliberately does not duplicate the query/data assets. The overlay
has a closed file allowlist, SHA-256 check and `clean=false`, preserving existing
SDK dependencies and recordings. Missing hunting assets fail explicitly, without
an empty-success fallback. The recording mode accepts only the reviewed fixed
`operator/public-evidence/hunting.json` snapshot. Neither build publishes itself.

`module` mode is restricted to the fixed `operator/hunts.mjs` maintenance file.
After the original expiry, `publish-runtime.sh` rejects every runtime publish.
`publish-hunts.sh` applies the time check only to the full `release` kind. Its other
kinds are not rejected for expiry, but every kind still requires the operator group's
`pawprint.expiresAt` tag to equal `ORIGINAL_EXPIRY`. Publishing a code-maintenance
overlay does not renew credentials, permit a login/job, or authorize another capture.
Publishing the operator app also requires the deployment-only
`OPERATOR_HUNT_CAPTURE_ID` setting to be empty, which `publish-hunts.sh` checks before
deploying.

The recorded hunting snapshot ran at **18:35:01–18:35:03 UTC on 2026-10-24**, before
the original deadline. Three Resource Graph queries succeeded: `php-assessments`
returned four Healthy assessment rows, and `appservice-runtimes` and
`appservice-runtime-discovery` each returned one PHP|8.4 row. Their evidence kinds mark them as leads or review-required items, not patch
proof. Eighteen hunts are unavailable: seven log-source
hunts carry the 1-MiB response-bound reason, and eleven Defender XDR hunts carry the
no-connector reason. Six are not applicable to the selected scope. The committed
runner keeps the 1-MiB bound, but each source query runs independently: a query
that stays under it still returns matches for review, and zero rows with unknown
source readiness are recorded as a source gap rather than clearance. The
snapshot records the upstream pack revision, not the runner revision that
produced it. It also states that no execution window was extended, so any rerun
needs a new authorized window. That statement does not address lookbacks: the
runner's `bindHuntQuery` (`operator/hunts.mjs`) rewrites the reviewed templates'
lookbacks to 24 hours when it binds each hunt.

Provenance is not fully reproducible from this repository. The committed
snapshot builder writes `reviewed: false`, and the page builder accepts only
`reviewed: true`, so the committed pipeline cannot produce the published file
as-is. The file's top-level `reviewedAt` (2026-10-24T18:47:18Z) falls after the
18:45:04Z deadline it records, while its queries ran at 18:35. Each of its 27
`queryTemplateSha256` values matches the corresponding template in the pinned
`detections/catalog.json`, and `operator/test/hunts.test.mjs` asserts this. The
committed `runHunts` records a response over the 1-MiB bound as `failed` with that
message, never as `unavailable`, so the seven 1-MiB `unavailable` entries in the
snapshot were not produced by this code. How the published file was generated is
not established.

Infrastructure entry: [operator.bicep](../infra/operator.bicep). Compiled modules
can be deployed individually through the authenticated ARM integration. AVM was
evaluated first; compact native Bicep is used here to avoid multi-megabyte optional
module expansions in this deployment channel and keep every privilege explicit.

The publisher is one outbound-only, pinned-image, 1-CPU/2-GiB container. It runs as a
user-assigned identity in an invocation-scoped helper resource group tagged
`dojo.temporary=true`. Its grants are Contributor on the operator resource group,
Reader on the private-live resource group only when one is named, Website Contributor
on the public app only when public walkthrough publication is requested, and the
`php2proof-operator-metadata` role (three read actions, defined by the operator stack)
at subscription scope. The repository does not automate removal of the helper group,
its identity or these role assignments after the worker finishes; that removal is a
manual step. The publisher verifies the protected runtime before extraction and uses
managed identity code publishing, never a publishing password, storage key or SAS.
Control-plane deployment success is not worker success or application readiness.

New Key Vault operations, Storage, Private Link, DNS, traffic and ingestion are
billable. Existing B1 capacity and Defender plans are not free, but are not
upgraded. Public retail prices are estimates, not a budget or billing hard cap.
Expiry tags are metadata, not automatic Azure teardown; review and remove the
owned operator resources and grants when the exercise ends.

## Reviewed public snapshots

Raw captures and run history remain private. Export a candidate:

```powershell
node operator\export-evidence.mjs private-capture.json new-reviewed-snapshot.json
```

Review the field-allowlisted output before a separate static deployment. Client
IPs, raw application lines, internal hosts, tenant/resource identifiers, tokens
and diagnostic errors are not public fields. The public evidence route serves
only reviewed local snapshots; it is not a workspace query proxy and cannot run
tests or publish itself.

The public host forwards only `/evidence/*` and its `/style.css` asset to this
application. Private console, login and job paths remain on the separate operator
hostname; adding a recording must not publish those routes.

## References

- [App Service VNet integration, including Basic tier](https://learn.microsoft.com/azure/app-service/overview-vnet-integration)
- [Defender for App Service](https://learn.microsoft.com/azure/defender-for-cloud/defender-for-app-service-introduction)
- [Microsoft alert validation](https://learn.microsoft.com/azure/defender-for-cloud/alert-validation)
- [Key Vault RBAC](https://learn.microsoft.com/azure/key-vault/general/rbac-guide)
- [Azure Identity JavaScript SDK](https://learn.microsoft.com/javascript/api/@azure/identity/managedidentitycredential)
