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
is included in this repository or the public recording. Login/test lifetime is
bounded by the original **2026-10-24 18:45:04.967 UTC** deadline.

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

The full CLI hunting catalogue remains in [the hunting guide](../docs/hunting-pack.md).
There is no arbitrary command, query or target input.

`protect`, `remediate`, deployment/repair, DNS writes, teardown, container execution
and security-plan changes are visibly unavailable. The console must not disable
Defender, reopen a fixed lab, weaken WAF or turn an intentionally harmless public
site into an RCE workload.

The Microsoft App Service `/This_Will_Generate_ASC_Alert` validation marker is
also deferred until registration eligibility and its observation deadline are
verified. Microsoft documents a possible 24-hour registration wait and roughly
1.5 hours or 2-4 hours for an alert. No request or alert is claimed when the
prerequisites do not fit the original lifetime.

## GhostPaw and evidence

The simulator sends `request`, `php-error`, `process-synthetic`,
`outbound-synthetic` and `canary`, with the benign WAF marker on the first request.
It reuses [the existing guarded lifecycle](../scripts/dojo.mjs), including exact
resource ownership, independent endpoint checks, origin rejection, redirects
refused, 15-second/64-KiB responses and 250-ms scenario pacing.

The application events are real ingested records containing **synthetic
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
- Persistent login throttling, one start per minute and ten starts per hour.
- One active lab execution, persistent leases, intent audit and idempotency.
- Ten-minute job deadline and a maximum of twenty bounded lab HTTP requests.
- Authorization, credential epoch, lease and expiry rechecked during execution.
- At-least-once queue delivery never automatically replays a potentially started
  simulation. A crashed/ambiguous job blocks new dispatch until reconciliation.
- Sessions and new test starts cannot outlive the original lab expiry.

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
write or public-site publishing permission.

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
The resulting runtime is independently SHA-256 verified and tested. Its allowlist,
sixteen-chunk maximum and combined 60-KiB protected-input bound are not expanded.
No `.env`, tests, credentials, arbitrary files or private container lab are shipped.

Infrastructure entry: [operator.bicep](../infra/operator.bicep). Compiled modules
can be deployed individually through the authenticated ARM integration. AVM was
evaluated first; compact native Bicep is used here to avoid multi-megabyte optional
module expansions in this deployment channel and keep every privilege explicit.

The publisher is one outbound-only, pinned-image, 1-CPU/2-GiB container, using a
temporary identity scoped to the operator group plus metadata-only subscription
reads. It verifies the protected runtime before extraction and uses managed
identity code publishing, never a publishing password, storage key or SAS.
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
