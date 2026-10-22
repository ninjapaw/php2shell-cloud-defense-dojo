# Security and responsible use

## Supported scope

Only the current dev-only defensive scaffold is supported. It is not hardened or
licensed as a production service. Never add exploit execution, arbitrary target
input, real sensitive data, or unlabelled synthetic detections.

## Reporting

Use this repository's GitHub **Security -> Report a vulnerability** if private
reporting has been enabled. Do not put credentials, private subscription data,
exploit payloads, or customer evidence in a public issue. If private reporting is
not available, first contact a maintainer to arrange a private channel; no
unverified reporting address is supplied here.

Provide the affected revision, component, impact, and a benign reproduction.
Redact account identifiers and secrets. Do not test a deployed lab without its
owner's explicit authorization.

## Safety controls

- Dev environment only; fixed resource naming and ownership checks.
- No arbitrary simulation targets, redirects, shell/process/egress payloads.
- Five benign scenario requests, bounded time/size, after live safety checks.
- HTTPS, profile-bound origin restrictions, no basic publishing credentials.
- No runtime role grants or generated secrets.
- Explicit subscription-wide CSPM and workspace-only Sentinel billing choices.
- Exact resource-group confirmation; no subscription or tenant deletion path.
- Manual protected OIDC workflows; no saved Azure credential artifacts.

Treat any new secret as a design change: use Key Vault references and managed
identity, add redaction tests, and update the threat/evidence boundaries.
