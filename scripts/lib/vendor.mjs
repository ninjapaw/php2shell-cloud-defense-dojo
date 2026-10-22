import { createHash } from "node:crypto";

export const VENDOR_FILES = [
  "LICENSE",
  "bicepconfig.json",
  "scripts/github-oidc-subject.mjs",
  "scripts/cloudflare-dns.mjs",
  "modules/types.bicep",
  "modules/monitoring/main.bicep",
  "modules/front-door-waf/profile.bicep",
  "modules/front-door-waf/main.bicep",
  "modules/php-web-app/main.bicep",
];

export function contentHash(contents) {
  return createHash("sha256").update(contents.replaceAll("\r\n", "\n")).digest("hex");
}
