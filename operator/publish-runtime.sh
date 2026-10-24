#!/usr/bin/env bash
set -euo pipefail
export AZURE_EXTENSION_USE_DYNAMIC_INSTALL=no
export AZURE_CORE_COLLECT_TELEMETRY=false

work="$(mktemp -d /tmp/php2proof-operator.XXXXXX)"
node_version=24.19.0
node_sha256=f625d97cd707df4ff96254916fbc5ff014f09c09effe5a1e0ca8f6d41a8789d4
curl --fail --show-error --silent --proto '=https' --tlsv1.2 \
  "https://nodejs.org/dist/v${node_version}/node-v${node_version}-linux-x64.tar.gz" -o "${work}/node.tar.gz"
printf '%s  %s\n' "$node_sha256" "${work}/node.tar.gz" | sha256sum --check --status
python3 - "${work}/node.tar.gz" "$work" <<'PY'
import sys
import tarfile
with tarfile.open(sys.argv[1], "r:gz") as package:
    package.extractall(sys.argv[2], filter="data")
PY
export PATH="${work}/node-v${node_version}-linux-x64/bin:${PATH}"
export OPERATOR_SOURCE_ROOT="${work}/source"

node --input-type=module <<'NODE'
import { createHash } from 'node:crypto';
import { mkdirSync, writeFileSync } from 'node:fs';
import { resolve, join } from 'node:path';
import { gunzipSync } from 'node:zlib';
const count = Number(process.env.SOURCE_COUNT);
if (!Number.isInteger(count) || count < 1 || count > 16) throw Error('Invalid protected source chunk count.');
const chunks = Array.from({length: count}, (_, index) => process.env[`SOURCE_${index}`]);
if (chunks.some(chunk => typeof chunk !== 'string' || chunk.length < 1 || chunk.length > 4000)) throw Error('Invalid protected source chunk.');
const encoded = chunks.join('');
if (encoded.length + 2 > 61440 || encoded.length % 4 !== 0 || !/^[A-Za-z0-9+/]+={0,2}$/.test(encoded)) throw Error('Protected source budget or encoding rejected.');
const bytes = Buffer.from(encoded, 'base64');
if (!/^[a-f0-9]{64}$/.test(process.env.SOURCE_SHA256 ?? '') || createHash('sha256').update(bytes).digest('hex') !== process.env.SOURCE_SHA256) throw Error('Protected runtime SHA-256 mismatch.');
const payload = JSON.parse(gunzipSync(bytes, {maxOutputLength: 2097152}));
const allowed = [
  'package.json','config/dev.json','config/operator.dev.json','scripts/dojo.mjs',
  'scripts/lib/config.mjs','scripts/lib/azure.mjs','scripts/lib/safety.mjs','detections/correlation.kql',
  'vendor/pawprint/LICENSE','vendor/pawprint/scripts/cloudflare-dns.mjs',
  'operator/package.json','operator/package-lock.json','operator/style.css',
  'operator/config.mjs','operator/auth.mjs','operator/azure.mjs','operator/store.mjs',
  'operator/control.mjs','operator/evidence.mjs','operator/server.mjs','operator/initialize.mjs',
];
if (payload.schemaVersion !== 1 || !payload.files || Object.keys(payload).length !== 2
    || Object.keys(payload.files).length !== allowed.length || allowed.some(key => typeof payload.files[key] !== 'string')
    || Object.keys(payload.files).some(key => !allowed.includes(key))) throw Error('Runtime file allowlist rejected.');
const root = resolve(process.env.OPERATOR_SOURCE_ROOT);
mkdirSync(root);
for (const [name, value] of Object.entries(payload.files)) {
  const path = resolve(root, name);
  if (!path.startsWith(`${root}/`)) throw Error('Runtime path escaped its private extraction root.');
  mkdirSync(resolve(path, '..'), {recursive: true});
  writeFileSync(path, value, {flag: 'wx', mode: 0o600});
}
const config = JSON.parse(payload.files['config/operator.dev.json']);
if (config.resourceGroup !== process.env.OPERATOR_GROUP || config.environment !== 'dev'
    || !/^[a-z0-9]{4,12}$/.test(process.env.DOJO_SUFFIX ?? '')
    || !Number.isFinite(Date.parse(process.env.ORIGINAL_EXPIRY))
    || Date.now() >= Date.parse(process.env.ORIGINAL_EXPIRY)) throw Error('Operator deployment ownership/lifetime rejected.');
console.log(JSON.stringify({sourceVerified: true, sha256: process.env.SOURCE_SHA256, files: allowed.length}));
NODE

az login --identity --client-id "$PUBLISHER_CLIENT_ID" --allow-no-subscriptions --output none
az account set --subscription "$AZURE_SUBSCRIPTION_ID"
actual_expiry="$(az group show --name "$OPERATOR_GROUP" --query "tags.\"pawprint.expiresAt\"" --output tsv)"
if [[ "$actual_expiry" != "$ORIGINAL_EXPIRY" ]]; then
  printf '%s\n' 'Original operator lifetime drifted; code publication denied.' >&2
  exit 1
fi
cd "$OPERATOR_SOURCE_ROOT"
npm ci --prefix operator --omit=dev --ignore-scripts --no-fund
python3 - "$OPERATOR_SOURCE_ROOT" "${work}/operator.zip" <<'PY'
import pathlib
import sys
import zipfile
root = pathlib.Path(sys.argv[1])
with zipfile.ZipFile(sys.argv[2], "w", zipfile.ZIP_DEFLATED) as archive:
    for path in root.rglob("*"):
        if path.is_file():
            archive.write(path, path.relative_to(root).as_posix())
PY
az webapp deploy --resource-group "$OPERATOR_GROUP" --name "p2p-${DOJO_SUFFIX}-operator" \
  --src-path "${work}/operator.zip" --type zip --clean true --restart true \
  --async false --track-status false --timeout 600000 --output none
node --input-type=module <<'NODE'
import { writeFileSync } from 'node:fs';
writeFileSync('/tmp/php2proof-operator-publish-report.json', JSON.stringify({
  $schema: 'https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#',
  contentVersion: '1.0.0.0', resources: [],
  outputs: {result: {type: 'object', value: {
    status: 'code-deployed', operation: 'publish-operator-runtime',
    timestamp: new Date().toISOString(), sourceSha256: process.env.SOURCE_SHA256,
    note: 'Code deployment only. Authentication, private connectivity and real scenario evidence require separate live verification.',
  }}},
}));
NODE
az deployment group create --resource-group "$OPERATOR_GROUP" --name "php2proof-operator-publish-${DOJO_SUFFIX}" \
  --template-file /tmp/php2proof-operator-publish-report.json --mode Incremental --output none
printf '%s\n' 'Operator runtime source and code publication finished; no credential values emitted.'
