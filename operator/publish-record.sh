#!/usr/bin/env bash
set -euo pipefail
export AZURE_EXTENSION_USE_DYNAMIC_INSTALL=no
export AZURE_CORE_COLLECT_TELEMETRY=false

work="$(mktemp -d /tmp/php2proof-record.XXXXXX)"
node_sha256=f625d97cd707df4ff96254916fbc5ff014f09c09effe5a1e0ca8f6d41a8789d4
curl --fail --show-error --silent --proto '=https' --tlsv1.2 \
  https://nodejs.org/dist/v24.19.0/node-v24.19.0-linux-x64.tar.gz -o "${work}/node.tar.gz"
printf '%s  %s\n' "$node_sha256" "${work}/node.tar.gz" | sha256sum --check --status
python3 - "${work}/node.tar.gz" "$work" <<'PY'
import sys
import tarfile
with tarfile.open(sys.argv[1], "r:gz") as package:
    package.extractall(sys.argv[2], filter="data")
PY
export PATH="${work}/node-v24.19.0-linux-x64/bin:${PATH}"
export RECORD_ROOT="${work}/record"

node --input-type=module <<'NODE'
import { createHash } from 'node:crypto';
import { mkdirSync, writeFileSync } from 'node:fs';
import { gunzipSync } from 'node:zlib';
const count = Number(process.env.SOURCE_COUNT);
if (!Number.isInteger(count) || count < 1 || count > 16) throw Error('Invalid record source count.');
const chunks = Array.from({length: count}, (_, index) => process.env[`SOURCE_${index}`]);
if (chunks.some(value => typeof value !== 'string' || value.length < 1 || value.length > 4000)) throw Error('Invalid protected record chunk.');
const encoded = chunks.join('');
if (encoded.length + 2 > 61440 || encoded.length % 4 || !/^[A-Za-z0-9+/]+={0,2}$/.test(encoded)) throw Error('Protected record source rejected.');
const bytes = Buffer.from(encoded, 'base64');
if (createHash('sha256').update(bytes).digest('hex') !== process.env.SOURCE_SHA256) throw Error('Reviewed publication checksum mismatch.');
const source = JSON.parse(gunzipSync(bytes, {maxOutputLength: 2097152}));
if (source.schemaVersion !== 1 || !source.files || Object.keys(source.files).length !== 2) throw Error('Only the reviewed record and walkthrough can be published.');
const recordKey = Object.keys(source.files).find(key => /^operator\/public-evidence\/[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\.json$/.test(key));
if (!recordKey || typeof source.files[recordKey] !== 'string' || typeof source.files['app/walkthrough.php'] !== 'string') throw Error('Publication targets escaped the two-file allowlist.');
const record = JSON.parse(source.files[recordKey]);
if (record.schemaVersion !== 1 || recordKey !== `operator/public-evidence/${record.runId}.json`
    || !Array.isArray(record.requests) || record.requests.length !== 5
    || record.requests.some(item => item.synthetic !== true)
    || !record.publication?.includes('manual review')) throw Error('Publication is not the reviewed redacted record.');
function inspect(value) {
  if (!value || typeof value !== 'object') return;
  for (const [key, item] of Object.entries(value)) {
    if (/^(?:raw|scope|clientip|hostname|tenantid|resourceid|password|token|authorization)$/i.test(key)) throw Error('Private evidence field cannot be published.');
    inspect(item);
  }
}
inspect(record);
const page = source.files['app/walkthrough.php'];
if (!page.startsWith('<?php') || !page.includes('allow_read_only();') || !page.includes('security_headers();')
    || !page.includes(`/evidence/${record.runId}`)) throw Error('Reviewed walkthrough boundary/link is missing.');
if (Date.now() >= Date.parse(process.env.ORIGINAL_EXPIRY)) throw Error('Original publication lifetime ended.');
mkdirSync(process.env.RECORD_ROOT);
writeFileSync(`${process.env.RECORD_ROOT}/record.json`, source.files[recordKey], {mode: 0o600});
writeFileSync(`${process.env.RECORD_ROOT}/walkthrough.php`, page, {mode: 0o600});
writeFileSync(`${process.env.RECORD_ROOT}/run-id.txt`, record.runId);
console.log(JSON.stringify({reviewedSourceVerified: true, runId: record.runId, sourceSha256: process.env.SOURCE_SHA256}));
NODE

az login --identity --client-id "$PUBLISHER_CLIENT_ID" --allow-no-subscriptions --output none
az account set --subscription "$AZURE_SUBSCRIPTION_ID"
[[ "$(az group show --name "$MAIN_GROUP" --query "tags.\"pawprint.expiresAt\"" --output tsv)" == "$ORIGINAL_EXPIRY" ]] || { echo 'Original lab lifetime drifted.' >&2; exit 1; }
[[ "$(az group show --name "$MAIN_GROUP" --query "tags.\"dojo.scenario\"" --output tsv)" == php2shell-cloud-defense-dojo ]] || { echo 'Public lab ownership drifted.' >&2; exit 1; }
[[ "$(az group show --name "$OPERATOR_GROUP" --query "tags.\"dojo.scenario\"" --output tsv)" == php2proof-operator ]] || { echo 'Operator ownership drifted.' >&2; exit 1; }
run_id="$(cat "${RECORD_ROOT}/run-id.txt")"
az webapp deploy --resource-group "$OPERATOR_GROUP" --name "p2p-${DOJO_SUFFIX}-operator" \
  --type static --src-path "${RECORD_ROOT}/record.json" \
  --target-path "/home/site/wwwroot/operator/public-evidence/${run_id}.json" \
  --clean false --restart false --async false --track-status false --timeout 600000 --output none
az webapp deploy --resource-group "$MAIN_GROUP" --name "p2s-${DOJO_SUFFIX}-app" \
  --type static --src-path "${RECORD_ROOT}/walkthrough.php" \
  --target-path /home/site/wwwroot/walkthrough.php \
  --clean false --restart true --async false --track-status false --timeout 600000 --output none
node --input-type=module <<'NODE'
import { writeFileSync, readFileSync } from 'node:fs';
writeFileSync('/tmp/php2proof-record-report.json', JSON.stringify({
  $schema: 'https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#',
  contentVersion: '1.0.0.0', resources: [],
  outputs: {result: {type: 'object', value: {
    status: 'files-deployed', operation: 'publish-reviewed-record',
    timestamp: new Date().toISOString(), sourceSha256: process.env.SOURCE_SHA256,
    runId: readFileSync(`${process.env.RECORD_ROOT}/run-id.txt`, 'utf8'),
    note: 'Only two reviewed static files deployed. HTTPS content and origin isolation require independent verification.',
  }}},
}));
NODE
az deployment group create --resource-group "$OPERATOR_GROUP" --name "php2proof-operator-record-publish-${DOJO_SUFFIX}" \
  --template-file /tmp/php2proof-record-report.json --mode Incremental --output none
