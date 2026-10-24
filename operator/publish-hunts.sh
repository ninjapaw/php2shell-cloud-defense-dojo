#!/usr/bin/env bash
set -euo pipefail
export AZURE_EXTENSION_USE_DYNAMIC_INSTALL=no
export AZURE_CORE_COLLECT_TELEMETRY=false
work="$(mktemp -d /tmp/php2proof-hunts.XXXXXX)"
export HUNT_PUBLICATION_ROOT="$work"
python3 - <<'PY'
import base64, datetime, gzip, hashlib, io, json, os, pathlib, re, zipfile
count = int(os.environ["SOURCE_COUNT"])
if not 1 <= count <= 16:
    raise ValueError("Hunting chunk count rejected.")
chunks = [os.environ["SOURCE_" + str(i)] for i in range(count)]
if any(not 1 <= len(chunk) <= 4000 for chunk in chunks):
    raise ValueError("Hunting chunk size rejected.")
encoded = "".join(chunks)
if len(encoded) + 2 > 61440:
    raise ValueError("Protected hunting source cap exceeded.")
content = base64.b64decode(encoded, validate=True)
if hashlib.sha256(content).hexdigest() != os.environ["SOURCE_SHA256"]:
    raise ValueError("Reviewed hunting source checksum mismatch.")
with gzip.GzipFile(fileobj=io.BytesIO(content)) as stream:
    decoded = stream.read(2097153)
if len(decoded) > 2097152:
    raise ValueError("Hunting source expansion exceeded.")
source = json.loads(decoded)
if source.get("schemaVersion") != 1 or set(source) != {"schemaVersion", "kind", "files"}:
    raise ValueError("Invalid hunting artifact schema.")
files = source["files"]
if source["kind"] == "release":
    catalog = json.loads(files["detections/catalog.json"])
    if catalog["source"]["revision"] != "41815ef397da1fb048925815ce7c77bfe4eca5e5" or len(catalog["queries"]) != 27:
        raise ValueError("Reviewed hunting revision/count drifted.")
    paths = [item["path"] for item in catalog["queries"]]
    if any(not re.fullmatch(r"detections/(?:[a-z0-9-]+/)?[a-z0-9-]+\.kql", path) for path in paths):
        raise ValueError("Hunting data path rejected.")
    allowed = set(paths + ["detections/catalog.json", "operator/hunts.mjs", "operator/config.mjs",
                          "operator/control.mjs", "operator/azure.mjs", "operator/server.mjs"])
elif source["kind"] == "module":
    allowed = {"operator/hunts.mjs"}
elif source["kind"] == "response-maintenance":
    allowed = {"scripts/lib/response.mjs", "scripts/response.mjs", "operator/response.mjs",
               "operator/config.mjs", "operator/control.mjs", "operator/server.mjs",
               "operator/public-scripts/response.mjs"}
    script = files.get("operator/public-scripts/response.mjs")
    if not isinstance(script, str) or len(script) > 262144 or "responseCli" not in script:
        raise ValueError("Reviewed response script bundle rejected.")
elif source["kind"] == "recording":
    allowed = {"operator/public-evidence/hunting.json"}
    snapshot = json.loads(files["operator/public-evidence/hunting.json"])
    if snapshot.get("reviewed") is not True or snapshot.get("kind") != "reviewed-hunting":
        raise ValueError("Unreviewed hunting evidence cannot be published.")
else:
    raise ValueError("Unknown hunting publication kind.")
if set(files) != allowed or any(not isinstance(value, str) for value in files.values()):
    raise ValueError("Hunting file allowlist rejected.")
expiry = datetime.datetime.fromisoformat(os.environ["ORIGINAL_EXPIRY"].replace("Z", "+00:00"))
if source["kind"] == "release" and datetime.datetime.now(datetime.timezone.utc) >= expiry:
    raise ValueError("Original hunting lifetime ended.")
root = pathlib.Path(os.environ["HUNT_PUBLICATION_ROOT"])
with zipfile.ZipFile(root / "hunting.zip", "w", zipfile.ZIP_DEFLATED) as archive:
    for name, value in files.items():
        archive.writestr(name, value)
(root / "kind.txt").write_text(source["kind"])
print(json.dumps({"verifiedSource": True, "kind": source["kind"], "files": len(files), "sha256": os.environ["SOURCE_SHA256"]}))
PY
az login --identity --client-id "$PUBLISHER_CLIENT_ID" --allow-no-subscriptions --output none
az account set --subscription "$AZURE_SUBSCRIPTION_ID"
[[ "$(az group show --name "$OPERATOR_GROUP" --query "tags.\"pawprint.expiresAt\"" --output tsv)" == "$ORIGINAL_EXPIRY" ]] || { echo 'Original operator lifetime drifted.' >&2; exit 1; }
[[ "$(az group show --name "$OPERATOR_GROUP" --query "tags.\"dojo.scenario\"" --output tsv)" == php2proof-operator ]] || { echo 'Operator ownership drifted.' >&2; exit 1; }
az webapp deploy --resource-group "$OPERATOR_GROUP" --name "p2p-${DOJO_SUFFIX}-operator" \
  --src-path "${work}/hunting.zip" --type zip --clean false --restart true \
  --async false --track-status false --timeout 600000 --output none
kind="$(cat "${work}/kind.txt")"
python3 - <<'PY'
import datetime, json, os, pathlib
root = pathlib.Path(os.environ["HUNT_PUBLICATION_ROOT"])
kind = (root / "kind.txt").read_text()
report = {"$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
          "contentVersion": "1.0.0.0", "resources": [],
          "outputs": {"result": {"type": "object", "value": {
              "status": "files-deployed", "kind": kind, "sourceSha256": os.environ["SOURCE_SHA256"],
              "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
              "note": "Bounded operator overlay only. Live queries, authentication, response execution, evidence and UI verification are separate."
          }}}}
(root / "report.json").write_text(json.dumps(report))
PY
az deployment group create --resource-group "$OPERATOR_GROUP" --name "php2proof-hunting-${kind}-${DOJO_SUFFIX}" \
  --template-file "${work}/report.json" --mode Incremental --output none
