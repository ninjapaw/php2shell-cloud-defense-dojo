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
elif source["kind"] == "deployment-guide-maintenance":
    allowed = {"operator/deploy.mjs", "operator/server.mjs"}
elif source["kind"] == "deployment-download-maintenance":
    allowed = {"operator/public-deployment/manifest.json", "operator/public-deployment/source.zip.00.b64"}
    manifest = json.loads(files["operator/public-deployment/manifest.json"])
    if manifest.get("schemaVersion") != 1 or manifest.get("kind") != "core-wizard-source" or manifest.get("parts") != 2 or not 1000 <= manifest.get("bytes", 0) <= 262144 or not re.fullmatch(r"[a-f0-9]{64}", manifest.get("sha256", "")):
        raise ValueError("Deployment download manifest rejected.")
    base64.b64decode(files["operator/public-deployment/source.zip.00.b64"], validate=True)
elif source["kind"] == "deployment-tail-maintenance":
    allowed = {"operator/public-deployment/source.zip.01.b64"}
    base64.b64decode(files["operator/public-deployment/source.zip.01.b64"], validate=True)
elif source["kind"] == "public-navigation-maintenance":
    allowed = {"app/index.php", "app/walkthrough.php", "app/assets/style.css"}
elif source["kind"] == "public-walkthrough-maintenance":
    allowed = {"app/walkthrough.php"}
    page = files.get("app/walkthrough.php")
    if not isinstance(page, str) or len(page) > 65536 or not page.startswith("<?php") or "/evidence/response" not in page:
        raise ValueError("Reviewed public walkthrough rejected.")
elif source["kind"] == "response-maintenance":
    allowed = {"scripts/lib/response.mjs", "scripts/response.mjs", "operator/response.mjs",
               "operator/config.mjs", "operator/control.mjs", "operator/server.mjs",
               "operator/public-scripts/response.mjs"}
    script = files.get("operator/public-scripts/response.mjs")
    if not isinstance(script, str) or len(script) > 262144 or "responseCli" not in script:
        raise ValueError("Reviewed response script bundle rejected.")
elif source["kind"] in ("private-live-foundation", "private-live-runtime"):
    foundation = {"scripts/lib/private-live.mjs", "scripts/lib/container-lab.mjs", "scripts/lib/response.mjs", "container-lab/images.json", "operator/public-live-template.json"}
    runtime = {
        "operator/config.mjs", "operator/auth.mjs", "operator/azure.mjs", "operator/control.mjs", "operator/server.mjs",
        "operator/store.mjs", "operator/style.css", "operator/live-config.mjs", "operator/live-authorize.mjs",
        "operator/live-control.mjs", "operator/live-waf.mjs", "operator/live-azure.mjs", "operator/live.mjs",
        "operator/live-evidence.mjs", "operator/live-public.mjs", "operator/live-capture.mjs",
        "operator/live-integrity.mjs", "operator/live-integrity.json",
    }
    allowed = foundation if source["kind"] == "private-live-foundation" else runtime
    if source["kind"] == "private-live-foundation":
        template = json.loads(files["operator/public-live-template.json"])
        if template.get("$schema") != "https://schema.management.azure.com/schemas/2018-05-01/subscriptionDeploymentTemplate.json#" or len(template.get("resources", [])) != 7 or template.get("metadata", {}).get("_generator", {}).get("name") != "bicep":
            raise ValueError("Native private live template source rejected.")
        (pathlib.Path(os.environ["HUNT_PUBLICATION_ROOT"]) / "native-private-live.json").write_text(files["operator/public-live-template.json"])
    window = json.loads(os.environ["LIVE_WINDOW_JSON"])
    if set(window) != {"schemaVersion", "id", "notBefore", "expiresAt", "resourceGroup", "autoTeardown"} or window["schemaVersion"] != 1 or window["autoTeardown"] is not True:
        raise ValueError("Private live publication needs its separate exact window.")
    if not re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}", window["id"]):
        raise ValueError("Invalid private live window UUID.")
    start, end = [datetime.datetime.fromisoformat(window[key].replace("Z", "+00:00")) for key in ("notBefore", "expiresAt")]
    if not 60 <= (end-start).total_seconds() <= 14400 or not start <= datetime.datetime.now(datetime.timezone.utc) < end or window["resourceGroup"] != "rg-p2sc-" + os.environ["DOJO_SUFFIX"] + "-dev":
        raise ValueError("Private live publication is outside its separate four-hour exact-group window.")
    (pathlib.Path(os.environ["HUNT_PUBLICATION_ROOT"]) / "live-window.json").write_text(json.dumps(window))
elif source["kind"] == "private-live-recording":
    allowed = {"operator/public-evidence/live.json"}
    snapshot = json.loads(files["operator/public-evidence/live.json"])
    if snapshot.get("reviewed") is not True or snapshot.get("kind") != "reviewed-private-live" or not 8 <= len(snapshot.get("steps", [])) <= 24:
        raise ValueError("Only a complete separately reviewed private live recording is publishable.")
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
        archive.writestr(name.removeprefix("app/") if source["kind"] in ("public-walkthrough-maintenance", "public-navigation-maintenance") else name, value)
(root / "kind.txt").write_text(source["kind"])
print(json.dumps({"verifiedSource": True, "kind": source["kind"], "files": len(files), "sha256": os.environ["SOURCE_SHA256"]}))
PY
az login --identity --client-id "$PUBLISHER_CLIENT_ID" --allow-no-subscriptions --output none
az account set --subscription "$AZURE_SUBSCRIPTION_ID"
[[ "$(az group show --name "$OPERATOR_GROUP" --query "tags.\"pawprint.expiresAt\"" --output tsv)" == "$ORIGINAL_EXPIRY" ]] || { echo 'Original operator lifetime drifted.' >&2; exit 1; }
[[ "$(az group show --name "$OPERATOR_GROUP" --query "tags.\"dojo.scenario\"" --output tsv)" == php2proof-operator ]] || { echo 'Operator ownership drifted.' >&2; exit 1; }
kind="$(cat "${work}/kind.txt")"
if [[ "$kind" == private-live-runtime || "$kind" == private-live-foundation ]]; then
  live_group="$(jq -er .resourceGroup "${work}/live-window.json")"
  live_id="$(jq -er .id "${work}/live-window.json")"
  live_expiry="$(jq -er .expiresAt "${work}/live-window.json")"
  [[ "$(az group show --name "$live_group" --query "tags.\"dojo.liveWindowId\"" -o tsv)" == "$live_id" ]] || { echo 'Private live group ownership drifted.' >&2; exit 1; }
  [[ "$(az group show --name "$live_group" --query "tags.\"dojo.liveScenario\"" -o tsv)" == php2proof-private-live ]] || { echo 'Private live group scenario drifted.' >&2; exit 1; }
  [[ "$(az group show --name "$live_group" --query "tags.\"pawprint.expiresAt\"" -o tsv)" == "$live_expiry" ]] || { echo 'Private live group expiry drifted.' >&2; exit 1; }
fi
if [[ "$kind" == private-live-foundation ]]; then
  az ts create --resource-group "$OPERATOR_GROUP" --name "php2proof-private-live-${DOJO_SUFFIX}" \
    --version "live-${live_id}" --location centralus --template-file "${work}/native-private-live.json" \
    --tags pawprint.managed=true pawprint.environment=dev "dojo.liveWindowId=${live_id}" \
    --only-show-errors --output none
fi
target_group="$OPERATOR_GROUP"
target_app="p2p-${DOJO_SUFFIX}-operator"
if [[ "$kind" == public-walkthrough-maintenance || "$kind" == public-navigation-maintenance ]]; then
  target_group="$MAIN_GROUP"
  target_app="p2s-${DOJO_SUFFIX}-app"
  [[ "$(az webapp show --resource-group "$target_group" --name "$target_app" --query "tags.\"pawprint.expiresAt\"" --output tsv)" == "$ORIGINAL_EXPIRY" ]] || { echo 'Public application lifetime drifted.' >&2; exit 1; }
  [[ "$(az webapp show --resource-group "$target_group" --name "$target_app" --query "tags.\"dojo.scenario\"" --output tsv)" == php2shell-cloud-defense-dojo ]] || { echo 'Public application ownership drifted.' >&2; exit 1; }
else
  [[ "$(az webapp config appsettings list --resource-group "$target_group" --name "$target_app" --query "[?name=='OPERATOR_INITIALIZE'].value | [0]" --output tsv)" == false ]] || { echo 'Credential initialization must remain disabled.' >&2; exit 1; }
  [[ -z "$(az webapp config appsettings list --resource-group "$target_group" --name "$target_app" --query "[?name=='OPERATOR_HUNT_CAPTURE_ID'].value | [0]" --output tsv)" ]] || { echo 'Hunting capture must remain disabled.' >&2; exit 1; }
  writes="$(az webapp config appsettings list --resource-group "$target_group" --name "$target_app" --query "[?name=='OPERATOR_RESPONSE_WRITES'].value | [0]" --output tsv)"
  [[ -z "$writes" || "$writes" == false ]] || { echo 'Response writes must remain disabled during code publication.' >&2; exit 1; }
fi
az webapp deploy --resource-group "$target_group" --name "$target_app" \
  --src-path "${work}/hunting.zip" --type zip --clean false --restart true \
  --async false --track-status false --timeout 600000 --output none
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
