#!/usr/bin/env bash
set -euo pipefail

[[ "$DOJO_CLOUD_OPERATION" == doctor || "$DOJO_CLOUD_OPERATION" == deploy || "$DOJO_CLOUD_OPERATION" == validate ]] || { echo "Unsupported cloud operation." >&2; exit 1; }
[[ "$DOJO_SUFFIX" =~ ^[a-z0-9]{4,12}$ ]] || { echo "Invalid cloud suffix." >&2; exit 1; }
az login --identity --client-id "$OPERATOR_CLIENT_ID" --allow-no-subscriptions --output none
az account set --subscription "$AZURE_SUBSCRIPTION_ID"
[[ "$(az account show --query id -o tsv)" == "$AZURE_SUBSCRIPTION_ID" ]] || { echo "Cloud subscription mismatch." >&2; exit 1; }
python3 - <<'PY'
import base64
import gzip
import hashlib
import json
import os
import pathlib

count = int(os.environ["SOURCE_PART_COUNT"])
if not 1 <= count <= 16:
    raise RuntimeError("Invalid protected source chunk count.")
encoded = "".join(os.environ[f"SOURCE_PART_{index}"] for index in range(count))
overlay_text = os.environ.get("SOURCE_OVERLAYS", "[]")
if len(encoded) + len(overlay_text.encode("utf8")) > 60 * 1024:
    raise RuntimeError("Protected source exceeds its size budget.")
archive = base64.b64decode(encoded, validate=True)
if hashlib.sha256(archive).hexdigest() != os.environ["SOURCE_SHA256"]:
    raise RuntimeError("Protected source checksum mismatch.")
bundle = json.loads(gzip.decompress(archive))
root = pathlib.Path("/tmp/php2proof-context")
if bundle.get("schemaVersion") != 2 or not isinstance(bundle.get("files"), dict):
    raise RuntimeError("Invalid cloud source manifest.")
for name, content in bundle["files"].items():
    relative = pathlib.PurePosixPath(name)
    if relative.is_absolute() or ".." in relative.parts or "\\" in name:
        raise RuntimeError("Invalid cloud source path.")
    target = root.joinpath(*relative.parts)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf8")
overlays = json.loads(overlay_text)
allowed_paths = {"scripts/lib/azure.mjs", "infra/main.bicep", "config/dev.json"}
if not isinstance(overlays, list) or len(overlays) > len(allowed_paths):
    raise RuntimeError("Invalid verified source overlay count.")
seen_paths = set()
for overlay in overlays:
    if not isinstance(overlay, dict) or overlay.get("path") not in allowed_paths or overlay["path"] in seen_paths:
        raise RuntimeError("Duplicate or unreviewed source overlay path.")
    if not isinstance(overlay.get("content"), str):
        raise RuntimeError("Source overlay content must be UTF-8 text.")
    if hashlib.sha256(overlay["content"].encode("utf8")).hexdigest() != overlay.get("sha256"):
        raise RuntimeError("Source overlay checksum mismatch.")
    root.joinpath(overlay["path"]).write_text(overlay["content"], encoding="utf8")
    seen_paths.add(overlay["path"])
PY
cd /tmp/php2proof-context

if [[ -n "${DOJO_REGISTER_PROVIDER:-}" ]]; then
  [[ "$DOJO_REGISTER_PROVIDER" == Microsoft.Cdn ]] || { echo "Unsupported provider registration." >&2; exit 1; }
  echo "Explicitly registering required Front Door provider Microsoft.Cdn."
  az provider register --namespace Microsoft.Cdn --wait --only-show-errors --output none
  [[ "$(az provider show --namespace Microsoft.Cdn --query registrationState -o tsv)" == Registered ]] || { echo "Front Door provider is not Registered." >&2; exit 1; }
fi

python3 - <<'PY'
import hashlib
import io
import pathlib
import tarfile
import urllib.request

url = "https://nodejs.org/dist/v24.19.0/node-v24.19.0-linux-x64.tar.gz"
expected = "f625d97cd707df4ff96254916fbc5ff014f09c09effe5a1e0ca8f6d41a8789d4"
with urllib.request.urlopen(url, timeout=90) as response:
    archive = response.read(150 * 1024 * 1024)
if hashlib.sha256(archive).hexdigest() != expected:
    raise RuntimeError("Pinned Node archive checksum mismatch.")
destination = pathlib.Path("/tmp/php2proof-node")
destination.mkdir(exist_ok=True)
with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as package:
    package.extractall(destination, filter="data")
PY
export PATH="/tmp/php2proof-node/node-v24.19.0-linux-x64/bin:$PATH"
node -e 'if (process.version !== "v24.19.0") throw new Error("Unexpected Node runtime.");'
if ! command -v zip > /dev/null; then
  tdnf install -y zip
fi
zip -v > /dev/null
az bicep install --version v0.48.1 --only-show-errors
[[ "$(az bicep version)" == *"0.48.1"* ]] || { echo "Unexpected Bicep version." >&2; exit 1; }
exec node scripts/cloud-runner.mjs run
