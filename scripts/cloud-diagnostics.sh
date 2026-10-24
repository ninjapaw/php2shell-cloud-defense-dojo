#!/usr/bin/env bash
set -euo pipefail
[[ "$FAILED_RUNNER_NAME" =~ ^p2p-[a-z0-9-]+$ ]] || { echo "Invalid diagnostic target." >&2; exit 1; }
az login --identity --client-id "$OPERATOR_CLIENT_ID" --allow-no-subscriptions --output none
az account set --subscription "$AZURE_SUBSCRIPTION_ID"
status=1
for attempt in {1..6}; do
  if az container logs --resource-group "$DIAGNOSTIC_GROUP" --name "$FAILED_RUNNER_NAME" \
    --container-name deployer --only-show-errors > /tmp/runner.log 2> /tmp/runner-error.log; then
    status=0
    break
  fi
  echo "Waiting for the exact-container diagnostic reader grant (attempt $attempt)." >&2
  sleep 15
done
export DIAGNOSTIC_EXIT="$status"
python3 - <<'PY'
import json
import os
import pathlib
import re

text = pathlib.Path("/tmp/runner.log").read_text() + pathlib.Path("/tmp/runner-error.log").read_text()
text = re.sub(r"(?i)Bearer\s+\S+", "[REDACTED]", text)
text = re.sub(r"\beyJ[\w-]+\.[\w-]+\.[\w-]+\b", "[REDACTED]", text)
text = re.sub(r"(?i)((?:access_token|client_secret|password|authorization|connectionstring)\s*[:=]\s*)\S+", r"\1[REDACTED]", text)
report = {"status": "read" if os.environ["DIAGNOSTIC_EXIT"] == "0" else "failed", "logTail": text[-4000:]}
template = {
    "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
    "contentVersion": "1.0.0.0", "parameters": {"report": {"type": "object"}},
    "resources": [], "outputs": {"diagnostic": {"type": "object", "value": "[parameters('report')]"}},
}
pathlib.Path("/tmp/report.json").write_text(json.dumps(template))
pathlib.Path("/tmp/parameters.json").write_text(json.dumps({"report": {"value": report}}))
PY
az deployment group what-if --resource-group "$MAIN_GROUP" --name php2proof-bootstrap-diagnostic \
  --template-file /tmp/report.json --parameters @/tmp/parameters.json --only-show-errors --output none
az deployment group create --resource-group "$MAIN_GROUP" --name php2proof-bootstrap-diagnostic \
  --template-file /tmp/report.json --parameters @/tmp/parameters.json --mode Incremental --only-show-errors --output none
[[ "$status" == 0 ]]
