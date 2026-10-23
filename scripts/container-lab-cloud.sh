#!/usr/bin/env bash
set -euo pipefail

[[ "$LAB_GROUP" =~ ^rg-p2sc-[a-z0-9]{4,12}-dev$ ]] || { echo "Invalid isolated group." >&2; exit 1; }
[[ "$LAB_CLUSTER" =~ ^p2sc-[a-z0-9]{4,12}-aks$ ]] || { echo "Invalid isolated cluster." >&2; exit 1; }
[[ "$LAB_REGISTRY" =~ ^p2sc[a-z0-9]{4,12}$ ]] || { echo "Invalid isolated registry." >&2; exit 1; }
[[ "$LAB_VARIANT" == vulnerable || "$LAB_VARIANT" == fixed ]] || { echo "Invalid comparison state." >&2; exit 1; }
az login --identity --client-id "$LAB_OPERATOR_CLIENT_ID" --allow-no-subscriptions --output none
az account set --subscription "$LAB_SUBSCRIPTION"
[[ "$(az account show --query id -o tsv)" == "$LAB_SUBSCRIPTION" ]] || { echo "Subscription mismatch." >&2; exit 1; }
registry_id="/subscriptions/$LAB_SUBSCRIPTION/resourceGroups/$LAB_GROUP/providers/Microsoft.ContainerRegistry/registries/$LAB_REGISTRY"
phase="initialization"
record_failure() {
  local status=$?
  trap - ERR
  echo "Container operation failed in phase $phase (exit $status)." >&2
  if ! az tag update --resource-id "$registry_id" --operation Merge \
    --tags "dojo.operationState=failed" "dojo.operationPhase=$phase" "dojo.operationExit=$status" \
    --only-show-errors --output none; then
    echo "Unable to persist operation diagnostics; inspect this exact runner's logs." >&2
  fi
  exit "$status"
}
trap record_failure ERR

invoke_cluster() {
  local command="$1"
  shift
  az aks command invoke --subscription "$LAB_SUBSCRIPTION" --resource-group "$LAB_GROUP" \
    --name "$LAB_CLUSTER" --command "$command" "$@" --only-show-errors -o json > /tmp/cluster-result.json
  if ! jq -e '.provisioningState == "Succeeded" and .exitCode == 0' /tmp/cluster-result.json > /dev/null; then
    echo "The bounded in-cluster operation failed; no successful result is asserted." >&2
    jq -r '[.provisioningState, .reason, .logs] | map(select(type == "string" and length > 0)) | join("\n")' /tmp/cluster-result.json >&2
    return 1
  fi
  jq -r '.logs' /tmp/cluster-result.json
}

case "$LAB_ACTION" in
  build|deploy|remediate)
    phase="source-context"
    mkdir -p /tmp/php2shell-context/container-lab /tmp/php2shell-context/app/assets
    while IFS= read -r path; do
      case "$path" in
        container-lab/Dockerfile|container-lab/apache.conf|container-lab/php.ini|container-lab/index.php|container-lab/health.php|app/lab.php|app/assets/style.css) ;;
        *) echo "Unexpected build-context path." >&2; exit 1 ;;
      esac
      printf '%s' "$LAB_CONTEXT" | jq -erj --arg path "$path" '.[$path]' > "/tmp/php2shell-context/$path"
    done < <(printf '%s' "$LAB_CONTEXT" | jq -er 'keys[]')
    comparisons=(fixed)
    if [[ "$LAB_VARIANT" == vulnerable ]]; then comparisons+=(vulnerable); fi
    for comparison in "${comparisons[@]}"; do
      version="$(printf '%s' "$LAB_IMAGES" | jq -er --arg variant "$comparison" '.[$variant].version')"
      source="$(printf '%s' "$LAB_IMAGES" | jq -er --arg variant "$comparison" '.[$variant].source')"
      [[ "$source" =~ ^docker.io/library/php@sha256:[a-f0-9]{64}$ ]] || { echo "Unpinned PHP source." >&2; exit 1; }
      [[ "$version" == 8.4.26 || "$version" == 8.4.27 ]] || { echo "Unreviewed PHP version." >&2; exit 1; }
      phase="import-$comparison"
      az acr import --subscription "$LAB_SUBSCRIPTION" --name "$LAB_REGISTRY" --source "$source" \
        --image "php-base:$version" --force --only-show-errors
      base_digest="${source##*@}"
      phase="build-$comparison"
      az acr build --subscription "$LAB_SUBSCRIPTION" --registry "$LAB_REGISTRY" \
        --image "php2shell:$version" --platform linux/amd64 \
        --file /tmp/php2shell-context/container-lab/Dockerfile \
        --build-arg "PHP_BASE_IMAGE=$LAB_REGISTRY.azurecr.io/php-base@$base_digest" \
        --build-arg "LAB_VARIANT=$comparison" --build-arg "PHP_VERSION_EXPECTED=$version" \
        --no-logs --only-show-errors /tmp/php2shell-context
    done
    version="$(printf '%s' "$LAB_IMAGES" | jq -er --arg variant "$LAB_VARIANT" '.[$variant].version')"
    digest="$(az acr repository show --subscription "$LAB_SUBSCRIPTION" --name "$LAB_REGISTRY" \
      --image "php2shell:$version" --query digest -o tsv --only-show-errors)"
    [[ "$digest" =~ ^sha256:[a-f0-9]{64}$ ]] || { echo "ACR did not return an immutable image digest." >&2; exit 1; }
    fixed_digest="$(az acr repository show --subscription "$LAB_SUBSCRIPTION" --name "$LAB_REGISTRY" \
      --image php2shell:8.4.27 --query digest -o tsv --only-show-errors)"
    [[ "$fixed_digest" =~ ^sha256:[a-f0-9]{64}$ ]] || { echo "Fixed comparison digest is missing." >&2; exit 1; }
    az tag update --resource-id "$registry_id" \
      --operation Merge --tags "dojo.imageDigest=$digest" "dojo.imageVariant=$LAB_VARIANT" \
      "dojo.fixedDigest=$fixed_digest" "dojo.buildState=built" --only-show-errors --output none
    if [[ "$LAB_ACTION" == build ]]; then
      printf 'Built image: %s.azurecr.io/php2shell@%s\n' "$LAB_REGISTRY" "$digest"
      exit 0
    fi
    printf '%s' "$LAB_WORKLOAD" | jq --arg image "$LAB_REGISTRY.azurecr.io/php2shell@$digest" \
      '(.items[] | select(.kind == "Deployment") | .spec.template.spec.containers[0].image) = $image' > /tmp/workload.json
    phase="workload-rollout"
    invoke_cluster 'kubectl apply -f workload.json && kubectl -n php2shell-isolated rollout status deployment/php-runtime --timeout=300s' --file /tmp/workload.json
    printf 'Deployed image: %s.azurecr.io/php2shell@%s\n' "$LAB_REGISTRY" "$digest"
    ;;
  validate|test-detection) ;;
  *) echo "Unsupported bounded container action." >&2; exit 1 ;;
esac

phase="sensor-validation"
invoke_cluster 'kubectl -n kube-system get daemonsets -o json'
sensor_records="$(jq -ec '.logs | fromjson | [.items[] | select(.metadata.name | contains("defender")) |
  {name: .metadata.name, desired: .status.desiredNumberScheduled, ready: .status.numberReady}]' /tmp/cluster-result.json)"
jq -e '.logs | fromjson | [.items[] | select(.metadata.name | contains("defender"))] |
  length > 0 and all(.[]; .status.desiredNumberScheduled > 0 and .status.numberReady == .status.desiredNumberScheduled)' /tmp/cluster-result.json > /dev/null
phase="pod-isolation"
invoke_cluster 'kubectl -n php2shell-isolated get pods -l app=php2shell-container-lab -o json'
jq -e '.logs | fromjson | [.items[] | select(.metadata.deletionTimestamp == null)] |
  length == 1 and all(.[]; .status.phase == "Running" and .spec.automountServiceAccountToken == false and
    .spec.securityContext.runAsNonRoot == true and .spec.securityContext.runAsUser == 10001 and
    .spec.securityContext.seccompProfile.type == "RuntimeDefault" and
    (.spec.hostNetwork != true) and (.spec.hostPID != true) and (.spec.hostIPC != true) and
    (.spec.containers | length) == 1 and
    .spec.containers[0].securityContext.readOnlyRootFilesystem == true and
    .spec.containers[0].securityContext.allowPrivilegeEscalation == false and
    .spec.containers[0].securityContext.privileged == false and
    .spec.containers[0].securityContext.capabilities.drop == ["ALL"] and
    (.spec.containers[0].securityContext.capabilities.add // [] | length) == 0 and
    (.spec.initContainers // [] | length) == 0 and
    all(.spec.volumes[]?; (has("hostPath") or has("secret") or has("projected")) | not) and
    (.spec.containers[0].image | test("@sha256:[a-f0-9]{64}$")) and
    .status.containerStatuses[0].ready == true)' /tmp/cluster-result.json > /dev/null
observed_image="$(jq -er '.logs | fromjson | [.items[] | select(.metadata.deletionTimestamp == null)] |
  .[0].spec.containers[0].image' /tmp/cluster-result.json)"
invoke_cluster 'kubectl get namespace/php2shell-isolated -o json'
jq -e '.logs | fromjson | .metadata.name == "php2shell-isolated" and
  .metadata.labels["pod-security.kubernetes.io/enforce"] == "restricted"' /tmp/cluster-result.json > /dev/null
phase="network-isolation"
invoke_cluster 'kubectl -n php2shell-isolated get networkpolicy/deny-all -o json'
jq -e '.logs | fromjson | .spec.podSelector == {} and (.spec.ingress // [] | length) == 0 and
  (.spec.egress // [] | length) == 0 and (.spec.policyTypes | sort) == ["Egress","Ingress"]' /tmp/cluster-result.json > /dev/null
invoke_cluster 'kubectl -n php2shell-isolated get services -o json'
jq -e '.logs | fromjson | .items | length == 0' /tmp/cluster-result.json > /dev/null
phase="runtime-health"
invoke_cluster 'kubectl -n php2shell-isolated exec deployment/php-runtime -- php -r '\''if (false === readfile("http://127.0.0.1:8080/health.php")) { exit(1); }'\'''
health="$(jq -er '.logs | fromjson' /tmp/cluster-result.json)"
version="$(printf '%s' "$LAB_IMAGES" | jq -er --arg variant "$LAB_VARIANT" '.[$variant].version')"
printf '%s' "$health" | jq -e --arg version "$version" --arg variant "$LAB_VARIANT" \
  '.scenario == "php2shell-container-lab" and .sapi == "apache2handler" and .phpVersion == $version and .variant == $variant and .matchesExpectedRuntime == true' > /dev/null
expected_digest="$(az acr repository show --subscription "$LAB_SUBSCRIPTION" --name "$LAB_REGISTRY" \
  --image "php2shell:$version" --query digest -o tsv --only-show-errors)"
[[ "$expected_digest" =~ ^sha256:[a-f0-9]{64}$ && "$observed_image" == "$LAB_REGISTRY.azurecr.io/php2shell@$expected_digest" ]] \
  || { echo "Observed running image does not match the independent ACR digest." >&2; exit 1; }
az tag update --resource-id "/subscriptions/$LAB_SUBSCRIPTION/resourceGroups/$LAB_GROUP/providers/Microsoft.ContainerService/managedClusters/$LAB_CLUSTER" \
  --operation Merge --tags "dojo.observedPhp=$version" "dojo.observedSapi=apache2handler" \
  "dojo.sensorReady=true" "dojo.podIsolationVerified=true" "dojo.networkIsolationVerified=true" \
  "dojo.observedImage=$observed_image" \
  "dojo.runtimeVerifiedAt=$(date -u +%Y-%m-%dT%H:%M:%SZ)" --only-show-errors --output none
az tag update --resource-id "$registry_id" --operation Merge --tags \
  "dojo.operationState=validated" "dojo.operationPhase=completed" --only-show-errors --output none

telemetry_identity=""
if [[ "$LAB_ACTION" == test-detection ]]; then
  invoke_cluster 'kubectl -n php2shell-isolated exec deployment/php-runtime -- id'
  telemetry_identity="$(jq -r '.logs' /tmp/cluster-result.json | tr '\r\n' ' ')"
  [[ "$telemetry_identity" == uid=10001* ]] || { echo "Unexpected workload process identity." >&2; exit 1; }
  echo "An authorized read-only process was executed. Verify audit/runtime ingestion independently."
  echo "This is NOT an exploit or guaranteed detection trigger. Inspect actual Defender alerts; no alert is fabricated."
fi

result="$(jq -cn --argjson health "$health" --arg image "$observed_image" \
  --argjson sensors "$sensor_records" --arg invocation "$LAB_INVOCATION_ID" --arg identity "$telemetry_identity" \
  '{health: $health, image: $image, sensorDaemonsets: $sensors, namespace: "php2shell-isolated",
    isolationVerified: true, invocationId: $invocation, telemetryIdentity: $identity,
    evidenceKind: "live-managed-identity-container-validation"}')"
printf 'PHP2SHELL_RESULT %s\n' "$result"
