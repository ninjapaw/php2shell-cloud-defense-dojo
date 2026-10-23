targetScope = 'resourceGroup'

param suffix string
param location string = resourceGroup().location
@allowed(['build', 'deploy', 'validate', 'test-detection', 'remediate'])
param action string
@allowed(['vulnerable', 'fixed'])
param variant string
param contextBundle string
param workload object
param images object
param invocationId string
param tags object

var base = 'p2sc-${suffix}'
resource operator 'Microsoft.ManagedIdentity/userAssignedIdentities@2024-11-30' existing = {
  name: '${base}-operator'
}

resource operation 'Microsoft.ContainerInstance/containerGroups@2025-09-01' = {
  name: '${base}-runner-${take(uniqueString(invocationId), 6)}'
  location: location
  tags: tags
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: { '${operator.id}': {} }
  }
  properties: {
    osType: 'Linux'
    restartPolicy: 'Never'
    containers: [
      {
        name: 'operator'
        properties: {
          image: 'mcr.microsoft.com/azure-cli@sha256:b23e5168ce9654b1385c565a2c6cf60695f7b0d03056f7a0fafdc7c59a084512'
          command: [
            '/bin/bash'
            '-c'
            '''
            set -euo pipefail
            printf '%s' "$LAB_BUNDLE" | base64 --decode | gzip --decompress > /tmp/lab-bundle.json
            jq -erj '.script' /tmp/lab-bundle.json > /tmp/lab-action.sh
            export LAB_CONTEXT="$(jq -ec '.files' /tmp/lab-bundle.json)"
            bash /tmp/lab-action.sh
            '''
          ]
          resources: { requests: { cpu: 1, memoryInGB: 2 } }
          environmentVariables: [
            { name: 'LAB_OPERATOR_CLIENT_ID', value: operator.properties.clientId }
            { name: 'LAB_INVOCATION_ID', value: invocationId }
            { name: 'LAB_SUBSCRIPTION', value: subscription().subscriptionId }
            { name: 'LAB_GROUP', value: resourceGroup().name }
            { name: 'LAB_REGISTRY', value: 'p2sc${suffix}' }
            { name: 'LAB_CLUSTER', value: '${base}-aks' }
            { name: 'LAB_ACTION', value: action }
            { name: 'LAB_VARIANT', value: variant }
            { name: 'LAB_IMAGES', value: string(images) }
            { name: 'LAB_BUNDLE', value: contextBundle }
            { name: 'LAB_WORKLOAD', value: string(workload) }
            { name: 'AZURE_CORE_COLLECT_TELEMETRY', value: 'false' }
            { name: 'AZURE_EXTENSION_USE_DYNAMIC_INSTALL', value: 'no' }
          ]
        }
      }
    ]
  }
}

output operationId string = operation.id
output runnerName string = operation.name
