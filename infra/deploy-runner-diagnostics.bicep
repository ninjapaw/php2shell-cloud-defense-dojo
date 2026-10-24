param location string = resourceGroup().location
param failedRunnerName string
param identityId string
param clientId string
param principalId string
param mainGroupName string
param invocationId string
param tags object

resource failed 'Microsoft.ContainerInstance/containerGroups@2025-09-01' existing = {
  name: failedRunnerName
}
resource logReader 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(failed.id, invocationId, 'diagnostic-log-reader')
  scope: failed
  properties: {
    principalId: principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', 'acdd72a7-3385-48ef-bd42-f606fba81ae7')
  }
}
resource diagnostic 'Microsoft.ContainerInstance/containerGroups@2025-09-01' = {
  name: 'p2p-diagnostics-${take(uniqueString(invocationId), 8)}'
  location: location
  tags: tags
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: { '${identityId}': {} }
  }
  properties: {
    osType: 'Linux'
    restartPolicy: 'Never'
    containers: [
      {
        name: 'diagnostic'
        properties: {
          image: 'mcr.microsoft.com/azure-cli@sha256:b23e5168ce9654b1385c565a2c6cf60695f7b0d03056f7a0fafdc7c59a084512'
          command: [
            'python3'
            '-c'
            'import subprocess, sys; sys.exit(subprocess.run(["/bin/bash", "-c", sys.argv[1]], timeout=300).returncode)'
            loadTextContent('../scripts/cloud-diagnostics.sh')
          ]
          resources: { requests: { cpu: 1, memoryInGB: 1 } }
          environmentVariables: [
            { name: 'OPERATOR_CLIENT_ID', value: clientId }
            { name: 'AZURE_SUBSCRIPTION_ID', value: subscription().subscriptionId }
            { name: 'AZURE_CONFIG_DIR', value: '/tmp/php2proof-azure' }
            { name: 'AZURE_CORE_COLLECT_TELEMETRY', value: 'false' }
            { name: 'DIAGNOSTIC_GROUP', value: resourceGroup().name }
            { name: 'FAILED_RUNNER_NAME', value: failedRunnerName }
            { name: 'MAIN_GROUP', value: mainGroupName }
          ]
        }
      }
    ]
  }
  dependsOn: [logReader]
}
output diagnosticId string = diagnostic.id
