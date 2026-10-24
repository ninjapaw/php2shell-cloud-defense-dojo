param suffix string
param location string = resourceGroup().location
param invocationId string
@allowed(['doctor', 'deploy', 'validate'])
param operation string
param mainGroupName string
param identityId string
param clientId string
param sourceSha256 string
@secure()
param sourceBundle object
@allowed(['', 'Microsoft.Cdn'])
param registrationProvider string = ''
param tags object

var overlayInputs = sourceBundle.?overlays ?? []
var sourceVariables = [for (chunk, index) in sourceBundle.chunks: {
  name: 'SOURCE_PART_${index}'
  secureValue: chunk
}]

resource runner 'Microsoft.ContainerInstance/containerGroups@2025-09-01' = {
  name: 'p2p-${suffix}-${operation}-${take(uniqueString(invocationId), 5)}'
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
        name: 'deployer'
        properties: {
          image: 'mcr.microsoft.com/azure-cli@sha256:b23e5168ce9654b1385c565a2c6cf60695f7b0d03056f7a0fafdc7c59a084512'
          command: [
            'python3'
            '-c'
            'import subprocess, sys; sys.exit(subprocess.run(["/bin/bash", "-c", sys.argv[1]], timeout=5400).returncode)'
            loadTextContent('../scripts/cloud-deploy.sh')
          ]
          resources: { requests: { cpu: 1, memoryInGB: 2 } }
          environmentVariables: concat([
            { name: 'OPERATOR_CLIENT_ID', value: clientId }
            { name: 'SOURCE_SHA256', value: sourceSha256 }
            { name: 'SOURCE_PART_COUNT', value: string(length(sourceBundle.chunks)) }
            { name: 'SOURCE_OVERLAYS', secureValue: string(overlayInputs) }
            { name: 'DOJO_REGISTER_PROVIDER', value: registrationProvider }
            { name: 'AZURE_SUBSCRIPTION_ID', value: subscription().subscriptionId }
            { name: 'AZURE_CONFIG_DIR', value: '/tmp/php2proof-azure' }
            { name: 'AZURE_CORE_COLLECT_TELEMETRY', value: 'false' }
            { name: 'AZURE_EXTENSION_USE_DYNAMIC_INSTALL', value: 'no' }
            { name: 'DOJO_CLOUD_GROUP', value: mainGroupName }
            { name: 'DOJO_SUFFIX', value: suffix }
            { name: 'DOJO_CLOUD_OPERATION', value: operation }
          ], sourceVariables)
        }
      }
    ]
  }
}
output runnerId string = runner.id
