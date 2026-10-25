targetScope = 'resourceGroup'
param suffix string
param location string = 'centralus'
param identityId string
param clientId string
param sourceSha256 string
param originalExpiry string
param liveWindow object = {}
param publicationId string = ''
@secure()
param sourceBundle object

var sourceVariables = [for (chunk, index) in sourceBundle.chunks: { name: 'SOURCE_${index}', secureValue: chunk }]

resource job 'Microsoft.ContainerInstance/containerGroups@2025-09-01' = {
  name: empty(publicationId) ? 'p2p-${suffix}-hunting-publish' : 'p2p-${suffix}-publish-${take(publicationId, 8)}'
  location: location
  identity: { type: 'UserAssigned', userAssignedIdentities: { '${identityId}': {} } }
  properties: {
    osType: 'Linux'
    restartPolicy: 'Never'
    containers: [{
      name: 'publish'
      properties: {
        image: 'mcr.microsoft.com/azure-cli@sha256:b23e5168ce9654b1385c565a2c6cf60695f7b0d03056f7a0fafdc7c59a084512'
        resources: { requests: { cpu: 1, memoryInGB: 2 } }
        command: ['/bin/bash', '-c', 'exec timeout 1200 bash -c "$1"', '--', loadTextContent('../operator/publish-hunts.sh')]
        environmentVariables: concat([
          { name: 'AZURE_SUBSCRIPTION_ID', value: subscription().subscriptionId }
          { name: 'PUBLISHER_CLIENT_ID', value: clientId }
          { name: 'OPERATOR_GROUP', value: loadJsonContent('../config/operator.dev.json').resourceGroup }
          { name: 'MAIN_GROUP', value: loadJsonContent('../config/dev.json').resourceGroup }
          { name: 'DOJO_SUFFIX', value: suffix }
          { name: 'ORIGINAL_EXPIRY', value: originalExpiry }
          { name: 'LIVE_WINDOW_JSON', value: string(liveWindow) }
          { name: 'SOURCE_SHA256', value: sourceSha256 }
          { name: 'SOURCE_COUNT', value: string(length(sourceBundle.chunks)) }
        ], sourceVariables)
      }
    }]
  }
}
output jobId string = job.id
