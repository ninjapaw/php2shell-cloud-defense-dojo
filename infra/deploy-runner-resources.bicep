param suffix string
param location string = resourceGroup().location
param tags object

resource operator 'Microsoft.ManagedIdentity/userAssignedIdentities@2024-11-30' = {
  name: 'p2p-${suffix}-deployer'
  location: location
  tags: tags
}
output identityId string = operator.id
output clientId string = operator.properties.clientId
output principalId string = operator.properties.principalId
