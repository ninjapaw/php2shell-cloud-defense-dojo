targetScope = 'resourceGroup'
param suffix string
param location string
param tags object
resource identity 'Microsoft.ManagedIdentity/userAssignedIdentities@2024-11-30' = {
  name: 'p2p-${suffix}-operator-publisher'
  location: location
  tags: tags
}
output identityId string = identity.id
output clientId string = identity.properties.clientId
output principalId string = identity.properties.principalId
