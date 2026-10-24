targetScope = 'resourceGroup'
param suffix string
param principalId string

resource vault 'Microsoft.KeyVault/vaults@2025-05-01' existing = { name: 'p2p-${suffix}-operator' }
resource verifier 'Microsoft.KeyVault/vaults/secrets@2025-05-01' existing = {
  parent: vault
  name: loadJsonContent('../config/operator.dev.json').credentialSecret
}
resource role 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(verifier.id, 'p2p-${suffix}-operator', 'operator-verifier')
  scope: verifier
  properties: {
    principalId: principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '4633458b-17de-408a-b874-0445c86b69e6')
  }
}
output verifierAssignmentId string = role.id
