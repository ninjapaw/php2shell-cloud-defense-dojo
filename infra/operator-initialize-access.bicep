targetScope = 'resourceGroup'

param principalId string
param suffix string
param invocationId string

resource vault 'Microsoft.KeyVault/vaults@2025-05-01' existing = { name: 'p2p-${suffix}-operator' }
resource role 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(vault.id, invocationId, 'temporary-operator-initialize')
  scope: vault
  properties: {
    principalId: principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', 'b86a8fe4-44ce-4948-aee5-eccb2c155cd7')
  }
}

output temporaryAssignmentId string = role.id
