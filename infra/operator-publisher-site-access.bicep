targetScope = 'resourceGroup'
param principalId string
param invocationId string
param suffix string
resource app 'Microsoft.Web/sites@2025-03-01' existing = { name: 'p2s-${suffix}-app' }
resource assignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(app.id, invocationId, 'publisher-public-walkthrough')
  scope: app
  properties: {
    principalId: principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', 'de139f84-1756-47ae-9be6-808fbbe84772')
  }
}
output assignmentId string = assignment.id
