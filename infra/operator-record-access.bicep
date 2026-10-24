targetScope = 'resourceGroup'
param suffix string
param principalId string
param invocationId string

resource site 'Microsoft.Web/sites@2025-03-01' existing = { name: 'p2s-${suffix}-app' }
resource publisher 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(site.id, invocationId, 'reviewed-record-publisher')
  scope: site
  properties: {
    principalId: principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', 'de139f84-1756-47ae-9be6-808fbbe84772')
  }
}
resource reader 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(resourceGroup().id, invocationId, 'reviewed-record-reader')
  properties: {
    principalId: principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', 'acdd72a7-3385-48ef-bd42-f606fba81ae7')
  }
}
output publisherId string = publisher.id
output readerId string = reader.id
