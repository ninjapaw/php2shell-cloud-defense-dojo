targetScope = 'resourceGroup'
param suffix string
param windowId string
param operatorPrincipalId string
param cleanupPrincipalId string
param runnerRoleId string
param cleanupRoleId string
param workspaceResourceId string

resource cluster 'Microsoft.ContainerService/managedClusters@2025-08-01' existing = { name: 'p2sc-${suffix}-aks' }
resource reader 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(resourceGroup().id, windowId, 'private-live-reader')
  properties: { principalId: operatorPrincipalId, principalType: 'ServicePrincipal', roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', 'acdd72a7-3385-48ef-bd42-f606fba81ae7') }
}
resource runner 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  scope: cluster
  name: guid(cluster.id, windowId, 'private-live-runner')
  properties: { principalId: operatorPrincipalId, principalType: 'ServicePrincipal', roleDefinitionId: runnerRoleId }
}
resource kubernetes 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  scope: cluster
  name: guid(cluster.id, windowId, 'private-live-kubernetes')
  properties: {
    principalId: operatorPrincipalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', 'b1ff04bb-8a4e-4dc4-8eb5-8693973ce19b')
  }
}
resource cleanup 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(resourceGroup().id, windowId, 'private-live-cleanup')
  properties: { principalId: cleanupPrincipalId, principalType: 'ServicePrincipal', roleDefinitionId: cleanupRoleId }
}
resource audit 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  name: 'private-live-audit'
  scope: cluster
  properties: {
    workspaceId: workspaceResourceId
    logAnalyticsDestinationType: 'Dedicated'
    logs: [{ category: 'kube-audit-admin', enabled: true }]
  }
}
