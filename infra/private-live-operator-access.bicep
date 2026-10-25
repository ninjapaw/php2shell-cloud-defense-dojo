targetScope = 'resourceGroup'
param suffix string
param windowId string
param operatorPrincipalId string
param cleanupPrincipalId string
param reportRoleId string
param verifierRoleId string
param cleanupRoleId string

var reportName = 'private-live-capture-${take(windowId, 8)}'
module report './private-live-report.bicep' = { name: reportName, params: { windowId: windowId } }
#disable-next-line no-deployments-resources // The existing report resource is required for exact-deployment IAM scope.
resource record 'Microsoft.Resources/deployments@2025-04-01' existing = { name: reportName }
resource reportWriter 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  scope: record
  name: guid(record.id, windowId, 'private-live-report-writer')
  properties: { principalId: operatorPrincipalId, principalType: 'ServicePrincipal', roleDefinitionId: reportRoleId }
  dependsOn: [report]
}
resource reportCleanup 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  scope: record
  name: guid(record.id, windowId, 'private-live-report-cleanup')
  properties: { principalId: cleanupPrincipalId, principalType: 'ServicePrincipal', roleDefinitionId: cleanupRoleId }
  dependsOn: [report]
}
resource vault 'Microsoft.KeyVault/vaults@2025-05-01' existing = { name: 'p2p-${suffix}-operator' }
resource verifier 'Microsoft.KeyVault/vaults/secrets@2025-05-01' existing = { parent: vault, name: 'operator-admin-verifier' }
resource verifierWriter 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  scope: verifier
  name: guid(verifier.id, windowId, 'private-live-verifier-writer')
  properties: { principalId: operatorPrincipalId, principalType: 'ServicePrincipal', roleDefinitionId: verifierRoleId }
}
resource verifierCleanup 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  scope: verifier
  name: guid(verifier.id, windowId, 'private-live-verifier-cleanup')
  properties: { principalId: cleanupPrincipalId, principalType: 'ServicePrincipal', roleDefinitionId: cleanupRoleId }
}
output reportWriterGrantId string = reportWriter.id
output reportCleanupGrantId string = reportCleanup.id
output verifierWriterGrantId string = verifierWriter.id
output verifierCleanupGrantId string = verifierCleanup.id
