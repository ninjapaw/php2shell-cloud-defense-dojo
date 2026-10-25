targetScope = 'resourceGroup'
param suffix string
param windowId string
param operatorPrincipalId string
param cleanupPrincipalId string
param writerRoleId string
param cleanupRoleId string

resource policy 'Microsoft.Network/frontDoorWebApplicationFirewallPolicies@2025-03-01' existing = { name: 'p2pop${suffix}waf' }
resource writer 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  scope: policy
  name: guid(policy.id, windowId, 'private-live-waf-writer')
  properties: { principalId: operatorPrincipalId, principalType: 'ServicePrincipal', roleDefinitionId: writerRoleId }
}
resource cleanup 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  scope: policy
  name: guid(policy.id, windowId, 'private-live-waf-cleanup')
  properties: { principalId: cleanupPrincipalId, principalType: 'ServicePrincipal', roleDefinitionId: cleanupRoleId }
}
output writerGrantId string = writer.id
output cleanupGrantId string = cleanup.id
