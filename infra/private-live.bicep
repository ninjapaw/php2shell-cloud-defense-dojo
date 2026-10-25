targetScope = 'subscription'

param suffix string
param window object
param tags object
param operatorPrincipalId string
param location string = 'centralus'
param mainGroupName string
param operatorGroupName string

resource privateGroup 'Microsoft.Resources/resourceGroups@2025-04-01' = {
  name: 'rg-p2sc-${suffix}-dev'
  location: location
  tags: tags
}
var mainGroupId = subscriptionResourceId('Microsoft.Resources/resourceGroups', mainGroupName)
var operatorGroupId = subscriptionResourceId('Microsoft.Resources/resourceGroups', operatorGroupName)
resource policy 'Microsoft.Network/frontDoorWebApplicationFirewallPolicies@2025-03-01' existing = { scope: resourceGroup(mainGroupName), name: 'p2pop${suffix}waf' }
#disable-next-line no-deployments-resources // Exact report resource identity must match the resource-scoped assignment module.
resource report 'Microsoft.Resources/deployments@2025-04-01' existing = { scope: resourceGroup(operatorGroupName), name: 'private-live-capture-${take(window.id, 8)}' }
resource vault 'Microsoft.KeyVault/vaults@2025-05-01' existing = { scope: resourceGroup(operatorGroupName), name: 'p2p-${suffix}-operator' }
resource verifier 'Microsoft.KeyVault/vaults/secrets@2025-05-01' existing = { parent: vault, name: 'operator-admin-verifier' }
var policyId = policy.id
var reportId = report.id
var verifierId = verifier.id
var roleSpecs = [
  { key: 'runner', actions: ['Microsoft.ContainerService/managedClusters/read', 'Microsoft.ContainerService/managedClusters/runcommand/action', 'Microsoft.ContainerService/managedClusters/commandResults/read'], dataActions: [], scopes: [privateGroup.id] }
  { key: 'waf', actions: ['Microsoft.Network/frontDoorWebApplicationFirewallPolicies/read', 'Microsoft.Network/frontDoorWebApplicationFirewallPolicies/write'], dataActions: [], scopes: [mainGroupId] }
  { key: 'report', actions: ['Microsoft.Resources/deployments/read', 'Microsoft.Resources/deployments/write'], dataActions: [], scopes: [operatorGroupId] }
  { key: 'verifier', actions: [], dataActions: ['Microsoft.KeyVault/vaults/secrets/setSecret/action'], scopes: [operatorGroupId] }
  { key: 'cleanup', actions: ['Microsoft.Resources/subscriptions/resourceGroups/read', 'Microsoft.Resources/subscriptions/resourceGroups/delete', 'Microsoft.Authorization/roleAssignments/delete'], dataActions: [], scopes: [privateGroup.id, mainGroupId, operatorGroupId] }
]
resource roles 'Microsoft.Authorization/roleDefinitions@2022-04-01' = [for role in roleSpecs: {
  name: guid(subscription().id, suffix, 'private-live', role.key)
  properties: {
    roleName: 'PHP to Proof ${suffix} private live ${role.key}'
    description: 'Closed private four-hour playbook; assignments are exact resources and cleanup revokes external grants.'
    type: 'CustomRole'
    assignableScopes: role.scopes
    permissions: [{ actions: role.actions, notActions: [], dataActions: role.dataActions, notDataActions: [] }]
  }
}]
module foundation './container-lab.bicep' = {
  scope: privateGroup
  name: 'private-live-foundation'
  params: { suffix: suffix, location: location, tags: tags }
}
module cleanup './private-live-cleanup.bicep' = {
  scope: privateGroup
  name: 'private-live-expiry'
  params: {
    suffix: suffix
    location: location
    window: window
    tags: tags
    externalGrants: [
      { worker: '${policyId}/providers/Microsoft.Authorization/roleAssignments/${guid(policyId, window.id, 'private-live-waf-writer')}', own: '${policyId}/providers/Microsoft.Authorization/roleAssignments/${guid(policyId, window.id, 'private-live-waf-cleanup')}' }
      { worker: '${reportId}/providers/Microsoft.Authorization/roleAssignments/${guid(reportId, window.id, 'private-live-report-writer')}', own: '${reportId}/providers/Microsoft.Authorization/roleAssignments/${guid(reportId, window.id, 'private-live-report-cleanup')}' }
      { worker: '${verifierId}/providers/Microsoft.Authorization/roleAssignments/${guid(verifierId, window.id, 'private-live-verifier-writer')}', own: '${verifierId}/providers/Microsoft.Authorization/roleAssignments/${guid(verifierId, window.id, 'private-live-verifier-cleanup')}' }
    ]
  }
}
module privateAccess './private-live-private-access.bicep' = {
  scope: privateGroup
  name: 'private-live-private-access'
  params: {
    suffix: suffix, windowId: window.id, operatorPrincipalId: operatorPrincipalId, cleanupPrincipalId: cleanup.outputs.principalId
    runnerRoleId: roles[0].id, cleanupRoleId: roles[4].id
    workspaceResourceId: '${mainGroupId}/providers/Microsoft.OperationalInsights/workspaces/p2s-${suffix}-logs'
  }
  dependsOn: [foundation]
}
module wafAccess './private-live-waf-access.bicep' = {
  scope: resourceGroup(mainGroupName)
  name: 'private-live-waf-access-${take(window.id, 8)}'
  params: {
    suffix: suffix, windowId: window.id, operatorPrincipalId: operatorPrincipalId, cleanupPrincipalId: cleanup.outputs.principalId
    writerRoleId: roles[1].id, cleanupRoleId: roles[4].id
  }
}
module operatorAccess './private-live-operator-access.bicep' = {
  scope: resourceGroup(operatorGroupName)
  name: 'private-live-operator-access-${take(window.id, 8)}'
  params: {
    suffix: suffix, windowId: window.id, operatorPrincipalId: operatorPrincipalId, cleanupPrincipalId: cleanup.outputs.principalId
    reportRoleId: roles[2].id, verifierRoleId: roles[3].id, cleanupRoleId: roles[4].id
  }
}
output privateGroupId string = privateGroup.id
output clusterId string = foundation.outputs.clusterId
output registryId string = foundation.outputs.registryId
output bootstrapIdentityId string = foundation.outputs.operatorId
output cleanupWorkflowId string = cleanup.outputs.workflowId
output expiresAt string = window.expiresAt
output expectedExternalGrants array = cleanup.outputs.externalGrantIds
output actualExternalGrants array = [
  { worker: wafAccess.outputs.writerGrantId, own: wafAccess.outputs.cleanupGrantId }
  { worker: operatorAccess.outputs.reportWriterGrantId, own: operatorAccess.outputs.reportCleanupGrantId }
  { worker: operatorAccess.outputs.verifierWriterGrantId, own: operatorAccess.outputs.verifierCleanupGrantId }
]
