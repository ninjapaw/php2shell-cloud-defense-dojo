targetScope = 'subscription'

param mainGroupName string
param helperGroupName string
param location string
param suffix string
param invocationId string
param sourceSha256 string
@secure()
param sourceBundle object
param startRunner bool = false
param registerCdn bool = false
@allowed(['doctor', 'deploy', 'validate'])
param operation string = 'doctor'

var tags = {
  'dojo.scenario': 'php2proof-deployment-runner'
  'dojo.invocationId': invocationId
  'dojo.mainGroup': mainGroupName
  'dojo.temporary': 'true'
}
resource mainGroup 'Microsoft.Resources/resourceGroups@2025-04-01' existing = {
  name: mainGroupName
}
resource helperGroup 'Microsoft.Resources/resourceGroups@2025-04-01' = {
  name: helperGroupName
  location: location
  tags: tags
}
module foundation './deploy-runner-resources.bicep' = {
  name: 'php2proof-runner-foundation'
  scope: helperGroup
  params: {
    suffix: suffix
    location: location
    tags: tags
  }
}
resource metadataRole 'Microsoft.Authorization/roleDefinitions@2022-04-01' = {
  name: guid(subscription().id, invocationId, 'php2proof-deployment-metadata')
  properties: {
    roleName: 'PHP to Proof deployment metadata ${take(invocationId, 8)}'
    description: 'Temporary deployment-history and provider/runtime metadata access. No workload writes or security-plan writes.'
    type: 'CustomRole'
    assignableScopes: [subscription().id]
    permissions: [
      {
        actions: concat([
          'Microsoft.Resources/subscriptions/read'
          'Microsoft.Resources/subscriptions/providers/read'
          'Microsoft.Resources/deployments/read'
          'Microsoft.Resources/deployments/write'
          'Microsoft.Resources/deployments/validate/action'
          'Microsoft.Resources/deployments/whatIf/action'
          'Microsoft.Resources/deployments/operations/read'
          'Microsoft.Resources/deployments/operationStatuses/read'
          'Microsoft.Authorization/permissions/read'
          'Microsoft.Web/geoRegions/read'
          'Microsoft.Web/availableStacks/read'
          'Microsoft.Security/pricings/read'
        ], registerCdn ? ['Microsoft.Cdn/register/action'] : [])
        notActions: []
        dataActions: []
        notDataActions: []
      }
    ]
  }
}
resource metadataAccess 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(subscription().id, invocationId, 'php2proof-deployment-metadata-access')
  properties: {
    principalId: foundation.outputs.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: metadataRole.id
  }
}
module workloadAccess './deploy-runner-access.bicep' = {
  name: 'php2proof-workload-access'
  scope: mainGroup
  params: {
    principalId: foundation.outputs.principalId
    invocationId: invocationId
  }
}
module job './deploy-runner-job.bicep' = if (startRunner) {
  name: 'php2proof-runner-${operation}'
  scope: helperGroup
  params: {
    suffix: suffix
    location: location
    invocationId: invocationId
    operation: operation
    mainGroupName: mainGroupName
    identityId: foundation.outputs.identityId
    clientId: foundation.outputs.clientId
    sourceSha256: sourceSha256
    sourceBundle: sourceBundle
    registrationProvider: registerCdn ? 'Microsoft.Cdn' : ''
    tags: tags
  }
  dependsOn: [metadataAccess, workloadAccess]
}
output identityId string = foundation.outputs.identityId
output principalId string = foundation.outputs.principalId
output metadataRoleId string = metadataRole.id
output metadataRoleAssignmentId string = metadataAccess.id
output workloadRoleAssignmentId string = workloadAccess.outputs.roleAssignmentId
output helperGroupId string = helperGroup.id
