targetScope = 'subscription'

param invocationId string
param suffix string
param location string = 'centralus'
param operatorGroupName string = loadJsonContent('../config/operator.dev.json').resourceGroup

var helperName = 'NP-PHPToProof-Operator-Deploy-Temp-${take(invocationId, 8)}'
var tags = {
  'dojo.scenario': 'php2proof-operator-publisher'
  'dojo.invocationId': invocationId
  'dojo.temporary': 'true'
}
resource helper 'Microsoft.Resources/resourceGroups@2025-04-01' = {
  name: helperName
  location: location
  tags: tags
}
module identity './operator-publisher-identity.bicep' = {
  name: 'operator-publisher-identity'
  scope: helper
  params: { suffix: suffix, location: location, tags: tags }
}
module contributor './operator-publisher-access.bicep' = {
  name: 'operator-publisher-access'
  scope: resourceGroup(operatorGroupName)
  params: { principalId: identity.outputs.principalId, invocationId: invocationId }
}
resource metadata 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(subscription().id, invocationId, 'operator-publisher-metadata')
  properties: {
    principalId: identity.outputs.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', guid(subscription().id, operatorGroupName, 'php2proof-operator-metadata'))
  }
}
output helperGroup string = helper.name
output clientId string = identity.outputs.clientId
output principalId string = identity.outputs.principalId
output identityId string = identity.outputs.identityId
output metadataAssignmentId string = metadata.id
output operatorAssignmentId string = contributor.outputs.assignmentId
