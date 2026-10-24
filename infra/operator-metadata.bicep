targetScope = 'subscription'

param principalId string
param suffix string
param operatorGroupName string = loadJsonContent('../config/operator.dev.json').resourceGroup

resource metadataRole 'Microsoft.Authorization/roleDefinitions@2022-04-01' = {
  name: guid(subscription().id, operatorGroupName, 'php2proof-operator-metadata')
  properties: {
    roleName: 'PHP to Proof operator metadata ${suffix}'
    description: 'Subscription identity and Defender pricing observations only. No plan writes or workload writes.'
    type: 'CustomRole'
    assignableScopes: [subscription().id]
    permissions: [{
      actions: [
        'Microsoft.Resources/subscriptions/read'
        'Microsoft.Security/pricings/read'
      ]
      notActions: []
      dataActions: []
      notDataActions: []
    }]
  }
}
resource assignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(subscription().id, operatorGroupName, suffix, 'operator-metadata')
  properties: {
    principalId: principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: metadataRole.id
  }
}

output roleId string = metadataRole.id
output assignmentId string = assignment.id
