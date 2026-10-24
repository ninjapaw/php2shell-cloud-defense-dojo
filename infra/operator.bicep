targetScope = 'subscription'

param suffix string
param expiresAt string
param credentialsReady bool = false
param initializeId string = ''
@description('Explicit response-write feature opt-in only. Does not renew expiry or grant write permissions.')
param responseWritesEnabled bool = false
param location string = loadJsonContent('../config/dev.json').location
param mainGroupName string = loadJsonContent('../config/dev.json').resourceGroup
param operatorGroupName string = loadJsonContent('../config/operator.dev.json').resourceGroup

var tags = {
  'pawprint.managed': 'true'
  'pawprint.environment': 'dev'
  'pawprint.expiresAt': expiresAt
  'dojo.scenario': 'php2proof-operator'
  'dojo.suffix': suffix
  'dojo.originalLab': mainGroupName
}

resource operatorGroup 'Microsoft.Resources/resourceGroups@2025-04-01' = {
  name: operatorGroupName
  location: location
  tags: tags
}

module endpoint './operator-endpoint.bicep' = {
  name: 'php2proof-operator-endpoint-${suffix}'
  scope: resourceGroup(mainGroupName)
  params: {
    suffix: suffix
    tags: tags
  }
}

module resources './operator-resources.bicep' = {
  name: 'php2proof-operator-resources-${suffix}'
  scope: operatorGroup
  params: {
    suffix: suffix
    mainGroupName: mainGroupName
    location: location
    expiresAt: expiresAt
    operatorOrigin: endpoint.outputs.origin
    frontDoorId: endpoint.outputs.frontDoorId
    workspaceId: endpoint.outputs.workspaceId
    credentialsReady: credentialsReady
    initializeId: initializeId
    responseWritesEnabled: responseWritesEnabled
    tags: tags
  }
}

module routes './operator-routes.bicep' = {
  name: 'php2proof-operator-routes-${suffix}'
  scope: resourceGroup(mainGroupName)
  params: {
    suffix: suffix
    operatorHostname: resources.outputs.defaultHostname
  }
}

module network './operator-network.bicep' = {
  name: 'php2proof-operator-private-network-${suffix}'
  scope: operatorGroup
  params: {
    suffix: suffix
    location: location
    storageAccountName: resources.outputs.storageAccount
    expiresAt: expiresAt
  }
}

module access './operator-access.bicep' = {
  name: 'php2proof-operator-read-access-${suffix}'
  scope: resourceGroup(mainGroupName)
  params: {
    suffix: suffix
    principalId: resources.outputs.principalId
  }
}

module metadata './operator-metadata.bicep' = {
  name: 'php2proof-operator-metadata-${suffix}'
  params: {
    principalId: resources.outputs.principalId
    suffix: suffix
    operatorGroupName: operatorGroupName
  }
}

output operatorUrl string = endpoint.outputs.origin
output operatorGroupId string = operatorGroup.id
output vaultName string = resources.outputs.vaultName
output storageAccount string = resources.outputs.storageAccount
output operatorAppName string = resources.outputs.appName
output operatorPrincipalId string = resources.outputs.principalId
output originalExpiry string = expiresAt
output publicApplicationPrivilegesChanged bool = false
