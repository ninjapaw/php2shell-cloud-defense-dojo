targetScope = 'resourceGroup'

param suffix string
param mainGroupName string
param location string
param expiresAt string
param operatorOrigin string
param frontDoorId string
param workspaceId string
param credentialsReady bool
param initializeId string = ''
param tags object

var storageName = 'p2pops${suffix}${take(uniqueString(subscription().id, resourceGroup().name), 5)}'
var verifierName = loadJsonContent('../config/operator.dev.json').credentialSecret
var vaultName = 'p2p-${suffix}-operator'
var appName = 'p2p-${suffix}-operator'
var retentionDays = loadJsonContent('../config/operator.dev.json').rawEvidenceRetentionDays

resource keyVault 'Microsoft.KeyVault/vaults@2025-05-01' = {
  name: vaultName
  location: location
  tags: tags
  properties: {
    tenantId: tenant().tenantId
    sku: { family: 'A', name: 'standard' }
    accessPolicies: []
    enableRbacAuthorization: true
    enableSoftDelete: true
    enablePurgeProtection: true
    softDeleteRetentionInDays: 7
    enabledForDeployment: false
    enabledForDiskEncryption: false
    enabledForTemplateDeployment: false
    publicNetworkAccess: 'Disabled'
    networkAcls: { defaultAction: 'Allow', bypass: 'None' }
  }
}

resource storageAccount 'Microsoft.Storage/storageAccounts@2025-06-01' = {
  name: storageName
  location: location
  tags: tags
  kind: 'StorageV2'
  sku: { name: 'Standard_LRS' }
  properties: {
    allowSharedKeyAccess: false
    allowBlobPublicAccess: false
    minimumTlsVersion: 'TLS1_2'
    supportsHttpsTrafficOnly: true
    publicNetworkAccess: 'Disabled'
    accessTier: 'Hot'
  }
}
resource blobs 'Microsoft.Storage/storageAccounts/blobServices@2025-06-01' = {
  parent: storageAccount
  name: 'default'
  properties: {
    deleteRetentionPolicy: { enabled: true, days: retentionDays }
    containerDeleteRetentionPolicy: { enabled: true, days: retentionDays }
    isVersioningEnabled: true
  }
}
resource privateContainer 'Microsoft.Storage/storageAccounts/blobServices/containers@2025-06-01' = {
  parent: blobs
  name: 'operator-private'
  properties: { publicAccess: 'None' }
}
resource deploymentContainer 'Microsoft.Storage/storageAccounts/blobServices/containers@2025-06-01' = {
  parent: blobs
  name: 'operator-deploy'
  properties: { publicAccess: 'None' }
}
resource queues 'Microsoft.Storage/storageAccounts/queueServices@2025-06-01' = {
  parent: storageAccount
  name: 'default'
  properties: {}
}
resource queue 'Microsoft.Storage/storageAccounts/queueServices/queues@2025-06-01' = {
  parent: queues
  name: 'operator-jobs'
  properties: {}
}
resource retention 'Microsoft.Storage/storageAccounts/managementPolicies@2025-06-01' = {
  parent: storageAccount
  name: 'default'
  properties: {
    policy: {
      rules: [{
        name: 'operator-evidence-retention'
        enabled: true
        type: 'Lifecycle'
        definition: {
          filters: {
            blobTypes: ['blockBlob']
            prefixMatch: ['operator-private/', 'operator-deploy/']
          }
          actions: {
            baseBlob: { delete: { daysAfterModificationGreaterThan: retentionDays } }
            snapshot: { delete: { daysAfterCreationGreaterThan: retentionDays } }
            version: { delete: { daysAfterCreationGreaterThan: retentionDays } }
          }
        }
      }]
    }
  }
}

resource site 'Microsoft.Web/sites@2025-03-01' = {
  name: appName
  location: location
  tags: tags
  kind: 'app,linux'
  identity: { type: 'SystemAssigned' }
  properties: {
    serverFarmId: resourceId(subscription().subscriptionId, mainGroupName, 'Microsoft.Web/serverfarms', 'p2s-${suffix}-plan')
    httpsOnly: true
    publicNetworkAccess: 'Enabled'
    clientAffinityEnabled: false
    siteConfig: {
      linuxFxVersion: 'NODE|24-lts'
      appCommandLine: 'node operator/server.mjs'
      alwaysOn: true
      ftpsState: 'Disabled'
      minTlsVersion: '1.2'
      ipSecurityRestrictionsDefaultAction: 'Deny'
      ipSecurityRestrictions: [{
        name: 'ThisFrontDoorOnly'
        priority: 100
        action: 'Allow'
        ipAddress: 'AzureFrontDoor.Backend'
        tag: 'ServiceTag'
        headers: { 'x-azure-fdid': [frontDoorId] }
      }]
      scmIpSecurityRestrictionsUseMain: false
      scmIpSecurityRestrictionsDefaultAction: 'Allow'
    }
  }
}
resource appsettings 'Microsoft.Web/sites/config@2025-03-01' = {
  parent: site
  name: 'appsettings'
  properties: {
    NODE_ENV: 'production'
    AZURE_SUBSCRIPTION_ID: subscription().subscriptionId
    AZURE_TENANT_ID: tenant().tenantId
    DOJO_SUFFIX: suffix
    OPERATOR_ORIGIN: operatorOrigin
    OPERATOR_FRONT_DOOR_ID: frontDoorId
    OPERATOR_STORAGE_ACCOUNT: storageName
    OPERATOR_VAULT_NAME: vaultName
    OPERATOR_EXPIRES_AT: expiresAt
    OPERATOR_WORKSPACE_ID: workspaceId
    SCM_DO_BUILD_DURING_DEPLOYMENT: 'false'
    OPERATOR_INITIALIZE: string(!empty(initializeId))
    OPERATOR_INITIALIZE_ID: initializeId
  }
}
resource publishing 'Microsoft.Web/sites/basicPublishingCredentialsPolicies@2025-03-01' = [for policy in ['ftp', 'scm']: {
  parent: site
  name: policy
  properties: { allow: false }
}]

resource verifier 'Microsoft.KeyVault/vaults/secrets@2025-05-01' existing = {
  parent: keyVault
  name: verifierName
}
resource blobRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(privateContainer.id, appName, 'operator-blob')
  scope: privateContainer
  properties: {
    principalId: site.identity.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', 'ba92f5b4-2d11-453d-a403-e96b0029c9fe')
  }
}
resource queueRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(queue.id, appName, 'operator-queue')
  scope: queue
  properties: {
    principalId: site.identity.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '974c5e8b-45b9-4653-ba55-5f855dd0fb88')
  }
}
resource credentialRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (credentialsReady) {
  name: guid(verifier.id, appName, 'operator-verifier')
  scope: verifier
  properties: {
    principalId: site.identity.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '4633458b-17de-408a-b874-0445c86b69e6')
  }
}

output vaultName string = vaultName
output storageAccount string = storageName
output principalId string = site.identity.principalId
output defaultHostname string = site.properties.defaultHostName
output appName string = appName
