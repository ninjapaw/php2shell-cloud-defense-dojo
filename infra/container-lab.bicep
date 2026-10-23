targetScope = 'resourceGroup'

@allowed(['dev'])
param environmentName string = 'dev'
@minLength(4)
@maxLength(12)
param suffix string
param location string = resourceGroup().location
param tags object

var base = 'p2sc-${suffix}'

resource registry 'Microsoft.ContainerRegistry/registries@2025-04-01' = {
  name: 'p2sc${suffix}'
  location: location
  tags: tags
  sku: { name: 'Basic' }
  properties: {
    adminUserEnabled: false
    anonymousPullEnabled: false
    publicNetworkAccess: 'Enabled'
    networkRuleBypassOptions: 'AzureServices'
  }
}

resource workspace 'Microsoft.OperationalInsights/workspaces@2025-07-01' = {
  name: '${base}-logs'
  location: location
  tags: tags
  properties: {
    sku: { name: 'PerGB2018' }
    retentionInDays: 30
    workspaceCapping: { dailyQuotaGb: 1 }
    features: { disableLocalAuth: true }
  }
}

resource operator 'Microsoft.ManagedIdentity/userAssignedIdentities@2024-11-30' = {
  name: '${base}-operator'
  location: location
  tags: tags
}

resource cluster 'Microsoft.ContainerService/managedClusters@2025-08-01' = {
  name: '${base}-aks'
  location: location
  tags: tags
  sku: { name: 'Base', tier: 'Free' }
  identity: { type: 'SystemAssigned' }
  properties: {
    dnsPrefix: '${base}-${environmentName}'
    nodeResourceGroup: '${base}-nodes-dev'
    enableRBAC: true
    disableLocalAccounts: true
    aadProfile: {
      managed: true
      enableAzureRBAC: true
      tenantID: subscription().tenantId
    }
    apiServerAccessProfile: {
      enablePrivateCluster: true
      enablePrivateClusterPublicFQDN: false
      disableRunCommand: false
    }
    agentPoolProfiles: [
      {
        name: 'system'
        mode: 'System'
        count: 1
        vmSize: 'Standard_D2s_v6'
        osType: 'Linux'
        osSKU: 'AzureLinux3'
        osDiskType: 'Managed'
        osDiskSizeGB: 64
        type: 'VirtualMachineScaleSets'
        enableNodePublicIP: false
        maxPods: 30
        securityProfile: {
          enableSecureBoot: true
          enableVTPM: true
          sshAccess: 'Disabled'
        }
        upgradeSettings: { maxSurge: '1' }
        tags: tags
      }
    ]
    networkProfile: {
      networkPlugin: 'azure'
      networkPluginMode: 'overlay'
      networkDataplane: 'cilium'
      networkPolicy: 'cilium'
      outboundType: 'managedNATGateway'
      loadBalancerSku: 'standard'
      serviceCidr: '10.90.0.0/16'
      dnsServiceIP: '10.90.0.10'
      podCidr: '10.91.0.0/16'
      natGatewayProfile: { managedOutboundIPProfile: { count: 1 } }
    }
    securityProfile: {
      defender: {
        logAnalyticsWorkspaceResourceId: workspace.id
        securityMonitoring: { enabled: true }
      }
      imageCleaner: { enabled: true, intervalHours: 24 }
    }
    autoUpgradeProfile: {
      upgradeChannel: 'patch'
      nodeOSUpgradeChannel: 'NodeImage'
    }
  }
}

resource registryOperator 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  scope: registry
  name: guid(registry.id, operator.id, 'lab-operator')
  properties: {
    principalId: operator.properties.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', 'b24988ac-6180-42a0-ab88-20f7382dd24c')
  }
}

resource clusterOperator 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  scope: cluster
  name: guid(cluster.id, operator.id, 'lab-operator')
  properties: {
    principalId: operator.properties.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', 'b24988ac-6180-42a0-ab88-20f7382dd24c')
  }
}

resource kubernetesOperator 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  scope: cluster
  name: guid(cluster.id, operator.id, 'lab-kubernetes-operator')
  properties: {
    principalId: operator.properties.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', 'b1ff04bb-8a4e-4dc4-8eb5-8693973ce19b')
  }
}

resource imagePull 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  scope: registry
  name: guid(registry.id, cluster.id, 'kubelet-pull')
  properties: {
    principalId: cluster.properties.identityProfile.kubeletidentity.objectId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '7f951dda-4ed3-4680-a7ca-43fe172d538d')
  }
}

output clusterId string = cluster.id
output registryId string = registry.id
output registryHost string = registry.properties.loginServer
output workspaceId string = workspace.id
output operatorId string = operator.id
