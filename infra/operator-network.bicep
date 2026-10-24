targetScope = 'resourceGroup'

param suffix string
param storageAccountName string
param location string = 'centralus'
param expiresAt string

var tags = {
  'pawprint.managed': 'true'
  'pawprint.environment': 'dev'
  'pawprint.expiresAt': expiresAt
  'dojo.scenario': 'php2proof-operator'
  'dojo.suffix': suffix
}
resource storage 'Microsoft.Storage/storageAccounts@2025-06-01' existing = { name: storageAccountName }
resource vault 'Microsoft.KeyVault/vaults@2025-05-01' existing = { name: 'p2p-${suffix}-operator' }
resource site 'Microsoft.Web/sites@2025-03-01' existing = { name: 'p2p-${suffix}-operator' }
resource vnet 'Microsoft.Network/virtualNetworks@2025-05-01' = {
  name: 'p2p-${suffix}-operator-vnet'
  location: location
  tags: tags
  properties: {
    addressSpace: { addressPrefixes: ['10.254.80.0/24'] }
    subnets: [
      {
        name: 'app-integration'
        properties: {
          addressPrefix: '10.254.80.0/26'
          delegations: [{ name: 'app-service', properties: { serviceName: 'Microsoft.Web/serverFarms' } }]
        }
      }
      {
        name: 'private-endpoints'
        properties: {
          addressPrefix: '10.254.80.64/27'
          privateEndpointNetworkPolicies: 'Disabled'
        }
      }
    ]
  }
}
var integrationSubnet = '${vnet.id}/subnets/app-integration'
var endpointSubnet = '${vnet.id}/subnets/private-endpoints'
var services = [
  { name: 'blob', groupId: 'blob', resourceType: 'Microsoft.Storage/storageAccounts', resourceName: storage.name, zone: 'privatelink.blob.${environment().suffixes.storage}' }
  { name: 'queue', groupId: 'queue', resourceType: 'Microsoft.Storage/storageAccounts', resourceName: storage.name, zone: 'privatelink.queue.${environment().suffixes.storage}' }
  { name: 'vault', groupId: 'vault', resourceType: 'Microsoft.KeyVault/vaults', resourceName: vault.name, zone: 'privatelink.vaultcore.azure.net' }
]
resource zones 'Microsoft.Network/privateDnsZones@2024-06-01' = [for service in services: {
  name: service.zone
  location: 'global'
  tags: tags
}]
resource links 'Microsoft.Network/privateDnsZones/virtualNetworkLinks@2024-06-01' = [for (service, index) in services: {
  parent: zones[index]
  name: 'operator'
  location: 'global'
  tags: tags
  properties: {
    registrationEnabled: false
    virtualNetwork: { id: vnet.id }
  }
}]
resource endpoints 'Microsoft.Network/privateEndpoints@2025-05-01' = [for service in services: {
  name: 'p2p-${suffix}-${service.name}-private'
  location: location
  tags: tags
  properties: {
    subnet: { id: endpointSubnet }
    privateLinkServiceConnections: [{
      name: 'operator-${service.name}'
      properties: {
        privateLinkServiceId: resourceId(service.resourceType, service.resourceName)
        groupIds: [service.groupId]
      }
    }]
  }
}]
resource groups 'Microsoft.Network/privateEndpoints/privateDnsZoneGroups@2025-05-01' = [for (service, index) in services: {
  parent: endpoints[index]
  name: 'default'
  properties: {
    privateDnsZoneConfigs: [{ name: service.name, properties: { privateDnsZoneId: zones[index].id } }]
  }
}]
resource integration 'Microsoft.Web/sites/networkConfig@2025-03-01' = {
  parent: site
  name: 'virtualNetwork'
  properties: { subnetResourceId: integrationSubnet }
}

output vnetId string = vnet.id
output integrationSubnetId string = integrationSubnet
output privateEndpointIds array = [for (service, index) in services: endpoints[index].id]
output publicStorageOrVaultAccessEnabled bool = false
output appServiceSkuUpgraded bool = false
