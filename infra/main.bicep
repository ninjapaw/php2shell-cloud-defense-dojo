targetScope = 'subscription'

@description('Only isolated development training is supported.')
@allowed(['dev'])
param environmentName string = 'dev'

@description('Exact isolated dev resource-group name from config/dev.json. The CLI checks existing ownership before deployment.')
@minLength(1)
@maxLength(90)
param groupName string

@description('User-chosen lowercase alphanumeric suffix; use the same value throughout the lifecycle.')
@minLength(4)
@maxLength(12)
param suffix string

@description('Regional workload location. Front Door is global.')
param location string

@description('Original creation time, retained during repair and remediation.')
param startedAt string

@description('Expiry reminder only; no automatic deletion is installed.')
param expiresAt string

@description('Configured lifetime, recorded for reporting.')
@minValue(1)
@maxValue(72)
param ttlHours int = 24

@description('Synthetic training surfaces are removed in fixed state. Neither state contains an exploit.')
@allowed(['training', 'fixed'])
param labState string = 'training'

@description('Detection first. Prevention is a separate explicit operator action.')
@allowed(['Detection', 'Prevention'])
param wafMode string = 'Detection'

@description('Supported Linux PHP stack, checked by doctor against the live runtime catalog.')
@allowed(['8.4', '8.5'])
param phpVersion string = '8.4'

@description('EXPLICIT BILLABLE subscription-wide Defender CSPM opt-in. False does not disable an existing plan.')
param enableDefenderCspm bool = false

@description('Remember a prior CSPM opt-in without silently re-enabling its pricing plan.')
param defenderCspmExpected bool = enableDefenderCspm

@description('EXPLICIT BILLABLE onboarding of this lab workspace to Microsoft Sentinel.')
param enableSentinel bool = false

@description('Opt-in synthetic training analytics. Requires Sentinel; hunting files work without this.')
param enableAnalytics bool = false

@description('Optional Cloudflare-hosted subdomain. The explicit domain command bootstraps and validates it.')
@maxLength(253)
param customDomainName string = ''

@description('Preserve an established association on repair. Enable initially only after DNS and Azure domain approval.')
param associateCustomDomain bool = false

var tags = {
  'pawprint.managed': 'true'
  'pawprint.runId': 'php2shell-${suffix}-${environmentName}'
  'pawprint.environment': environmentName
  'pawprint.startedAt': startedAt
  'pawprint.expiresAt': expiresAt
  'pawprint.ttlHours': string(ttlHours)
  'dojo.scenario': 'php2shell-cloud-defense-dojo'
  'dojo.suffix': suffix
  'dojo.state': labState
  'dojo.wafMode': wafMode
  'dojo.defenderCspmExpected': defenderCspmExpected ? 'true' : 'false'
  'dojo.sentinel': enableSentinel ? 'true' : 'false'
  'dojo.analytics': enableAnalytics ? 'true' : 'false'
  'dojo.customDomain': customDomainName
  'dojo.customDomainReady': associateCustomDomain ? 'true' : 'false'
}

resource group 'Microsoft.Resources/resourceGroups@2025-04-01' = {
  name: groupName
  location: location
  tags: tags
}

module lab './resources.bicep' = {
  name: 'php2shell-lab-${suffix}'
  scope: group
  params: {
    suffix: suffix
    location: location
    tags: tags
    labState: labState
    wafMode: wafMode
    phpVersion: phpVersion
    enableSentinel: enableSentinel
    enableAnalytics: enableAnalytics
    customDomainName: customDomainName
    associateCustomDomain: associateCustomDomain
  }
}

module cspm './modules/defender-cspm.bicep' = if (enableDefenderCspm) {
  name: 'php2shell-cspm-${suffix}'
}

output resourceGroupName string = group.name
output appId string = lab.outputs.appId
output appHostName string = lab.outputs.appHostName
output endpointHostName string = lab.outputs.endpointHostName
output workspaceId string = lab.outputs.workspaceId
