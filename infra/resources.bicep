import { pawprintTags } from '../vendor/pawprint/modules/types.bicep'

param suffix string
param location string
param tags pawprintTags
@allowed(['training', 'fixed'])
param labState string
@allowed(['Detection', 'Prevention'])
param wafMode string
param phpVersion string
param enableSentinel bool
param enableAnalytics bool
param customDomainName string = ''
param associateCustomDomain bool = false

var baseName = 'p2s-${suffix}'
var appName = '${baseName}-app'
var workspaceName = '${baseName}-logs'

module monitoring '../vendor/pawprint/modules/monitoring/main.bicep' = {
  name: 'monitoring'
  params: {
    location: location
    workspaceName: workspaceName
    applicationInsightsName: '${baseName}-insights'
    emitApplicationInsightsConnectionString: false
    dailyQuotaGb: 1
    retentionInDays: 30
    tags: tags
  }
}

module edgeProfile '../vendor/pawprint/modules/front-door-waf/profile.bicep' = {
  name: 'edge-profile'
  params: {
    profileName: '${baseName}-edge'
    location: 'global'
    tags: tags
  }
}

module app '../vendor/pawprint/modules/php-web-app/main.bicep' = {
  name: 'php-app'
  params: {
    appName: appName
    planName: '${baseName}-plan'
    location: location
    frontDoorId: edgeProfile.outputs.frontDoorId
    workspaceId: monitoring.outputs.workspaceId
    phpVersion: phpVersion
    tags: tags
    appSettings: [
      { name: 'LAB_ENVIRONMENT', value: 'dev' }
      { name: 'LAB_STATE', value: labState }
      { name: 'LAB_RESOURCE_ID', value: resourceId('Microsoft.Web/sites', appName) }
      { name: 'PHP_INI_SCAN_DIR', value: '/usr/local/etc/php/conf.d:/home/site/wwwroot/conf.d' }
    ]
  }
}

module edge '../vendor/pawprint/modules/front-door-waf/main.bicep' = {
  name: 'edge-routing'
  params: {
    profileName: '${baseName}-edge'
    endpointName: '${baseName}-entry'
    policyName: 'p2s${suffix}waf'
    location: 'global'
    originHostName: app.outputs.hostName
    workspaceId: monitoring.outputs.workspaceId
    wafMode: wafMode
    enableTrainingMarker: true
    customDomainName: customDomainName
    associateCustomDomain: associateCustomDomain
    tags: tags
  }
}

module sentinel './modules/sentinel.bicep' = if (enableSentinel) {
  name: 'sentinel'
  params: {
    workspaceName: workspaceName
    enableAnalytics: enableAnalytics
    appResourceId: app.outputs.resourceId
  }
}

output appId string = app.outputs.resourceId
output appHostName string = app.outputs.hostName
output endpointHostName string = edge.outputs.endpointHostName
output workspaceId string = monitoring.outputs.workspaceId
