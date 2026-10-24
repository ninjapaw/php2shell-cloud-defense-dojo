targetScope = 'resourceGroup'

param suffix string
param workspaceResourceId string

resource site 'Microsoft.Web/sites@2025-03-01' existing = { name: 'p2p-${suffix}-operator' }
resource logs 'Microsoft.Web/sites/config@2025-03-01' = {
  parent: site
  name: 'logs'
  properties: {
    applicationLogs: { fileSystem: { level: 'Information' } }
    httpLogs: { fileSystem: { enabled: true, retentionInDays: 1, retentionInMb: 25 } }
  }
}
resource diagnostics 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  name: 'operator-to-workspace'
  scope: site
  properties: {
    workspaceId: workspaceResourceId
    logAnalyticsDestinationType: 'Dedicated'
    logs: [
      { category: 'AppServiceConsoleLogs', enabled: true }
      { category: 'AppServiceHTTPLogs', enabled: true }
    ]
  }
}
