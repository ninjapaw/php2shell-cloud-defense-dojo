targetScope = 'resourceGroup'

param suffix string
param operatorHostname string

resource profile 'Microsoft.Cdn/profiles@2025-04-15' existing = { name: 'p2s-${suffix}-edge' }
resource operatorEndpoint 'Microsoft.Cdn/profiles/afdEndpoints@2025-04-15' existing = { parent: profile, name: 'p2p-${suffix}-operator' }
resource publicEndpoint 'Microsoft.Cdn/profiles/afdEndpoints@2025-04-15' existing = { parent: profile, name: 'p2s-${suffix}-entry' }
resource customDomain 'Microsoft.Cdn/profiles/customDomains@2025-04-15' existing = { parent: profile, name: 'application-domain' }
resource originGroup 'Microsoft.Cdn/profiles/originGroups@2025-04-15' = {
  parent: profile
  name: 'operator'
  properties: {
    sessionAffinityState: 'Disabled'
    healthProbeSettings: { probePath: '/health', probeRequestType: 'GET', probeProtocol: 'Https', probeIntervalInSeconds: 120 }
    loadBalancingSettings: { sampleSize: 4, successfulSamplesRequired: 3, additionalLatencyInMilliseconds: 50 }
  }
}
resource origin 'Microsoft.Cdn/profiles/originGroups/origins@2025-04-15' = {
  parent: originGroup
  name: 'operator'
  properties: {
    hostName: operatorHostname
    originHostHeader: operatorHostname
    httpsPort: 443
    httpPort: 80
    priority: 1
    weight: 1000
    enabledState: 'Enabled'
    enforceCertificateNameCheck: true
  }
}
resource privateRoute 'Microsoft.Cdn/profiles/afdEndpoints/routes@2025-04-15' = {
  parent: operatorEndpoint
  name: 'operator'
  properties: {
    originGroup: { id: originGroup.id }
    supportedProtocols: ['Https']
    patternsToMatch: ['/*']
    forwardingProtocol: 'HttpsOnly'
    linkToDefaultDomain: 'Enabled'
    enabledState: 'Enabled'
    httpsRedirect: 'Enabled'
  }
  dependsOn: [origin]
}
resource publicEvidenceRoute 'Microsoft.Cdn/profiles/afdEndpoints/routes@2025-04-15' = {
  parent: publicEndpoint
  name: 'recorded-evidence'
  properties: {
    originGroup: { id: originGroup.id }
    supportedProtocols: ['Https']
    patternsToMatch: ['/evidence/*', '/style.css']
    forwardingProtocol: 'HttpsOnly'
    linkToDefaultDomain: 'Enabled'
    enabledState: 'Enabled'
    httpsRedirect: 'Enabled'
    customDomains: [{ id: customDomain.id }]
  }
  dependsOn: [origin]
}
