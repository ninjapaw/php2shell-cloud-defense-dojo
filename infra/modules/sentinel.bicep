param workspaceName string
param appResourceId string
param enableAnalytics bool = false

resource workspace 'Microsoft.OperationalInsights/workspaces@2025-07-01' existing = {
  name: workspaceName
}

resource onboarding 'Microsoft.SecurityInsights/onboardingStates@2025-09-01' = {
  scope: workspace
  name: 'default'
  properties: {
    customerManagedKey: false
  }
}

resource correlation 'Microsoft.SecurityInsights/alertRules@2025-09-01' = {
  name: guid(workspace.id, 'php2shell-synthetic-correlation')
  scope: workspace
  kind: 'Scheduled'
  properties: {
    displayName: 'PHP to Proof - SYNTHETIC multi-signal training correlation'
    description: 'Correlates a benign WAF marker with labelled synthetic PHP events. Not a Defender alert, verified CVE finding, process execution, outbound connection, or proof of compromise. Review resource, run ID and timestamps.'
    severity: 'Informational'
    enabled: enableAnalytics
    query: replace(loadTextContent('../../detections/correlation.kql'), '__APP_RESOURCE_ID__', appResourceId)
    queryFrequency: 'PT15M'
    queryPeriod: 'PT1H'
    triggerOperator: 'GreaterThan'
    triggerThreshold: 0
    suppressionEnabled: false
    suppressionDuration: 'PT1H'
    incidentConfiguration: {
      createIncident: false
    }
    eventGroupingSettings: {
      aggregationKind: 'SingleAlert'
    }
    customDetails: {
      RunId: 'RunId'
      AppResourceId: 'AppResourceId'
      EvidenceKind: 'EvidenceKind'
    }
  }
  dependsOn: [onboarding]
}
