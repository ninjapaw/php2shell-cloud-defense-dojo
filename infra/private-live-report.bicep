targetScope = 'resourceGroup'
param windowId string
output result object = { schemaVersion: 1, windowId: windowId, status: 'not-started' }
