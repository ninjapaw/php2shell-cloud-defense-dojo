targetScope = 'resourceGroup'

param suffix string
param location string = resourceGroup().location
param window object
param tags object
param externalGrants array
var arm = substring(environment().resourceManager, 0, max(0, length(environment().resourceManager) - 1))

resource workflow 'Microsoft.Logic/workflows@2019-05-01' = {
  name: 'p2sc-${suffix}-expiry'
  location: location
  tags: tags
  identity: { type: 'SystemAssigned' }
  properties: {
    state: 'Enabled'
    definition: {
      '$schema': 'https://schema.management.azure.com/providers/Microsoft.Logic/schemas/2016-06-01/workflowdefinition.json#'
      contentVersion: '1.0.0.0'
      parameters: {
        privateGroupId: { type: 'String', defaultValue: resourceGroup().id }
        externalGrants: { type: 'Array', defaultValue: externalGrants }
      }
      triggers: {
        AtExpiry: {
          type: 'Recurrence'
          recurrence: { frequency: 'Minute', interval: 5, startTime: window.expiresAt }
          runtimeConfiguration: { concurrency: { runs: 1 } }
        }
      }
      actions: {
        InitializeCounter: {
          type: 'InitializeVariable'
          inputs: { variables: [{ name: 'CleanupCount', type: 'integer', value: 0 }] }
          runAfter: {}
        }
        ReadOwnedGroup: {
          type: 'Http'
          inputs: {
            method: 'GET'
            uri: '${arm}${resourceGroup().id}?api-version=2025-04-01'
            authentication: { type: 'ManagedServiceIdentity', audience: environment().resourceManager }
            retryPolicy: { type: 'exponential', count: 4, interval: 'PT20S' }
          }
          runAfter: { InitializeCounter: ['Succeeded'] }
        }
        CheckBoundary: {
          type: 'If'
          expression: {
            and: [
              { greaterOrEquals: ['@ticks(utcNow())', '@ticks(\'${window.expiresAt}\')'] }
              { equals: ['@body(\'ReadOwnedGroup\')?[\'tags\']?[\'dojo.liveWindowId\']', window.id] }
              { equals: ['@body(\'ReadOwnedGroup\')?[\'tags\']?[\'dojo.liveScenario\']', 'php2proof-private-live'] }
              { equals: ['@body(\'ReadOwnedGroup\')?[\'tags\']?[\'pawprint.environment\']', 'dev'] }
              { equals: ['@body(\'ReadOwnedGroup\')?[\'tags\']?[\'pawprint.expiresAt\']', window.expiresAt] }
            ]
          }
          actions: {
            RetryRevocation: {
              type: 'Until'
              expression: '@equals(variables(\'CleanupCount\'),length(parameters(\'externalGrants\')))'
              limit: { count: 120, timeout: 'PT1H' }
              actions: {
                DeleteWorkerGrant: {
                  type: 'Http'
                  inputs: {
                    method: 'DELETE'
                    uri: '@concat(\'${arm}\',parameters(\'externalGrants\')[variables(\'CleanupCount\')][\'worker\'],\'?api-version=2022-04-01\')'
                    authentication: { type: 'ManagedServiceIdentity', audience: environment().resourceManager }
                    retryPolicy: { type: 'exponential', count: 4, interval: 'PT20S' }
                  }
                  runAfter: {}
                }
                WorkerRemoved: {
                  type: 'If'
                  expression: '@contains(createArray(200,204,404),outputs(\'DeleteWorkerGrant\')?[\'statusCode\'])'
                  actions: {
                    DeleteCleanupGrant: {
                      type: 'Http'
                      inputs: {
                        method: 'DELETE'
                        uri: '@concat(\'${arm}\',parameters(\'externalGrants\')[variables(\'CleanupCount\')][\'own\'],\'?api-version=2022-04-01\')'
                        authentication: { type: 'ManagedServiceIdentity', audience: environment().resourceManager }
                        retryPolicy: { type: 'exponential', count: 4, interval: 'PT20S' }
                      }
                      runAfter: {}
                    }
                    CleanupGrantRemoved: {
                      type: 'If'
                      expression: '@contains(createArray(200,204,404),outputs(\'DeleteCleanupGrant\')?[\'statusCode\'])'
                      actions: {
                        CountCompletedPair: { type: 'IncrementVariable', inputs: { name: 'CleanupCount', value: 1 }, runAfter: {} }
                      }
                      else: { actions: { CleanupGrantFailed: { type: 'Compose', inputs: 'Owned cleanup grant was not removed; group deletion is denied.', runAfter: {} } } }
                      runAfter: { DeleteCleanupGrant: ['Succeeded', 'Failed', 'TimedOut'] }
                    }
                  }
                  else: { actions: { WorkerGrantFailed: { type: 'Compose', inputs: 'Owned execution grant was not removed; its cleanup grant is retained for retry.', runAfter: {} } } }
                  runAfter: { DeleteWorkerGrant: ['Succeeded', 'Failed', 'TimedOut'] }
                }
                WaitBeforeNextPair: {
                  type: 'If'
                  expression: '@less(variables(\'CleanupCount\'),length(parameters(\'externalGrants\')))'
                  actions: {
                    Pause: { type: 'Wait', inputs: { interval: { count: 30, unit: 'Second' } }, runAfter: {} }
                  }
                  else: { actions: {} }
                  runAfter: { WorkerRemoved: ['Succeeded', 'Failed', 'TimedOut', 'Skipped'] }
                }
              }
              runAfter: {}
            }
            DeleteOnlyAfterRevocation: {
              type: 'If'
              expression: '@equals(variables(\'CleanupCount\'),length(parameters(\'externalGrants\')))'
              actions: {
                DeletePrivateGroup: {
                  type: 'Http'
                  operationOptions: 'DisableAsyncPattern'
                  inputs: {
                    method: 'DELETE'
                    uri: '${arm}${resourceGroup().id}?api-version=2025-04-01'
                    authentication: { type: 'ManagedServiceIdentity', audience: environment().resourceManager }
                    retryPolicy: { type: 'exponential', count: 4, interval: 'PT20S' }
                  }
                  runAfter: {}
                }
              }
              else: { actions: { RevocationFailed: { type: 'Terminate', inputs: { runStatus: 'Failed', runError: { code: 'ScopedGrantCleanupIncomplete', message: 'Durable bounded retries did not prove scoped grant removal. Private resources remain billable; an owner must reconcile cleanup before deletion.' } }, runAfter: {} } } }
              runAfter: { RetryRevocation: ['Succeeded', 'Failed', 'TimedOut'] }
            }
          }
          else: { actions: { BoundaryMismatch: { type: 'Terminate', inputs: { runStatus: 'Failed', runError: { code: 'PrivateBoundaryMismatch', message: 'Exact private window/group tags or expiry did not match; nothing was deleted.' } }, runAfter: {} } } }
          runAfter: { ReadOwnedGroup: ['Succeeded'] }
        }
      }
      outputs: {}
    }
    parameters: {}
  }
}

output principalId string = workflow.identity.principalId
output workflowId string = workflow.id
output externalGrantIds array = externalGrants
