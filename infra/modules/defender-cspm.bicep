targetScope = 'subscription'

// A false caller condition omits this module; it must never write Free on teardown.
resource posture 'Microsoft.Security/pricings@2026-07-01' = {
  name: 'CloudPosture'
  properties: {
    pricingTier: 'Standard'
  }
}
