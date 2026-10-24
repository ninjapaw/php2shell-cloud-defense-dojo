function Start-Php2ProofWizard {
    param([string[]]$Arguments)
    $ErrorActionPreference = 'Stop'
    $node = Get-Command node -CommandType Application -ErrorAction Stop
    $entry = Join-Path $PSScriptRoot 'wizard.mjs'
    & $node.Source $entry @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "The deployment wizard stopped with exit code $LASTEXITCODE. No successful deployment is asserted."
    }
}

if ($MyInvocation.InvocationName -ne '.') {
    try {
        Start-Php2ProofWizard -Arguments $args
    } catch {
        Write-Error "Wizard could not finish: $($_.Exception.Message). Requires Node24.19+ and Microsoft's Azure CLI; see https://nodejs.org/download/release/ and https://learn.microsoft.com/cli/azure/install-azure-cli-windows."
        exit 1
    }
}
