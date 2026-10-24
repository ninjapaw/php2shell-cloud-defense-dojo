BeforeAll {
    . (Join-Path $PSScriptRoot '..\scripts\start.ps1')
    function Invoke-Php2ProofTestNode {
        $script:NodeArguments = @($args)
        $global:LASTEXITCODE = $script:RequestedNodeExit
    }
}

Describe 'PowerShell deployment wizard launcher' {
    BeforeEach {
        $script:NodeArguments = @()
        $script:RequestedNodeExit = 0
        Mock Get-Command { [pscustomobject]@{ Source = 'Invoke-Php2ProofTestNode' } } -ParameterFilter { $Name -eq 'node' }
    }
    It 'forwards arguments as values, including a profile path with spaces' {
        Start-Php2ProofWizard -Arguments @('--profile', 'C:\test folder\profile.json')
        $script:NodeArguments[0] | Should -Match 'scripts[\\/]wizard\.mjs$'
        $script:NodeArguments[1] | Should -Be '--profile'
        $script:NodeArguments[2] | Should -Be 'C:\test folder\profile.json'
    }
    It 'propagates a failed wizard rather than asserting successful deployment' {
        $script:RequestedNodeExit = 2
        { Start-Php2ProofWizard -Arguments @('--check') } | Should -Throw '*exit code 2*'
    }
    It 'fails closed when Node is missing' {
        Mock Get-Command { throw 'Node missing' } -ParameterFilter { $Name -eq 'node' }
        { Start-Php2ProofWizard -Arguments @('--check') } | Should -Throw '*Node missing*'
        $script:NodeArguments.Count | Should -Be 0
    }
}
