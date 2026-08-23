[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateSet(
        'podpilot-viewer',
        'podpilot-investigator',
        'podpilot-approver',
        'podpilot-breakglass'
    )]
    [string]$User
)

$ErrorActionPreference = 'Stop'
$expectedServer = 'https://api.sno.192-168-0-200.sslip.io:6443'
$secretName = 'podpilot-test-user-credentials'
$secretNamespace = 'openshift-config'

$actualServer = (& oc whoami --show-server).TrimEnd('/')
if ($LASTEXITCODE -ne 0 -or $actualServer -ne $expectedServer) {
    throw "Refusing to read credentials from unexpected cluster '$actualServer'."
}

$allowed = (& oc auth can-i get "secret/$secretName" -n $secretNamespace).Trim()
if ($LASTEXITCODE -ne 0 -or $allowed -ne 'yes') {
    throw "The current identity cannot read the PoC bootstrap credential Secret."
}

$secret = & oc get secret $secretName -n $secretNamespace -o json | ConvertFrom-Json
if ($LASTEXITCODE -ne 0) {
    throw "Unable to read the PoC bootstrap credential Secret."
}

try {
    $encoded = $secret.data.PSObject.Properties[$User].Value
    if (-not $encoded) {
        throw "The bootstrap Secret has no credential for '$User'."
    }

    $password = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($encoded))
    Set-Clipboard -Value $password
    Write-Host "Password for '$User' copied to the Windows clipboard; it was not printed."
} finally {
    $password = $null
    $encoded = $null
    $secret = $null
}
