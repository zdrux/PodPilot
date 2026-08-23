[CmdletBinding()]
param(
    [string]$BootstrapKubeconfig = $env:PODPILOT_BOOTSTRAP_KUBECONFIG,
    [ValidatePattern('^[1-9][0-9]*[smh]$')]
    [string]$Duration = '8h'
)

$ErrorActionPreference = 'Stop'
$expectedServer = 'https://api.sno.192-168-0-200.sslip.io:6443'
$expectedIdentity = 'system:serviceaccount:ai-ops:ai-observer'

if ([string]::IsNullOrWhiteSpace($BootstrapKubeconfig)) {
    $BootstrapKubeconfig = 'C:\Users\zdrux\Documents\Codex\2026-08-22\i-w\work\sno-agent\build-20260822-205029\auth\kubeconfig'
}

if (-not (Get-Command oc -ErrorAction SilentlyContinue)) {
    throw 'The OpenShift CLI (oc) is not available on PATH.'
}

if (-not (Test-Path -LiteralPath $BootstrapKubeconfig -PathType Leaf)) {
    throw "External bootstrap kubeconfig not found. Set PODPILOT_BOOTSTRAP_KUBECONFIG or pass -BootstrapKubeconfig."
}

$previousKubeconfig = $env:KUBECONFIG

try {
    $env:KUBECONFIG = $BootstrapKubeconfig
    $bootstrapConfig = oc config view --raw --minify -o json | ConvertFrom-Json
    if ($LASTEXITCODE -ne 0) {
        throw 'Unable to read the external bootstrap kubeconfig.'
    }

    $cluster = $bootstrapConfig.clusters[0].cluster
    if ($cluster.server -ne $expectedServer) {
        throw "Refusing unexpected cluster API '$($cluster.server)'; expected '$expectedServer'."
    }

    if ([string]::IsNullOrWhiteSpace($cluster.'certificate-authority-data')) {
        throw 'The bootstrap kubeconfig does not contain embedded certificate authority data.'
    }

    $observerToken = (oc -n ai-ops create token ai-observer --duration=$Duration).Trim()
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($observerToken)) {
        throw 'Unable to create a short-lived token for ai-ops/ai-observer.'
    }

    $credentialDirectory = Join-Path ([System.IO.Path]::GetTempPath()) 'PodPilot'
    New-Item -ItemType Directory -Force -Path $credentialDirectory | Out-Null
    $observerKubeconfig = Join-Path $credentialDirectory 'ai-observer.kubeconfig'

    $configText = @"
apiVersion: v1
kind: Config
clusters:
  - name: sno
    cluster:
      server: $($cluster.server)
      certificate-authority-data: $($cluster.'certificate-authority-data')
contexts:
  - name: ai-observer@sno
    context:
      cluster: sno
      namespace: ai-ops
      user: ai-observer
current-context: ai-observer@sno
users:
  - name: ai-observer
    user:
      token: $observerToken
"@

    Set-Content -LiteralPath $observerKubeconfig -Value $configText -Encoding utf8 -NoNewline
    $env:KUBECONFIG = $observerKubeconfig

    $actualIdentity = (oc whoami).Trim()
    if ($LASTEXITCODE -ne 0 -or $actualIdentity -ne $expectedIdentity) {
        throw "Observer identity verification failed; received '$actualIdentity'."
    }

    $canCreatePods = (oc auth can-i create pods -n ai-ops).Trim()
    $canCreateClusterRoleBindings = (oc auth can-i create clusterrolebindings.rbac.authorization.k8s.io).Trim()
    if ($canCreatePods -ne 'yes' -or $canCreateClusterRoleBindings -ne 'yes') {
        throw 'PoC access check failed: the service account does not have the expected cluster-admin permissions.'
    }

    Write-Output "Connected to disposable PoC cluster $expectedServer as $expectedIdentity with cluster-admin access."
    Write-Output "KUBECONFIG points to a temporary credential valid for approximately $Duration."
}
catch {
    $env:KUBECONFIG = $previousKubeconfig
    throw
}
