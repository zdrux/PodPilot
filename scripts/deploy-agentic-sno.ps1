param(
    [string]$BootstrapKubeconfig = $env:PODPILOT_BOOTSTRAP_KUBECONFIG
)

$ErrorActionPreference = 'Stop'

$openRouterKey = $env:OPENROUTER_API_KEY
if (-not $openRouterKey) {
    $openRouterKey = [Environment]::GetEnvironmentVariable('OPENROUTER_API_KEY', 'User')
}
if (-not $openRouterKey) {
    $openRouterKey = [Environment]::GetEnvironmentVariable('OPENROUTER_API_KEY', 'Machine')
}
if (-not $openRouterKey) {
    throw 'OPENROUTER_API_KEY is not available in the process, user, or machine environment.'
}

. "$PSScriptRoot\connect-sno.ps1" -BootstrapKubeconfig $BootstrapKubeconfig

$runtimeIdentity = 'system:serviceaccount:ai-ops:podpilot-investigator'
$canRead = oc auth can-i get pods --all-namespaces --as=$runtimeIdentity
if ($LASTEXITCODE -ne 0 -or $canRead.Trim() -ne 'yes') {
    throw 'The PodPilot runtime identity cannot perform its expected cluster read.'
}
$canMutate = oc auth can-i patch deployments.apps --all-namespaces --as=$runtimeIdentity
$canMutateResult = $canMutate.Trim()
# `oc auth can-i` deliberately exits 1 when authorization is denied. Treat the
# explicit `no` response as the successful least-privilege outcome. OpenShift
# may append reconciliation diagnostics for referenced roles that are not installed.
$canMutateDecision = ($canMutateResult -split '\s+', 2)[0]
if ($canMutateDecision -notin @('yes', 'no')) {
    throw 'Unable to verify mutation access for the PodPilot runtime identity.'
}
if ($canMutateDecision -eq 'yes') {
    throw 'Refusing the agentic lab deployment because podpilot-investigator can patch Deployments.'
}

oc apply -k deploy/openshift/build/sno-binary
if ($LASTEXITCODE -ne 0) { throw 'Unable to apply the SNO binary build resources.' }

$tarCommand = Get-Command tar.exe -ErrorAction SilentlyContinue
if (-not $tarCommand) {
    throw 'tar.exe is required to create the bounded binary build context.'
}
$buildArchive = Join-Path (
    [System.IO.Path]::GetTempPath()
) ("podpilot-agentic-build-{0}.tar.gz" -f [guid]::NewGuid().ToString('N'))
try {
    & $tarCommand.Source -czf $buildArchive `
        --exclude='*/__pycache__/*' `
        --exclude='*.pyc' `
        Dockerfile Dockerfile.oc-runner requirements.lock pyproject.toml `
        apps/api apps/web apps/oc-runner `
        packages/openshift-client packages/diagnostics
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $buildArchive -PathType Leaf)) {
        throw 'Unable to create the bounded binary build context.'
    }

    oc start-build podpilot --from-archive=$buildArchive --follow -n ai-ops
    if ($LASTEXITCODE -ne 0) { throw 'The PodPilot application image build failed.' }
    oc start-build podpilot-oc-runner --from-archive=$buildArchive --follow -n ai-ops
    if ($LASTEXITCODE -ne 0) { throw 'The PodPilot oc runner image build failed.' }
}
finally {
    if (Test-Path -LiteralPath $buildArchive -PathType Leaf) {
        Remove-Item -LiteralPath $buildArchive -Force
    }
}

oc apply -k deploy/openshift/overlays/sno-milestone-one
if ($LASTEXITCODE -ne 0) { throw 'Unable to apply the agentic SNO overlay.' }
oc rollout restart deployment/podpilot -n ai-ops
if ($LASTEXITCODE -ne 0) { throw 'Unable to restart PodPilot onto the newly built image.' }
oc rollout status deployment/podpilot -n ai-ops --timeout=600s
if ($LASTEXITCODE -ne 0) { throw 'The PodPilot rollout did not become ready.' }

$openRouterKey | oc exec -i deployment/podpilot -n ai-ops -c api -- `
    python -m podpilot_api.lab_openrouter --credential-stdin
if ($LASTEXITCODE -ne 0) {
    throw 'The OpenRouter Chat Completions profile could not be configured and probed.'
}

Write-Output (
    'Agentic SNO lab deployed with openai/gpt-oss-120b via OpenRouter Chat Completions. ' +
    'The oc runner uses podpilot-investigator and has no Deployment patch permission.'
)
