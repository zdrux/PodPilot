param([string]$BootstrapKubeconfig = $env:PODPILOT_BOOTSTRAP_KUBECONFIG)
$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\connect-sno.ps1" -BootstrapKubeconfig $BootstrapKubeconfig

# Preserve the existing database before the opt-in migration. Backup stays on its protected PVC.
@'
import sqlite3, datetime
from podpilot_api.settings import get_settings
path = get_settings().database_url.removeprefix('sqlite:///')
destination = path + '.before-incidents-' + datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%d%H%M%S')
with sqlite3.connect(path) as source, sqlite3.connect(destination) as target:
    source.backup(target)
print('Database backup completed on the PodPilot PVC.')
'@ | oc exec -i deployment/podpilot -n ai-ops -c api -- python -
if ($LASTEXITCODE -ne 0) { throw 'Database backup failed.' }

$incidentArchive = Join-Path ([IO.Path]::GetTempPath()) ("podpilot-incidents-{0}.tar.gz" -f [guid]::NewGuid().ToString('N'))
try {
    tar.exe -czf $incidentArchive --exclude='*/__pycache__/*' --exclude='*.pyc' `
        Dockerfile requirements.lock pyproject.toml apps/api apps/web packages/openshift-client packages/diagnostics
    if ($LASTEXITCODE -ne 0) { throw 'Build archive failed.' }
    oc start-build podpilot --from-archive=$incidentArchive --follow -n ai-ops
    if ($LASTEXITCODE -ne 0) { throw 'Incident application build failed.' }
} finally {
    if (Test-Path -LiteralPath $incidentArchive) { Remove-Item -LiteralPath $incidentArchive }
}
oc apply --dry-run=server -k deploy/openshift/overlays/sno-incident-response
if ($LASTEXITCODE -ne 0) { throw 'Incident composition validation failed.' }
oc apply -k deploy/openshift/overlays/sno-incident-response
if ($LASTEXITCODE -ne 0) { throw 'Incident deployment failed.' }
oc rollout restart deployment/podpilot -n ai-ops
if ($LASTEXITCODE -ne 0) { throw 'Unable to restart onto the newly built image.' }
oc rollout status deployment/podpilot -n ai-ops --timeout=600s
if ($LASTEXITCODE -ne 0) { throw 'Incident rollout did not become ready.' }
oc auth can-i get pods --all-namespaces --as=system:serviceaccount:ai-ops:podpilot-incident-reader
oc auth can-i patch deployments.apps --all-namespaces --as=system:serviceaccount:ai-ops:podpilot-incident-reader
if ($LASTEXITCODE -eq 0) { throw 'Investigation reader unexpectedly has mutation access.' }
Write-Output 'Incident PoC deployed. Configure its Secret-backed connection and Alertmanager receiver next.'
