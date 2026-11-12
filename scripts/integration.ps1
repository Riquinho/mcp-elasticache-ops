<#
.SYNOPSIS
  Disk-gated integration run: checks free space, brings up the throwaway cluster, runs `pytest -m integration`,
  and always tears everything down (`down -v`, `image prune -f`, fstrim). Never uses `prune -a`.
  Below -MinFreeGB but at or above -ReducedMinFreeGB it runs the reduced-footprint mode instead: one small Valkey
  container (--rm), no cluster, the whole suite against it.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File scripts/integration.ps1
  powershell -ExecutionPolicy Bypass -File scripts/integration.ps1 -MinFreeGB 8 -Wsl:$false
#>
param(
    [int]$MinFreeGB = 5,
    [int]$ReducedMinFreeGB = 2,
    [string]$Drive = 'C',
    [string]$ComposeFile = 'tests/docker-compose.cluster.yml',
    [string]$Distro = 'Ubuntu',
    [bool]$Wsl = $true
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot

function Invoke-Docker {
    if ($Wsl) { & wsl -d $Distro -e docker @args } else { & docker @args }
}

$free = [math]::Round((Get-PSDrive -Name $Drive).Free / 1GB, 1)
$reduced = $false
if ($free -lt $MinFreeGB) {
    if ($free -lt $ReducedMinFreeGB) {
        Write-Host "disk gate: ${free}G free on ${Drive}: (< ${ReducedMinFreeGB}G required even for the reduced run)"
        Write-Host "INTEGRATION SKIPPED: not enough disk, nothing was started. Trigger the CI integration job instead (workflow_dispatch or the 'integration' PR label)."
        Write-Host "To free space (only what tests created; never 'prune -a', never named volumes in use):"
        Write-Host "  1. wsl -d Ubuntu -e docker image prune -f"
        Write-Host "  2. wsl -d Ubuntu -e docker volume ls -q -f dangling=true   (remove only 64-hex anonymous names)"
        Write-Host "  3. wsl -d Ubuntu -e docker builder prune -f --filter until=24h"
        Write-Host "  4. wsl -d Ubuntu -u root -e fstrim -v /"
        Write-Host "Then re-run this script. The gates are not lowered."
        exit 0
    }
    $reduced = $true
    Write-Host "disk gate: ${free}G free on ${Drive}: (< ${MinFreeGB}G): reduced-footprint mode, one Valkey container and no cluster"
} else {
    Write-Host "disk gate: ${free}G free on ${Drive}: (>= ${MinFreeGB}G), running integration"
}

if ($reduced) {
    $name = 'prova-elasticache-ops-redis'
    $code = 1
    try {
        Invoke-Docker rm -f $name 2>&1 | Out-Null
        Invoke-Docker run --rm -d --name $name -p '127.0.0.1:16379:6379' 'valkey/valkey:8-alpine' | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'docker run failed' }
        Start-Sleep -Seconds 3
        $env:REDIS_TEST_URL = 'redis://127.0.0.1:16379/0'
        Push-Location $root
        try {
            uv run pytest -q
            $code = $LASTEXITCODE
        } finally {
            Pop-Location
        }
    } finally {
        Invoke-Docker rm -f $name 2>&1 | Out-Null
        Invoke-Docker image prune -f 2>&1 | Out-Null
        if ($Wsl) { & wsl -d $Distro -u root -e fstrim -v / 2>&1 | Out-Null }
    }
    exit $code
}

if ($Wsl) {
    $winPath = (Join-Path $root $ComposeFile)
    $file = (& wsl -d $Distro -e wslpath -a ($winPath -replace '\\', '/')).Trim()
} else {
    $file = Join-Path $root $ComposeFile
}

$code = 1
try {
    Invoke-Docker compose -f $file up -d --wait --wait-timeout 90
    if ($LASTEXITCODE -ne 0) { throw 'docker compose up failed' }
    $env:CLUSTER_TEST_HOST = '127.0.0.1'
    $env:CLUSTER_TEST_PORT = '7001'
    Push-Location $root
    try {
        uv run pytest -q -m integration tests/test_dataplane_integration.py
        $code = $LASTEXITCODE
    } finally {
        Pop-Location
    }
} finally {
    Invoke-Docker compose -f $file down -v --remove-orphans 2>&1 | Out-Null
    Invoke-Docker image prune -f 2>&1 | Out-Null
    if ($Wsl) { & wsl -d $Distro -u root -e fstrim -v / 2>&1 | Out-Null }
}
exit $code
