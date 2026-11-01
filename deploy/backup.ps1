param(
    [string]$Output = ""
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
if (-not $Output) {
    $stamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $Output = Join-Path $root "data\backups\threatlens-$stamp.dump"
}
New-Item -ItemType Directory -Force -Path (Split-Path -Parent $Output) | Out-Null
$containerPath = "/tmp/threatlens-backup.dump"

Push-Location $root
try {
    docker compose exec -T postgres pg_dump -U threatlens -d threatlens -Fc -f $containerPath
    if ($LASTEXITCODE -ne 0) { throw "pg_dump failed" }
    docker compose cp "postgres:$containerPath" $Output
    if ($LASTEXITCODE -ne 0) { throw "docker compose cp failed" }
    docker compose exec -T postgres rm -f $containerPath
    Write-Host "Backup written to $Output"
} finally {
    Pop-Location
}
