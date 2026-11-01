param(
    [Parameter(Mandatory = $true)]
    [string]$InputFile
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$InputFile = (Resolve-Path $InputFile).Path
if (-not (Test-Path $InputFile)) { throw "Backup file not found: $InputFile" }

$containerPath = "/tmp/threatlens-restore.dump"
Push-Location $root
try {
    docker compose stop api worker beat
    docker compose cp $InputFile "postgres:$containerPath"
    if ($LASTEXITCODE -ne 0) { throw "docker compose cp failed" }
    docker compose exec -T postgres pg_restore -U threatlens -d threatlens --clean --if-exists --no-owner $containerPath
    if ($LASTEXITCODE -ne 0) { throw "pg_restore failed" }
    docker compose exec -T postgres rm -f $containerPath
    docker compose start api worker beat
    Write-Host "Restore complete. Verify /api/v1/health before resuming traffic."
} finally {
    Pop-Location
}
