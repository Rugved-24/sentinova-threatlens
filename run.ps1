$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $root

$python = Join-Path $root ".venv\Scripts\python.exe"
if (-not (Test-Path -LiteralPath $python)) {
    $launcher = Get-Command py -ErrorAction SilentlyContinue
    if ($launcher) {
        & py -3 -m venv .venv
    } else {
        & python -m venv .venv
    }
}

if (-not (Test-Path -LiteralPath (Join-Path $root ".env"))) {
    Copy-Item -LiteralPath (Join-Path $root ".env.example") -Destination (Join-Path $root ".env")
}

if (-not (Test-Path -LiteralPath (Join-Path $root ".venv\Lib\site-packages\fastapi"))) {
    & $python -m pip install --disable-pip-version-check -r requirements.txt
}

if (-not (Test-Path -LiteralPath (Join-Path $root "frontend\node_modules"))) {
    Push-Location frontend
    try { npm install } finally { Pop-Location }
}

if (-not (Test-Path -LiteralPath (Join-Path $root "frontend\dist\index.html"))) {
    Push-Location frontend
    try { npm run build } finally { Pop-Location }
}

$listening = Get-NetTCPConnection -LocalPort 8000 -State Listen -ErrorAction SilentlyContinue
if ($listening) {
    Write-Host "ThreatLens is already running at http://127.0.0.1:8000"
    Start-Process "http://127.0.0.1:8000"
    exit 0
}

New-Item -ItemType Directory -Force -Path (Join-Path $root "data") | Out-Null
$outLog = Join-Path $root "data\server.log"
$errLog = Join-Path $root "data\server.err.log"

$process = Start-Process -FilePath $python -ArgumentList @(
    "-m", "uvicorn", "app.main:app", "--app-dir", "backend",
    "--host", "127.0.0.1", "--port", "8000"
) -WorkingDirectory $root -RedirectStandardOutput $outLog -RedirectStandardError $errLog -WindowStyle Hidden -PassThru

Start-Sleep -Seconds 4
$process.Refresh()
if ($process.HasExited) {
    Write-Host "ThreatLens failed to start. See $errLog"
    Get-Content -LiteralPath $errLog -Tail 20
    exit 1
}

Write-Host "ThreatLens is running at http://127.0.0.1:8000"
Write-Host "API docs: http://127.0.0.1:8000/api/docs"
Write-Host "Server log: $outLog"
Start-Process "http://127.0.0.1:8000"
