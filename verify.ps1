$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $root

$python = Join-Path $root ".venv\Scripts\python.exe"
if (-not (Test-Path -LiteralPath $python)) {
    throw "Virtual environment not found. Run .\run.ps1 first."
}

function Assert-ExitCode([string]$name) {
    if ($LASTEXITCODE -ne 0) {
        throw "$name failed with exit code $LASTEXITCODE"
    }
}

$serverProcess = $null
$existing = Get-NetTCPConnection -LocalPort 8000 -State Listen -ErrorAction SilentlyContinue
if (-not $existing) {
    $outLog = Join-Path $root "data\verify-server.log"
    $errLog = Join-Path $root "data\verify-server.err.log"
    New-Item -ItemType Directory -Force -Path (Join-Path $root "data") | Out-Null
    $serverProcess = Start-Process -FilePath $python -ArgumentList @(
        "-m", "uvicorn", "app.main:app", "--app-dir", "backend",
        "--host", "127.0.0.1", "--port", "8000"
    ) -WorkingDirectory $root -RedirectStandardOutput $outLog -RedirectStandardError $errLog -WindowStyle Hidden -PassThru
    Start-Sleep -Seconds 4
    $serverProcess.Refresh()
    if ($serverProcess.HasExited) {
        throw "Verification server failed to start. See $errLog"
    }
}

try {
    & $python -m pytest -q
    Assert-ExitCode "pytest"

    & $python -m ruff check backend
    Assert-ExitCode "ruff"

    & $python -m pip_audit -r requirements.txt
    Assert-ExitCode "pip-audit"

    & $python -m bandit -q -c pyproject.toml -r backend\app
    Assert-ExitCode "bandit"

    Push-Location frontend
    try {
        npm run lint
        Assert-ExitCode "eslint"

        npm run build
        Assert-ExitCode "frontend build"

        npm audit --omit=dev
        Assert-ExitCode "npm audit"

        npm run e2e
        Assert-ExitCode "browser smoke"
    } finally {
        Pop-Location
    }
} finally {
    if ($serverProcess) {
        Get-NetTCPConnection -LocalPort 8000 -State Listen -ErrorAction SilentlyContinue |
            Select-Object -ExpandProperty OwningProcess -Unique |
            ForEach-Object { Stop-Process -Id $_ -Force -ErrorAction SilentlyContinue }
    }
}

Write-Host "All verification checks passed."
