param([string]$Directory = (Join-Path $PSScriptRoot "certs"))

$ErrorActionPreference = "Stop"
New-Item -ItemType Directory -Force -Path $Directory | Out-Null
$crt = Join-Path $Directory "server.crt"
$key = Join-Path $Directory "server.key"

if ((Test-Path $crt) -and (Test-Path $key)) {
    Write-Host "TLS certificate already exists: $crt"
    exit 0
}

$openssl = Get-Command openssl -ErrorAction SilentlyContinue
if ($openssl) {
    & $openssl.Source req -x509 -nodes -newkey rsa:2048 -days 365 `
        -keyout $key -out $crt `
        -subj "/CN=localhost" `
        -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
} else {
    docker run --rm -v "${Directory}:/certs" alpine/openssl req -x509 -nodes `
        -newkey rsa:2048 -days 365 `
        -keyout /certs/server.key -out /certs/server.crt `
        -subj "/CN=localhost" `
        -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
}

if (-not ((Test-Path $crt) -and (Test-Path $key))) {
    throw "TLS certificate generation failed"
}
Write-Host "Generated self-signed development certificate in $Directory"
Write-Host "Replace it with a trusted certificate before exposing ThreatLens outside localhost."
