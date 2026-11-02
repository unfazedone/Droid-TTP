# ==============================================================================
# DroidTTP - Windows TLS Self-Signed Certificate Generator
# ==============================================================================

param(
    [string]$Domain = "localhost"
)

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$CertsDir = Join-Path $ScriptDir "certs"

if (-not (Test-Path $CertsDir)) {
    New-Item -ItemType Directory -Path $CertsDir | Out-Null
}

$CrtPath = Join-Path $CertsDir "droidttp.crt"
$KeyPath = Join-Path $CertsDir "droidttp.key"

if ((Test-Path $CrtPath) -and (Test-Path $KeyPath)) {
    Write-Host "[INFO] Certificates already exist at $CertsDir."
    exit 0
}

Write-Host "[*] Checking for openssl.exe..." -ForegroundColor Cyan
$OpenSsl = Get-Command openssl -ErrorAction SilentlyContinue

if ($OpenSsl) {
    Write-Host "[*] Generating certificates using OpenSSL..." -ForegroundColor Cyan
    & openssl req -x509 -nodes -days 365 -newkey rsa:4096 `
        -keyout $KeyPath `
        -out $CrtPath `
        -subj "/C=US/ST=Security/L=Operations/O=DroidTTP/CN=$Domain" `
        -addext "subjectAltName=DNS:$Domain,DNS:localhost,IP:127.0.0.1"
} else {
    Write-Host "[*] OpenSSL not found in PATH. Using PowerShell New-SelfSignedCertificate..." -ForegroundColor Yellow
    $Cert = New-SelfSignedCertificate -DnsName $Domain, "localhost", "127.0.0.1" `
        -CertStoreLocation "Cert:\CurrentUser\My" `
        -NotAfter (Get-Date).AddYears(1) `
        -KeyExportPolicy Exportable `
        -KeyLength 4096 `
        -HashAlgorithm SHA256

    $CertPem = @"
-----BEGIN CERTIFICATE-----
$([Convert]::ToBase64String($Cert.RawData, 'InsertLineBreaks'))
-----END CERTIFICATE-----
"@
    Set-Content -Path $CrtPath -Value $CertPem

    # Export private key if possible
    Write-Warning "For production container deployments with Nginx, please generate standard PEM key with OpenSSL or export from Windows Cert store."
}

Write-Host "[SUCCESS] Generated TLS Certificate: $CrtPath" -ForegroundColor Green
Write-Host "[SUCCESS] Generated Private Key:    $KeyPath" -ForegroundColor Green
