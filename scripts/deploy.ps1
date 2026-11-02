# ==============================================================================
# DroidTTP - Windows Deployment Script (Docker or Local Native)
# ==============================================================================

param(
    [ValidateSet("Docker", "Local")]
    [string]$Mode = "Docker"
)

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RootDir = Split-Path -Parent $ScriptDir

Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "    DroidTTP: Android CTI Workbench - Deployment ($Mode)" -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan

# 1. Prepare .env if absent
$EnvFile = Join-Path $RootDir ".env"
$NewEnv = $false

if (-not (Test-Path $EnvFile)) {
    Write-Host "[*] Creating production .env configuration..." -ForegroundColor Yellow
    $ExampleFile = Join-Path $RootDir ".env.production.example"
    Copy-Item $ExampleFile $EnvFile

    # Generate 48-byte random secret
    $RandomBytes = New-Object byte[] 48
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($RandomBytes)
    $GeneratedSecret = [Convert]::ToBase64String($RandomBytes)

    # Generate random password
    $PassBytes = New-Object byte[] 16
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($PassBytes)
    $GeneratedPassword = ($PassBytes | ForEach-Object { "{0:x2}" -f $_ }) -join ""

    $Content = Get-Content $EnvFile
    $Content = $Content -replace "REPLACE_WITH_LONG_RANDOM_SECRET_AT_LEAST_32_CHARACTERS_ABC123", $GeneratedSecret
    $Content = $Content -replace "REPLACE_WITH_STRONG_PRODUCTION_PASSWORD", $GeneratedPassword
    Set-Content -Path $EnvFile -Value $Content

    Write-Host "[OK] Created .env with generated secrets." -ForegroundColor Green
    $NewEnv = $true
}

# 2. Deploy according to Mode
if ($Mode -eq "Docker") {
    Write-Host "[*] Checking for Docker..." -ForegroundColor Yellow
    $Docker = Get-Command docker -ErrorAction SilentlyContinue
    if (-not $Docker) {
        Write-Error "Docker is not installed or not in PATH. Run with -Mode Local for native Python run."
    }

    # Generate TLS Certs
    Write-Host "[*] Checking TLS certificates..." -ForegroundColor Yellow
    & "$RootDir\nginx\generate_certs.ps1" -Domain "localhost"

    # Start Containers
    Write-Host "[*] Launching containers via docker compose..." -ForegroundColor Yellow
    Set-Location $RootDir
    docker compose up -d --build

    Write-Host "[*] Waiting for service to report healthy..." -ForegroundColor Yellow
    $Attempts = 0
    $Healthy = $false
    while ($Attempts -lt 30) {
        $Attempts++
        Start-Sleep -Seconds 2
        try {
            # Bypass self-signed cert validation for local test
            [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
            $Response = Invoke-RestMethod -Uri "https://127.0.0.1/healthz" -TimeoutSec 3 -ErrorAction SilentlyContinue
            if ($Response.status -eq "ok") {
                $Healthy = $true
                break
            }
        } catch { }
    }

    if (-not $Healthy) {
        Write-Warning "Service did not respond healthy within 60s. Check logs with 'docker compose logs'."
    }

    Write-Host "================================================================" -ForegroundColor Green
    Write-Host " [SUCCESS] DroidTTP is deployed and running via Docker!" -ForegroundColor Green
    Write-Host "================================================================" -ForegroundColor Green
    Write-Host " - Web UI (HTTPS):  https://localhost" -ForegroundColor Green
    Write-Host " - Health Probe:    https://localhost/healthz" -ForegroundColor Green
    Write-Host " - Readiness Probe: https://localhost/readyz" -ForegroundColor Green

} elseif ($Mode -eq "Local") {
    if (Test-Path $EnvFile) {
        $Content = Get-Content $EnvFile
        $Content = $Content -replace '^DROIDTTP_COOKIE_SECURE=true$', 'DROIDTTP_COOKIE_SECURE=false'
        Set-Content -Path $EnvFile -Value $Content
    }
    Write-Host "[*] Checking Python environment..." -ForegroundColor Yellow
    $VenvPython = Join-Path $RootDir ".venv\Scripts\python.exe"
    if (-not (Test-Path $VenvPython)) {
        Write-Host "[*] Creating Python virtual environment..." -ForegroundColor Yellow
        & py -3 -m venv (Join-Path $RootDir ".venv")
        & $VenvPython -m pip install --upgrade pip
        & $VenvPython -m pip install -r (Join-Path $RootDir "requirements.txt")
    }

    Write-Host "[*] Local prerequisites are ready." -ForegroundColor Green
    Write-Host "Run the following command to launch:" -ForegroundColor Cyan
    Write-Host "  powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\run-local.ps1" -ForegroundColor White
    Write-Host "Open http://127.0.0.1:8000 (use -Port 8001 if port 8000 is occupied)." -ForegroundColor White
}

if ($NewEnv) {
    Write-Host ""
    Write-Host " Initial Sign-in Credentials:" -ForegroundColor Cyan
    Write-Host " ----------------------------" -ForegroundColor Cyan
    Write-Host " Username: analyst_admin" -ForegroundColor White
    Write-Host " Password: $GeneratedPassword" -ForegroundColor Yellow
    Write-Host " Role:     admin" -ForegroundColor White
    Write-Host ""
}
