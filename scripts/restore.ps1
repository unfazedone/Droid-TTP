# ==============================================================================
# DroidTTP - Windows Backup Restoration Script
# ==============================================================================

param(
    [Parameter(Mandatory = $true)]
    [string]$ArchivePath,
    [string]$TargetDir = "$PSScriptRoot\..\data"
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path $ArchivePath)) {
    Write-Error "Backup archive not found at: $ArchivePath"
}

Write-Host "==================================================" -ForegroundColor Cyan
Write-Host " Starting DroidTTP Restoration" -ForegroundColor Cyan
Write-Host " Archive:    $ArchivePath" -ForegroundColor Cyan
Write-Host " Target Dir: $TargetDir" -ForegroundColor Cyan
Write-Host "==================================================" -ForegroundColor Cyan

# Verify checksum if present
$ChecksumFile = "$ArchivePath.sha256"
if (Test-Path $ChecksumFile) {
    Write-Host "[*] Checking SHA-256 hash..." -ForegroundColor Yellow
    $ExpectedHash = ((Get-Content $ChecksumFile) -split '\s+')[0].Trim().ToUpper()
    $ActualHash = (Get-FileHash -Path $ArchivePath -Algorithm SHA256).Hash.ToUpper()
    if ($ExpectedHash -eq $ActualHash) {
        Write-Host "[OK] SHA-256 integrity verified." -ForegroundColor Green
    } else {
        Write-Warning "Checksum mismatch! Expected: $ExpectedHash, Got: $ActualHash"
    }
}

$TempExtract = Join-Path ([System.IO.Path]::GetTempPath()) ("droidttp_restore_" + [System.Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $TempExtract | Out-Null

try {
    Write-Host "[*] Extracting backup archive..." -ForegroundColor Yellow
    Expand-Archive -Path $ArchivePath -DestinationPath $TempExtract -Force

    if (-not (Test-Path $TargetDir)) {
        New-Item -ItemType Directory -Path $TargetDir -Force | Out-Null
    }
    $SamplesDir = Join-Path $TargetDir "samples"
    if (-not (Test-Path $SamplesDir)) {
        New-Item -ItemType Directory -Path $SamplesDir -Force | Out-Null
    }

    # Database
    $DbExtract = Join-Path $TempExtract "droidttp.sqlite3"
    if (Test-Path $DbExtract) {
        Write-Host "[*] Restoring database file..." -ForegroundColor Yellow
        Copy-Item $DbExtract (Join-Path $TargetDir "droidttp.sqlite3") -Force
        Write-Host "[OK] Database restored." -ForegroundColor Green
    }

    # Samples
    $SamplesExtract = Join-Path $TempExtract "samples"
    if (Test-Path $SamplesExtract) {
        Write-Host "[*] Restoring sample storage..." -ForegroundColor Yellow
        Copy-Item -Path "$SamplesExtract\*" -Destination $SamplesDir -Recurse -Force -ErrorAction SilentlyContinue
        Write-Host "[OK] Samples restored." -ForegroundColor Green
    }

    Write-Host "==================================================" -ForegroundColor Green
    Write-Host " Restoration Completed Successfully!" -ForegroundColor Green
    Write-Host "==================================================" -ForegroundColor Green
} finally {
    Remove-Item -Path $TempExtract -Recurse -Force -ErrorAction SilentlyContinue
}
