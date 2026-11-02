# ==============================================================================
# DroidTTP - Windows Automated Hot Backup Script
# ==============================================================================

param(
    [string]$DataDir = "$PSScriptRoot\..\data",
    [string]$BackupDir = "$PSScriptRoot\..\backups"
)

$ErrorActionPreference = "Stop"

$Timestamp = (Get-Date).ToUniversalTime().ToString("yyyyMMdd_HHmmssZ")
$BackupName = "droidttp_backup_$Timestamp"
$TempDest = Join-Path $BackupDir $BackupName

if (-not (Test-Path $BackupDir)) {
    New-Item -ItemType Directory -Path $BackupDir | Out-Null
}
New-Item -ItemType Directory -Path $TempDest | Out-Null

Write-Host "==================================================" -ForegroundColor Cyan
Write-Host " Starting DroidTTP Backup: $Timestamp" -ForegroundColor Cyan
Write-Host " Source: $DataDir" -ForegroundColor Cyan
Write-Host " Target: $TempDest" -ForegroundColor Cyan
Write-Host "==================================================" -ForegroundColor Cyan

# 1. Database backup
$DbSource = Join-Path $DataDir "droidttp.sqlite3"
$DbTarget = Join-Path $TempDest "droidttp.sqlite3"

if (Test-Path $DbSource) {
    Write-Host "[*] Copying SQLite database..." -ForegroundColor Yellow
    Copy-Item $DbSource $DbTarget -Force
    Write-Host "[OK] Database copied." -ForegroundColor Green
} else {
    Write-Warning "Database file not found at $DbSource"
}

# 2. Samples backup
$SamplesSource = Join-Path $DataDir "samples"
$SamplesTarget = Join-Path $TempDest "samples"

if (Test-Path $SamplesSource) {
    Write-Host "[*] Copying sample storage..." -ForegroundColor Yellow
    Copy-Item -Path "$SamplesSource\*" -Destination $SamplesTarget -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host "[OK] Samples copied." -ForegroundColor Green
}

# 3. Create Manifest
$Manifest = @{
    backup_version = "1.0"
    timestamp = $Timestamp
    source_dir = $DataDir
    created_at = (Get-Date).ToUniversalTime().ToString("o")
} | ConvertTo-Json -Depth 3

Set-Content -Path (Join-Path $TempDest "manifest.json") -Value $Manifest

# 4. Create ZIP Archive
$ZipFile = Join-Path $BackupDir "$BackupName.zip"
Write-Host "[*] Compressing backup into $ZipFile..." -ForegroundColor Yellow
Compress-Archive -Path "$TempDest\*" -DestinationPath $ZipFile -CompressionLevel Optimal
Remove-Item -Path $TempDest -Recurse -Force

# 5. Compute SHA256 Checksum
$Hash = (Get-FileHash -Path $ZipFile -Algorithm SHA256).Hash
Set-Content -Path "$ZipFile.sha256" -Value "$Hash  $BackupName.zip"

Write-Host "==================================================" -ForegroundColor Green
Write-Host " Backup Completed Successfully!" -ForegroundColor Green
Write-Host " Archive:  $ZipFile" -ForegroundColor Green
Write-Host " SHA-256:  $Hash" -ForegroundColor Green
Write-Host "==================================================" -ForegroundColor Green
