param(
    [ValidateRange(1, 65535)]
    [int]$Port = 8000
)

$ErrorActionPreference = "Stop"
$RootDir = Split-Path -Parent $PSScriptRoot
$Python = Join-Path $RootDir ".venv\Scripts\python.exe"

if (-not (Test-Path $Python)) {
    throw "Project Python environment not found. Create .venv and install requirements.txt first."
}
if (-not (Test-Path (Join-Path $RootDir ".env"))) {
    throw "Missing .env. Copy .env.example to .env and configure a private password and 32+ character secret."
}

$Worker = $null
Push-Location $RootDir
try {
    $Worker = Start-Process -FilePath $Python -ArgumentList @("-m", "app.queue_worker") -WorkingDirectory $RootDir -PassThru -WindowStyle Hidden
    Start-Sleep -Milliseconds 500
    if ($Worker.HasExited) {
        throw "The analysis worker exited during startup. Check Python dependencies and data-directory permissions."
    }

    Write-Host "DroidTTP: http://127.0.0.1:$Port"
    Write-Host "Press Ctrl+C to stop the web app and its queue worker."
    & $Python -m uvicorn app.main:app --reload --host 127.0.0.1 --port $Port
    if ($LASTEXITCODE -ne 0) {
        throw "The web server exited with code $LASTEXITCODE."
    }
}
finally {
    if ($Worker -and -not $Worker.HasExited) {
        Stop-Process -Id $Worker.Id
        $Worker.WaitForExit()
    }
    Pop-Location
}
