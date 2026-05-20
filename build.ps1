# build.ps1
# ---------
# One-click script to build BehaviorShield.exe from source.
# Run from the project root:
#   .\build.ps1
#
# Output: dist\BehaviorShield.exe

$ErrorActionPreference = "Stop"
$ProjectRoot = $PSScriptRoot

Write-Host ""
Write-Host "========================================================" -ForegroundColor Cyan
Write-Host "  BehaviorShield -- EXE Build Script" -ForegroundColor Cyan
Write-Host "========================================================" -ForegroundColor Cyan
Write-Host ""

# ── Step 1: Ensure PyInstaller is installed ──────────────────────
Write-Host "[1/4] Checking PyInstaller..." -ForegroundColor Yellow
try {
    python -m PyInstaller --version | Out-Null
    Write-Host "      PyInstaller found." -ForegroundColor Green
} catch {
    Write-Host "      Installing PyInstaller..." -ForegroundColor Yellow
    pip install pyinstaller
    Write-Host "      PyInstaller installed." -ForegroundColor Green
}

# ── Step 2: Clean previous build ────────────────────────────────
Write-Host ""
Write-Host "[2/4] Cleaning previous build artifacts..." -ForegroundColor Yellow
if (Test-Path "$ProjectRoot\dist\BehaviorShield.exe") {
    Remove-Item "$ProjectRoot\dist\BehaviorShield.exe" -Force
    Write-Host "      Removed old BehaviorShield.exe" -ForegroundColor Green
} else {
    Write-Host "      Nothing to clean." -ForegroundColor Gray
}

# ── Step 3: Build the EXE ───────────────────────────────────────
Write-Host ""
Write-Host "[3/4] Building BehaviorShield.exe..." -ForegroundColor Yellow
Write-Host "      (This may take 1-3 minutes)" -ForegroundColor Gray
Write-Host ""

Set-Location $ProjectRoot
python -m PyInstaller BehaviorShield.spec --clean --noconfirm

# ── Step 4: Verify output ────────────────────────────────────────
Write-Host ""
Write-Host "[4/4] Verifying output..." -ForegroundColor Yellow
$exePath = "$ProjectRoot\dist\BehaviorShield.exe"

if (Test-Path $exePath) {
    $size = (Get-Item $exePath).Length
    $sizeMB = [math]::Round($size / 1MB, 1)
    Write-Host ""
    Write-Host "========================================================" -ForegroundColor Green
    Write-Host "  BUILD SUCCESSFUL!" -ForegroundColor Green
    Write-Host "  Output : dist\BehaviorShield.exe" -ForegroundColor Green
    Write-Host "  Size   : $sizeMB MB" -ForegroundColor Green
    Write-Host "========================================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "  To run: Right-click dist\BehaviorShield.exe -> Run as Administrator" -ForegroundColor Cyan
    Write-Host "  (The EXE will auto-prompt for UAC elevation if needed)" -ForegroundColor Gray
    Write-Host ""
} else {
    Write-Host ""
    Write-Host "========================================================" -ForegroundColor Red
    Write-Host "  BUILD FAILED -- BehaviorShield.exe not found in dist\" -ForegroundColor Red
    Write-Host "  Check the output above for errors." -ForegroundColor Red
    Write-Host "========================================================" -ForegroundColor Red
    exit 1
}
