# build.ps1
# ---------
# One-click script to build BehaviorShield.exe from source.
# Run from the project root:
#   .\build.ps1
#
# Output: dist\BehaviorShield.exe

$ErrorActionPreference = "Stop"
$ProjectRoot = $PSScriptRoot

# Dynamically add Node.js to PATH if it was just installed but not active in this session
if (-not (Get-Command npm -ErrorAction SilentlyContinue)) {
    if (Test-Path "C:\Program Files\nodejs") {
        $env:Path += ";C:\Program Files\nodejs"
    }
}

Write-Host ""
Write-Host "========================================================" -ForegroundColor Cyan
Write-Host "  BehaviorShield -- EXE Build Script" -ForegroundColor Cyan
Write-Host "========================================================" -ForegroundColor Cyan
Write-Host ""

# ── Step 1: Ensure PyInstaller is installed ──────────────────────
Write-Host "[1/6] Checking PyInstaller..." -ForegroundColor Yellow

$oldEAP = $ErrorActionPreference
$ErrorActionPreference = "Continue"

# Check if PyInstaller is importable without raising tracebacks on stderr
$hasPyInstaller = python -c "import sys, importlib.util; sys.exit(0 if importlib.util.find_spec('PyInstaller') else 1)" 2>&1
$isInstalled = ($LASTEXITCODE -eq 0)

if (-not $isInstalled) {
    Write-Host "      PyInstaller not found. Installing..." -ForegroundColor Yellow
    pip install pyinstaller
    $hasPyInstaller = python -c "import sys, importlib.util; sys.exit(0 if importlib.util.find_spec('PyInstaller') else 1)" 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Host "      Failed to install PyInstaller. Please install it manually with 'pip install pyinstaller'." -ForegroundColor Red
        $ErrorActionPreference = $oldEAP
        exit 1
    }
    Write-Host "      PyInstaller installed successfully." -ForegroundColor Green
} else {
    Write-Host "      PyInstaller found." -ForegroundColor Green
}

$ErrorActionPreference = $oldEAP

# ── Step 2: Ensure Python dependencies are installed ────────────────
Write-Host ""
Write-Host "[2/6] Installing Python dependencies from requirements.txt..." -ForegroundColor Yellow
pip install -r "$ProjectRoot\requirements.txt"
if ($LASTEXITCODE -ne 0) {
    Write-Host "      Warning: Some Python dependencies failed to install. The build will proceed, but the application might fail to run." -ForegroundColor Yellow
} else {
    Write-Host "      Python dependencies verified/installed." -ForegroundColor Green
}

# ── Step 3: Build React Frontend ────────────────────────────────
Write-Host ""
Write-Host "[3/6] Building React Frontend..." -ForegroundColor Yellow
$npmCheck = Get-Command npm -ErrorAction SilentlyContinue
if ($npmCheck) {
    try {
        Write-Host "      Installing frontend dependencies (npm install)..." -ForegroundColor Gray
        Push-Location "$ProjectRoot\frontend"
        npm install --no-audit --no-fund
        Write-Host "      Building production assets (npm run build)..." -ForegroundColor Gray
        npm run build
        Pop-Location
        Write-Host "      Frontend built successfully." -ForegroundColor Green
    } catch {
        Write-Host "      Warning: Failed to build frontend. Packaging will continue, but the UI dashboard may not be functional." -ForegroundColor Yellow
        if ($PWD.Path -like "*\frontend") { Pop-Location }
    }
} else {
    Write-Host "      Warning: 'npm' was not found on your system. Packaging will continue, but the UI dashboard will not be functional." -ForegroundColor Yellow
    Write-Host "      Please install Node.js/npm if you want to bundle the React dashboard." -ForegroundColor Gray
}

# ── Step 4: Clean previous build ────────────────────────────────
Write-Host ""
Write-Host "[4/6] Cleaning previous build artifacts..." -ForegroundColor Yellow
if (Test-Path "$ProjectRoot\dist\BehaviorShield.exe") {
    Remove-Item "$ProjectRoot\dist\BehaviorShield.exe" -Force
    Write-Host "      Removed old BehaviorShield.exe" -ForegroundColor Green
} else {
    Write-Host "      Nothing to clean." -ForegroundColor Gray
}

# ── Step 5: Build the EXE ───────────────────────────────────────
Write-Host ""
Write-Host "[5/6] Building BehaviorShield.exe..." -ForegroundColor Yellow
Write-Host "      (This may take 1-3 minutes)" -ForegroundColor Gray
Write-Host ""

Set-Location $ProjectRoot
python -m PyInstaller BehaviorShield.spec --clean --noconfirm

# ── Step 6: Verify output ────────────────────────────────────────
Write-Host ""
Write-Host "[6/6] Verifying output..." -ForegroundColor Yellow
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
