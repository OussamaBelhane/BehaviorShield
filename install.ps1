# install.ps1
# -----------
# Installer and Launcher script for BehaviorShield.
# Run this on a clean Windows machine as Administrator.
#
# What this script does:
#   1. Relaunches itself as Administrator if not already elevated.
#   2. Downloads and installs Microsoft Sysmon (if not already installed).
#   3. Copies BehaviorShield.exe and sysmon.xml to C:\BehaviorShield.
#   4. Configures Sysmon with BehaviorShield's custom sysmon.xml.
#   5. Creates a Desktop Shortcut for easy access.
#   6. Launches BehaviorShield immediately.

$ErrorActionPreference = "Stop"

# 1. Elevate privileges if not admin
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "This installer requires Administrator privileges." -ForegroundColor Yellow
    Write-Host "Relaunching as Administrator..." -ForegroundColor Yellow
    Start-Process powershell -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    Exit
}

Write-Host "========================================================" -ForegroundColor Cyan
Write-Host "  BehaviorShield Installer" -ForegroundColor Cyan
Write-Host "========================================================" -ForegroundColor Cyan
Write-Host ""

$InstallDir = "C:\BehaviorShield"
if (-not (Test-Path $InstallDir)) {
    Write-Host "[+] Creating installation directory at $InstallDir..." -ForegroundColor Gray
    New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
}

# 2. Handle Sysmon installation
$SysmonService = Get-Service -Name "Sysmon" -ErrorAction SilentlyContinue
if ($null -eq $SysmonService) {
    Write-Host "[+] Sysmon not detected. Downloading from official Sysinternals source..." -ForegroundColor Yellow
    $ZipPath = Join-Path $InstallDir "Sysmon.zip"
    
    # Use TLS 1.2/1.3 for download if possible
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" -OutFile $ZipPath
    
    Write-Host "[+] Extracting Sysmon..." -ForegroundColor Gray
    Expand-Archive -Path $ZipPath -DestinationPath $InstallDir -Force
    Remove-Item $ZipPath -Force
    
    # Check architecture to run Sysmon or Sysmon64
    $SysmonExeName = "Sysmon64.exe"
    if ([Environment]::Is64BitOperatingSystem) {
        $SysmonExeName = "Sysmon64.exe"
    } else {
        $SysmonExeName = "Sysmon.exe"
    }
    
    $SysmonExe = Join-Path $InstallDir $SysmonExeName
    $ConfigPath = Join-Path $InstallDir "sysmon.xml"
    
    # Copy configuration
    if (Test-Path "config\sysmon.xml") {
        Copy-Item "config\sysmon.xml" -Destination $ConfigPath -Force
    } else {
        # Fallback inline creation of sysmon.xml if not running from root folder
        $inlineXml = @"
<Sysmon schemaversion="4.81">
  <HashAlgorithms>SHA256</HashAlgorithms>
  <EventFiltering>
    <ProcessCreate onmatch="include">
      <Rule groupRelation="or">
        <Image condition="contains">\</Image>
      </Rule>
    </ProcessCreate>
    <FileCreate onmatch="include">
      <Rule groupRelation="or">
        <TargetFilename condition="contains">\</TargetFilename>
      </Rule>
    </FileCreate>
  </EventFiltering>
</Sysmon>
"@
        Set-Content -Path $ConfigPath -Value $inlineXml -Encoding UTF8
    }

    Write-Host "[+] Installing Sysmon..." -ForegroundColor Yellow
    Start-Process -FilePath $SysmonExe -ArgumentList "-accepteula -i `"$ConfigPath`"" -Wait -NoNewWindow
    Write-Host "[+] Sysmon installed and configured successfully." -ForegroundColor Green
} else {
    Write-Host "[+] Sysmon service is already running on this machine." -ForegroundColor Green
}

# 3. Copy BehaviorShield executable
Write-Host "[+] Packaging and copying application files..." -ForegroundColor Gray
$TargetExe = Join-Path $InstallDir "BehaviorShield.exe"

if (Test-Path "dist\BehaviorShield.exe") {
    Copy-Item "dist\BehaviorShield.exe" -Destination $TargetExe -Force
    Write-Host "[+] BehaviorShield.exe copied to $TargetExe." -ForegroundColor Green
} else {
    Write-Host "[-] Error: dist\BehaviorShield.exe not found. Please build it first on your development PC using build.ps1." -ForegroundColor Red
    Exit 1
}

# Copy sysmon config to the local installation directory just in case
if (Test-Path "config\sysmon.xml") {
    Copy-Item "config\sysmon.xml" -Destination (Join-Path $InstallDir "sysmon.xml") -Force
}

# 4. Create Desktop Shortcut
Write-Host "[+] Creating Desktop Shortcut..." -ForegroundColor Gray
try {
    $WshShell = New-Object -ComObject WScript.Shell
    $DesktopPath = [System.Environment]::GetFolderPath("Desktop")
    $Shortcut = $WshShell.CreateShortcut((Join-Path $DesktopPath "BehaviorShield.lnk"))
    $Shortcut.TargetPath = $TargetExe
    $Shortcut.WorkingDirectory = $InstallDir
    $Shortcut.IconLocation = $TargetExe
    $Shortcut.Save()
    Write-Host "[+] Desktop shortcut created successfully." -ForegroundColor Green
} catch {
    Write-Host "[-] Failed to create shortcut: $_" -ForegroundColor Yellow
}

# 5. Launch the application
Write-Host ""
Write-Host "[+] Launching BehaviorShield..." -ForegroundColor Green
Start-Process -FilePath $TargetExe -WorkingDirectory $InstallDir

Write-Host ""
Write-Host "========================================================" -ForegroundColor Green
Write-Host "  INSTALLATION COMPLETE!" -ForegroundColor Green
Write-Host "  You can now launch BehaviorShield via the Desktop shortcut." -ForegroundColor Green
Write-Host "  The UI dashboard is accessible at: http://localhost:5000" -ForegroundColor Green
Write-Host "========================================================" -ForegroundColor Green
Write-Host ""
pause
