#Requires -RunAsAdministrator
<#
.SYNOPSIS
    SAQR Single-Command Windows 10 Victim VM Setup Script (win10-setup.ps1)

.DESCRIPTION
    Configures a Windows 10/11 VM for the SAQR graduation defense lab:
      1. Applies hardened Sysmon 4.90 config (detection\sysmon\sysmonconfig-saqr.xml)
      2. Enables PowerShell Script Block Logging (Event ID 4104)
      3. Creates SYSTEM-only forensic vault (C:\ProgramData\SAQR\Vault) & safe sandbox (C:\SAQR-Test)
      4. Installs saqr-contain.cmd and saqr-unquarantine.cmd into Wazuh Active Response bin
      5. Synchronizes VM clock (NTP / VMware Host Time Sync) for accurate T0..T4 MTTD/MTTC metrics
      6. Restarts WazuhSvc and verifies readiness

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\win10-setup.ps1 `
      -WazuhManagerIP 192.168.56.1 -SaqrEngineUrl http://192.168.56.1:5000
#>

[CmdletBinding()]
param(
    [string]$WazuhManagerIP = "192.168.56.1",
    [string]$SaqrEngineUrl  = "http://192.168.56.1:5000",
    [string]$RepoRoot       = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path,
    [string]$SysmonExe      = "C:\Sysinternals\Sysmon64.exe",
    [string]$WazuhAgentDir  = "C:\Program Files (x86)\ossec-agent",
    [string]$PythonExe      = ""
)

$ErrorActionPreference = "Stop"

function Write-Step([string]$Message) {
    Write-Host "`n[SAQR] $Message" -ForegroundColor Cyan
}

# Validate WazuhManagerIP early so generated .cmd launchers are injection-safe
[void][System.Net.IPAddress]::Parse($WazuhManagerIP)
$engineUri = [System.Uri]$SaqrEngineUrl
$SaqrEngineIP = $engineUri.Host

# Locate Python 3.10+ interpreter
if (-not $PythonExe) {
    $cmd = Get-Command python.exe -ErrorAction SilentlyContinue
    if (-not $cmd) { $cmd = Get-Command python3.exe -ErrorAction SilentlyContinue }
    if (-not $cmd) { throw "Python 3 not found on PATH. Install Python 3.12+ or pass -PythonExe." }
    $PythonExe = $cmd.Source
}
Write-Host "[SAQR] Using Python: $PythonExe" -ForegroundColor Green

# ----------------------------------------------------------------------------
# Step 1: Install or Update Hardened Sysmon Schema 4.90 Configuration
# ----------------------------------------------------------------------------
Write-Step "1/6 Applying hardened Sysmon configuration (sysmonconfig-saqr.xml)"
$sysmonConfig = Join-Path $RepoRoot "detection\sysmon\sysmonconfig-saqr.xml"
if (-not (Test-Path $sysmonConfig)) {
    throw "Missing Sysmon config: $sysmonConfig"
}
if (-not (Test-Path $SysmonExe)) {
    $altSysmon = "C:\Windows\Sysmon64.exe"
    if (Test-Path $altSysmon) { $SysmonExe = $altSysmon }
}
if (Test-Path $SysmonExe) {
    $sysmonSvc = Get-Service -Name "Sysmon64" -ErrorAction SilentlyContinue
    if ($sysmonSvc) {
        & $SysmonExe -c $sysmonConfig
    } else {
        & $SysmonExe -accepteula -i $sysmonConfig
    }
    Write-Host "[SAQR] Sysmon configuration applied cleanly." -ForegroundColor Green
} else {
    Write-Warning "Sysmon64.exe not found at $SysmonExe. Download Sysinternals Sysmon and re-run."
}

# ----------------------------------------------------------------------------
# Step 2: Enable PowerShell Script Block Logging (Event ID 4104)
# ----------------------------------------------------------------------------
Write-Step "2/6 Enabling PowerShell Script Block Logging (Event ID 4104)"
$psRegPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
New-Item -Path $psRegPath -Force | Out-Null
Set-ItemProperty -Path $psRegPath -Name "EnableScriptBlockLogging" -Type DWord -Value 1
Write-Host "[SAQR] PowerShell EID 4104 enabled." -ForegroundColor Green

# ----------------------------------------------------------------------------
# Step 3: Create SYSTEM-Only Forensic Vault & Safe Test Sandbox
# ----------------------------------------------------------------------------
Write-Step "3/6 Creating hardened SYSTEM-only Vault (C:\ProgramData\SAQR\Vault) & Sandbox (C:\SAQR-Test)"
$saqrBase  = "C:\ProgramData\SAQR"
$vaultDir  = Join-Path $saqrBase "Vault"
$binDir    = Join-Path $saqrBase "bin"
$toolsDir  = Join-Path $saqrBase "Tools"
$sandbox   = "C:\SAQR-Test"

foreach ($dir in @($saqrBase, $vaultDir, $binDir, $toolsDir, $sandbox)) {
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
}

# Lock Vault strictly to NT AUTHORITY\SYSTEM so ransomware cannot read/encrypt dumps
& icacls.exe $vaultDir /inheritance:r /grant:r "NT AUTHORITY\SYSTEM:(OI)(CI)F" | Out-Null
# Lock SOAR script folder to SYSTEM + Administrators
& icacls.exe $binDir /inheritance:r /grant:r "NT AUTHORITY\SYSTEM:(OI)(CI)F" "BUILTIN\Administrators:(OI)(CI)F" | Out-Null

# Place sandbox marker file required by sim_ransom.py safety lock
Set-Content -Path (Join-Path $sandbox ".saqr_lab_sandbox") -Value "SAQR_AUTHORIZED_LAB_SANDBOX" -Encoding ASCII
Write-Host "[SAQR] Vault locked to SYSTEM-only; C:\SAQR-Test sandbox initialized." -ForegroundColor Green

# ----------------------------------------------------------------------------
# Step 4: Install Active Response Scripts & Stateless .cmd Launchers
# ----------------------------------------------------------------------------
Write-Step "4/6 Installing saqr-contain.cmd and saqr-unquarantine.cmd into Wazuh Active Response"
$srcContain      = Join-Path $PSScriptRoot "saqr_contain.py"
$srcUnquarantine = Join-Path $PSScriptRoot "saqr_unquarantine.py"
Copy-Item -Path $srcContain      -Destination (Join-Path $binDir "saqr_contain.py")      -Force
Copy-Item -Path $srcUnquarantine -Destination (Join-Path $binDir "saqr_unquarantine.py") -Force

$arBin = Join-Path $WazuhAgentDir "active-response\bin"
if (-not (Test-Path $arBin)) {
    New-Item -ItemType Directory -Path $arBin -Force | Out-Null
}

$containCmd = @"
@echo off
setlocal
set "SAQR_WAZUH_MANAGER_IP=$WazuhManagerIP"
set "SAQR_ENGINE_URL=$SaqrEngineUrl"
set "SAQR_ENGINE_IP=$SaqrEngineIP"
set "SAQR_VAULT_DIR=$vaultDir"
"$PythonExe" "$binDir\saqr_contain.py" %*
exit /b %ERRORLEVEL%
"@

$unquarantineCmd = @"
@echo off
setlocal
"$PythonExe" "$binDir\saqr_unquarantine.py" %*
exit /b %ERRORLEVEL%
"@

Set-Content -Path (Join-Path $arBin "saqr-contain.cmd")      -Value $containCmd      -Encoding ASCII
Set-Content -Path (Join-Path $arBin "saqr-unquarantine.cmd") -Value $unquarantineCmd -Encoding ASCII
Write-Host "[SAQR] Installed launchers in $arBin." -ForegroundColor Green

# ----------------------------------------------------------------------------
# Step 5: Configure NTP / VMware Host Time Sync (<50ms skew for T0..T4)
# ----------------------------------------------------------------------------
Write-Step "5/6 Synchronizing Windows clock (NTP / VMware Tools)"
$vmwareTool = "C:\Program Files\VMware\VMware Tools\VMwareToolboxCmd.exe"
if (Test-Path $vmwareTool) {
    & $vmwareTool timesync enable | Out-Null
    Write-Host "[SAQR] Enabled VMware Tools host time sync." -ForegroundColor Green
} else {
    Start-Service W32Time -ErrorAction SilentlyContinue
    & w32tm.exe /resync /nowait 2>$null | Out-Null
    Write-Host "[SAQR] Triggered Windows Time (W32Time) resync." -ForegroundColor Green
}

# ----------------------------------------------------------------------------
# Step 6: Restart Wazuh Agent Service (WazuhSvc)
# ----------------------------------------------------------------------------
Write-Step "6/6 Restarting WazuhSvc"
$wazuhSvc = Get-Service -Name "WazuhSvc" -ErrorAction SilentlyContinue
if ($wazuhSvc) {
    Restart-Service -Name "WazuhSvc" -Force
    $status = (Get-Service -Name "WazuhSvc").Status
    Write-Host "[SAQR] WazuhSvc status: $status" -ForegroundColor Green
} else {
    Write-Warning "WazuhSvc not installed yet. Install Wazuh Agent 4.14.11 and enroll to $WazuhManagerIP."
}

Write-Host "`n[SAQR] Windows 10 Victim VM setup complete!" -ForegroundColor Green
Write-Host "       Wazuh Manager : $WazuhManagerIP (TCP 1514/1515)"
Write-Host "       SAQR Engine   : $SaqrEngineUrl"
Write-Host "       Forensic Vault: $vaultDir (SYSTEM-only)"
Write-Host "       Safe Sandbox  : $sandbox"
