# BASTION agent installer
# ============================================================
# Installs bastion-agent.exe to run automatically at user logon
# via Windows Scheduled Tasks. Runs in USER context (not SYSTEM)
# because the agent needs:
#   - DPAPI CurrentUser scope for the attestation key
#   - Access to HKCU registry decoys
#   - Visibility into the user's DNS client cache
#   - Camera/mic device handles owned by the user session
#
# A SYSTEM-scope service would silently break all of the above.
#
# Usage:
#   .\install.ps1                # build (release) + install + start
#   .\install.ps1 -SkipBuild     # skip cargo build, use existing binary
#   .\install.ps1 -Uninstall     # remove the scheduled task and binary
#
# Idempotent: re-running replaces the task and binary cleanly.
# Does NOT require admin (scheduled tasks in user scope don't need it).

[CmdletBinding()]
param(
    [switch]$Uninstall,
    [switch]$SkipBuild
)

$ErrorActionPreference = 'Stop'

$TaskName    = 'BastionAgent'
$InstallDir  = Join-Path $env:LOCALAPPDATA 'Bastion'
$TargetExe   = Join-Path $InstallDir 'bastion-agent.exe'
$LogPath     = Join-Path $InstallDir 'agent.log'
$RepoRoot    = Split-Path -Parent $PSScriptRoot
$AgentDir    = Join-Path $RepoRoot 'agent'
$SourceExe   = Join-Path $AgentDir 'target\release\bastion-agent.exe'

function Write-Step($msg) { Write-Host "[bastion] $msg" -ForegroundColor Cyan }
function Write-Ok($msg)   { Write-Host "[bastion] $msg" -ForegroundColor Green }
function Write-Warn2($m)  { Write-Host "[bastion] $m" -ForegroundColor Yellow }

function Stop-Task {
    $existing = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if ($existing) {
        Write-Step "stopping existing task"
        try { Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue } catch { }
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
    }
    Get-Process -Name 'bastion-agent' -ErrorAction SilentlyContinue | ForEach-Object {
        Write-Step "killing running bastion-agent (pid $($_.Id))"
        Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
    }
}

if ($Uninstall) {
    Write-Step "uninstalling"
    Stop-Task
    if (Test-Path $TargetExe) {
        Remove-Item -Path $TargetExe -Force -ErrorAction SilentlyContinue
        Write-Ok "removed $TargetExe"
    }
    Write-Ok "done. (data dir at $env:APPDATA\bastion\bastion preserved â€” delete manually if you want a clean slate)"
    return
}

# 1. Build (unless skipped or binary already exists in the install dir)
if (-not $SkipBuild) {
    Write-Step "building agent (release)"
    $env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
    Push-Location $AgentDir
    try {
        cargo build --release
        if ($LASTEXITCODE -ne 0) { throw "cargo build failed (exit $LASTEXITCODE)" }
    } finally {
        Pop-Location
    }
}

if (-not (Test-Path $SourceExe)) {
    throw "source binary not found at $SourceExe â€” build it with: cd agent ; cargo build --release"
}

# 2. Stop any running task/process so we can overwrite the binary
Stop-Task

# 3. Copy binary to per-user install dir
if (-not (Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
}
Write-Step "copying binary to $TargetExe"
Copy-Item -Path $SourceExe -Destination $TargetExe -Force

# 4. Register scheduled task: run at logon, hidden, restart on failure
Write-Step "registering scheduled task '$TaskName'"
$action = New-ScheduledTaskAction `
    -Execute $TargetExe `
    -WorkingDirectory $InstallDir

$trigger = New-ScheduledTaskTrigger -AtLogOn -User "$env:USERDOMAIN\$env:USERNAME"

# Restart up to 3 times if the agent crashes; keep running across battery
# states; no idle/network conditions.
$settings = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -StartWhenAvailable `
    -RestartCount 3 `
    -RestartInterval (New-TimeSpan -Minutes 1) `
    -ExecutionTimeLimit (New-TimeSpan -Days 0) `
    -MultipleInstances IgnoreNew `
    -Hidden

$principal = New-ScheduledTaskPrincipal `
    -UserId "$env:USERDOMAIN\$env:USERNAME" `
    -LogonType Interactive `
    -RunLevel Limited

Register-ScheduledTask `
    -TaskName $TaskName `
    -Action $action `
    -Trigger $trigger `
    -Settings $settings `
    -Principal $principal `
    -Description 'BASTION local defensive monitoring agent (user-scope).' `
    -Force | Out-Null

# 5. Start it now
Write-Step "starting task"
Start-ScheduledTask -TaskName $TaskName
Start-Sleep -Seconds 2

# 6. Show token + verify it's listening
$tokenPath = Join-Path $env:APPDATA 'bastion\bastion\data\token.txt'
if (Test-Path $tokenPath) {
    $token = (Get-Content $tokenPath).Trim()
    Write-Ok "agent online"
    Write-Host ""
    Write-Host "  bearer token: " -NoNewline; Write-Host $token -ForegroundColor White
    Write-Host "  api:          http://127.0.0.1:7878"
    Write-Host "  data dir:     $env:APPDATA\bastion\bastion\data"
    Write-Host ""
    Write-Host "Paste the token into the BASTION desktop app (one time â€” it persists in localStorage)."
} else {
    Write-Warn2 "token file not found yet â€” give it a few more seconds, then check $tokenPath"
}

# Quick liveness check
try {
    $r = Invoke-WebRequest -Uri 'http://127.0.0.1:7878/api/health' -UseBasicParsing -TimeoutSec 3 -ErrorAction SilentlyContinue
    if ($r.StatusCode -eq 200 -or $r.StatusCode -eq 401) {
        Write-Ok "port 7878 responding"
    }
} catch {
    Write-Warn2 "port 7878 not responding yet â€” may still be starting"
}

Write-Host ""
Write-Host "Manage:"
Write-Host "  status:    Get-ScheduledTask -TaskName $TaskName"
Write-Host "  stop:      Stop-ScheduledTask -TaskName $TaskName"
Write-Host "  start:     Start-ScheduledTask -TaskName $TaskName"
Write-Host "  uninstall: .\install.ps1 -Uninstall"
