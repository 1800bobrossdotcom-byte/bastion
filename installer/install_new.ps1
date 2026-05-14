[CmdletBinding()]
param(
    [switch]$Uninstall,
    [switch]$SkipBuild
)
$ErrorActionPreference = 'Stop'
$TaskName    = 'BastionAgent'
$InstallDir  = Join-Path $env:LOCALAPPDATA 'Bastion'
$TargetExe   = Join-Path $env:LOCALAPPDATA 'Bastion\bastion-agent.exe'
$SourceExe   = 'C:\Users\giann\bastion\agent\target\release\bastion-agent.exe'

function Write-Step($msg) { Write-Host "[bastion] $msg" -ForegroundColor Cyan }
function Write-Ok($msg)   { Write-Host "[bastion] $msg" -ForegroundColor Green }

if ($Uninstall) {
    Write-Step "Uninstalling..."
    Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue | Unregister-ScheduledTask -Confirm:$false
    Return
}

if (-not (Test-Path $InstallDir)) { New-Item -ItemType Directory -Path $InstallDir -Force }
Copy-Item -Path $SourceExe -Destination $TargetExe -Force
$action = New-ScheduledTaskAction -Execute $TargetExe -WorkingDirectory $InstallDir
$trigger = New-ScheduledTaskTrigger -AtLogOn -User "$env:USERDOMAIN\$env:USERNAME"
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit (New-TimeSpan -Days 0)
$principal = New-ScheduledTaskPrincipal -UserId "$env:USERDOMAIN\$env:USERNAME" -LogonType Interactive -RunLevel Limited
Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Settings $settings -Principal $principal -Force | Out-Null
Start-ScheduledTask -TaskName $TaskName
Start-Sleep -Seconds 2
$tokenPath = Join-Path $env:APPDATA 'bastion\bastion\data\token.txt'
if (Test-Path $tokenPath) {
    $token = (Get-Content $tokenPath).Trim()
    Write-Ok "Agent online"
    Write-Host "Bearer token: $token"
} else {
    Write-Host "Token not found yet."
}
