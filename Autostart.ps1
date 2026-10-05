# Installs the "IP Rotator" scheduled task (auto-start at logon).
# Self-elevates to Administrator on double-click.
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
  exit
}
$taskName = "IP Rotator"
$scriptPath = Join-Path $PSScriptRoot "IP-Rotator.ps1"

if (-not (Test-Path $scriptPath)) { Write-Host "ERROR: $scriptPath not found."; exit 1 }

$action = New-ScheduledTaskAction -Execute "powershell.exe" `
  -Argument "-NoProfile -ExecutionPolicy Bypass -Command `"Start-Sleep 30; & '$scriptPath'`""
$trigger = New-ScheduledTaskTrigger -AtLogOn
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
  -ExecutionTimeLimit 0 -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)

Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger `
  -Settings $settings -RunLevel Highest -Force | Out-Null
Write-Host "OK: '$taskName' will start automatically ~30s after logon."
