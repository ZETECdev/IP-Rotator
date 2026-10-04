<# ============================================================
  IP ROTATOR - EDIT THE SETTINGS BELOW WHEN YOU OPEN THIS FILE
  ============================================================
  1. Edit the minutes below (MinutesPerCountry).
  2. Save the file.
  3. Right click > Run with PowerShell AS ADMINISTRATOR
     (or double-click Start-IP-Rotator.bat).
  Requirements: official WireGuard client + a folder with
  your WireGuard *.conf profiles (e.g. from Proton VPN).
============================================================ #>
param(
  [double]$MinutesPerCountry = 1,  # <-- EDIT HERE: minutes per country (1, 2, 0.5 = 30s)
  [int]$ConnectionTimeoutSec = 10, # <-- max seconds to connect; skips to next if slower
  [string]$ProfilesFolder = "",    # <-- empty = "profiles" folder next to this script
  [bool]$GapKillSwitch = $true     # <-- true = block internet during the switch gap
)

$ErrorActionPreference = "Stop"
$WireGuardExe = "$env:ProgramFiles\WireGuard\wireguard.exe"
$WgExe = "$env:ProgramFiles\WireGuard\wg.exe"
if ([string]::IsNullOrWhiteSpace($ProfilesFolder)) {
  $ProfilesFolder = Join-Path $PSScriptRoot "profiles"
}

function Write-Log($m) { Write-Host "[$(Get-Date -Format 'HH:mm:ss')] $m" }
function Test-Admin {
  $p = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
  return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}
function Get-Shuffled($a) {
  $r = @($a)
  for ($i = $r.Count - 1; $i -gt 0; $i--) { $j = Get-Random -Maximum ($i + 1); $t = $r[$i]; $r[$i] = $r[$j]; $r[$j] = $t }
  return $r
}
function Get-TunnelName($p) { return [IO.Path]::GetFileNameWithoutExtension($p) }

function Stop-Tunnel($t) {
  if (-not $t) { return }
  try { & $WireGuardExe /uninstalltunnelservice $t 2>&1 | Out-Null } catch {}
  for ($i = 0; $i -lt 50; $i++) {
    if (-not (Get-Service -Name "WireGuardTunnel`$$t" -ErrorAction SilentlyContinue)) { break }
    Start-Sleep -Milliseconds 100
  }
}
function Test-Handshake($t) {
  try {
    foreach ($l in @(& $WgExe show $t latest-handshakes 2>&1)) {
      $s = "$l".Trim() -split "\s+"
      if ($s.Count -ge 2 -and $s[1] -match "^\d+$" -and [long]$s[1] -ne 0) { return $true }
    }
  } catch {}
  return $false
}
function Test-Internet {
  try { $r = Invoke-WebRequest -Uri "https://api.protonvpn.ch/vpn/location" -TimeoutSec 5 -UseBasicParsing; if ($r.StatusCode -eq 200) { return $true } } catch {}
  try { $r = Invoke-WebRequest -Uri "https://ifconfig.me/ip" -TimeoutSec 5 -UseBasicParsing; if ($r.StatusCode -eq 200) { return $true } } catch {}
  return $false
}
function Get-EndpointInfo($conf) {
  $m = Select-String -Path $conf -Pattern "^\s*Endpoint\s*=\s*(.+)\s*$" | Select-Object -First 1
  if (-not $m) { return $null }
  $ep = $m.Matches[0].Groups[1].Value.Trim()
  if ($ep -match "^(.*):(\d+)$") {
    $h = $Matches[1].Trim("[]"); $pt = [int]$Matches[2]
    $ip = $h
    if ($h -notmatch "^\d+\.\d+\.\d+\.\d+$" -and $h -notmatch ":") {
      try { $ip = ([Net.Dns]::GetHostAddresses($h) | Where-Object { $_.AddressFamily -eq "InterNetwork" } | Select-Object -First 1).IPAddressToString; if (-not $ip) { $ip = $h } } catch { $ip = $h }
    }
    return @{ Host = $h; IP = $ip; Port = $pt }
  }
  return $null
}
function Ensure-KillSwitch($files) {
  # Native WireGuard for Windows kill-switch: with AllowedIPs 0.0.0.0/0,
  # the tunnel service already firewall-blocks leaks while connected.
  # Here we verify that and add an explicit BlockUntunneledTraffic = true.
  foreach ($f in $files) {
    $txt = Get-Content $f.FullName -Raw
    if ($txt -notmatch "0\.0\.0\.0/0") { Write-Log "WARNING $($f.Name): no 0.0.0.0/0, native kill-switch does NOT apply."; continue }
    if ($txt -notmatch "(?im)BlockUntunneledTraffic") {
      Copy-Item $f.FullName ($f.FullName + ".bak") -Force
      $txt = $txt -replace "(?im)(\[Interface\])", '$1' + "`r`nBlockUntunneledTraffic = true"
      Set-Content $f.FullName $txt -Encoding Ascii
      Write-Log "Kill-switch enabled for $($f.Name) (.bak backup created)."
    }
  }
}

$script:FwBackup = $null
function Enable-GapBlock($tunnel, $ep) {
  # Blocks default outbound traffic; only the VPN handshake + DHCP pass.
  # Once the tunnel is up, an allow rule for the tunnel interface is added.
  try {
    $script:FwBackup = Get-NetFirewallProfile -Profile Domain, Private, Public | Select-Object Name, DefaultOutboundAction
    Set-NetFirewallProfile -Profile Domain, Private, Public -DefaultOutboundAction Block
    if ($ep -and $ep.IP) {
      New-NetFirewallRule -DisplayName "IPRotator-KS-Allow-VPN" -Direction Outbound -Action Allow -Profile Any -Protocol UDP -RemoteAddress $ep.IP -RemotePort $ep.Port -Enabled True | Out-Null
    }
    New-NetFirewallRule -DisplayName "IPRotator-KS-Allow-DHCP" -Direction Outbound -Action Allow -Profile Any -Protocol UDP -LocalPort 68 -RemotePort 67 -Enabled True | Out-Null
    Write-Log "Gap kill-switch: firewall locked, VPN/DHCP only."
  } catch { Write-Log "WARNING could not enable gap block: $($_.Exception.Message)" }
}
function Enable-TunnelAllow($tunnel) {
  try {
    Remove-NetFirewallRule -DisplayName "IPRotator-KS-Allow-TUNNEL" -ErrorAction SilentlyContinue
    # The interface appears after the service is installed; retry a few times
    for ($i = 0; $i -lt 10; $i++) {
      try { New-NetFirewallRule -DisplayName "IPRotator-KS-Allow-TUNNEL" -Direction Outbound -Action Allow -Profile Any -InterfaceAlias $tunnel -Enabled True | Out-Null; break }
      catch { Start-Sleep -Milliseconds 500 }
    }
  } catch {}
}
function Disable-GapBlock {
  try { Remove-NetFirewallRule -DisplayName "IPRotator-KS-Allow-VPN" -ErrorAction SilentlyContinue } catch {}
  try { Remove-NetFirewallRule -DisplayName "IPRotator-KS-Allow-DHCP" -ErrorAction SilentlyContinue } catch {}
  try { Remove-NetFirewallRule -DisplayName "IPRotator-KS-Allow-TUNNEL" -ErrorAction SilentlyContinue } catch {}
  if ($script:FwBackup) {
    try {
      foreach ($b in $script:FwBackup) { Set-NetFirewallProfile -Profile $b.Name -DefaultOutboundAction $b.DefaultOutboundAction }
      $script:FwBackup = $null
      Write-Log "Gap kill-switch: firewall restored."
    } catch {}
  }
}

# ---------- validation ----------
if (-not (Test-Admin)) { Write-Log "ERROR: run AS ADMINISTRATOR."; exit 1 }
if ([double]$MinutesPerCountry -le 0) { Write-Log "ERROR: MinutesPerCountry must be > 0."; exit 1 }
if ([int]$ConnectionTimeoutSec -lt 5) { Write-Log "ERROR: ConnectionTimeoutSec must be >= 5."; exit 1 }
if (-not (Test-Path $WireGuardExe)) { Write-Log "ERROR: install WireGuard: https://download.wireguard.com/windows-client/"; exit 1 }
if (-not (Test-Path $ProfilesFolder)) { Write-Log "ERROR: $ProfilesFolder not found. Create 'profiles' next to the script with your .conf files."; exit 1 }
$profiles = @(Get-ChildItem -Path $ProfilesFolder -Filter "*.conf" -File)
if ($profiles.Count -eq 0) { Write-Log "ERROR: no *.conf in $ProfilesFolder."; exit 1 }
Ensure-KillSwitch $profiles

Write-Log "Countries: $($profiles.Count) | Per country: $MinutesPerCountry min | Timeout: ${ConnectionTimeoutSec}s | Gap-KS: $GapKillSwitch"
Write-Log "Ctrl+C to stop."
$activeTunnel = $null; $round = 0
try {
  while ($true) {
    $round++
    $order = Get-Shuffled $profiles
    Write-Log "===== ROUND $round (random, no repeats) ====="
    foreach ($f in $order) {
      $tunnel = Get-TunnelName $f.FullName
      $ep = Get-EndpointInfo $f.FullName
      $epLabel = if ($ep) { "$($ep.Host):$($ep.Port)" } else { "unknown-endpoint" }
      Write-Log "--- $($f.Name) -> $epLabel ---"
      if ($activeTunnel -and $activeTunnel -ne $tunnel) { Stop-Tunnel $activeTunnel; $activeTunnel = $null }
      Stop-Tunnel $tunnel
      if ($GapKillSwitch) { Enable-GapBlock $tunnel $ep }
      & $WireGuardExe /installtunnelservice "$($f.FullName)" 2>&1 | Out-String | ForEach-Object { $t = "$_".Trim(); if ($t) { Write-Log "wg: $t" } }
      $activeTunnel = $tunnel
      if ($GapKillSwitch) { Enable-TunnelAllow $tunnel }
      $ok = $false; $t0 = Get-Date
      while (((Get-Date) - $t0).TotalSeconds -lt $ConnectionTimeoutSec) {
        Start-Sleep -Seconds 1
        if (Test-Handshake $tunnel -and (Test-Internet)) { $ok = $true; break }
        Write-Log "  waiting... $([int]((Get-Date)-$t0).TotalSeconds)s/${ConnectionTimeoutSec}s"
      }
      if ($GapKillSwitch) { Disable-GapBlock }
      if (-not $ok) {
        Write-Log "TIMEOUT, skipping to next."
        Stop-Tunnel $tunnel; $activeTunnel = $null
        continue
      }
      $ip = ""; try { $ip = (Invoke-WebRequest -Uri "https://ifconfig.me/ip" -TimeoutSec 5 -UseBasicParsing).Content.Trim() } catch {}
      Write-Log "CONNECTED $($f.Name) IP=$ip. Holding $MinutesPerCountry min (native kill-switch active)."
      $totalSecs = [int]([double]$MinutesPerCountry * 60)
      $endTime = (Get-Date).AddSeconds($totalSecs)
      while ((Get-Date) -lt $endTime) {
        $remaining = [int]($endTime - (Get-Date)).TotalSeconds
        Write-Progress -Activity "Connected $($f.Name) ($ip)" -Status "Switching in ${remaining}s" -PercentComplete ((($totalSecs - $remaining) / $totalSecs) * 100)
        Start-Sleep -Seconds 1
      }
      Write-Progress -Activity " " -Completed
      Stop-Tunnel $tunnel; $activeTunnel = $null
    }
  }
} finally {
  Disable-GapBlock
  if ($activeTunnel) { Stop-Tunnel $activeTunnel }
}
