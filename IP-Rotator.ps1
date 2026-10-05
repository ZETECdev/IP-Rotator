<# ============================================================
  IP ROTATOR - FIRST RUN WIZARD (no manual edit needed)
  ============================================================
  1. Double-click Start-IP-Rotator.bat (as Administrator).
  2. First time: it asks 4 values in the terminal and saves
     them to IP-Rotator.config.json next to this script.
  3. Next runs: config is loaded automatically. CLI args
     still override it, e.g.:
     .\IP-Rotator.ps1 -MinutesPerCountry 2
  Requirements: official WireGuard client + a folder with
  your WireGuard *.conf profiles (e.g. from Proton VPN).
============================================================ #>
param(
  [double]$MinutesPerCountry = 1,  # default if no config yet (minutes per country: 1, 2, 0.5 = 30s)
  [int]$ConnectionTimeoutSec = 10, # default if no config yet (min 5)
  [string]$ProfilesFolder = "",    # empty = "profiles" folder next to this script
  [bool]$GapKillSwitch = $true,    # default if no config yet
  [bool]$DeleteFailedProfiles = $true # default if no config yet (auto-delete .conf that fails to connect)
)

$ErrorActionPreference = "Stop"
$WireGuardExe = "$env:ProgramFiles\WireGuard\wireguard.exe"
$WgExe = "$env:ProgramFiles\WireGuard\wg.exe"
if ([string]::IsNullOrWhiteSpace($ProfilesFolder)) {
  $ProfilesFolder = Join-Path $PSScriptRoot "profiles"
}

# ---------- first-run wizard: ask once, persist to IP-Rotator.config.json ----------
$ConfigFile = Join-Path $PSScriptRoot "IP-Rotator.config.json"
$boundMinutes = $PSBoundParameters.ContainsKey("MinutesPerCountry")
$boundTimeout = $PSBoundParameters.ContainsKey("ConnectionTimeoutSec")
$boundGap = $PSBoundParameters.ContainsKey("GapKillSwitch")
$boundDel = $PSBoundParameters.ContainsKey("DeleteFailedProfiles")
if (Test-Path $ConfigFile) {
  try {
    $cfg = Get-Content $ConfigFile -Raw | ConvertFrom-Json
    if (-not $boundMinutes -and $null -ne $cfg.MinutesPerCountry) { $MinutesPerCountry = [double]$cfg.MinutesPerCountry }
    if (-not $boundTimeout -and $null -ne $cfg.ConnectionTimeoutSec) { $ConnectionTimeoutSec = [int]$cfg.ConnectionTimeoutSec }
    if (-not $boundGap -and $null -ne $cfg.GapKillSwitch) { $GapKillSwitch = [bool]$cfg.GapKillSwitch }
    if (-not $boundDel -and $null -ne $cfg.DeleteFailedProfiles) { $DeleteFailedProfiles = [bool]$cfg.DeleteFailedProfiles }
    Write-Host "[config] loaded from IP-Rotator.config.json"
  } catch { Write-Host "[config] WARNING: could not read IP-Rotator.config.json, using defaults/args." }
} else {
  $interactive = [Environment]::UserInteractive -and -not [Console]::IsInputRedirected
  $canAsk = $interactive -and -not $boundMinutes -and -not $boundTimeout -and -not $boundGap -and -not $boundDel
  if ($canAsk) {
    Write-Host ""
    Write-Host "=== IP Rotator - first run: setup (Enter = default) ==="
    $a = Read-Host "Minutes per country [$MinutesPerCountry]"
    if (-not [string]::IsNullOrWhiteSpace($a)) {
      $v = 0; if ([double]::TryParse($a.Replace(",", "."), [ref]$v) -and $v -gt 0) { $MinutesPerCountry = $v } else { Write-Host "Invalid value, using $MinutesPerCountry" }
    }
    $b = Read-Host "Max seconds to connect (>=5) [$ConnectionTimeoutSec]"
    if (-not [string]::IsNullOrWhiteSpace($b)) {
      $w = 0; if ([int]::TryParse($b, [ref]$w) -and $w -ge 5) { $ConnectionTimeoutSec = $w } else { Write-Host "Invalid value, using $ConnectionTimeoutSec" }
    }
    $c = Read-Host "Gap kill-switch? (Y/N) [$(if ($GapKillSwitch) { 'Y' } else { 'N' })]"
    if (-not [string]::IsNullOrWhiteSpace($c)) {
      $c = $c.Trim().ToUpper()
      if ($c -in @("S", "SI", "Y", "YES", "TRUE", "1")) { $GapKillSwitch = $true }
      elseif ($c -in @("N", "NO", "FALSE", "0")) { $GapKillSwitch = $false }
      else { Write-Host "Invalid value, using $GapKillSwitch" }
    }
    $d = Read-Host "Delete profiles that fail to connect? (Y/N) [$(if ($DeleteFailedProfiles) { 'Y' } else { 'N' })]"
    if (-not [string]::IsNullOrWhiteSpace($d)) {
      $d = $d.Trim().ToUpper()
      if ($d -in @("S", "SI", "Y", "YES", "TRUE", "1")) { $DeleteFailedProfiles = $true }
      elseif ($d -in @("N", "NO", "FALSE", "0")) { $DeleteFailedProfiles = $false }
      else { Write-Host "Invalid value, using $DeleteFailedProfiles" }
    }
  }
  try {
    @{ MinutesPerCountry = $MinutesPerCountry; ConnectionTimeoutSec = $ConnectionTimeoutSec; GapKillSwitch = $GapKillSwitch; DeleteFailedProfiles = $DeleteFailedProfiles } | ConvertTo-Json | Set-Content $ConfigFile -Encoding Ascii
    if ($canAsk) { Write-Host "[config] saved to IP-Rotator.config.json. Delete that file to ask again." }
  } catch { Write-Host "[config] WARNING: could not save IP-Rotator.config.json" }
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
  # Short timeouts: this runs inside the 1s-poll connect loop,
  # long timeouts here would blow past ConnectionTimeoutSec.
  try { $r = Invoke-WebRequest -Uri "https://api.protonvpn.ch/vpn/location" -TimeoutSec 3 -UseBasicParsing; if ($r.StatusCode -eq 200) { return $true } } catch {}
  try { $r = Invoke-WebRequest -Uri "https://ifconfig.me/ip" -TimeoutSec 3 -UseBasicParsing; if ($r.StatusCode -eq 200) { return $true } } catch {}
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
  # Native WireGuard for Windows kill-switch is AUTOMATIC whenever a peer
  # routes 0.0.0.0/0 (firewall rules block leaks while connected).
  # Do NOT add "BlockUntunneledTraffic" to the .conf files: older WireGuard
  # versions reject that key as invalid, the tunnel service then never
  # starts, and every server TIMEOUTs. Self-heal files patched by old
  # versions of this script by removing that line.
  foreach ($f in $files) {
    $txt = Get-Content $f.FullName -Raw
    if ($txt -notmatch "0\.0\.0\.0/0") { Write-Log "WARNING $($f.Name): no 0.0.0.0/0, native kill-switch does NOT apply."; continue }
    if ($txt -match "(?im)^\s*BlockUntunneledTraffic\s*=.*$") {
      $txt = $txt -replace "(?im)^\s*BlockUntunneledTraffic\s*=.*\r?\n?", ""
      Set-Content $f.FullName $txt -Encoding Ascii
      Write-Log "Removed unsupported BlockUntunneledTraffic from $($f.Name) (native /0 kill-switch still applies)."
    }
  }
}

$script:FwBaseline = $null
function Save-FirewallBaseline {
  if ($script:FwBaseline) { return }
  try { $script:FwBaseline = Get-NetFirewallProfile -Profile Domain, Private, Public | Select-Object Name, DefaultOutboundAction }
  catch { Write-Log "WARNING could not read firewall baseline: $($_.Exception.Message)" }
}
function Remove-StaleKsRules {
  try { Get-NetFirewallRule -DisplayName "IPRotator*" -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue } catch {}
  foreach ($n in @("IPRotator-KS-Allow-VPN", "IPRotator-KS-Allow-DNS", "IPRotator-KS-Allow-DNS-TCP", "IPRotator-KS-Allow-DHCP", "IPRotator-KS-Allow-TUNNEL")) {
    try { Remove-NetFirewallRule -DisplayName $n -ErrorAction SilentlyContinue } catch {}
  }
}
function Enable-GapBlock($tunnel, $ep) {
  # Blocks default outbound traffic; only VPN handshake + DNS + DHCP pass.
  # Tunnel traffic is allowed separately via Enable-TunnelAllow once the
  # interface exists. Baseline is saved ONCE so a crash can't overwrite it.
  # BUGFIX: old code allowed only one resolved endpoint IP and no DNS, so
  # DNS round-robin or hostname endpoints + the HTTPS internet check failed
  # every time (TIMEOUT loop). Now we allow the VPN UDP port to any + DNS.
  Save-FirewallBaseline
  try {
    Remove-StaleKsRules
    Set-NetFirewallProfile -Profile Domain, Private, Public -DefaultOutboundAction Block
    $port = 51820; if ($ep -and $ep.Port) { $port = [int]$ep.Port }
    New-NetFirewallRule -DisplayName "IPRotator-KS-Allow-VPN" -Direction Outbound -Action Allow -Profile Any -Protocol UDP -RemotePort $port -Enabled True | Out-Null
    New-NetFirewallRule -DisplayName "IPRotator-KS-Allow-DNS" -Direction Outbound -Action Allow -Profile Any -Protocol UDP -RemotePort 53 -Enabled True | Out-Null
    New-NetFirewallRule -DisplayName "IPRotator-KS-Allow-DNS-TCP" -Direction Outbound -Action Allow -Profile Any -Protocol TCP -RemotePort 53 -Enabled True | Out-Null
    New-NetFirewallRule -DisplayName "IPRotator-KS-Allow-DHCP" -Direction Outbound -Action Allow -Profile Any -Protocol UDP -LocalPort 68 -RemotePort 67 -Enabled True | Out-Null
    Write-Log "Gap kill-switch: firewall locked (VPN :$port / DNS / DHCP only)."
  } catch { Write-Log "WARNING could not enable gap block: $($_.Exception.Message)" }
}
function Enable-TunnelAllow($tunnel) {
  # The interface appears a bit after the service is installed; retry ~10s.
  # Returns $true on success so the caller can retry inside the wait loop.
  # NOTE: "interface not found" on the first tries is EXPECTED and harmless:
  # the vNIC doesn't exist yet right after /installtunnelservice. We check
  # Get-NetAdapter first so no red error text is printed; the rule is
  # created (and the connection succeeds) once the interface appears.
  try {
    try { Remove-NetFirewallRule -DisplayName "IPRotator-KS-Allow-TUNNEL" -ErrorAction SilentlyContinue } catch {}
    for ($i = 0; $i -lt 20; $i++) {
      try {
        if (-not (Get-NetAdapter -InterfaceAlias $tunnel -ErrorAction SilentlyContinue)) { Start-Sleep -Milliseconds 500; continue }
        New-NetFirewallRule -DisplayName "IPRotator-KS-Allow-TUNNEL" -Direction Outbound -Action Allow -Profile Any -InterfaceAlias $tunnel -Enabled True -ErrorAction Stop | Out-Null
        return $true
      }
      catch { Start-Sleep -Milliseconds 500 }
    }
    Write-Log "WARNING tunnel interface '$tunnel' not found for firewall rule, will retry."
  } catch {}
  return $false
}
function Disable-GapBlock {
  Remove-StaleKsRules
  if ($script:FwBaseline) {
    try {
      foreach ($b in $script:FwBaseline) { Set-NetFirewallProfile -Profile $b.Name -DefaultOutboundAction $b.DefaultOutboundAction }
      Write-Log "Gap kill-switch: firewall restored."
    } catch { Write-Log "WARNING could not restore firewall: $($_.Exception.Message)" }
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
# Save firewall baseline once + clean leftovers from a previous crash
# (killed window leaves DefaultOutboundAction=Block + tunnel service behind).
Save-FirewallBaseline
Disable-GapBlock
try {
  $leftovers = @(Get-Service -Name "WireGuardTunnel$*" -ErrorAction SilentlyContinue)
  foreach ($s in $leftovers) {
    $lt = ($s.Name -replace "^WireGuardTunnel\$", "")
    if ($lt) { Write-Log "Cleaning leftover tunnel $lt..."; Stop-Tunnel $lt }
  }
} catch {}

Write-Log "Countries: $($profiles.Count) | Per country: $MinutesPerCountry min | Timeout: ${ConnectionTimeoutSec}s | Gap-KS: $GapKillSwitch | DelFailed: $DeleteFailedProfiles"
Write-Log "Ctrl+C to stop."
$activeTunnel = $null; $round = 0
try {
  while ($true) {
    $round++
    # Re-scan every round so auto-deleted / added profiles take effect immediately.
    $profiles = @(Get-ChildItem -Path $ProfilesFolder -Filter "*.conf" -File)
    if ($profiles.Count -eq 0) { Write-Log "ERROR: no *.conf left in $ProfilesFolder (all deleted?). Stopping."; break }
    Ensure-KillSwitch $profiles
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
      if ($GapKillSwitch) { [void](Enable-TunnelAllow $tunnel) }
      $ok = $false; $t0 = Get-Date; $tunnelOk = -not $GapKillSwitch
      $sawHandshake = $false
      while (((Get-Date) - $t0).TotalSeconds -lt $ConnectionTimeoutSec) {
        Start-Sleep -Seconds 1
        $elapsed = [int]((Get-Date) - $t0).TotalSeconds
        if ($elapsed -gt $ConnectionTimeoutSec) { $elapsed = $ConnectionTimeoutSec }
        # Interface may appear late: keep retrying the TUNNEL allow rule,
        # otherwise the HTTPS check stays blocked and every server TIMEOUTs.
        if ($GapKillSwitch -and -not $tunnelOk) { $tunnelOk = Enable-TunnelAllow $tunnel }
        $hs = Test-Handshake $tunnel
        if ($hs) { $sawHandshake = $true }
        if (-not $hs) { Write-Log "  waiting... ${elapsed}s/${ConnectionTimeoutSec}s (no handshake yet)"; continue }
        Write-Log "  handshake OK, checking internet..."
        if (Test-Internet) { $ok = $true; break }
        Write-Log "  waiting... ${elapsed}s/${ConnectionTimeoutSec}s (handshake OK, no internet yet)"
      }
      if ($GapKillSwitch) { Disable-GapBlock }
      if (-not $ok) {
        if (-not $sawHandshake) {
          Write-Log "TIMEOUT: no WireGuard handshake for $($f.Name)."
          try {
            $svc = Get-Service -Name "WireGuardTunnel`$$tunnel" -ErrorAction SilentlyContinue
            Write-Log "  diag: service=$($svc.Status) ($($svc.Name))"
          } catch {}
          try {
            $dump = @(& $WgExe show $tunnel 2>&1 | Out-String).Trim()
            if ($dump) { Write-Log "  diag wg show: $($dump.Substring(0, [Math]::Min(300, $dump.Length)))" }
            else { Write-Log "  diag wg show: (empty - interface down?)" }
          } catch { Write-Log "  diag wg show failed" }
          Write-Log "  TIP: test this .conf in the WireGuard GUI (Import + Activate). If GUI also fails: bad/expired config, UDP blocked, or Proton app fighting. Quit Proton app fully first."
        } else {
          Write-Log "TIMEOUT: handshake OK but no internet for $($f.Name)."
        }
        Write-Log "TIMEOUT, skipping to next."
        Stop-Tunnel $tunnel; $activeTunnel = $null
        if ($DeleteFailedProfiles) {
          try {
            Remove-Item -LiteralPath $f.FullName -Force
            Write-Log "Deleted failed profile $($f.Name)."
          } catch { Write-Log "WARNING could not delete $($f.Name): $($_.Exception.Message)" }
        }
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
