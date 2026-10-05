# Reset-Network.ps1 - emergency restore, no reboot needed.
# Run as Administrator (or double-click Reset-Network.bat).
# 1. Deletes all IPRotator-* firewall rules (gap kill-switch leftovers).
# 2. Sets firewall DefaultOutboundAction back to Allow (Domain/Private/Public).
# 3. Uninstalls ALL leftover WireGuard tunnel services (native kill-switch).
# 4. Flushes DNS.
$ErrorActionPreference = "Continue"
function Write-Log($m) { Write-Host "[$(Get-Date -Format 'HH:mm:ss')] $m" }
$p = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { Write-Log "ERROR: run AS ADMINISTRATOR."; exit 1 }

$WireGuardExe = "$env:ProgramFiles\WireGuard\wireguard.exe"

Write-Log "Step 1/4: removing IPRotator firewall rules..."
try { Get-NetFirewallRule -DisplayName "IPRotator*" -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue } catch {}
foreach ($n in @("IPRotator-KS-Allow-VPN", "IPRotator-KS-Allow-DNS", "IPRotator-KS-Allow-DNS-TCP", "IPRotator-KS-Allow-DHCP", "IPRotator-KS-Allow-TUNNEL")) {
  try { Remove-NetFirewallRule -DisplayName $n -ErrorAction SilentlyContinue } catch {}
}
Write-Log "  rules removed."

Write-Log "Step 2/4: restoring firewall outbound to Allow..."
try {
  Set-NetFirewallProfile -Profile Domain, Private, Public -DefaultOutboundAction Allow
  Get-NetFirewallProfile -Profile Domain, Private, Public | ForEach-Object { Write-Log "  $($_.Name): outbound=$($_.DefaultOutboundAction)" }
} catch { Write-Log "  WARNING: $($_.Exception.Message)" }

Write-Log "Step 3/4: removing leftover WireGuard tunnels..."
try {
  $svcs = @(Get-Service -Name "WireGuardTunnel$*" -ErrorAction SilentlyContinue)
  if (-not $svcs -or $svcs.Count -eq 0) { Write-Log "  no tunnel services found." }
  foreach ($s in $svcs) {
    $t = ($s.Name -replace "^WireGuardTunnel\$", "")
    Write-Log "  uninstalling $t ($($s.Name))..."
    try {
      if (Test-Path $WireGuardExe) { & $WireGuardExe /uninstalltunnelservice $t 2>&1 | Out-Null }
      else { sc.exe delete "$($s.Name)" | Out-Null }
    } catch {}
    for ($i = 0; $i -lt 50; $i++) {
      if (-not (Get-Service -Name $s.Name -ErrorAction SilentlyContinue)) { break }
      Start-Sleep -Milliseconds 100
    }
    if (Get-Service -Name $s.Name -ErrorAction SilentlyContinue) {
      Write-Log "  still present, forcing sc delete..."
      try { sc.exe delete "$($s.Name)" | Out-Null } catch {}
    }
  }
} catch { Write-Log "  WARNING: $($_.Exception.Message)" }

Write-Log "Step 4/4: flushing DNS..."
try { ipconfig /flushdns | Out-Null; Write-Log "  DNS flushed." } catch {}

Write-Log "Quick internet check..."
try { $r = Invoke-WebRequest -Uri "https://ifconfig.me/ip" -TimeoutSec 5 -UseBasicParsing; Write-Log "  INTERNET OK, IP=$($r.Content.Trim())" }
catch { Write-Log "  still no internet: check cable/WiFi, router, or reboot as last resort." }

Write-Log "DONE. You should have internet again without rebooting."
