# IP Rotator

Automatically rotate your public IP by cycling through WireGuard VPN
profiles (e.g. one per country) on Windows. Stay on each location for a
configurable time, skip any location that is slow to connect, never repeat
a location until all of them have been used, then shuffle and start over —
forever, with kill-switch protection and optional auto-start on boot.

Designed for a **paid Proton VPN subscription** (Plus/Unlimited or
equivalent) so the rotator can cycle through the full Plus server fleet.
A free Proton account also works but only sees the small free pool
(use `--tier 1` in the downloader).

## How it works

1. Reads every `*.conf` file in `profiles/` (one WireGuard profile per country/server).
2. Shuffles them (Fisher-Yates) and connects to each one in turn via the
   official WireGuard for Windows tunnel service
   (`wireguard.exe /installtunnelservice`).
3. A connection is accepted only after a real WireGuard handshake **plus**
   a working internet check. If that takes longer than
   `ConnectionTimeoutSec` (default 10 s), the profile is skipped — and
   deleted when `DeleteFailedProfiles` is true (default), so bad
   profiles never slow down future rounds.
4. Holds the connection for `MinutesPerCountry` (default 1 minute), then
   moves to the next profile. Press `N` (or `Space`/`Enter`) at any time
   in the open terminal to skip the current server immediately — while
   connecting or while connected — and jump to the next one (a manual
   skip never deletes the profile). Once every profile has been used, the
   list is reshuffled and a new round starts. `Ctrl+C` stops and
   disconnects cleanly.

> Note: the Proton VPN Windows app has no command line, so this project
> drives the official WireGuard client directly with your provider's
> WireGuard configs (Proton VPN, or any WireGuard provider).

## Features

- ⏱️ Configurable time per country (`MinutesPerCountry`)
- ⏩ Auto-skip slow servers (`ConnectionTimeoutSec`)
- ⏭️ Manual skip: press `N` (or `Space`/`Enter`) in the terminal to jump to the next server immediately (works while connecting and while connected, never deletes the profile)
- 🗑️ Auto-delete profiles that fail to connect (`DeleteFailedProfiles`, default Y)
- 🔀 Random order with no repeats until all profiles are used
- 🛡️ Two-layer kill-switch (native WireGuard + gap firewall block)
- 🚀 Auto-start on Windows logon (scheduled task)
- 📝 Simple setup, no dependencies besides WireGuard

## Requirements

- Windows 10/11 with Administrator rights
- A **paid Proton VPN subscription** (Plus/Unlimited or equivalent) to
  access the full server fleet (free accounts only get a handful of
  locations)
- Official WireGuard client:
  https://download.wireguard.com/windows-client/wireguard-installer.exe
- One WireGuard `.conf` file per location in `profiles/`
  (see [Get WireGuard profiles](#get-wireguard-profiles))
- Close the Proton VPN app (disconnect + quit) so it does not fight over
  the default route

## Get WireGuard profiles

Using Proton VPN as an example:

1. Go to https://account.protonvpn.com → log in → **Downloads**.
2. Under **WireGuard configuration**, pick a server and **Generate / Download** it.
3. Save it as `profiles/CH.conf`, `profiles/ES.conf`, … (short names, no spaces).
4. Repeat for every country you want to rotate through.

A sanitized template is included at `profiles/EXAMPLE.example.conf`.
⚠️ **Never commit real `.conf` files** — they contain private keys and are
ignored by `.gitignore` for that reason.

### Bulk download (optional)

Downloading hundreds of servers one by one on the website is painful
(plus Proton rate-limits generation to ~20 configs per ~20 min).
`tools/Download-Profiles.py` automates it: headed-Chrome login first
(you solve 2FA/CAPTCHA manually, credentials are never stored), and
**after login it asks what to download**. Existing `.conf` files are
never re-downloaded (skipped).

```powershell
pip install selenium
# Interactive (default): login, then pick country / ALL / quit.
# A country downloads ALL its servers (~1/min to dodge the rate limit),
# then it asks again for another country.
python tools\Download-Profiles.py
```

Menu answers: `ES` (one country), `ES,PT` (several), `ALL` (every
country/city/server), `Q` (quit). The list shows `total / already
downloaded` per country. Pause/resume any time with `Ctrl+C`. By default
it downloads paid (`--tier 2`) servers, matching the paid-subscription
requirement; free accounts can pass `--tier 1` instead.

Non-interactive (for background runs — the menu needs a terminal):

```powershell
# preview what would be downloaded (no rate-limit cost):
python tools\Download-Profiles.py --countries ES,CH,US --per-country 5 --list-only
# everything, no questions (default --per-country 0 = ALL servers):
python tools\Download-Profiles.py --all
# only some countries, limited per country:
python tools\Download-Profiles.py --countries ES,CH,US --per-country 5
# force the menu / force batch mode:
python tools\Download-Profiles.py --interactive
python tools\Download-Profiles.py --no-interactive
```

## Usage

```powershell
# 1. Test run (right-click PowerShell > Run as administrator):
Set-ExecutionPolicy Bypass -Scope Process -Force
.\IP-Rotator.ps1

# 2. Or simply double-click:
Start-IP-Rotator.bat   # self-elevates and starts the rotator
```

First run asks 4 values in the terminal and saves them to
`IP-Rotator.config.json` (delete that file to ask again):

```
Minutes per country [1]              -> MinutesPerCountry (1, 2, 0.5 = 30s)
Max seconds to connect (>=5) [10]    -> ConnectionTimeoutSec (min 5)
Gap kill-switch? (Y/N) [Y]           -> GapKillSwitch
Delete profiles that fail to connect? (Y/N) [Y] -> DeleteFailedProfiles (bad .conf is deleted, default Y)
```

Command-line overrides also work:

```powershell
.\IP-Rotator.ps1 -MinutesPerCountry 2 -ConnectionTimeoutSec 10 -DeleteFailedProfiles $false
```

While it runs, the terminal stays open showing the log. Focus that window
and press `N` (or `Space`/`Enter`) to skip the current server and jump to
the next one immediately. Manual skips work both while connecting
(`waiting...`) and while holding a connection, and never delete the
`.conf` (only automatic `TIMEOUT`s delete when `DeleteFailedProfiles`
is true).

## Auto-start on boot

- Double-click `Install-Autostart.bat` (self-elevates, asks for admin once). It creates a
  scheduled task named **IP Rotator** that starts ~30 s after logon with
  highest privileges and restarts itself up to 3 times on failure.
- Check it with `Win+R > taskschd.msc`.
- To remove: double-click `Remove-Autostart.bat`.

## Kill-switch

- **While connected:** WireGuard for Windows automatically firewall-blocks
  leaks whenever a peer routes `0.0.0.0/0` (all these profiles do) — no
  config key needed. Do NOT add `BlockUntunneledTraffic` to the `.conf`
  files: older WireGuard versions reject it as invalid and the tunnel
  never starts (the script removes that line if an old version added it).
- **During the 1–2 s switch gap:** with `GapKillSwitch = true` the script
  sets the firewall default outbound action to Block, allows only VPN UDP +
  DNS (UDP/TCP 53) + DHCP, adds an allow rule for the tunnel interface
  (retried ~10 s, then retried inside the wait loop), and restores the
  firewall as soon as the handshake succeeds (always restored, even on
  `Ctrl+C`, via `finally`).
- Set `GapKillSwitch = false` in `IP-Rotator.config.json` (or `-GapKillSwitch $false`) if you only want the native protection.
- Always stop with `Ctrl+C`, never by closing the window with X:
  closing the window kills PowerShell without running `finally` and leaves
  the firewall on Block + the tunnel service installed (no internet, not
  even Proton VPN can connect).

## Files

| File                    | Purpose                                    |
|-------------------------|--------------------------------------------|
| `IP-Rotator.ps1`        | Main rotation script                       |
| `IP-Rotator.config.json`| First-run answers (auto-created, per-machine) |
| `Start-IP-Rotator.bat`  | Double-click launcher (self-elevates)      |
| `Reset-Network.ps1` / `Reset-Network.bat` | Emergency restore: removes IPRotator rules, sets firewall back to Allow, deletes leftover tunnels, flushes DNS (no reboot) |
| `Install-Autostart.bat` (`Autostart.ps1`) | Double-click to create the logon scheduled task (self-elevating) |
| `Remove-Autostart.bat`  | Deletes the scheduled task                 |
| `profiles/`             | Your `*.conf` files (never committed)      |

## Troubleshooting

| Symptom | Fix |
|---|---|
| `ERROR: run AS ADMINISTRATOR` | Right-click PowerShell > Run as administrator |
| `ERROR: no *.conf in ...` | Put your `.conf` files in `profiles/` |
| `TIMEOUT, skipping` for all | First double-click `Reset-Network.bat`, then check internet/DNS, close Proton app, verify WireGuard installed, try raising `ConnectionTimeoutSec` (old versions blocked DNS, causing false TIMEOUTs on every server) |
| No internet after `Ctrl+C` / killed window | Double-click `Reset-Network.bat` (no reboot needed). It deletes `IPRotator-*` rules, sets firewall outbound back to Allow, and uninstalls leftover `WireGuardTunnel$*` services |
| Task does not start at boot | Re-run `Install-Autostart.ps1`, check `taskschd.msc` > **IP Rotator** > History |

## License

MIT — see [LICENSE](LICENSE).
