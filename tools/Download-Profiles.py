#!/usr/bin/env python3
r"""Bulk-download WireGuard .conf profiles from your Proton VPN account.

Why: account.protonvpn.com only lets you download one config at a time.
This script logs you in (headed Chrome, so you can solve 2FA/CAPTCHA
manually), then generates configs for ALL servers via the same API calls
the website itself makes. No credentials are stored anywhere.

Rate limits: Proton allows roughly ~20 generated configs per ~20 minutes.
The script pauses automatically and resumes (already-downloaded files are
skipped, so you can stop/resume any time with Ctrl+C).

Requires: pip install selenium   (Chrome is driven automatically)
Usage:
    python tools/Download-Profiles.py
        Interactive menu: pick a country (downloads ALL its servers,
        ~1/min to dodge the rate-limit), then it asks again.
        Options: <code> (e.g. ES), ALL (every country), Q (quit).
    python tools/Download-Profiles.py --all
        Non-interactive: download EVERYTHING without asking (for background runs).
    python tools/Download-Profiles.py --countries ES,CH,US --per-country 5
    python tools/Download-Profiles.py --per-country 2 --list-only
    python tools/Download-Profiles.py --per-country 0   (0 = ALL servers, default)
    python tools/Download-Profiles.py --no-interactive   (batch mode even in terminal)
"""
import argparse
import base64
import hashlib
import json
import os
import re
import sys
import time
import getpass

LOGIN_URL = "https://account.protonvpn.com/login"
DOWNLOADS_URL = "https://account.protonvpn.com/downloads"
API_LOGICALS = "/api/vpn/logicals"
API_KEY = "/api/vpn/v1/certificate/key/EC"
API_CERT = "/api/vpn/v1/certificate"
COOLDOWN_SEC = 20 * 60
APPVERSION = None  # captured from the page's own traffic (see capture_api_headers)
UID = None  # x-pm-uid, required for all authenticated API calls (rotates per session)


def get_uid_from_storage(driver):
    """Read x-pm-uid from localStorage (ps-1 / any key with UID)."""
    try:
        return driver.execute_script(
            """
            try {
              const raw = localStorage.getItem('ps-1');
              if (raw) { try { const j = JSON.parse(raw); if (j && j.UID) return j.UID; } catch(e){} }
              for (let i = 0; i < localStorage.length; i++) {
                const k = localStorage.key(i);
                try { const v = JSON.parse(localStorage.getItem(k)); if (v && v.UID) return v.UID; } catch(e){}
              }
              return null;
            } catch(e){ return null; }
            """
        )
    except Exception:
        return None


def capture_api_headers(driver, tries=4):
    """Read x-pm-appversion + x-pm-uid the web app itself sends.

    The API rejects calls without them (401 "token no valido"), and both
    values change (appversion per release, UID per session), so we capture
    them from real page traffic instead of hardcoding. Falls back to
    localStorage for UID.
    """
    import json as _json

    appversion = None
    uid = None
    for _ in range(tries):
        try:
            for entry in driver.get_log("performance"):
                try:
                    msg = _json.loads(entry["message"])["message"]
                except Exception:
                    continue
                if msg.get("method") != "Network.requestWillBeSent":
                    continue
                req = msg.get("params", {}).get("request", {})
                if "/api/" not in req.get("url", ""):
                    continue
                for k, v in (req.get("headers") or {}).items():
                    kl = k.lower()
                    if kl == "x-pm-appversion" and v and not appversion:
                        appversion = v
                    elif kl == "x-pm-uid" and v and not uid:
                        uid = v
                if appversion and uid:
                    break
        except Exception:
            pass
        if appversion and uid:
            break
        # UID is also in localStorage even if no API traffic was captured yet
        if not uid:
            uid = get_uid_from_storage(driver)
        if appversion and uid:
            break
        time.sleep(3)
    if not uid:
        uid = get_uid_from_storage(driver)
    return appversion, uid


def capture_appversion(driver, tries=4):
    """Back-compat wrapper: returns appversion only."""
    appversion, _ = capture_api_headers(driver, tries=tries)
    return appversion


def sanitize(name):
    return re.sub(r"[^A-Za-z0-9._-]+", "-", name).strip("-") or "server"


def js_fetch(driver, method, path, body=None):
    """Run a same-origin fetch() inside the logged-in page. Returns (status, json)."""
    try:
        driver.set_script_timeout(60)
    except Exception:
        pass
    script = """
    const [method, path, body, appversion, uid, callback] = arguments;
    const headers = {'Accept': 'application/vnd.protonmail.v1+json'};
    if (appversion) headers['x-pm-appversion'] = appversion;
    if (uid) headers['x-pm-uid'] = uid;
    if (body !== null) headers['Content-Type'] = 'application/json';
    fetch(path, {method, headers, body, credentials: 'same-origin'})
      .then(async r => callback({status: r.status, text: await r.text()}))
      .catch(e => callback({status: 0, text: String(e)}));
    """
    # Refresh UID from storage if we don't have one yet (it rotates per session)
    global UID
    if not UID:
        try:
            UID = get_uid_from_storage(driver)
        except Exception:
            pass
    try:
        res = driver.execute_async_script(script, method, path, body, APPVERSION, UID)
    except Exception as e:
        return 0, {"_error": str(e)[:200]}
    try:
        return res["status"], json.loads(res["text"])
    except Exception:
        return res.get("status", 0) if isinstance(res, dict) else 0, {
            "_raw": str((res.get("text") if isinstance(res, dict) else res) or "")[:200]
        }


def submit_step(driver, field, wait_for):
    """Submit the form containing `field` without depending on UI language.

    Presses Enter and waits for the expected change. Only if nothing
    happened does it fall back to clicking the form's submit button
    located purely via DOM (never by visible text). This avoids
    double-submitting fast transitions.
    """
    from selenium.webdriver.common.keys import Keys
    from selenium.webdriver.support.ui import WebDriverWait

    try:
        field.send_keys(Keys.RETURN)
    except Exception:
        pass
    try:
        WebDriverWait(driver, 10).until(wait_for)
        return
    except Exception:
        pass
    try:
        driver.execute_script(
            """
            const el = arguments[0];
            const form = el.closest('form') || document.querySelector('form');
            if (!form) return false;
            const btn = form.querySelector("button[type='submit']") ||
                        form.querySelector("button:not([type])") ||
                        form.querySelector("button");
            if (btn) { btn.click(); return true; }
            if (form.requestSubmit) { form.requestSubmit(); return true; }
            form.submit(); return true;
            """,
            field,
        )
    except Exception:
        pass


def login(driver, username, password):
    from selenium.webdriver.common.by import By
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC

    driver.get(LOGIN_URL)
    user_field = WebDriverWait(driver, 60).until(
        EC.presence_of_element_located((By.ID, "username"))
    )
    user_field.send_keys(username)
    submit_step(driver, user_field,
                EC.presence_of_element_located((By.ID, "password")))

    # Stage 2: Password (id is stable across languages)
    pass_field = WebDriverWait(driver, 60).until(
        EC.presence_of_element_located((By.ID, "password"))
    )
    pass_field.send_keys(password)
    submit_step(driver, pass_field,
                lambda d: "/login" not in d.current_url)

    # Logged in = we left /login (2FA/CAPTCHA can be solved manually meanwhile)
    print("If Proton asks for 2FA/CAPTCHA, solve it in the Chrome window...")
    WebDriverWait(driver, 300).until(lambda d: "/login" not in d.current_url)
    time.sleep(3)
    print("Logged in.")


def x25519_priv_from_ec(priv_b64):
    raw = base64.b64decode(priv_b64)[-32:]
    h = bytearray(hashlib.sha512(raw).digest()[:32])
    h[0] &= 0xF8
    h[31] = (h[31] & 0x7F) | 0x40
    return base64.b64encode(bytes(h)).decode()


def build_conf(priv_x25519, peer_pubkey, peer_ip):
    return f"""[Interface]
PrivateKey = {priv_x25519}
Address = 10.2.0.2/32
DNS = 10.2.0.1
BlockUntunneledTraffic = true

[Peer]
PublicKey = {peer_pubkey}
AllowedIPs = 0.0.0.0/0
Endpoint = {peer_ip}:51820
"""


RETRY_SEC = 15  # short retry for transient network/driver failures (NOT rate-limit)


def is_rate_limit(status, data):
    """True only for Proton's real quota response (HTTP 429 / Code 2028)."""
    if status == 429:
        return True
    try:
        if isinstance(data, dict):
            if data.get("Code") == 2028:
                return True
            if "Too many" in str(data.get("Error", "")):
                return True
    except Exception:
        pass
    return False


def wait_cooldown(seconds):
    """Sleep with a visible countdown (prints every minute). Ctrl+C still aborts."""
    end = time.time() + seconds
    while True:
        left = int(end - time.time())
        if left <= 0:
            break
        if left > 60:
            print(f"  rate-limited by Proton, retrying in ~{left // 60} min ({left}s)...")
            time.sleep(min(60, left))
        else:
            print(f"  rate-limited by Proton, retrying in {left}s...")
            time.sleep(left)


def try_refresh_uid(driver):
    """Refresh UID from the page's storage. Returns True if it changed."""
    global UID
    try:
        fresh = get_uid_from_storage(driver)
        if fresh and fresh != UID:
            UID = fresh
            print(f"  refreshed uid ({UID[:6]}...), retrying...")
            return True
    except Exception:
        pass
    return False


def download_targets(driver, targets, out_dir, delay):
    """Download .conf for each server in targets. Skips files that exist."""
    global UID
    os.makedirs(out_dir, exist_ok=True)
    done = 0
    for s in targets:
        fname = f"{s['EntryCountry']}-{sanitize(s['Name'])}.conf"
        path = os.path.join(out_dir, fname)
        if os.path.exists(path):
            print(f"  skip (exists) {fname}")
            continue
        fails = 0
        ok = False
        while not ok:
            st, key = js_fetch(driver, "GET", API_KEY)
            if st == 401:
                if try_refresh_uid(driver):
                    continue
                print("  session expired, log in again in the Chrome window (60s)...")
                time.sleep(60)
                continue
            if is_rate_limit(st, key):
                wait_cooldown(COOLDOWN_SEC)
                fails = 0
                continue
            if st != 200:
                # Transient (HTTP 0 = driver/fetch failed, 5xx, ...): short retry, NO 20-min wait.
                fails += 1
                print(f"  keygen HTTP {st} ({str(key)[:160]}), retrying in {RETRY_SEC}s "
                      f"(attempt {fails}, no cooldown)...")
                if fails % 3 == 0:
                    try_refresh_uid(driver)
                if fails % 5 == 0:
                    print("  Hint: check the Chrome window (logged in? network OK?). Continuing...")
                time.sleep(RETRY_SEC)
                continue
            try:
                priv_ec = key["PrivateKey"].split("\n")[1]
                pub_ec = key["PublicKey"].split("\n")[1]
            except Exception:
                fails += 1
                print(f"  bad key response ({str(key)[:120]}), retrying in {RETRY_SEC}s (attempt {fails})...")
                time.sleep(RETRY_SEC)
                continue
            fails = 0
            peer = s["Servers"][0]
            body = json.dumps({
                "ClientPublicKey": pub_ec,
                "Mode": "persistent",
                "DeviceName": f"IPRotator-{sanitize(s['Name'])}"[:64],
                "Features": {
                    "peerName": s["Name"],
                    "peerIp": peer["EntryIP"],
                    "peerPublicKey": peer["X25519PublicKey"],
                    "platform": "Windows",
                },
            })
            st, reg = js_fetch(driver, "POST", API_CERT, body)
            if st == 401:
                # Session/UID may have rotated: refresh UID automatically first
                try:
                    fresh = get_uid_from_storage(driver)
                    if fresh:
                        UID = fresh
                        print(f"  401, refreshed uid ({UID[:6]}...), retrying once...")
                        st, reg = js_fetch(driver, "POST", API_CERT, body)
                        if st == 200:
                            pass  # fall through to save below
                        else:
                            print("  session expired, log in again in the Chrome window (60s)...")
                            time.sleep(60)
                            continue
                    else:
                        print("  session expired, log in again in the Chrome window (60s)...")
                        time.sleep(60)
                        continue
                except Exception:
                    print("  session expired, log in again in the Chrome window (60s)...")
                    time.sleep(60)
                    continue
                if st == 401:
                    print("  session expired, log in again in the Chrome window (60s)...")
                    time.sleep(60)
                    continue
            if is_rate_limit(st, reg):
                wait_cooldown(COOLDOWN_SEC)
                continue
            if st != 200:
                print(f"  register HTTP {st} ({str(reg)[:160]}), retrying in {RETRY_SEC}s (no cooldown)...")
                time.sleep(RETRY_SEC)
                continue
            conf = build_conf(
                x25519_priv_from_ec(priv_ec),
                reg["Features"]["peerPublicKey"],
                reg["Features"]["peerIp"],
            )
            with open(path, "w", newline="") as f:
                f.write(conf)
            done += 1
            print(f"  [{done}] saved {fname}")
            ok = True
            time.sleep(delay)
    return done


def country_counts(servers):
    counts = {}
    for s in servers:
        cc = (s.get("EntryCountry") or "").upper()
        counts[cc] = counts.get(cc, 0) + 1
    return counts


def existing_counts(out_dir):
    counts = {}
    if not os.path.isdir(out_dir):
        return counts
    for fn in os.listdir(out_dir):
        if fn.lower().endswith(".conf") and "-" in fn:
            cc = fn.split("-", 1)[0].upper()
            counts[cc] = counts.get(cc, 0) + 1
    return counts


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="", help="output folder for .conf files (default: profiles/ next to the repo)")
    ap.add_argument("--countries", default="", help="comma list like ES,CH,US (default: all countries)")
    ap.add_argument("--per-country", type=int, default=0, help="configs per country in batch mode (0 = ALL servers of every city/country, default: 0)")
    ap.add_argument("--all", action="store_true", help="non-interactive: download EVERYTHING without asking (use for background runs)")
    ap.add_argument("--interactive", action="store_true", help="force country-picker menu even if --countries/--all given")
    ap.add_argument("--no-interactive", action="store_true", help="never ask, batch mode (default when stdin is not a terminal)")
    ap.add_argument("--tier", type=int, default=2, help="1=Free, 2=Paid")
    ap.add_argument("--standard-only", action="store_true", default=True, help="only non-SecureCore/non-Tor servers (default: True)")
    ap.add_argument("--no-standard-only", action="store_false", dest="standard_only", help="disable standard-only filtering (same as --any-features)")
    ap.add_argument("--any-features", action="store_true", help="include SecureCore/Tor servers too")
    ap.add_argument("--max", type=int, default=9999)
    ap.add_argument("--list-only", action="store_true", help="list matching servers, download nothing")
    ap.add_argument("--delay", type=float, default=2.0, help="seconds between servers")
    ap.add_argument("--keep-open", action="store_true", help="leave Chrome open on error for inspection")
    ap.add_argument("--username", default=os.environ.get("PROTON_USER", ""), help="Proton username/email (or set PROTON_USER env)")
    ap.add_argument("--password", default=os.environ.get("PROTON_PASS", ""), help="Proton password (or set PROTON_PASS env)")
    args = ap.parse_args()
    if not args.out:
        # profiles/ next to the repo root, regardless of cwd:
        # <root>/tools/Download-Profiles.py -> <root>/profiles
        args.out = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "profiles"))

    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options

    username = (args.username or "").strip() or input("Proton username/email: ").strip()
    password = args.password or getpass.getpass("Proton password (not stored): ")

    opts = Options()
    opts.add_argument("--incognito")
    opts.add_argument("--disable-blink-features=AutomationControlled")
    opts.set_capability("goog:loggingPrefs", {"performance": "ALL"})
    if args.keep_open:
        opts.add_experimental_option("detach", True)
    driver = webdriver.Chrome(options=opts)
    try:
        login(driver, username, password)

        global APPVERSION, UID
        print("Capturing API headers from page traffic...")
        APPVERSION, UID = capture_api_headers(driver)
        if not APPVERSION or not UID:
            print("  no API traffic seen yet, opening Downloads to trigger some...")
            driver.get(DOWNLOADS_URL)
            time.sleep(8)
            APPVERSION, UID = capture_api_headers(driver)
        if not APPVERSION:
            print("ERROR: could not capture x-pm-appversion. The site may have changed.")
            return 1
        if not UID:
            print("ERROR: could not capture x-pm-uid (login may not have completed).")
            print("  Tip: re-run with --keep-open and check the Chrome window.")
            return 1
        print(f"  appversion: {APPVERSION}")
        print(f"  uid: {UID[:6]}... (captured)")

        print("Fetching server list from the API...")
        status, data = 0, {}
        for _ in range(6):  # session/cookies may need a few seconds after redirect
            status, data = js_fetch(driver, "GET", API_LOGICALS)
            if status == 200:
                break
            # UID rotates per session; refresh it from storage on 401
            if status == 401:
                try:
                    fresh = get_uid_from_storage(driver)
                    if fresh and fresh != UID:
                        UID = fresh
                        print(f"  refreshed uid ({UID[:6]}...), retrying...")
                except Exception:
                    pass
            print(f"  API not ready (HTTP {status} {str(data)[:200]}), retrying in 5s...")
            time.sleep(5)
        if status != 200:
            print(f"ERROR fetching server list: HTTP {status} {data}")
            return 1
        servers = data.get("LogicalServers", [])
        print(f"Total servers advertised: {len(servers)}")

        # Eligible = everything matching tier/status/features (no country limit yet)
        all_eligible = []
        for s in servers:
            if s.get("Status") != 1:
                continue
            if s.get("Tier") != args.tier:
                continue
            # Features is a bitmask (1=SecureCore, 2=Tor, 4=P2P, 8=Streaming, 16=IPv6...).
            # Standard-only means: exclude SecureCore (1) and Tor (2) only.
            if not args.any_features and args.standard_only and ((s.get("Features") or 0) & 3) != 0:
                continue
            all_eligible.append(s)
        all_eligible.sort(key=lambda s: ((s.get("EntryCountry") or ""), (s.get("Name") or "")))
        avail = country_counts(all_eligible)
        print(f"Eligible (tier={args.tier}, standard-only={args.standard_only and not args.any_features}): "
              f"{len(all_eligible)} servers across {len(avail)} countries.")

        def apply_batch_filter(pool):
            want = {c.strip().upper() for c in args.countries.split(",") if c.strip()}
            if args.all:
                want = set()
            per_country = {}
            targets = []
            limit = args.per_country if args.per_country and args.per_country > 0 else None
            for s in pool:
                cc = (s.get("EntryCountry") or "").upper()
                if want and cc not in want:
                    continue
                if limit is not None:
                    n = per_country.get(cc, 0)
                    if n >= limit:
                        continue
                    per_country[cc] = n + 1
                else:
                    per_country[cc] = per_country.get(cc, 0) + 1
                targets.append(s)
                if len(targets) >= args.max:
                    break
            return targets, per_country

        if args.list_only:
            targets, per_country = apply_batch_filter(all_eligible)
            print(f"Selected: {len(targets)} servers across {len(per_country)} countries.")
            for s in targets[:50]:
                print(f"  {s['EntryCountry']}  {s['Name']}")
            if len(targets) > 50:
                print(f"  ... and {len(targets) - 50} more")
            return 0

        # Interactive? Por defecto SIEMPRE se pregunta tras el login.
        # Solo se evita con batch flags: --all, --countries, --no-interactive, --list-only.
        want_cli = {c.strip().upper() for c in args.countries.split(",") if c.strip()}
        if args.list_only or args.no_interactive or args.all or want_cli:
            use_menu = True if args.interactive else False
        else:
            use_menu = True

        # Pace: batch uses --delay as-is; menu defaults to ~1/min to stay
        # under Proton's ~20 certs / 20 min limit unless --delay was given.
        delay_given = "--delay" in sys.argv
        menu_delay = args.delay if delay_given else 60.0

        os.makedirs(args.out, exist_ok=True)

        if not use_menu:
            targets, per_country = apply_batch_filter(all_eligible)
            print(f"Selected: {len(targets)} servers across {len(per_country)} countries "
                  f"(delay={args.delay}s, existing files are skipped).")
            done = download_targets(driver, targets, args.out, args.delay)
            print(f"Done. {done} new configs in {args.out}")
            return 0

        # ---- Interactive country picker ----
        print(f"\nMenu pace: 1 server/min (delay={menu_delay}s) to stay under "
              f"Proton's limit. Override with --delay N.")
        print("Existing .conf files are NOT downloaded again (skip).")
        total_done = 0
        while True:
            have = existing_counts(args.out)
            print("\nAvailable countries (code: total / already downloaded):")
            for cc in sorted(avail):
                print(f"  {cc}: {avail[cc]} / {have.get(cc, 0)} downloaded")
            print(f"  ALL: {len(all_eligible)} servers in {len(avail)} countries")
            try:
                choice = input("Pick country (code or list e.g. ES,PT), ALL for everything, Q to quit: ").strip().upper()
            except (EOFError, KeyboardInterrupt):
                print("\nExiting.")
                break
            if not choice or choice in ("Q", "QUIT", "EXIT"):
                break
            if choice == "ALL":
                targets = [s for s in all_eligible]
                print(f"Downloading EVERYTHING: {len(targets)} servers...")
                total_done += download_targets(driver, targets, args.out, menu_delay)
                print(f"Finished. {total_done} new in total in {args.out}")
                break  # ALL covers everything; leave the menu
            codes = {c.strip().upper() for c in choice.replace(";", ",").split(",") if c.strip()}
            unknown = [c for c in codes if c not in avail]
            if unknown:
                print(f"  Invalid code(s): {', '.join(unknown)}. Pick one from the list or ALL.")
                continue
            targets = [s for s in all_eligible if (s.get("EntryCountry") or "").upper() in codes]
            if not targets:
                print("  Nothing to download for that selection.")
                continue
            print(f"Downloading {len(targets)} servers from {', '.join(sorted(codes))}...")
            total_done += download_targets(driver, targets, args.out, menu_delay)
            print(f"  Done ({', '.join(sorted(codes))}). New this session: {total_done}.")
            # loop: ask for another country
        print(f"Done. {total_done} new configs in {args.out}")
        return 0
    finally:
        if args.keep_open and "driver" in dir():
            print("Keeping Chrome open for inspection (--keep-open).")
        else:
            try:
                driver.quit()
            except Exception:
                pass


if __name__ == "__main__":
    sys.exit(main())
