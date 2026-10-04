#!/usr/bin/env python3
"""Bulk-download WireGuard .conf profiles from your Proton VPN account.

Why: account.protonvpn.com only lets you download one config at a time.
This script logs you in (headed Chrome, so you can solve 2FA/CAPTCHA
manually), then generates N configs per country via the same API calls
the website itself makes. No credentials are stored anywhere.

Rate limits: Proton allows roughly ~20 generated configs per ~20 minutes.
The script pauses automatically and resumes (already-downloaded files are
skipped, so you can stop/resume any time with Ctrl+C).

Requires: pip install selenium   (Chrome is driven automatically)
Usage:
    python Download-Profiles.py --out ..\\profiles --per-country 2 --list-only
    python Download-Profiles.py --out ..\\profiles --per-country 2
    python Download-Profiles.py --out ..\\profiles --countries ES,CH,US --per-country 5
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
API_LOGICALS = "/api/vpn/logicals"
API_KEY = "/api/vpn/v1/certificate/key/EC"
API_CERT = "/api/vpn/v1/certificate"
COOLDOWN_SEC = 20 * 60


def sanitize(name):
    return re.sub(r"[^A-Za-z0-9._-]+", "-", name).strip("-") or "server"


def js_fetch(driver, method, path, body=None):
    """Run a same-origin fetch() inside the logged-in page. Returns (status, json)."""
    script = """
    const [method, path, body] = arguments;
    const headers = {'Accept': 'application/vnd.protonmail.v1+json'};
    if (body !== null) headers['Content-Type'] = 'application/json';
    return fetch(path, {method, headers, body, credentials: 'same-origin'})
      .then(async r => ({status: r.status, text: await r.text()}))
      .catch(e => ({status: 0, text: String(e)}));
    """
    res = driver.execute_script(script, method, path, body)
    try:
        return res["status"], json.loads(res["text"])
    except Exception:
        return res.get("status", 0), {"_raw": (res.get("text") or "")[:200]}


def login(driver, username, password):
    from selenium.webdriver.common.by import By
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC

    driver.get(LOGIN_URL)
    WebDriverWait(driver, 60).until(EC.presence_of_element_located((By.ID, "username"))).send_keys(username)
    driver.find_element(By.XPATH, "//button[contains(text(),'Continue')]").click()
    WebDriverWait(driver, 60).until(EC.presence_of_element_located((By.ID, "password"))).send_keys(password)
    driver.find_element(By.XPATH, "//button[contains(text(),'Sign in')]").click()
    print("If Proton asks for 2FA/CAPTCHA, solve it in the Chrome window...")
    WebDriverWait(driver, 300).until(lambda d: "/login" not in d.current_url)
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


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=os.path.join("..", "profiles"), help="output folder for .conf files")
    ap.add_argument("--countries", default="", help="comma list like ES,CH,US (default: all)")
    ap.add_argument("--per-country", type=int, default=2, help="configs per country")
    ap.add_argument("--tier", type=int, default=2, help="1=Free, 2=Paid")
    ap.add_argument("--standard-only", action="store_true", default=True, help="only standard servers (no SecureCore/Tor/P2P)")
    ap.add_argument("--any-features", action="store_true", help="include special-feature servers")
    ap.add_argument("--max", type=int, default=9999)
    ap.add_argument("--list-only", action="store_true", help="list matching servers, download nothing")
    ap.add_argument("--delay", type=float, default=2.0, help="seconds between servers")
    args = ap.parse_args()

    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options

    username = input("Proton username/email: ").strip()
    password = getpass.getpass("Proton password (not stored): ")

    opts = Options()
    opts.add_argument("--disable-blink-features=AutomationControlled")
    driver = webdriver.Chrome(options=opts)
    try:
        login(driver, username, password)

        status, data = js_fetch(driver, "GET", API_LOGICALS)
        if status != 200:
            print(f"ERROR fetching server list: HTTP {status} {data}")
            return 1
        servers = data.get("LogicalServers", [])
        print(f"Total servers advertised: {len(servers)}")

        want = {c.strip().upper() for c in args.countries.split(",") if c.strip()}
        per_country = {}
        targets = []
        for s in servers:
            if s.get("Status") != 1:
                continue
            if s.get("Tier") != args.tier:
                continue
            cc = (s.get("EntryCountry") or "").upper()
            if want and cc not in want:
                continue
            if not args.any_features and args.standard_only and (s.get("Features") or 0) != 0:
                continue
            n = per_country.get(cc, 0)
            if n >= args.per_country:
                continue
            per_country[cc] = n + 1
            targets.append(s)
            if len(targets) >= args.max:
                break

        print(f"Selected: {len(targets)} servers across {len(per_country)} countries.")
        if args.list_only:
            for s in targets[:50]:
                print(f"  {s['EntryCountry']}  {s['Name']}")
            if len(targets) > 50:
                print(f"  ... and {len(targets) - 50} more")
            return 0

        os.makedirs(args.out, exist_ok=True)
        done = 0
        for s in targets:
            fname = f"{s['EntryCountry']}-{sanitize(s['Name'])}.conf"
            path = os.path.join(args.out, fname)
            if os.path.exists(path):
                print(f"  skip (exists) {fname}")
                continue
            ok = False
            while not ok:
                st, key = js_fetch(driver, "GET", API_KEY)
                if st != 200:
                    print(f"  keygen HTTP {st}, cooling down 20 min...")
                    time.sleep(COOLDOWN_SEC)
                    continue
                try:
                    priv_ec = key["PrivateKey"].split("\n")[1]
                    pub_ec = key["PublicKey"].split("\n")[1]
                except Exception:
                    print(f"  bad key response, cooling down 20 min...")
                    time.sleep(COOLDOWN_SEC)
                    continue
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
                    print("  session expired, log in again in the Chrome window (60s)...")
                    time.sleep(60)
                    continue
                if st != 200:
                    print(f"  register HTTP {st} ({str(reg)[:120]}), cooling down 20 min...")
                    time.sleep(COOLDOWN_SEC)
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
                time.sleep(args.delay)
        print(f"Done. {done} new configs in {args.out}")
        return 0
    finally:
        try:
            driver.quit()
        except Exception:
            pass


if __name__ == "__main__":
    sys.exit(main())
