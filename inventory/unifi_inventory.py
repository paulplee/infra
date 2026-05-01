#!/usr/bin/env python3
import argparse
import json
import requests
import urllib3
import datetime as dt
from pathlib import Path

# Disable SSL warnings for self-signed certs (common on local UDM)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class UnifiClient:
    def __init__(self, url, username, password, site="default"):
        self.url = url.rstrip("/")
        self.username = username
        self.password = password
        self.site = site
        self.session = requests.Session()
        self.session.verify = False
        self.csrf_token = None

    def login(self):
        """Login to UDM/UniFi Controller"""
        # Try UDM-OS style login first (UniFi OS)
        login_url = f"{self.url}/api/auth/login"
        payload = {"username": self.username, "password": self.password}
        headers = {"Content-Type": "application/json"}
        
        try:
            resp = self.session.post(login_url, json=payload, headers=headers)
            if resp.status_code == 200:
                # Capture CSRF token if present (needed for some endpoints)
                self.csrf_token = resp.headers.get("x-csrf-token")
                return True
            
            # Fallback for older controllers (unlikely for UDM Pro but good practice)
            login_url_old = f"{self.url}/api/login"
            resp = self.session.post(login_url_old, json=payload, headers=headers)
            return resp.status_code == 200
        except Exception as e:
            print(f"Login failed: {e}")
            return False

    def get_api(self, endpoint):
        """Generic GET wrapper handling UniFi OS path prefixes"""
        # On UDM Pro (UniFi OS), Network app is usually at /proxy/network
        # We try both /proxy/network/api/s/{site}/... and /api/s/{site}/...
        
        paths = [
            f"/proxy/network/api/s/{self.site}/{endpoint}",
            f"/api/s/{self.site}/{endpoint}"
        ]
        
        for path in paths:
            full_url = f"{self.url}{path}"
            try:
                resp = self.session.get(full_url)
                if resp.status_code == 200:
                    return resp.json()
            except:
                continue
        return None

    def get_clients(self):
        """Get connected clients (stations)"""
        data = self.get_api("stat/sta")
        return data.get("data", []) if data else []

    def get_devices(self):
        """Get UniFi devices (Switches, APs, Gateways)"""
        data = self.get_api("stat/device")
        return data.get("data", []) if data else []

    def get_networks(self):
        """Get Networks / VLANs"""
        data = self.get_api("rest/networkconf")
        return data.get("data", []) if data else []

    def get_firewall_rules(self):
        """Get Firewall Rules"""
        data = self.get_api("rest/firewallrule")
        return data.get("data", []) if data else []
    
    def get_firewall_groups(self):
        """Get Firewall Groups"""
        data = self.get_api("rest/firewallgroup")
        return data.get("data", []) if data else []

    def get_health(self):
        """Get System Health / Dashboard stats"""
        data = self.get_api("stat/health")
        return data.get("data", []) if data else []

def main():
    ap = argparse.ArgumentParser(description="Dump UniFi Network Controller configuration and state")
    ap.add_argument("--url", required=True, help="Controller URL (e.g. https://192.168.1.1)")
    ap.add_argument("--user", required=True, help="Username (local user recommended)")
    ap.add_argument("--password", required=True, help="Password")
    ap.add_argument("--out", default=None, help="Output JSON path")
    ap.add_argument("--site", default="default", help="Site ID (default: default)")
    args = ap.parse_args()

    print(f"Connecting to {args.url}...")
    client = UnifiClient(args.url, args.user, args.password, args.site)
    
    if not client.login():
        print("Error: Login failed. Check credentials and URL.")
        return

    print("Login successful. Fetching data...")
    
    inventory = {
        "schema": "pplx_unifi_inventory_v1",
        "collected_at_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "controller_url": args.url,
        "networks": client.get_networks(),
        "devices": client.get_devices(),
        "clients": client.get_clients(),
        "firewall": {
            "rules": client.get_firewall_rules(),
            "groups": client.get_firewall_groups()
        },
        "health": client.get_health()
    }

    # Basic stats summary for console output
    n_nets = len(inventory["networks"])
    n_devs = len(inventory["devices"])
    n_clients = len(inventory["clients"])
    n_rules = len(inventory["firewall"]["rules"])
    
    print(f"Collected: {n_nets} Networks, {n_devs} Devices, {n_clients} Clients, {n_rules} Firewall Rules")

    if args.out:
        out_path = Path(args.out)
    else:
        output_dir = Path("output")
        output_dir.mkdir(exist_ok=True)
        out_path = output_dir / "unifi-inventory.json"

    out_path.write_text(json.dumps(inventory, indent=2), encoding="utf-8")
    print(f"Saved to: {out_path.absolute()}")

if __name__ == "__main__":
    main()
