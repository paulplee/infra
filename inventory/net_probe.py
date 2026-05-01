#!/usr/bin/env python3
import argparse
import datetime as dt
import ipaddress
import json
import platform
import shutil
import subprocess
from pathlib import Path

def run(cmd, timeout=30):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, shell=isinstance(cmd, str))
        return (p.stdout or "").strip()
    except Exception:
        return ""

def which(cmd):
    return shutil.which(cmd) is not None

def default_gateway():
    sys = platform.system().lower()
    if sys == "linux":
        out = run(["bash", "-lc", "ip route show default 2>/dev/null | head -n 1"])
        return out
    if sys == "darwin":
        out = run(["bash", "-lc", "route -n get default 2>/dev/null | head -n 20"])
        return out
    if sys == "windows":
        out = run(["powershell","-NoProfile","-Command",
                   "(Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Sort-Object RouteMetric | Select-Object -First 1 | ConvertTo-Json -Depth 3)"])
        return out
    return ""

def neighbor_table():
    sys = platform.system().lower()
    if sys == "linux":
        return run(["bash","-lc","ip neigh show 2>/dev/null"])
    if sys == "darwin":
        return run(["bash","-lc","arp -a 2>/dev/null"])
    if sys == "windows":
        return run(["powershell","-NoProfile","-Command","arp -a"])
    return ""

def ping_sweep(cidr, limit=1024):
    net = ipaddress.ip_network(cidr, strict=False)
    hosts = list(net.hosts())
    if len(hosts) > limit:
        return {"error": f"Refusing sweep > {limit} hosts", "count": len(hosts)}

    sys = platform.system().lower()
    results = []
    for ip in hosts:
        ip_s = str(ip)
        if sys == "windows":
            cmd = ["powershell","-NoProfile","-Command", f"Test-Connection -Quiet -Count 1 -TimeoutSeconds 1 {ip_s}"]
            out = run(cmd, timeout=3)
            alive = out.strip().lower() == "true"
        else:
            # macOS uses -W in ms? Linux uses seconds; keep conservative and accept some false negatives.
            cmd = ["bash","-lc", f"ping -c 1 -W 1 {ip_s} >/dev/null 2>&1; echo $?"]
            out = run(cmd, timeout=3)
            alive = out.strip() == "0"
        if alive:
            results.append(ip_s)
    return {"alive": results, "count_alive": len(results), "cidr": cidr}

def nmap_scan(cidr):
    if not which("nmap"):
        return {"error": "nmap not installed"}
    out = run(["bash","-lc", f"nmap -sn {cidr}"], timeout=120)
    return {"raw": out}

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cidr", help="CIDR to scan (example: 192.168.50.0/24)")
    ap.add_argument("--ping-sweep", action="store_true", help="Ping sweep the CIDR (slow/noisy)")
    ap.add_argument("--nmap", action="store_true", help="If nmap exists, run nmap -sn CIDR")
    ap.add_argument("--out", default=None, help="Output JSON path")
    args = ap.parse_args()

    data = {
        "schema": "pplx_infra_netprobe_v1",
        "collected_at_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "host_platform": platform.platform(),
        "default_gateway_info": default_gateway(),
        "neighbor_table": neighbor_table(),
    }

    if args.cidr:
        data["target_cidr"] = args.cidr
        if args.ping_sweep:
            data["ping_sweep"] = ping_sweep(args.cidr)
        if args.nmap:
            data["nmap_ping_scan"] = nmap_scan(args.cidr)

    if args.out:
        out_path = Path(args.out)
    else:
        output_dir = Path("output")
        output_dir.mkdir(exist_ok=True)
        out_path = output_dir / "netprobe.json"

    out_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    print(str(out_path))

if __name__ == "__main__":
    main()

