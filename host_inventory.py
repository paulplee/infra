#!/usr/bin/env python3
import argparse
import datetime as dt
import json
import os
import platform
import re
import shutil
import socket
import subprocess
from pathlib import Path

# --- Helper Functions ---

def run(cmd, timeout=30):
    """Run a command safely and return stdout as text (or '' on failure)."""
    try:
        # shell=True if cmd is a string, False if list
        is_shell = isinstance(cmd, str)
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, shell=is_shell)
        if p.returncode == 0:
            return (p.stdout or "").strip()
        return (p.stdout or "").strip()
    except Exception:
        return ""

def which(cmd):
    return shutil.which(cmd) is not None

def try_import_psutil():
    try:
        import psutil  # type: ignore
        return psutil
    except Exception:
        return None

def parse_json_lenient(txt):
    """
    Parse JSON robustly:
    - Normal JSON array/object works.
    - If a tool prints JSON objects one-per-line (no commas), try to load line-by-line.
    """
    if not txt:
        return None
    txt = txt.strip()
    try:
        return json.loads(txt)
    except Exception:
        pass

    # Try JSON-per-line fallback (common in some Docker CLI versions)
    items = []
    for line in txt.splitlines():
        line = line.strip().rstrip(",")
        if not line:
            continue
        try:
            items.append(json.loads(line))
        except Exception:
            continue
    return items or None

# --- System Inventory Functions ---

def get_basic_identity():
    hostname = socket.gethostname()
    fqdn = socket.getfqdn()
    return {
        "hostname": hostname,
        "fqdn": fqdn if fqdn and fqdn != hostname else None,
        "user": os.environ.get("USERNAME") or os.environ.get("USER"),
    }

def get_os():
    return {
        "platform": platform.system(),
        "platform_release": platform.release(),
        "platform_version": platform.version(),
        "machine": platform.machine(),
        "python": platform.python_version(),
    }

def get_uptime_seconds(psutil):
    if not psutil:
        return None
    try:
        boot = dt.datetime.fromtimestamp(psutil.boot_time(), dt.timezone.utc)
        now = dt.datetime.now(dt.timezone.utc)
        return int((now - boot).total_seconds())
    except Exception:
        return None

def get_cpu(psutil):
    cpu = {
        "physical_cores": None,
        "logical_cores": None,
        "model": None,
    }
    if psutil:
        try:
            cpu["physical_cores"] = psutil.cpu_count(logical=False)
            cpu["logical_cores"] = psutil.cpu_count(logical=True)
        except Exception:
            pass

    sys = platform.system().lower()
    if sys == "linux":
        txt = run("lscpu | sed -n 's/^Model name:\\s*//p' | head -n 1")
        cpu["model"] = txt or None
    elif sys == "darwin":
        txt = run("sysctl -n machdep.cpu.brand_string")
        cpu["model"] = txt or None
    elif sys == "windows":
        txt = run(["powershell", "-NoProfile", "-Command", "(Get-CimInstance Win32_Processor | Select-Object -First 1 -ExpandProperty Name)"])
        cpu["model"] = txt or None

    return cpu

def get_memory(psutil):
    if not psutil:
        return {"total_bytes": None}
    try:
        vm = psutil.virtual_memory()
        return {"total_bytes": int(vm.total)}
    except Exception:
        return {"total_bytes": None}

def get_disks_and_mounts(psutil):
    disks = []
    mounts = []

    sys = platform.system().lower()
    if psutil:
        try:
            for part in psutil.disk_partitions(all=False):
                usage = None
                try:
                    u = psutil.disk_usage(part.mountpoint)
                    usage = {"total": int(u.total), "used": int(u.used), "free": int(u.free)}
                except Exception:
                    pass
                mounts.append({
                    "device": part.device,
                    "mountpoint": part.mountpoint,
                    "fstype": part.fstype,
                    "opts": part.opts,
                    "usage_bytes": usage,
                })
        except Exception:
            pass

    # Best-effort physical disk summary
    if sys == "linux":
        lsblk = run("lsblk -J -o NAME,MODEL,SERIAL,SIZE,TYPE,TRAN,ROTA,MOUNTPOINT,FSTYPE 2>/dev/null")
        if lsblk:
            try:
                obj = json.loads(lsblk)
                disks = obj.get("blockdevices", [])
            except Exception:
                pass
    elif sys == "darwin":
        sp = run("system_profiler SPStorageDataType -json 2>/dev/null")
        if sp:
            try:
                obj = json.loads(sp)
                disks = obj.get("SPStorageDataType", [])
            except Exception:
                pass
    elif sys == "windows":
        txt = run(["powershell", "-NoProfile", "-Command",
                   "Get-PhysicalDisk | Select FriendlyName,SerialNumber,MediaType,Size,BusType | ConvertTo-Json -Depth 3"])
        if txt:
            try:
                disks = json.loads(txt)
            except Exception:
                pass

    return {"physical_disks": disks or None, "mounts": mounts or None}

def get_network(psutil):
    sys = platform.system().lower()
    interfaces = {}
    if psutil:
        try:
            addrs = psutil.net_if_addrs()
            stats = psutil.net_if_stats()
            for ifname, addrlist in addrs.items():
                entry = {"mac": None, "ipv4": [], "ipv6": [], "is_up": None, "speed_mbps": None}
                st = stats.get(ifname)
                if st:
                    entry["is_up"] = bool(st.isup)
                    entry["speed_mbps"] = st.speed if st.speed >= 0 else None
                for a in addrlist:
                    fam = getattr(a.family, "name", str(a.family))
                    if "AF_LINK" in fam or "AF_PACKET" in fam:
                        entry["mac"] = a.address
                    elif a.family == socket.AF_INET:
                        entry["ipv4"].append({"ip": a.address, "netmask": a.netmask})
                    elif a.family == socket.AF_INET6:
                        entry["ipv6"].append({"ip": a.address, "netmask": a.netmask})
                interfaces[ifname] = entry
        except Exception:
            interfaces = {}

    # Default route + DNS (best-effort)
    default_gateway = None
    dns_servers = None

    if sys == "linux":
        gw = run("ip route show default 2>/dev/null | head -n 1")
        m = re.search(r"default via ([0-9.]+)", gw or "")
        default_gateway = m.group(1) if m else None
        resolv = run("cat /etc/resolv.conf 2>/dev/null | sed -n 's/^nameserver\\s\\+//p'")
        dns_servers = [x.strip() for x in resolv.splitlines() if x.strip()] if resolv else None
    elif sys == "darwin":
        gw = run("route -n get default 2>/dev/null | sed -n 's/^gateway: //p' | head -n 1")
        default_gateway = gw or None
        dns = run("scutil --dns 2>/dev/null | sed -n 's/.*nameserver\\[[0-9]\\+\\] : //p'")
        dns_servers = [x.strip() for x in dns.splitlines() if x.strip()] if dns else None
    elif sys == "windows":
        gw = run(["powershell", "-NoProfile", "-Command",
                  "(Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Sort-Object RouteMetric | Select-Object -First 1 -ExpandProperty NextHop)"])
        default_gateway = gw or None
        dns = run(["powershell", "-NoProfile", "-Command",
                   "(Get-DnsClientServerAddress -AddressFamily IPv4 | Select-Object -ExpandProperty ServerAddresses) -join \"`n\""])
        dns_servers = [x.strip() for x in dns.splitlines() if x.strip()] if dns else None

    return {
        "interfaces": interfaces or None,
        "default_gateway": default_gateway,
        "dns_servers": dns_servers,
    }

def get_gpu():
    sys = platform.system().lower()
    gpus = []
    software = {}

    if sys == "linux":
        # 1. Gather PCI devices (Base of Truth) via lspci
        # We use a map keyed by PCI slot to merge info from other tools
        pci_map = {} 
        
        if which("lspci"):
            # -vmm: machine readable, verbose
            out = run("lspci -vmm") 
            # Output is blocks separated by newlines.
            # Slot:	00:02.0
            # Class:	VGA compatible controller
            # Vendor:	Intel Corporation
            # Device:	UHD Graphics 620
            current_dev = {}
            for line in out.splitlines():
                if not line.strip():
                    if current_dev:
                        cls = current_dev.get("Class", "").lower()
                        if "vga" in cls or "3d" in cls or "display" in cls:
                            slot = current_dev.get("Slot")
                            if slot:
                                pci_map[slot] = {
                                    "name": current_dev.get("Device"),
                                    "vendor": current_dev.get("Vendor"),
                                    "pci_slot": slot,
                                    "type": "pci_device" # generic
                                }
                    current_dev = {}
                else:
                    if ":" in line:
                        key, val = line.split(":", 1)
                        current_dev[key.strip()] = val.strip()
            
            # Catch last block
            if current_dev:
                 cls = current_dev.get("Class", "").lower()
                 if "vga" in cls or "3d" in cls or "display" in cls:
                    slot = current_dev.get("Slot")
                    if slot:
                        pci_map[slot] = {
                            "name": current_dev.get("Device"),
                            "vendor": current_dev.get("Vendor"),
                            "pci_slot": slot,
                            "type": "pci_device"
                        }

        # 2. NVIDIA Enrichment
        if which("nvidia-smi"):
            try:
                # pci.bus_id gives 0000:01:00.0
                out = run("nvidia-smi --query-gpu=pci.bus_id,name,driver_version,memory.total --format=csv,noheader")
                if out:
                    for line in out.splitlines():
                        parts = [x.strip() for x in line.split(",")]
                        if len(parts) >= 4:
                            bus_id_long = parts[0] # e.g. 00000000:01:00.0
                            
                            # Try to match with pci_map keys (usually 01:00.0)
                            # We extract the last 3 parts: bus:device.function
                            match_slot = None
                            # Regex to find XX:YY.Z at the end
                            m = re.search(r"([0-9a-fA-F]{2}:[0-9a-fA-F]{2}\.[0-9a-fA-F]+)$", bus_id_long)
                            if m:
                                match_slot = m.group(1)
                            
                            entry = {
                                "name": parts[1],
                                "driver_version": parts[2],
                                "memory_total": parts[3],
                                "type": "nvidia",
                                "pci_slot": bus_id_long
                            }
                            
                            if match_slot and match_slot in pci_map:
                                pci_map[match_slot].update(entry)
                            else:
                                pci_map[bus_id_long] = entry
            except Exception:
                pass
        
        # 3. AMD ROCm Enrichment (Basic check)
        if which("rocm-smi"):
             # If rocm-smi works, we might assume AMD GPUs are present and driven by ROCm
             # Parsing rocm-smi is complex, but we can mark them if we find them in lspci
             # For now, just noting the software presence is often enough, 
             # but we could try to match if needed.
             pass

        gpus = list(pci_map.values())

        # 4. Software: CUDA, ROCm
        if which("nvcc"):
            out = run("nvcc --version")
            if out:
                m = re.search(r"release ([0-9.]+)", out)
                if m:
                    software["cuda_version"] = m.group(1)
        
        if which("rocminfo") or which("rocm-smi"):
             software["rocm_detected"] = True

    elif sys == "darwin":
        out = run("system_profiler SPDisplaysDataType -json 2>/dev/null")
        if out:
            try:
                data = json.loads(out)
                items = data.get("SPDisplaysDataType", [])
                for item in items:
                    gpus.append({
                        "name": item.get("sppci_model"),
                        "vendor": item.get("spdisplays_vendor"),
                        "memory": item.get("spdisplays_vram"),
                        "metal": item.get("spdisplays_metal"),
                    })
            except Exception:
                pass

    elif sys == "windows":
        out = run(["powershell", "-NoProfile", "-Command", 
                   "Get-CimInstance Win32_VideoController | Select-Object Name,DriverVersion,AdapterRAM | ConvertTo-Json"])
        if out:
            try:
                items = parse_json_lenient(out)
                if isinstance(items, dict): items = [items]
                if isinstance(items, list):
                    for item in items:
                        gpus.append({
                            "name": item.get("Name"),
                            "driver_version": item.get("DriverVersion"),
                            "memory_bytes": item.get("AdapterRAM")
                        })
            except Exception:
                pass
        
        if which("nvcc"):
             out = run("nvcc --version")
             if out:
                m = re.search(r"release ([0-9.]+)", out)
                if m:
                    software["cuda_version"] = m.group(1)

    return {"devices": gpus, "software": software} if (gpus or software) else None

def get_motherboard():
    sys = platform.system().lower()
    info = {"vendor": None, "name": None, "version": None}

    if sys == "linux":
        # Try /sys/class/dmi/id/ first (often readable without root)
        def read_dmi(fname):
            try:
                return Path(f"/sys/class/dmi/id/{fname}").read_text().strip()
            except Exception:
                return None
        
        info["vendor"] = read_dmi("board_vendor")
        info["name"] = read_dmi("board_name")
        info["version"] = read_dmi("board_version")

        # Fallback to system info if board info is missing (common on some VMs or laptops)
        if not info["vendor"]:
            info["vendor"] = read_dmi("sys_vendor")
        if not info["name"]:
            info["name"] = read_dmi("product_name")

    elif sys == "darwin":
        # macOS doesn't expose "motherboard" per se, but the system model is the closest equivalent
        # sysctl hw.model gives "MacBookPro16,1"
        model_id = run("sysctl -n hw.model")
        # system_profiler gives "MacBook Pro (16-inch, 2019)"
        # We can put Apple as vendor
        info["vendor"] = "Apple Inc."
        info["name"] = model_id
        
    elif sys == "windows":
        out = run(["powershell", "-NoProfile", "-Command", 
                   "Get-CimInstance Win32_BaseBoard | Select-Object Manufacturer,Product,Version | ConvertTo-Json"])
        if out:
            try:
                obj = parse_json_lenient(out)
                if isinstance(obj, list): obj = obj[0]
                if isinstance(obj, dict):
                    info["vendor"] = obj.get("Manufacturer")
                    info["name"] = obj.get("Product")
                    info["version"] = obj.get("Version")
            except Exception:
                pass

    return info

def get_virtualization_hints():
    hints = []
    if which("docker"): hints.append("docker")
    if which("podman"): hints.append("podman")
    if which("kubectl"): hints.append("kubernetes_client")
    return hints or None

def get_listening_ports():
    sys = platform.system().lower()
    if sys in ("linux", "darwin") and which("lsof"):
        out = run("lsof -nP -iTCP -sTCP:LISTEN 2>/dev/null | awk 'NR>1{print $1,$9}' | head -n 200")
        return out.splitlines() if out else None
    if sys == "linux" and which("ss"):
        out = run("ss -lntup 2>/dev/null | head -n 200")
        return out.splitlines() if out else None
    if sys == "windows":
        out = run(["powershell", "-NoProfile", "-Command",
                   "Get-NetTCPConnection -State Listen | Select-Object -First 200 LocalAddress,LocalPort,OwningProcess | ConvertTo-Json -Depth 3"])
        if out:
            try:
                return json.loads(out)
            except Exception:
                return None
    return None

# --- Docker Discovery Functions ---

def docker_cmd_base():
    # Prefer "docker compose" (v2). Fall back to "docker-compose" if present.
    if which("docker"):
        # If "docker compose version" works, use it.
        test = run(["docker", "compose", "version"])
        if test:
            return ["docker", "compose"]
    if which("docker-compose"):
        return ["docker-compose"]
    return None

def get_docker_summary(max_projects=30, max_containers=200, include_inspect=True):
    base = docker_cmd_base()
    if not base:
        return None

    docker_info = {
        "compose_projects": [],
        "standalone_containers_sample": None,
        "notes": [],
    }

    # 1. List Compose Projects
    # "docker compose ls --format json" exists in modern Compose.
    ls_txt = run(base + ["ls", "--format", "json"])
    projects = parse_json_lenient(ls_txt) if ls_txt else None
    if isinstance(projects, dict):
        projects = [projects]
    if not isinstance(projects, list):
        projects = []
    
    projects = projects[:max_projects]

    # 2. For each project, collect ps + config + optional inspect
    for pr in projects:
        # Field names vary by version (Name vs name vs Project)
        name = pr.get("Name") or pr.get("name") or pr.get("Project") or pr.get("project")
        if not name:
            continue

        # Collect 'ps'
        ps_txt = run(base + ["-p", name, "ps", "-a", "--format", "json"])
        ps = parse_json_lenient(ps_txt) if ps_txt else None
        if isinstance(ps, dict):
            ps = [ps]
        if not isinstance(ps, list):
            ps = []
        ps = ps[:max_containers]

        # Collect 'config' (rendered yaml) - useful but may contain secrets!
        cfg_txt = run(base + ["-p", name, "config"])
        rendered_config = cfg_txt[:200000] if cfg_txt else None  # Cap size at 200KB

        entry = {
            "project": name,
            "ls_record": pr,
            "ps": ps,
            "rendered_config": rendered_config,
            "containers_inspect": None,
        }

        # Optional: Inspect IDs found in ps
        if include_inspect and ps:
            ids = []
            for row in ps:
                cid = row.get("ID") or row.get("Id") or row.get("id")
                if cid:
                    ids.append(cid)
            ids = ids[:max_containers]

            if ids:
                insp_txt = run(["docker", "inspect"] + ids, timeout=60)
                entry["containers_inspect"] = parse_json_lenient(insp_txt)

        docker_info["compose_projects"].append(entry)

    # 3. Standalone "docker ps" (for non-compose containers)
    if which("docker"):
        ps_txt = run(["docker", "ps", "-a", "--no-trunc", "--format", "json"])
        docker_info["standalone_containers_sample"] = parse_json_lenient(ps_txt)

    return docker_info

# --- Main ---

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=None, help="Output JSON path (default: ./inventory-<hostname>.json)")
    ap.add_argument("--no-ports", action="store_true", help="Skip listening ports enumeration")
    ap.add_argument("--no-docker", action="store_true", help="Skip Docker enumeration")
    args = ap.parse_args()

    psutil = try_import_psutil()

    data = {
        "schema": "pplx_infra_inventory_v2",
        "collected_at_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "identity": get_basic_identity(),
        "os": get_os(),
        "uptime_seconds": get_uptime_seconds(psutil),
        "cpu": get_cpu(psutil),
        "memory": get_memory(psutil),
        "gpu": get_gpu(),
        "motherboard": get_motherboard(),
        "storage": get_disks_and_mounts(psutil),
        "network": get_network(psutil),
        "capabilities": get_virtualization_hints(),
    }

    if not args.no_ports:
        data["listening_ports_sample"] = get_listening_ports()

    # Auto-detect and run Docker collection
    if not args.no_docker:
        if which("docker") or which("docker-compose"):
            try:
                data["docker"] = get_docker_summary(include_inspect=True)
            except Exception as e:
                data["docker_error"] = str(e)

    hostname = data["identity"]["hostname"] or "unknown-host"
    if args.out:
        out_path = Path(args.out)
    else:
        output_dir = Path("output")
        output_dir.mkdir(exist_ok=True)
        out_path = output_dir / f"inventory-{hostname}.json"

    out_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    print(f"Inventory saved to: {out_path.absolute()}")

if __name__ == "__main__":
    main()

