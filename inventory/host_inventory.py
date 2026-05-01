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

# --- Sensitive Data Redaction ---

# Patterns for keys/names that indicate sensitive values
SENSITIVE_KEY_PATTERNS = [
    # API keys and tokens
    r"api[_-]?key",
    r"apikey",
    r"api[_-]?secret",
    r"access[_-]?key",
    r"access[_-]?token",
    r"auth[_-]?token",
    r"bearer[_-]?token",
    r"token",
    # Passwords and secrets
    r"password",
    r"passwd",
    r"pwd",
    r"secret",
    r"credential",
    # Specific service keys
    r"openai[_-]?key",
    r"openai[_-]?api",
    r"anthropic[_-]?key",
    r"anthropic[_-]?api",
    r"azure[_-]?key",
    r"aws[_-]?secret",
    r"aws[_-]?access",
    r"gcp[_-]?key",
    r"google[_-]?api",
    r"stripe[_-]?key",
    r"stripe[_-]?secret",
    r"github[_-]?token",
    r"gitlab[_-]?token",
    r"slack[_-]?token",
    r"discord[_-]?token",
    r"twilio[_-]?",
    r"sendgrid[_-]?",
    r"mailgun[_-]?",
    # Database credentials
    r"db[_-]?pass",
    r"database[_-]?pass",
    r"mysql[_-]?pass",
    r"postgres[_-]?pass",
    r"redis[_-]?pass",
    r"mongo[_-]?pass",
    r"connection[_-]?string",
    # SSH and certificates
    r"ssh[_-]?key",
    r"private[_-]?key",
    r"priv[_-]?key",
    r"pem",
    r"cert[_-]?key",
    # Encryption
    r"encrypt[_-]?key",
    r"decrypt[_-]?key",
    r"signing[_-]?key",
    r"jwt[_-]?secret",
    # Generic
    r"auth",
    r"_key$",
    r"_secret$",
    r"_token$",
    r"_pass$",
    r"_password$",
]

# Compile patterns for efficiency
SENSITIVE_KEY_REGEX = re.compile(
    "|".join(SENSITIVE_KEY_PATTERNS),
    re.IGNORECASE
)

# Patterns for values that look like secrets (even without key context)
SENSITIVE_VALUE_PATTERNS = [
    # OpenAI API keys (including sk-proj-..., sk-..., etc.)
    r"sk-[a-zA-Z0-9\-_]{20,}",
    r"sk-proj-[a-zA-Z0-9\-_]{20,}",
    # Anthropic API keys
    r"sk-ant-[a-zA-Z0-9\-_]{20,}",
    # AWS access key IDs
    r"AKIA[0-9A-Z]{16}",
    # AWS secret keys (40 chars, alphanumeric + special)
    r"(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])",
    # GitHub tokens
    r"ghp_[a-zA-Z0-9]{36}",
    r"gho_[a-zA-Z0-9]{36}",
    r"ghu_[a-zA-Z0-9]{36}",
    r"ghs_[a-zA-Z0-9]{36}",
    r"ghr_[a-zA-Z0-9]{36}",
    # GitLab tokens
    r"glpat-[a-zA-Z0-9\-]{20}",
    # Slack tokens
    r"xox[baprs]-[a-zA-Z0-9\-]+",
    # Stripe keys
    r"sk_live_[a-zA-Z0-9]{24,}",
    r"sk_test_[a-zA-Z0-9]{24,}",
    r"pk_live_[a-zA-Z0-9]{24,}",
    r"pk_test_[a-zA-Z0-9]{24,}",
    # Generic long base64-ish secrets (32+ chars)
    r"(?<![A-Za-z0-9])[A-Za-z0-9+/]{32,}={0,2}(?![A-Za-z0-9])",
    # Bearer tokens
    r"Bearer\s+[a-zA-Z0-9\-_.]+",
    # Basic auth in URLs
    r"://[^:]+:[^@]+@",
]

SENSITIVE_VALUE_REGEX = re.compile(
    "|".join(SENSITIVE_VALUE_PATTERNS)
)

REDACTED_PLACEHOLDER = "[REDACTED]"


def is_sensitive_key(key):
    """Check if a key name indicates a sensitive value."""
    if not key:
        return False
    return bool(SENSITIVE_KEY_REGEX.search(str(key)))


def redact_sensitive_value(value, key=None):
    """
    Redact a value if it appears to be sensitive.
    If key is provided, check if the key indicates sensitivity.
    Also checks the value itself for known secret patterns.
    """
    if value is None:
        return value
    
    # If key indicates sensitivity, redact the whole value
    if key and is_sensitive_key(key):
        return REDACTED_PLACEHOLDER
    
    # Check if value itself looks like a secret
    value_str = str(value)
    if SENSITIVE_VALUE_REGEX.search(value_str):
        return REDACTED_PLACEHOLDER
    
    return value


def redact_dict(d, parent_key=None):
    """Recursively redact sensitive values in a dictionary."""
    if not isinstance(d, dict):
        return d
    
    result = {}
    for key, value in d.items():
        if isinstance(value, dict):
            result[key] = redact_dict(value, key)
        elif isinstance(value, list):
            result[key] = redact_list(value, key)
        elif isinstance(value, str):
            result[key] = redact_sensitive_value(value, key)
        else:
            result[key] = value
    return result


def redact_list(lst, parent_key=None):
    """Recursively redact sensitive values in a list."""
    if not isinstance(lst, list):
        return lst
    
    result = []
    for item in lst:
        if isinstance(item, dict):
            result.append(redact_dict(item, parent_key))
        elif isinstance(item, list):
            result.append(redact_list(item, parent_key))
        elif isinstance(item, str):
            # Handle environment variable format: KEY=VALUE
            if "=" in item and parent_key and "env" in str(parent_key).lower():
                parts = item.split("=", 1)
                if len(parts) == 2:
                    env_key, env_value = parts
                    if is_sensitive_key(env_key):
                        result.append(f"{env_key}={REDACTED_PLACEHOLDER}")
                    elif SENSITIVE_VALUE_REGEX.search(env_value):
                        result.append(f"{env_key}={REDACTED_PLACEHOLDER}")
                    else:
                        result.append(item)
                else:
                    result.append(item)
            else:
                result.append(redact_sensitive_value(item, parent_key))
        else:
            result.append(item)
    return result


def redact_yaml_content(yaml_text):
    """Redact sensitive values in YAML/docker-compose content."""
    if not yaml_text:
        return yaml_text
    
    lines = yaml_text.split("\n")
    result_lines = []
    
    for line in lines:
        # Match key: value patterns
        match = re.match(r'^(\s*)([^:]+):\s*(.*)$', line)
        if match:
            indent, key, value = match.groups()
            key_stripped = key.strip().strip('-').strip()
            value_stripped = value.strip()
            
            # Check if key indicates sensitivity
            if is_sensitive_key(key_stripped) and value_stripped:
                # Keep quotes if present
                if value_stripped.startswith('"') and value_stripped.endswith('"'):
                    result_lines.append(f'{indent}{key}: "{REDACTED_PLACEHOLDER}"')
                elif value_stripped.startswith("'") and value_stripped.endswith("'"):
                    result_lines.append(f"{indent}{key}: '{REDACTED_PLACEHOLDER}'")
                else:
                    result_lines.append(f'{indent}{key}: {REDACTED_PLACEHOLDER}')
            # Check if value looks like a secret
            elif SENSITIVE_VALUE_REGEX.search(value_stripped):
                result_lines.append(f'{indent}{key}: {REDACTED_PLACEHOLDER}')
            # Handle KEY=VALUE in environment sections
            elif "=" in value_stripped:
                env_match = re.match(r'^([A-Z_][A-Z0-9_]*)=(.*)$', value_stripped, re.IGNORECASE)
                if env_match:
                    env_key, env_value = env_match.groups()
                    if is_sensitive_key(env_key) or SENSITIVE_VALUE_REGEX.search(env_value):
                        result_lines.append(f'{indent}{key}: {env_key}={REDACTED_PLACEHOLDER}')
                    else:
                        result_lines.append(line)
                else:
                    result_lines.append(line)
            else:
                result_lines.append(line)
        else:
            # Check for standalone environment variables: - KEY=VALUE
            env_line_match = re.match(r'^(\s*-\s*)([A-Z_][A-Z0-9_]*)=(.*)$', line, re.IGNORECASE)
            if env_line_match:
                indent, env_key, env_value = env_line_match.groups()
                if is_sensitive_key(env_key) or SENSITIVE_VALUE_REGEX.search(env_value):
                    result_lines.append(f'{indent}{env_key}={REDACTED_PLACEHOLDER}')
                else:
                    result_lines.append(line)
            else:
                result_lines.append(line)
    
    return "\n".join(result_lines)


def redact_inventory_data(data):
    """
    Main function to redact sensitive information from the inventory data.
    Applies appropriate redaction to different sections.
    """
    if not isinstance(data, dict):
        return data
    
    result = {}
    
    for key, value in data.items():
        if key == "docker":
            # Special handling for Docker data
            result[key] = redact_docker_data(value)
        elif key in ("rendered_config", "compose_files"):
            # YAML content needs special handling
            if isinstance(value, dict):
                result[key] = {k: redact_yaml_content(v) for k, v in value.items()}
            elif isinstance(value, str):
                result[key] = redact_yaml_content(value)
            else:
                result[key] = value
        elif isinstance(value, dict):
            result[key] = redact_inventory_data(value)
        elif isinstance(value, list):
            result[key] = redact_list(value, key)
        else:
            result[key] = value
    
    return result


def redact_docker_data(docker_data):
    """Redact sensitive information from Docker inventory data."""
    if not docker_data:
        return docker_data
    
    if not isinstance(docker_data, dict):
        return docker_data
    
    result = {}
    
    for key, value in docker_data.items():
        if key == "compose_projects":
            result[key] = [redact_compose_project(p) for p in (value or [])]
        elif key == "standalone_containers_sample":
            result[key] = redact_list(value, key) if value else None
        else:
            result[key] = value
    
    return result


def redact_compose_project(project):
    """Redact sensitive information from a single compose project."""
    if not isinstance(project, dict):
        return project
    
    result = {}
    
    for key, value in project.items():
        if key == "rendered_config":
            result[key] = redact_yaml_content(value) if value else None
        elif key == "compose_files":
            if isinstance(value, dict):
                result[key] = {k: redact_yaml_content(v) for k, v in value.items()}
            else:
                result[key] = value
        elif key == "containers_inspect":
            result[key] = redact_containers_inspect(value)
        elif key == "ps":
            result[key] = redact_list(value, key) if value else None
        else:
            result[key] = value
    
    return result


def redact_containers_inspect(inspect_data):
    """Redact sensitive information from docker inspect output."""
    if not inspect_data:
        return inspect_data
    
    if isinstance(inspect_data, list):
        return [redact_container_inspect(c) for c in inspect_data]
    elif isinstance(inspect_data, dict):
        return redact_container_inspect(inspect_data)
    
    return inspect_data


def redact_container_inspect(container):
    """Redact a single container's inspect data - deep recursive redaction."""
    if not isinstance(container, dict):
        return container
    
    return redact_docker_dict_deep(container)


def redact_container_config(config):
    """Redact container Config section from docker inspect."""
    if not isinstance(config, dict):
        return config
    
    return redact_docker_dict_deep(config)


def redact_docker_dict_deep(d):
    """
    Deep recursive redaction for Docker inspect data.
    Handles Env lists at any nesting level.
    """
    if not isinstance(d, dict):
        return d
    
    result = {}
    
    for key, value in d.items():
        # Handle Env lists (environment variables)
        if key == "Env" or key.lower() == "env":
            if isinstance(value, list):
                result[key] = redact_env_list(value)
            else:
                result[key] = value
        # Handle nested dicts
        elif isinstance(value, dict):
            result[key] = redact_docker_dict_deep(value)
        # Handle lists (could contain dicts with Env)
        elif isinstance(value, list):
            result[key] = redact_docker_list_deep(value, key)
        # Handle string values - check for sensitive patterns
        elif isinstance(value, str):
            result[key] = redact_sensitive_value(value, key)
        else:
            result[key] = value
    
    return result


def redact_docker_list_deep(lst, parent_key=None):
    """
    Deep recursive redaction for lists in Docker data.
    """
    if not isinstance(lst, list):
        return lst
    
    result = []
    for item in lst:
        if isinstance(item, dict):
            result.append(redact_docker_dict_deep(item))
        elif isinstance(item, list):
            result.append(redact_docker_list_deep(item, parent_key))
        elif isinstance(item, str):
            # Handle environment variable format: KEY=VALUE
            if "=" in item:
                parts = item.split("=", 1)
                if len(parts) == 2:
                    env_key, env_value = parts
                    if is_sensitive_key(env_key) or SENSITIVE_VALUE_REGEX.search(env_value):
                        result.append(f"{env_key}={REDACTED_PLACEHOLDER}")
                    else:
                        result.append(item)
                else:
                    result.append(item)
            else:
                result.append(redact_sensitive_value(item, parent_key))
        else:
            result.append(item)
    
    return result


def redact_env_list(env_list):
    """Redact environment variables in a list of KEY=VALUE strings."""
    if not env_list:
        return env_list
    
    result = []
    for item in env_list:
        if isinstance(item, str) and "=" in item:
            parts = item.split("=", 1)
            if len(parts) == 2:
                env_key, env_value = parts
                if is_sensitive_key(env_key) or SENSITIVE_VALUE_REGEX.search(env_value):
                    result.append(f"{env_key}={REDACTED_PLACEHOLDER}")
                else:
                    result.append(item)
            else:
                result.append(item)
        else:
            result.append(item)
    
    return result


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
    info = {
        "platform": platform.system(),
        "platform_release": platform.release(),
        "platform_version": platform.version(),
        "machine": platform.machine(),
        "python": platform.python_version(),
    }
    
    # Enrich with /etc/os-release on Linux
    if info["platform"] == "Linux":
        try:
            os_release = Path("/etc/os-release").read_text()
            env = {}
            for line in os_release.splitlines():
                if "=" in line:
                    k, v = line.split("=", 1)
                    env[k] = v.strip('"')
            info["distro_id"] = env.get("ID")
            info["distro_name"] = env.get("PRETTY_NAME") or env.get("NAME")
            info["distro_version"] = env.get("VERSION_ID")
        except Exception:
            pass
            
    return info

def get_system_packages():
    """Get list of installed system packages (apt, rpm, brew, etc.)"""
    sys = platform.system().lower()
    pkgs = []
    
    if sys == "linux":
        # Debian/Ubuntu
        if which("dpkg-query"):
            # Name, Version, Architecture, Description (short)
            out = run("dpkg-query -W -f='${Package}|${Version}|${Architecture}|${Summary}\n'")
            if out:
                for line in out.splitlines():
                    parts = line.split("|")
                    if len(parts) >= 4:
                        pkgs.append({
                            "name": parts[0],
                            "version": parts[1],
                            "arch": parts[2],
                            "summary": parts[3],
                            "manager": "dpkg"
                        })
        # RHEL/CentOS/Fedora
        elif which("rpm"):
            out = run("rpm -qa --qf '%{NAME}|%{VERSION}-%{RELEASE}|%{ARCH}|%{SUMMARY}\n'")
            if out:
                for line in out.splitlines():
                    parts = line.split("|")
                    if len(parts) >= 4:
                        pkgs.append({
                            "name": parts[0],
                            "version": parts[1],
                            "arch": parts[2],
                            "summary": parts[3],
                            "manager": "rpm"
                        })
        # Arch Linux
        elif which("pacman"):
             out = run("pacman -Q")
             if out:
                 for line in out.splitlines():
                     parts = line.split()
                     if len(parts) >= 2:
                         pkgs.append({"name": parts[0], "version": parts[1], "manager": "pacman"})

        # Nix (on any Linux/macOS)
        if which("nix-env"):
            out = run("nix-env -q")
            if out:
                for line in out.splitlines():
                    if line.strip():
                        pkgs.append({"name": line.strip(), "manager": "nix-env"})
        
        # Nix Profile (newer CLI)
        if which("nix"):
            out = run("nix profile list --json")
            if out:
                try:
                    data = json.loads(out)
                    # Structure varies, but usually has 'elements'
                    elements = data.get("elements", [])
                    for el in elements:
                        # storePaths usually contains the name-version
                        paths = el.get("storePaths", [])
                        for p in paths:
                            # /nix/store/hash-name-version
                            name = Path(p).name
                            # strip hash (32 chars + 1 dash)
                            if len(name) > 33:
                                name = name[33:]
                            pkgs.append({"name": name, "manager": "nix-profile"})
                except: pass

    elif sys == "darwin":
        if which("brew"):
            out = run("brew list --versions")
            if out:
                for line in out.splitlines():
                    parts = line.split()
                    if len(parts) >= 2:
                        pkgs.append({
                            "name": parts[0],
                            "version": parts[1],
                            "manager": "brew"
                        })

    elif sys == "windows":
        # PowerShell Get-Package is slow and might not be available everywhere.
        # WinGet is better if available.
        if which("winget"):
            # winget list is interactive/slow, maybe skip for now or use basic powershell
            pass
        
        # Fallback to simple registry check via PowerShell
        out = run(["powershell", "-NoProfile", "-Command", 
                   "Get-ItemProperty HKLM:\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* | Select-Object DisplayName, DisplayVersion | ConvertTo-Json"])
        if out:
            try:
                items = parse_json_lenient(out)
                if isinstance(items, list):
                    for item in items:
                        if item.get("DisplayName"):
                            pkgs.append({
                                "name": item.get("DisplayName"),
                                "version": item.get("DisplayVersion"),
                                "manager": "registry"
                            })
            except: pass

    return pkgs or None

def get_system_services():
    """Get running system services"""
    sys = platform.system().lower()
    services = []

    if sys == "linux":
        if which("systemctl"):
            out = run("systemctl list-units --type=service --state=running --no-pager --no-legend")
            if out:
                for line in out.splitlines():
                    parts = line.split(None, 4)
                    if len(parts) >= 4:
                        services.append({
                            "name": parts[0],
                            "status": parts[2], # active
                            "state": parts[3], # running
                            "description": parts[4] if len(parts) > 4 else ""
                        })
    
    elif sys == "darwin":
        # launchctl list is cryptic, maybe just list loaded ones
        out = run("launchctl list")
        if out:
            for line in out.splitlines()[1:]: # skip header
                parts = line.split("\t")
                if len(parts) >= 3:
                    services.append({
                        "pid": parts[0],
                        "status": parts[1],
                        "name": parts[2]
                    })

    elif sys == "windows":
        out = run(["powershell", "-NoProfile", "-Command", 
                   "Get-Service | Where-Object {$_.Status -eq 'Running'} | Select-Object Name,DisplayName,Status | ConvertTo-Json"])
        if out:
            try:
                items = parse_json_lenient(out)
                if isinstance(items, list):
                    for item in items:
                        services.append({
                            "name": item.get("Name"),
                            "display_name": item.get("DisplayName"),
                            "status": "running"
                        })
            except: pass

    return services or None

def get_usb_devices():
    sys = platform.system().lower()
    devices = []

    if sys == "linux":
        if which("lsusb"):
            out = run("lsusb")
            # Bus 002 Device 001: ID 1d6b:0003 Linux Foundation 3.0 root hub
            for line in out.splitlines():
                m = re.search(r"ID\s+([0-9a-fA-F:]+)\s+(.*)", line)
                if m:
                    devices.append({
                        "id": m.group(1),
                        "name": m.group(2),
                        "raw": line
                    })
    
    elif sys == "darwin":
        out = run("system_profiler SPUSBDataType -json 2>/dev/null")
        if out:
            try:
                data = json.loads(out)
                # Recursive parsing might be needed, but let's try flat first level
                def parse_usb_items(items):
                    res = []
                    for item in items:
                        res.append({
                            "name": item.get("_name"),
                            "vendor": item.get("vendor_id"),
                            "product": item.get("product_id"),
                            "serial": item.get("serial_num")
                        })
                        if "_items" in item:
                            res.extend(parse_usb_items(item["_items"]))
                    return res
                
                devices = parse_usb_items(data.get("SPUSBDataType", []))
            except: pass

    elif sys == "windows":
        out = run(["powershell", "-NoProfile", "-Command",
                   "Get-PnpDevice -Class USB | Select-Object FriendlyName,Status,Manufacturer | ConvertTo-Json"])
        if out:
            try:
                items = parse_json_lenient(out)
                if isinstance(items, list):
                    for item in items:
                        devices.append({
                            "name": item.get("FriendlyName"),
                            "vendor": item.get("Manufacturer"),
                            "status": item.get("Status")
                        })
            except: pass

    return devices or None

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
    total_bytes = None
    
    # Try psutil first
    if psutil:
        try:
            vm = psutil.virtual_memory()
            total_bytes = int(vm.total)
        except Exception:
            pass
    
    # Linux fallback: read from /proc/meminfo
    if total_bytes is None and platform.system().lower() == "linux":
        try:
            meminfo = Path("/proc/meminfo").read_text()
            for line in meminfo.splitlines():
                if line.startswith("MemTotal:"):
                    # Format: "MemTotal:       131892224 kB"
                    parts = line.split()
                    if len(parts) >= 2:
                        kb = int(parts[1])
                        total_bytes = kb * 1024  # Convert kB to bytes
                    break
        except Exception:
            pass
    
    return {"total_bytes": total_bytes}

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

    # Fallback for Linux if psutil is missing or failed
    if not interfaces and sys == "linux":
        try:
            for p in Path("/sys/class/net").iterdir():
                ifname = p.name
                entry = {"mac": None, "ipv4": [], "ipv6": [], "is_up": None, "speed_mbps": None}
                
                # Read MAC
                try:
                    entry["mac"] = (p / "address").read_text().strip()
                except: pass
                
                # Read Operstate
                try:
                    st = (p / "operstate").read_text().strip()
                    entry["is_up"] = (st == "up")
                except: pass
                
                # Read Speed
                try:
                    sp = (p / "speed").read_text().strip()
                    entry["speed_mbps"] = int(sp) if sp.isdigit() else None
                except: pass
                
                # Read IPs via 'ip addr'
                ip_out = run(f"ip addr show {ifname}")
                if ip_out:
                    # inet 192.168.50.151/24 brd ...
                    for m in re.finditer(r"inet\s+([0-9.]+)/([0-9]+)", ip_out):
                        entry["ipv4"].append({"ip": m.group(1), "netmask": m.group(2)}) # netmask as CIDR
                    # inet6 fe80::.../64 scope link
                    for m in re.finditer(r"inet6\s+([0-9a-fA-F:]+)/([0-9]+)", ip_out):
                        entry["ipv6"].append({"ip": m.group(1), "netmask": m.group(2)})

                interfaces[ifname] = entry
        except Exception:
            pass

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

        # Raspberry Pi detection (Device Tree)
        if not info["name"]:
            try:
                # /sys/firmware/devicetree/base/model contains null-terminated string
                model_path = Path("/sys/firmware/devicetree/base/model")
                if model_path.exists():
                    model = model_path.read_text().strip('\x00')
                    if model:
                        info["vendor"] = "Raspberry Pi Foundation"
                        info["name"] = model
            except: pass

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

def get_network_hardware():
    sys = platform.system().lower()
    devices = []

    if sys == "linux":
        if which("lspci"):
            # -vmm: machine readable, verbose
            # -k: show kernel drivers (might not work well with -vmm in all versions, but let's try separate or just basic info)
            # We will stick to basic info from -vmm for reliability
            out = run("lspci -vmm")
            current_dev = {}
            for line in out.splitlines():
                if not line.strip():
                    if current_dev:
                        cls = current_dev.get("Class", "").lower()
                        if "network" in cls or "ethernet" in cls:
                            devices.append({
                                "vendor": current_dev.get("Vendor"),
                                "name": current_dev.get("Device"),
                                "pci_slot": current_dev.get("Slot"),
                                "type": current_dev.get("Class")
                            })
                    current_dev = {}
                else:
                    if ":" in line:
                        key, val = line.split(":", 1)
                        current_dev[key.strip()] = val.strip()
            
            # Catch last
            if current_dev:
                 cls = current_dev.get("Class", "").lower()
                 if "network" in cls or "ethernet" in cls:
                    devices.append({
                        "vendor": current_dev.get("Vendor"),
                        "name": current_dev.get("Device"),
                        "pci_slot": current_dev.get("Slot"),
                        "type": current_dev.get("Class")
                    })
        
        # Try to enrich with link speed from sysfs
        for dev in devices:
            slot = dev.get("pci_slot") # e.g. 04:00.0
            if slot:
                # Try to find /sys/bus/pci/devices/*slot*/net/*
                # We need to handle short slot vs long slot
                # Globbing is easiest
                try:
                    # We look for any directory ending in the slot ID
                    candidates = list(Path("/sys/bus/pci/devices").glob(f"*{slot}"))
                    if candidates:
                        pci_path = candidates[0]
                        net_dir = pci_path / "net"
                        if net_dir.exists():
                            # There should be one folder here usually, e.g. enp4s0
                            ifaces = list(net_dir.iterdir())
                            if ifaces:
                                iface_name = ifaces[0].name
                                dev["interface_name"] = iface_name
                                # Read speed
                                try:
                                    sp = (ifaces[0] / "speed").read_text().strip()
                                    if sp.isdigit():
                                        dev["current_link_speed_mbps"] = int(sp)
                                except: pass
                except: pass

    elif sys == "darwin":
        out = run("system_profiler SPNetworkDataType -json 2>/dev/null")
        if out:
            try:
                data = json.loads(out)
                items = data.get("SPNetworkDataType", [])
                for item in items:
                    # We want physical hardware info
                    if item.get("interface"):
                        devices.append({
                            "name": item.get("type"),
                            "hardware": item.get("hardware"),
                            "interface": item.get("interface"),
                            "vendor": "Apple" if "Airport" in item.get("type", "") else None
                        })
            except Exception:
                pass

    elif sys == "windows":
        out = run(["powershell", "-NoProfile", "-Command", 
                   "Get-NetAdapter | Select-Object Name,InterfaceDescription,DriverVersion,MacAddress,LinkSpeed | ConvertTo-Json"])
        if out:
            try:
                items = parse_json_lenient(out)
                if isinstance(items, dict): items = [items]
                if isinstance(items, list):
                    for item in items:
                        devices.append({
                            "name": item.get("Name"),
                            "description": item.get("InterfaceDescription"),
                            "driver_version": item.get("DriverVersion"),
                            "speed": item.get("LinkSpeed")
                        })
            except Exception:
                pass

    return devices or None

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

        # Collect original docker-compose.yml files
        compose_files_content = {}
        config_files_str = pr.get("ConfigFiles") or pr.get("configFiles")
        if config_files_str:
            # ConfigFiles is usually comma-separated
            paths = [p.strip() for p in config_files_str.split(",")]
            for p in paths:
                try:
                    path_obj = Path(p)
                    if path_obj.exists() and path_obj.is_file():
                        # Limit size to avoid huge files
                        content = path_obj.read_text(encoding="utf-8", errors="replace")
                        if len(content) > 100000:
                            content = content[:100000] + "\n... (truncated)"
                        compose_files_content[p] = content
                except Exception as e:
                    compose_files_content[p] = f"Error reading file: {e}"

        entry = {
            "project": name,
            "ls_record": pr,
            "ps": ps,
            "rendered_config": rendered_config,
            "compose_files": compose_files_content,
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
    ap.add_argument("--no-redact", action="store_true", help="Disable redaction of sensitive information")
    args = ap.parse_args()

    psutil = try_import_psutil()

    net_info = get_network(psutil)
    net_info["hardware"] = get_network_hardware()

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
        "network": net_info,
        "usb_devices": get_usb_devices(),
        "system_packages": get_system_packages(),
        "system_services": get_system_services(),
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

    # Apply redaction to remove sensitive information
    if not args.no_redact:
        data = redact_inventory_data(data)
        data["_redaction_applied"] = True

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

