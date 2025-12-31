# Infra

This repository contains lightweight, cross-platform Python utilities designed to audit computer infrastructure and map network topology.

The primary goal is to generate consistent, detailed JSON snapshots of **Host Inventory** (Hardware, OS, Docker) and **Network Topology**. These snapshots are intended to be uploaded to an AI assistant (Perplexity) to provide accurate context for infrastructure design, debugging, and optimization advice.

## 📂 The Scripts

### 1. `host_inventory.py`

**Purpose:** Generates a detailed "identity card" for a specific machine.

* **System:** Hostname, OS version (including Distro details for Ubuntu/Debian/Raspbian), Kernel, Uptime.
* **Hardware:**
  * **Core:** Motherboard model/vendor, CPU model/cores, RAM.
  * **GPU:** Detailed probing for NVIDIA (Driver, VRAM), AMD, and Integrated graphics.
  * **Storage:** Physical Disks (NVMe/SATA) and Mount points.
  * **Network:** Physical NIC specs and negotiated Link Speed (e.g., 1Gbps, 10Gbps).
  * **Peripherals:** Connected USB devices.
* **Software:**
  * **Packages:** Full list of installed system packages (supports `apt`, `rpm`, `pacman`, `brew`, and `nix`).
  * **Services:** Active system services (systemd, launchd, Windows Services).
* **Network Config:** Interface IPs, MAC addresses, Default Gateway, DNS servers.
* **Docker:** (If detected) Lists all Compose projects, running containers, and renders `docker-compose` configurations for deep context.

### 2. `net_probe.py`

**Purpose:** Scans the local network to build a topology map.

* **Discovery:** Dumps the ARP/Neighbor table to see who the host is talking to.
* **Sweep:** Optional Ping Sweep to find active IPs in a subnet.
* **Nmap:** Optional integration with `nmap` (if installed) for deeper scanning.

***

## 🚀 Setup & Requirements

These scripts are designed to be "drop-in" and run on **Linux**, **macOS**, and **Windows**.

### Prerequisites

* **Python 3.9+**
* (Optional) **Nmap**: For advanced network scanning in `net_probe.py`.

### Installation

Clone the repo and install the optional dependency `psutil` (highly recommended for accurate disk/network stats, though the scripts will run without it).

***

## 📖 Usage

### Collecting Host Inventory

Run this on **every machine** you want to document (Servers, NAS, Dev Laptops).

**Linux / macOS:**

```bash
sudo python3 host_inventory.py
```

*(Note: `sudo` is recommended on Linux to see all listening ports and Docker details)*

**Windows (PowerShell):**

```powershell
python host_inventory.py
```

**Output:**
Generates a file named `output/inventory-<hostname>.json`.

***

### Mapping Network Topology

Run this from a machine inside the network you want to map.

**Basic Neighbor Check:**

```bash
python3 net_probe.py
```

**Active Subnet Scan (Ping Sweep):**
*Replace the CIDR with your actual subnet (e.g., 192.168.1.0/24 or 10.10.1.0/24)*

```bash
# Scan home LAN
python3 net_probe.py --cidr 192.168.50.0/24 --ping-sweep

# Scan office
python3 net_probe.py --cidr 10.10.1.0/24 --nmap
```

**Output:**
Generates a file named `output/netprobe.json`.

### 3. `unifi_inventory.py`

**Purpose:** Extracts deep network configuration from a Ubiquiti UniFi Controller (UDM Pro, Cloud Key, etc.).

* **Topology:** Lists all UniFi devices (Switches, APs) and connected clients.
* **Configuration:** Dumps VLANs, Subnets, and WiFi settings.
* **Security:** Exports all Firewall Rules and Groups.

**Usage:**
You need a local user on your UDM (Settings -> System -> Admins -> Add New Admin -> Local Access Only).

```bash
python3 unifi_inventory.py --url https://192.168.1.1 --user <username> --password <password>
```

**Output:**
Generates a file named `output/unifi-inventory.json`.

***

## 🧠 Workflow: Getting AI Advice

1. **Run** `host_inventory.py` on your key nodes.
2. **Run** `unifi_inventory.py` to get the ground truth of your network config.
3. **Run** `net_probe.py` to verify what is actually reachable.
4. **Upload** the resulting `.json` files to your Perplexity Infrastructure Project.
5. **Prompt:**
    > "I have uploaded my UniFi config and host inventory. Are my firewall rules correctly isolating the IoT VLAN from my NAS?"

***

## ⚠️ Security & Privacy Note

**Do not commit the generated JSON files to this repository.**

The `inventory-*.json` files contain sensitive information, including:

* Internal IP addresses.
* Environment variables (if they are hardcoded in your `docker-compose.yml` configs).
* MAC addresses.

These files are meant for **private analysis** only.
