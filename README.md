# Infra

This repository contains lightweight, cross-platform Python utilities designed to audit computer infrastructure and map network topology.

The primary goal is to generate consistent, detailed JSON snapshots of **Host Inventory** (Hardware, OS, Docker) and **Network Topology**. These snapshots are intended to be uploaded to an AI assistant (Perplexity) to provide accurate context for infrastructure design, debugging, and optimization advice.

## 📂 The Scripts

### 1. `host_inventory.py`

**Purpose:** Generates a detailed "identity card" for a specific machine.

* **System:** Hostname, OS version, Kernel, Uptime.
* **Hardware:** CPU model/cores, RAM, Physical Disks, and Mount points.
* **Network:** Interface IPs, MAC addresses, Default Gateway, DNS servers.
* **Services:** Listening ports (sample) to identify active services.
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
python3 net_probe.py --cidr 192.168.50.0/24 --ping-sweep
```

**Output:**
Generates a file named `output/netprobe.json`.

***

## 🧠 Workflow: Getting AI Advice

1. **Run** `host_inventory.py` on your key nodes (e.g., your NAS, your router/gateway, your main workstation).
2. **Run** `net_probe.py` to map the layout.
3. **Upload** the resulting `.json` files to your Perplexity Infrastructure Project.
4. **Prompt:**
    > "I have uploaded the inventory for my NAS (ae86) and my Network Probe data. Based on the current Docker containers running on ae86, how should I configure the network segmentation?"

***

## ⚠️ Security & Privacy Note

**Do not commit the generated JSON files to this repository.**

The `inventory-*.json` files contain sensitive information, including:

* Internal IP addresses.
* Environment variables (if they are hardcoded in your `docker-compose.yml` configs).
* MAC addresses.

These files are meant for **private analysis** only.
