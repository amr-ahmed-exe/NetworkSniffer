<div align="center">

# Network Sniffer

A professional network packet capture and analysis tool built with Python and Scapy. This project demonstrates core cybersecurity concepts including network traffic analysis, protocol dissection, and packet inspection.

![Python](https://img.shields.io/badge/Python-3.8%2B-blue?logo=python&logoColor=white)
![Scapy](https://img.shields.io/badge/Scapy-2.5%2B-green)
![License](https://img.shields.io/badge/License-MIT-yellow)

</div>

##  Table of Contents

- [Features](#-features)
- [Requirements](#-requirements)
- [Installation](#-installation)
- [Usage](#-usage)
- [Project Structure](#-project-structure)
- [Screenshots](#-screenshots)
- [How It Works](#-how-it-works)
- [License](#-license)

##  Features

- **Real-Time Packet Capture** — Capture live network traffic using Scapy's powerful sniffing engine
- **Multi-Layer Protocol Analysis** — Deep inspection of:
  - Layer 2: Ethernet (MAC addresses), ARP
  - Layer 3: IP (source/destination, TTL, protocol)
  - Layer 4: TCP (ports, flags), UDP (ports, length), ICMP (type, code)
  - Layer 7: DNS (queries, responses), HTTP (method, host, path)
- **Rich Terminal UI** — Beautiful, colourful display with per-protocol colour coding
- **Payload Inspection** — View raw packet data in HEX and ASCII formats
- **Flexible Filtering** — Predefined shortcuts (tcp, udp, dns, http…) and custom BPF expressions
- **Multiple Export Formats** — Save captures as PCAP, JSON, CSV, or text reports
- **Comprehensive Statistics** — Protocol distribution, top IPs, packets/sec, and more
- **Memory-Efficient** — Callback-based architecture prevents memory exhaustion

##  Requirements

| Requirement | Details |
|---|---|
| Python | 3.8 or higher |
| OS | Windows 10/11 (with Npcap), Linux, macOS |
| Privileges | Administrator/root required for packet capture |
| Npcap | Required on Windows — [Download here](https://npcap.com/) |

##  Installation

```bash
# 1. Clone the repository
git clone https://github.com/YOUR_USERNAME/CodeAlpha_NetworkSniffer.git
cd CodeAlpha_NetworkSniffer

# 2. Create a virtual environment (recommended)
python -m venv venv
source venv/bin/activate        # Linux/macOS
# venv\Scripts\activate         # Windows

# 3. Install dependencies
pip install -r requirements.txt
```

##  Usage

> **⚠ Important:** Run the terminal as **Administrator** (Windows) or with `sudo` (Linux/macOS).

### Basic Commands

```bash
# Capture 50 packets on the default interface
python -m sniffer.main -c 50

# Capture TCP packets for 30 seconds
python -m sniffer.main -f tcp -t 30

# Capture DNS queries only
python -m sniffer.main -f dns -c 20

# Capture on a specific interface
python -m sniffer.main -i "Wi-Fi" -c 30
```

### Export Options

```bash
# Export to JSON
python -m sniffer.main -c 30 --export json -o ./output

# Export to CSV
python -m sniffer.main -c 30 --export csv

# Export to PCAP (Wireshark-compatible)
python -m sniffer.main -c 30 --export pcap

# Export all formats
python -m sniffer.main -c 30 --export all -o ./output
```

### Utility Commands

```bash
# List available network interfaces
python -m sniffer.main --list-interfaces

# List predefined filter shortcuts
python -m sniffer.main --list-filters

# Hide payload details
python -m sniffer.main -c 20 --no-payload

# Show help
python -m sniffer.main --help
```

### Predefined Filters

| Shortcut | BPF Expression | Description |
|---|---|---|
| `tcp` | `tcp` | TCP packets only |
| `udp` | `udp` | UDP packets only |
| `icmp` | `icmp` | ICMP packets only |
| `dns` | `udp port 53 or tcp port 53` | DNS queries and responses |
| `http` | `tcp port 80` | HTTP traffic |
| `https` | `tcp port 443` | HTTPS traffic |
| `arp` | `arp` | ARP packets |
| `ssh` | `tcp port 22` | SSH connections |
| `ftp` | `tcp port 21` | FTP connections |
| `smtp` | `tcp port 25` | SMTP email traffic |
| `dhcp` | `udp port 67 or udp port 68` | DHCP traffic |

You can also use any custom BPF expression:

```bash
python -m sniffer.main -f "host 192.168.1.1 and tcp port 443"
```

##  Project Structure

```
CodeAlpha_NetworkSniffer/
├── README.md                  # Project documentation
├── requirements.txt           # Python dependencies
├── sniffer/
│   ├── main.py               # CLI entry point (argparse)
│   ├── capture.py            # Packet capture engine (scapy.sniff)
│   ├── analyzer.py           # Deep packet inspection & statistics
│   ├── display.py            # Rich terminal UI & formatting
│   ├── filters.py            # BPF filter management
│   └── export.py             # PCAP/JSON/CSV/TXT export
└── output/                    # Exported capture files
```

##  How It Works

1. **Capture Engine** (`capture.py`): Uses Scapy's `sniff()` with a callback function for real-time processing. Packets are captured using raw sockets, requiring elevated privileges.

2. **Packet Analyzer** (`analyzer.py`): Each captured packet is dissected layer by layer. The analyzer extracts structured information from Ethernet, IP, TCP/UDP/ICMP, DNS, HTTP, and ARP layers.

3. **Display Engine** (`display.py`): Uses the `rich` library to render colourful, formatted output. Each protocol has its own colour scheme, and payload data is shown in hex/ASCII panels.

4. **Filter System** (`filters.py`): Supports both predefined shortcuts and raw Berkeley Packet Filter (BPF) expressions. Filters are applied at the kernel level for optimal performance.

5. **Export System** (`export.py`): Captured data can be exported to multiple formats for further analysis in tools like Wireshark (PCAP), Excel (CSV), or custom scripts (JSON).

##  License

Copyright © 2026 **Amr Ahmed**. All Rights Reserved.

##  Acknowledgements

- [Scapy](https://scapy.net/) — Powerful packet manipulation library
- [Rich](https://rich.readthedocs.io/) — Beautiful terminal formatting
