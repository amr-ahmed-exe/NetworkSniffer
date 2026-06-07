"""
Export Module
=============
Export captured packet data to various file formats:
  - PCAP  (Wireshark-compatible)
  - JSON  (detailed per-packet analysis)
  - CSV   (tabular summary)
  - TXT   (human-readable statistics report)
"""

import csv
import json
import os
from datetime import datetime
from typing import Any

from scapy.utils import wrpcap
from scapy.packet import Packet


def _ensure_dir(path: str) -> None:
    """Create the output directory if it does not exist."""
    os.makedirs(path, exist_ok=True)


def _timestamped_name(base: str, ext: str) -> str:
    """Return a file name like ``base_20250607_143210.ext``."""
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    return f"{base}_{ts}.{ext}"


# ---------------------------------------------------------------------------
# PCAP export
# ---------------------------------------------------------------------------

def export_pcap(packets: list[Packet], output_dir: str = "./output") -> str:
    """Write raw packets to a PCAP file.  Returns the output path."""
    _ensure_dir(output_dir)
    filename = _timestamped_name("capture", "pcap")
    filepath = os.path.join(output_dir, filename)
    wrpcap(filepath, packets)
    return filepath


# ---------------------------------------------------------------------------
# JSON export
# ---------------------------------------------------------------------------

def export_json(analysed: list[dict[str, Any]], output_dir: str = "./output") -> str:
    """Write analysed packet dictionaries to a JSON file."""
    _ensure_dir(output_dir)
    filename = _timestamped_name("capture", "json")
    filepath = os.path.join(output_dir, filename)

    # Make sure every value is JSON-serialisable
    def _sanitise(obj: Any) -> Any:
        if isinstance(obj, bytes):
            return obj.hex()
        if isinstance(obj, (set, frozenset)):
            return list(obj)
        return obj

    with open(filepath, "w", encoding="utf-8") as fh:
        json.dump(analysed, fh, indent=2, default=_sanitise, ensure_ascii=False)

    return filepath


# ---------------------------------------------------------------------------
# CSV export
# ---------------------------------------------------------------------------

_CSV_COLUMNS = [
    "number",
    "timestamp",
    "src_ip",
    "dst_ip",
    "protocol",
    "src_port",
    "dst_port",
    "length",
    "flags_raw",
    "dns_query",
    "http_method",
    "http_host",
    "http_path",
    "icmp_label",
    "arp_op",
]


def export_csv(analysed: list[dict[str, Any]], output_dir: str = "./output") -> str:
    """Write a summary CSV with one row per packet."""
    _ensure_dir(output_dir)
    filename = _timestamped_name("capture", "csv")
    filepath = os.path.join(output_dir, filename)

    with open(filepath, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=_CSV_COLUMNS, extrasaction="ignore")
        writer.writeheader()
        for row in analysed:
            # Flatten list fields for CSV
            flat = dict(row)
            if "flags" in flat and isinstance(flat["flags"], list):
                flat["flags_raw"] = " ".join(flat["flags"])
            writer.writerow(flat)

    return filepath


# ---------------------------------------------------------------------------
# TXT report
# ---------------------------------------------------------------------------

def export_txt_report(
    stats: Any,
    output_dir: str = "./output",
) -> str:
    """Write a human-readable text report of the capture statistics."""
    _ensure_dir(output_dir)
    filename = _timestamped_name("report", "txt")
    filepath = os.path.join(output_dir, filename)

    lines: list[str] = []
    lines.append("=" * 60)
    lines.append("  CodeAlpha Network Sniffer — Capture Report")
    lines.append("=" * 60)
    lines.append("")
    lines.append(f"  Total Packets : {stats.total_packets}")
    lines.append(f"  Total Bytes   : {stats.total_bytes:,}")
    lines.append(f"  Duration      : {stats.duration_seconds:.1f} seconds")
    lines.append("")

    # Protocol breakdown
    lines.append("  Protocol Breakdown")
    lines.append("  " + "-" * 40)
    for proto, count in sorted(stats.protocol_counts.items(), key=lambda x: x[1], reverse=True):
        pct = (count / stats.total_packets * 100) if stats.total_packets else 0
        bar = "#" * int(pct / 2)
        lines.append(f"  {proto:<12} {count:>6}  ({pct:5.1f}%)  {bar}")
    lines.append("")

    # Top source IPs
    lines.append("  Top Source IPs")
    lines.append("  " + "-" * 40)
    for ip, count in stats.top_src_ips:
        lines.append(f"  {ip:<20} {count:>6} packets")
    lines.append("")

    # Top destination IPs
    lines.append("  Top Destination IPs")
    lines.append("  " + "-" * 40)
    for ip, count in stats.top_dst_ips:
        lines.append(f"  {ip:<20} {count:>6} packets")
    lines.append("")
    lines.append("=" * 60)

    with open(filepath, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))

    return filepath
