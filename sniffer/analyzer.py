"""
Analyzer Module
===============
Deep packet inspection utilities.  Each helper function accepts a single
Scapy packet and returns a structured dictionary of extracted fields.
"""

from datetime import datetime
from typing import Any, Optional

from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.http import HTTPRequest, HTTPResponse
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Packet, Raw


# ---------------------------------------------------------------------------
# Protocol number → human-readable label
# ---------------------------------------------------------------------------

_PROTO_MAP: dict[int, str] = {
    1:  "ICMP",
    6:  "TCP",
    17: "UDP",
    2:  "IGMP",
    47: "GRE",
    50: "ESP",
    51: "AH",
    58: "ICMPv6",
    89: "OSPF",
}


def _proto_label(proto_num: int) -> str:
    return _PROTO_MAP.get(proto_num, f"OTHER({proto_num})")


# ---------------------------------------------------------------------------
# TCP flag helpers
# ---------------------------------------------------------------------------

_TCP_FLAGS = {
    "F": "FIN",
    "S": "SYN",
    "R": "RST",
    "P": "PSH",
    "A": "ACK",
    "U": "URG",
    "E": "ECE",
    "C": "CWR",
}


def _decode_tcp_flags(flag_field) -> list[str]:
    """Return human-readable list of active TCP flags."""
    flags: list[str] = []
    flag_str = str(flag_field)
    for short, full in _TCP_FLAGS.items():
        if short in flag_str:
            flags.append(full)
    return flags


# ---------------------------------------------------------------------------
# Payload extraction
# ---------------------------------------------------------------------------

def _extract_payload(pkt: Packet, max_bytes: int = 200) -> Optional[dict[str, str]]:
    """Return the first *max_bytes* of raw payload as hex and ASCII."""
    if not pkt.haslayer(Raw):
        return None

    raw_data: bytes = bytes(pkt[Raw].load)[:max_bytes]
    hex_str = raw_data.hex(" ")
    ascii_str = "".join(chr(b) if 32 <= b < 127 else "." for b in raw_data)

    return {
        "hex":   hex_str,
        "ascii": ascii_str,
        "length": len(pkt[Raw].load),
    }


# ---------------------------------------------------------------------------
# Layer-specific analysers
# ---------------------------------------------------------------------------

def _analyse_ethernet(pkt: Packet) -> dict[str, str]:
    if pkt.haslayer(Ether):
        eth = pkt[Ether]
        return {
            "src_mac": eth.src,
            "dst_mac": eth.dst,
            "ether_type": hex(eth.type),
        }
    return {}


def _analyse_ip(pkt: Packet) -> dict[str, Any]:
    if pkt.haslayer(IP):
        ip = pkt[IP]
        return {
            "src_ip":   ip.src,
            "dst_ip":   ip.dst,
            "ttl":      ip.ttl,
            "ip_len":   ip.len,
            "proto_num": ip.proto,
            "protocol": _proto_label(ip.proto),
            "ip_id":    ip.id,
        }
    return {}


def _analyse_tcp(pkt: Packet) -> dict[str, Any]:
    if pkt.haslayer(TCP):
        tcp = pkt[TCP]
        return {
            "src_port":  tcp.sport,
            "dst_port":  tcp.dport,
            "seq":       tcp.seq,
            "ack":       tcp.ack,
            "flags":     _decode_tcp_flags(tcp.flags),
            "flags_raw": str(tcp.flags),
            "window":    tcp.window,
        }
    return {}


def _analyse_udp(pkt: Packet) -> dict[str, Any]:
    if pkt.haslayer(UDP):
        udp = pkt[UDP]
        return {
            "src_port": udp.sport,
            "dst_port": udp.dport,
            "udp_len":  udp.len,
        }
    return {}


def _analyse_icmp(pkt: Packet) -> dict[str, Any]:
    if pkt.haslayer(ICMP):
        icmp = pkt[ICMP]
        type_names = {
            0: "Echo Reply",
            3: "Destination Unreachable",
            5: "Redirect",
            8: "Echo Request",
            11: "Time Exceeded",
        }
        return {
            "icmp_type":  icmp.type,
            "icmp_code":  icmp.code,
            "icmp_label": type_names.get(icmp.type, f"Type {icmp.type}"),
        }
    return {}


def _analyse_dns(pkt: Packet) -> dict[str, Any]:
    if not pkt.haslayer(DNS):
        return {}

    dns = pkt[DNS]
    info: dict[str, Any] = {"dns_id": dns.id}

    # Query
    if dns.qd and pkt.haslayer(DNSQR):
        qr = pkt[DNSQR]
        info["dns_query"] = qr.qname.decode(errors="replace").rstrip(".")
        info["dns_qtype"] = qr.qtype

    # Answers
    if dns.an and pkt.haslayer(DNSRR):
        answers = []
        rr = dns.an
        for _ in range(dns.ancount):
            if rr is None:
                break
            answers.append({
                "name":  rr.rrname.decode(errors="replace").rstrip(".") if isinstance(rr.rrname, bytes) else str(rr.rrname),
                "rdata": rr.rdata.decode(errors="replace") if isinstance(rr.rdata, bytes) else str(rr.rdata),
                "ttl":   rr.ttl,
            })
            rr = rr.payload if hasattr(rr, "payload") and isinstance(rr.payload, DNSRR) else None
        info["dns_answers"] = answers

    return info


def _analyse_http(pkt: Packet) -> dict[str, Any]:
    info: dict[str, Any] = {}

    if pkt.haslayer(HTTPRequest):
        http = pkt[HTTPRequest]
        info["http_method"] = http.Method.decode(errors="replace") if isinstance(http.Method, bytes) else str(http.Method)
        info["http_host"]   = http.Host.decode(errors="replace") if isinstance(http.Host, bytes) else str(http.Host)
        info["http_path"]   = http.Path.decode(errors="replace") if isinstance(http.Path, bytes) else str(http.Path)

    if pkt.haslayer(HTTPResponse):
        http = pkt[HTTPResponse]
        info["http_status"] = http.Status_Code.decode(errors="replace") if isinstance(http.Status_Code, bytes) else str(http.Status_Code)

    return info


def _analyse_arp(pkt: Packet) -> dict[str, Any]:
    if pkt.haslayer(ARP):
        arp = pkt[ARP]
        op_map = {1: "ARP Request", 2: "ARP Reply"}
        return {
            "arp_op":     op_map.get(arp.op, f"op={arp.op}"),
            "arp_src_ip": arp.psrc,
            "arp_dst_ip": arp.pdst,
            "arp_src_mac": arp.hwsrc,
            "arp_dst_mac": arp.hwdst,
        }
    return {}


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def analyse_packet(pkt: Packet, packet_number: int = 0) -> dict[str, Any]:
    """Perform full dissection on *pkt* and return a flat info dictionary."""

    info: dict[str, Any] = {
        "number":    packet_number,
        "timestamp": datetime.fromtimestamp(float(pkt.time)).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
        "length":    len(pkt),
    }

    # Layer 2
    info.update(_analyse_ethernet(pkt))
    info.update(_analyse_arp(pkt))

    # Layer 3
    info.update(_analyse_ip(pkt))

    # Layer 4
    info.update(_analyse_tcp(pkt))
    info.update(_analyse_udp(pkt))
    info.update(_analyse_icmp(pkt))

    # Layer 7
    info.update(_analyse_dns(pkt))
    info.update(_analyse_http(pkt))

    # Determine the highest-level protocol label
    if "dns_query" in info or "dns_answers" in info:
        info["protocol"] = "DNS"
    elif "http_method" in info:
        info["protocol"] = "HTTP"
    elif "http_status" in info:
        info["protocol"] = "HTTP"
    elif "arp_op" in info:
        info["protocol"] = "ARP"

    # Payload
    payload = _extract_payload(pkt)
    if payload:
        info["payload"] = payload

    return info


# ---------------------------------------------------------------------------
# Statistics accumulator
# ---------------------------------------------------------------------------

class PacketStats:
    """Accumulates live statistics while packets are being captured."""

    def __init__(self) -> None:
        self.total_packets: int = 0
        self.total_bytes: int = 0
        self.protocol_counts: dict[str, int] = {}
        self.src_ip_counts: dict[str, int] = {}
        self.dst_ip_counts: dict[str, int] = {}
        self.src_port_counts: dict[int, int] = {}
        self.dst_port_counts: dict[int, int] = {}
        self.start_time: Optional[datetime] = None
        self.end_time: Optional[datetime] = None

    def update(self, info: dict[str, Any]) -> None:
        now = datetime.now()
        if self.start_time is None:
            self.start_time = now
        self.end_time = now

        self.total_packets += 1
        self.total_bytes += info.get("length", 0)

        proto = info.get("protocol", "UNKNOWN")
        self.protocol_counts[proto] = self.protocol_counts.get(proto, 0) + 1

        if "src_ip" in info:
            self.src_ip_counts[info["src_ip"]] = self.src_ip_counts.get(info["src_ip"], 0) + 1
        if "dst_ip" in info:
            self.dst_ip_counts[info["dst_ip"]] = self.dst_ip_counts.get(info["dst_ip"], 0) + 1
        if "src_port" in info:
            self.src_port_counts[info["src_port"]] = self.src_port_counts.get(info["src_port"], 0) + 1
        if "dst_port" in info:
            self.dst_port_counts[info["dst_port"]] = self.dst_port_counts.get(info["dst_port"], 0) + 1

    @property
    def duration_seconds(self) -> float:
        if self.start_time and self.end_time:
            return (self.end_time - self.start_time).total_seconds()
        return 0.0

    @property
    def top_src_ips(self) -> list[tuple[str, int]]:
        return sorted(self.src_ip_counts.items(), key=lambda x: x[1], reverse=True)[:10]

    @property
    def top_dst_ips(self) -> list[tuple[str, int]]:
        return sorted(self.dst_ip_counts.items(), key=lambda x: x[1], reverse=True)[:10]

    @property
    def top_src_ports(self) -> list[tuple[int, int]]:
        return sorted(self.src_port_counts.items(), key=lambda x: x[1], reverse=True)[:10]

    @property
    def top_dst_ports(self) -> list[tuple[int, int]]:
        return sorted(self.dst_port_counts.items(), key=lambda x: x[1], reverse=True)[:10]
