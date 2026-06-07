"""
Capture Module
==============
Packet capture engine wrapping Scapy's ``sniff()`` with memory-safe
callback processing, interface selection, and graceful shutdown.
"""

import sys
from typing import Any, Callable, Optional

from scapy.all import conf, get_if_list, sniff
from scapy.packet import Packet

from . import analyzer, display, filters


def list_interfaces() -> list[str]:
    """Return a list of available network interfaces."""
    try:
        return get_if_list()
    except Exception:
        return []


def show_interfaces() -> None:
    """Print available network interfaces to the console."""
    ifaces = list_interfaces()
    if not ifaces:
        display.show_warning("No network interfaces found.")
        return

    display.show_info("Available network interfaces:")
    for idx, iface in enumerate(ifaces, 1):
        display.console.print(f"    [bold cyan]{idx}.[/bold cyan] {iface}")
    display.console.print()


def start_capture(
    interface: Optional[str] = None,
    bpf_filter: Optional[str] = None,
    count: int = 0,
    timeout: Optional[int] = None,
    show_payload: bool = True,
    export_format: Optional[str] = None,
    output_dir: str = "./output",
) -> dict[str, Any]:
    """
    Start capturing packets and processing them in real time.

    Parameters
    ----------
    interface : str, optional
        Network interface to capture on.  ``None`` → default interface.
    bpf_filter : str, optional
        Already-resolved BPF filter string.
    count : int
        Number of packets to capture (0 = unlimited until Ctrl-C).
    timeout : int, optional
        Capture duration in seconds.
    show_payload : bool
        Whether to print payload details for each packet.
    export_format : str, optional
        Format to export after capture: ``pcap``, ``json``, ``csv``, or ``all``.
    output_dir : str
        Directory for exported files.

    Returns
    -------
    dict with keys ``stats`` (:class:`analyzer.PacketStats`),
    ``packets`` (list of raw packets), and ``analysed`` (list of dicts).
    """

    stats = analyzer.PacketStats()
    captured_packets: list[Packet] = []
    analysed_packets: list[dict[str, Any]] = []
    packet_counter = {"n": 0}

    # ---- Per-packet callback (invoked by scapy.sniff) ---- #
    def _on_packet(pkt: Packet) -> None:
        packet_counter["n"] += 1
        info = analyzer.analyse_packet(pkt, packet_number=packet_counter["n"])
        stats.update(info)

        # Store for possible export
        captured_packets.append(pkt)
        analysed_packets.append(info)

        # Live display
        display.print_packet_row(info, show_payload=show_payload)

    # ---- Show configuration ---- #
    display.show_capture_config(interface, bpf_filter, count or None, timeout)
    display.print_packet_header()
    display.show_start_message()

    # ---- Run the sniffer ---- #
    try:
        sniff_kwargs: dict[str, Any] = {
            "prn":   _on_packet,
            "store": False,       # we store manually to control memory
        }
        if interface:
            sniff_kwargs["iface"] = interface
        if bpf_filter:
            sniff_kwargs["filter"] = bpf_filter
        if count and count > 0:
            sniff_kwargs["count"] = count
        if timeout and timeout > 0:
            sniff_kwargs["timeout"] = timeout

        sniff(**sniff_kwargs)

        if count and count > 0:
            display.show_stop_message(f"captured {count} packets")
        elif timeout:
            display.show_stop_message(f"timeout after {timeout}s")
        else:
            display.show_stop_message()

    except KeyboardInterrupt:
        display.show_stop_message("user interrupt (Ctrl+C)")
    except PermissionError:
        display.show_error(
            "Permission denied! Run the sniffer with Administrator/root privileges."
        )
        sys.exit(1)
    except OSError as exc:
        display.show_error(f"OS error during capture: {exc}")
        display.show_warning(
            "On Windows make sure Npcap is installed: https://npcap.com/"
        )
        sys.exit(1)

    # ---- Statistics ---- #
    if stats.total_packets > 0:
        display.show_statistics(stats)
    else:
        display.show_warning("No packets captured.")

    # ---- Export ---- #
    if export_format and stats.total_packets > 0:
        _do_export(export_format, captured_packets, analysed_packets, stats, output_dir)

    return {
        "stats":    stats,
        "packets":  captured_packets,
        "analysed": analysed_packets,
    }


def _do_export(
    fmt: str,
    packets: list[Packet],
    analysed: list[dict[str, Any]],
    stats: analyzer.PacketStats,
    output_dir: str,
) -> None:
    """Handle the export step based on the requested format."""
    from . import export as exp

    fmt = fmt.strip().lower()
    formats = [fmt] if fmt != "all" else ["pcap", "json", "csv", "txt"]

    for f in formats:
        try:
            if f == "pcap":
                path = exp.export_pcap(packets, output_dir)
            elif f == "json":
                path = exp.export_json(analysed, output_dir)
            elif f == "csv":
                path = exp.export_csv(analysed, output_dir)
            elif f == "txt":
                path = exp.export_txt_report(stats, output_dir)
            else:
                display.show_warning(f"Unknown export format: {f}")
                continue
            display.show_export_message(f, path)
        except Exception as exc:
            display.show_error(f"Failed to export {f}: {exc}")
