"""
Main Entry Point
=================
CLI interface for the CodeAlpha Network Sniffer.

Usage examples
--------------
    # Capture 50 packets on the default interface
    python -m sniffer.main -c 50

    # Capture TCP packets for 30 seconds
    python -m sniffer.main -f tcp -t 30

    # Capture DNS queries and export as JSON
    python -m sniffer.main -f dns -c 20 --export json

    # Capture everything and save as PCAP
    python -m sniffer.main -t 60 --export pcap -o ./output

    # List available network interfaces
    python -m sniffer.main --list-interfaces
"""

import argparse
import sys

from . import capture, display, filters


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="network-sniffer",
        description=(
            "CodeAlpha Network Sniffer - Capture and analyse network packets "
            "in real time with a rich terminal UI."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  %(prog)s -c 50                     Capture 50 packets\n"
            "  %(prog)s -f tcp -t 30               TCP only, 30-second timeout\n"
            "  %(prog)s -f dns -c 20 --export json DNS packets -> JSON\n"
            "  %(prog)s --export all -o ./output   All formats export\n"
            "  %(prog)s --list-interfaces           Show available interfaces\n"
            "  %(prog)s --list-filters              Show predefined filters\n"
        ),
    )

    # Capture parameters
    parser.add_argument(
        "-i", "--interface",
        type=str, default=None,
        help="Network interface to capture on (default: system default).",
    )
    parser.add_argument(
        "-c", "--count",
        type=int, default=0,
        help="Number of packets to capture. 0 = unlimited (default: 0).",
    )
    parser.add_argument(
        "-t", "--timeout",
        type=int, default=None,
        help="Stop capture after N seconds.",
    )

    # Filter
    parser.add_argument(
        "-f", "--filter",
        type=str, default=None,
        help=(
            "Packet filter -- either a predefined name (tcp, udp, icmp, dns, "
            "http, https, arp, ssh, ftp, smtp, dhcp) or a raw BPF expression."
        ),
    )

    # Display
    parser.add_argument(
        "--no-payload",
        action="store_true",
        help="Hide payload details for each packet.",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output.",
    )

    # Export
    parser.add_argument(
        "--export",
        type=str, default=None,
        choices=["pcap", "json", "csv", "txt", "all"],
        help="Export captured data in the specified format.",
    )
    parser.add_argument(
        "-o", "--output",
        type=str, default="./output",
        help="Output directory for exported files (default: ./output).",
    )

    # Info commands
    parser.add_argument(
        "--list-interfaces",
        action="store_true",
        help="List available network interfaces and exit.",
    )
    parser.add_argument(
        "--list-filters",
        action="store_true",
        help="List predefined BPF filter shortcuts and exit.",
    )

    return parser


def main(argv: list[str] | None = None) -> None:
    parser = _build_parser()
    args = parser.parse_args(argv)

    # ---- Info-only commands ---- #
    if args.list_interfaces:
        display.show_banner()
        capture.show_interfaces()
        return

    if args.list_filters:
        display.show_banner()
        display.show_info("Predefined BPF filter shortcuts:\n")
        for name, expr in filters.list_available_filters().items():
            display.console.print(f"    [bold cyan]{name:<10}[/bold cyan] -> [dim]{expr}[/dim]")
        display.console.print()
        return

    # ---- Resolve the BPF filter ---- #
    bpf = filters.resolve_filter(args.filter)

    # ---- Show banner ---- #
    display.show_banner()

    # ---- Start capture ---- #
    capture.start_capture(
        interface=args.interface,
        bpf_filter=bpf,
        count=args.count,
        timeout=args.timeout,
        show_payload=not args.no_payload,
        export_format=args.export,
        output_dir=args.output,
    )


if __name__ == "__main__":
    main()
