import io
import sys
from typing import Any, Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.columns import Columns
from rich.rule import Rule
from rich import box


# Force UTF-8 output on Windows to avoid cp1252 encoding errors
if sys.platform == "win32":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

console = Console(force_terminal=True)


# ---------------------------------------------------------------------------
# Colour palette per protocol
# ---------------------------------------------------------------------------

PROTO_STYLES: dict[str, str] = {
    "TCP":     "bold cyan",
    "UDP":     "bold green",
    "ICMP":    "bold yellow",
    "DNS":     "bold magenta",
    "HTTP":    "bold bright_red",
    "ARP":     "bold bright_yellow",
    "IGMP":    "bold blue",
    "UNKNOWN": "dim white",
}


def _style_for(proto: str) -> str:
    return PROTO_STYLES.get(proto, "dim white")


# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------

BANNER = """
[bold cyan]  +===========================================================+
  |                                                           |
  |                   [bold white]Network Sniffer v1.0[/bold white]                    |
  |                       [bold white]By Amr Ahmed[/bold white]                        |
  |                                                           |
  +===========================================================+
[/bold cyan]"""


def show_banner() -> None:
    console.print(BANNER)

def show_capture_config(
    interface: Optional[str],
    bpf_filter: Optional[str],
    count: Optional[int],
    timeout: Optional[int],
) -> None:
    """Print a nice summary panel of the capture parameters."""
    grid = Table(show_header=False, box=None, padding=(0, 2))
    grid.add_column(style="bold bright_cyan", min_width=14)
    grid.add_column()

    grid.add_row("Interface", interface or "default")
    grid.add_row("BPF Filter", bpf_filter or "none (capture all)")
    grid.add_row("Packet Count", str(count) if count else "unlimited")
    grid.add_row("Timeout", f"{timeout}s" if timeout else "unlimited")

    console.print(Panel(
        grid,
        title="[bold white][*] Capture Configuration[/bold white]",
        border_style="bright_cyan",
        padding=(1, 2),
    ))
    console.print()

# Live packet row
_live_table_created = False
_live_table: Optional[Table] = None


def print_packet_header() -> None:
    """Print the column header for live packet output."""
    header = Text()
    header.append(f"{'#':<6}", style="bold white")
    header.append(f"{'Time':<15}", style="bold white")
    header.append(f"{'Source':<22}", style="bold white")
    header.append(f"{'Destination':<22}", style="bold white")
    header.append(f"{'Proto':<8}", style="bold white")
    header.append(f"{'Len':>6}  ", style="bold white")
    header.append("Info", style="bold white")

    console.print(Rule(style="bright_cyan"))
    console.print(header)
    console.print(Rule(style="bright_cyan"))


def print_packet_row(info: dict[str, Any], show_payload: bool = True) -> None:
    """Print a single coloured row for a captured packet."""
    proto = info.get("protocol", "UNKNOWN")
    style = _style_for(proto)

    # Build the source and destination columns
    src = info.get("src_ip", info.get("arp_src_ip", "?"))
    dst = info.get("dst_ip", info.get("arp_dst_ip", "?"))

    if "src_port" in info:
        src = f"{src}:{info['src_port']}"
    if "dst_port" in info:
        dst = f"{dst}:{info['dst_port']}"

    # Build the info column
    info_parts: list[str] = []

    if "flags" in info:
        info_parts.append(f"[{' '.join(info['flags'])}]")
    if "icmp_label" in info:
        info_parts.append(info["icmp_label"])
    if "dns_query" in info:
        info_parts.append(f"Query: {info['dns_query']}")
    if "dns_answers" in info:
        for ans in info["dns_answers"][:2]:
            info_parts.append(f"-> {ans['rdata']}")
    if "http_method" in info:
        info_parts.append(f"{info['http_method']} {info.get('http_host', '')}{info.get('http_path', '')}")
    if "http_status" in info:
        info_parts.append(f"Status: {info['http_status']}")
    if "arp_op" in info:
        info_parts.append(f"{info['arp_op']} {info.get('arp_src_ip', '')} -> {info.get('arp_dst_ip', '')}")

    info_str = " | ".join(info_parts) if info_parts else ""

    # Timestamp — show only time portion
    ts = info.get("timestamp", "")
    time_short = ts.split(" ")[-1] if " " in ts else ts

    row = Text()
    row.append(f"{info.get('number', 0):<6}", style="bold white")
    row.append(f"{time_short:<15}", style="dim")
    row.append(f"{src:<22}", style=style)
    row.append(f"{dst:<22}", style=style)
    row.append(f"{proto:<8}", style=style)
    row.append(f"{info.get('length', 0):>6}  ", style="dim")
    row.append(info_str, style=style)

    console.print(row)

    # Optional payload panel
    if show_payload and "payload" in info:
        _print_payload_panel(info["payload"])


def _print_payload_panel(payload: dict[str, Any]) -> None:
    """Print a compact payload detail panel."""
    hex_display = payload.get("hex", "")
    ascii_display = payload.get("ascii", "")
    total_len = payload.get("length", 0)

    content = Text()
    content.append("HEX   | ", style="bold bright_cyan")
    content.append(hex_display[:80], style="dim green")
    if len(hex_display) > 80:
        content.append("...", style="dim")
    content.append("\n")
    content.append("ASCII | ", style="bold bright_cyan")
    content.append(ascii_display[:80], style="dim yellow")
    if len(ascii_display) > 80:
        content.append("...", style="dim")

    console.print(Panel(
        content,
        title=f"[dim]Payload ({total_len} bytes)[/dim]",
        border_style="dim cyan",
        padding=(0, 1),
        expand=False,
    ))


# Statistics display
def show_statistics(stats: Any) -> None:
    """Print a comprehensive statistics summary after capture ends."""
    console.print()
    console.print(Rule("[bold bright_cyan][#] Capture Statistics[/bold bright_cyan]", style="bright_cyan"))
    console.print()

    # ---- Overview ----
    overview = Table(show_header=False, box=None, padding=(0, 3))
    overview.add_column(style="bold bright_cyan", min_width=18)
    overview.add_column(style="bold white")
    overview.add_row("Total Packets", str(stats.total_packets))
    overview.add_row("Total Data", f"{stats.total_bytes:,} bytes")
    overview.add_row("Duration", f"{stats.duration_seconds:.1f} seconds")
    if stats.duration_seconds > 0:
        pps = stats.total_packets / stats.duration_seconds
        overview.add_row("Packets/sec", f"{pps:.1f}")

    console.print(Panel(overview, title="[bold white]Overview[/bold white]", border_style="bright_cyan", padding=(1, 2)))
    console.print()

    # ---- Protocol breakdown ----
    proto_table = Table(
        title="Protocol Breakdown",
        box=box.ROUNDED,
        border_style="bright_cyan",
        header_style="bold bright_white",
        title_style="bold bright_cyan",
    )
    proto_table.add_column("Protocol", style="bold", min_width=12)
    proto_table.add_column("Count", justify="right", style="bold white")
    proto_table.add_column("Percentage", justify="right")
    proto_table.add_column("Bar", min_width=30)

    for proto, count in sorted(stats.protocol_counts.items(), key=lambda x: x[1], reverse=True):
        pct = (count / stats.total_packets * 100) if stats.total_packets else 0
        bar_len = int(pct / 100 * 25)
        bar = "#" * bar_len + "." * (25 - bar_len)
        style = _style_for(proto)
        proto_table.add_row(
            Text(proto, style=style),
            str(count),
            f"{pct:.1f}%",
            Text(bar, style=style),
        )

    console.print(proto_table)
    console.print()

    # ---- Top IPs ----
    if stats.top_src_ips:
        ip_table = Table(
            title="Top Source IPs",
            box=box.SIMPLE_HEAVY,
            border_style="cyan",
            header_style="bold",
            title_style="bold cyan",
        )
        ip_table.add_column("IP Address", style="bright_green", min_width=18)
        ip_table.add_column("Packets", justify="right", style="bold white")

        for ip, count in stats.top_src_ips[:5]:
            ip_table.add_row(ip, str(count))

        console.print(ip_table)
        console.print()

    if stats.top_dst_ips:
        ip_table = Table(
            title="Top Destination IPs",
            box=box.SIMPLE_HEAVY,
            border_style="cyan",
            header_style="bold",
            title_style="bold cyan",
        )
        ip_table.add_column("IP Address", style="bright_red", min_width=18)
        ip_table.add_column("Packets", justify="right", style="bold white")

        for ip, count in stats.top_dst_ips[:5]:
            ip_table.add_row(ip, str(count))

        console.print(ip_table)

    console.print()
    console.print(Rule(style="bright_cyan"))


# Status messages
def show_start_message() -> None:
    console.print(
        "\n  [bold bright_green]>>  Sniffing started...[/bold bright_green]  "
        "[dim](Press Ctrl+C to stop)[/dim]\n"
    )


def show_stop_message(reason: str = "user interrupt") -> None:
    console.print(
        f"\n  [bold bright_red][X] Sniffing stopped[/bold bright_red]  "
        f"[dim]({reason})[/dim]\n"
    )


def show_export_message(fmt: str, path: str) -> None:
    console.print(
        f"  [bold bright_green][OK][/bold bright_green]  Exported {fmt.upper()} -> "
        f"[bold underline]{path}[/bold underline]"
    )


def show_error(msg: str) -> None:
    console.print(f"  [bold red][!] Error:[/bold red] {msg}")


def show_warning(msg: str) -> None:
    console.print(f"  [bold yellow][!] Warning:[/bold yellow] {msg}")


def show_info(msg: str) -> None:
    console.print(f"  [bold bright_cyan][i][/bold bright_cyan]  {msg}")
