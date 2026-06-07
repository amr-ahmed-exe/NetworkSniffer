"""
Filters Module
==============
Provides predefined BPF (Berkeley Packet Filter) expressions and
a helper to build or validate custom filter strings for Scapy's sniff().
"""

from typing import Optional


# ---------------------------------------------------------------------------
# Predefined BPF filter catalogue
# ---------------------------------------------------------------------------

PREDEFINED_FILTERS: dict[str, str] = {
    "tcp":   "tcp",
    "udp":   "udp",
    "icmp":  "icmp",
    "dns":   "udp port 53 or tcp port 53",
    "http":  "tcp port 80",
    "https": "tcp port 443",
    "arp":   "arp",
    "ssh":   "tcp port 22",
    "ftp":   "tcp port 21",
    "smtp":  "tcp port 25",
    "dhcp":  "udp port 67 or udp port 68",
}


def get_filter(name: str) -> Optional[str]:
    """Return a BPF string for a predefined filter *name* (case-insensitive).

    Returns ``None`` when *name* is not recognised.
    """
    return PREDEFINED_FILTERS.get(name.strip().lower())


def resolve_filter(user_input: Optional[str]) -> Optional[str]:
    """Accept either a predefined shortcut **or** a raw BPF expression.

    Resolution order:
    1. If *user_input* matches a key in ``PREDEFINED_FILTERS``, return its value.
    2. Otherwise treat *user_input* as a literal BPF expression and return it as-is.
    3. Return ``None`` when *user_input* is ``None`` or empty.
    """
    if not user_input:
        return None

    predefined = get_filter(user_input)
    if predefined is not None:
        return predefined

    # Assume the user typed a raw BPF expression (e.g. "host 192.168.1.1")
    return user_input.strip()


def list_available_filters() -> dict[str, str]:
    """Return a copy of the predefined-filter catalogue."""
    return dict(PREDEFINED_FILTERS)
