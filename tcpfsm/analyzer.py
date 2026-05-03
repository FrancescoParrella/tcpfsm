from __future__ import annotations

from pathlib import Path

from .connection import Connection, ConnectionTracker
from .pcap_reader import read_pcap


def analyze(
    path: str | Path,
    half_open_timeout: float = 30.0,
) -> list[Connection]:
    """Parse *path* and return one Connection per TCP flow, in encounter order."""
    packets = list(read_pcap(path))
    if not packets:
        return []
    tracker = ConnectionTracker(half_open_timeout=half_open_timeout)
    for pkt in packets:
        tracker.feed(pkt)
    tracker.finalize(packets[-1].timestamp)
    return tracker.connections
