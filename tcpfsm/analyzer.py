"""
analyzer — orchestrates pcap reading and connection reconstruction.

Normalizes 4-tuples so the initiator (SYN sender) is always first.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Optional

from .connection import Connection, ConnKey
from .pcap_reader import TCPPacket, read_pcap


def _normalize_key(pkt: TCPPacket, known_initiators: set[ConnKey]) -> tuple[ConnKey, bool]:
    """
    Return (canonical_key, from_initiator).

    The canonical key always has the initiator first.
    We determine the initiator by who sent the first SYN we've seen.
    If we haven't decided yet, the current packet's direction becomes the candidate.
    """
    forward: ConnKey = (pkt.src_ip, pkt.src_port, pkt.dst_ip, pkt.dst_port)
    reverse: ConnKey = (pkt.dst_ip, pkt.dst_port, pkt.src_ip, pkt.src_port)

    if forward in known_initiators:
        return forward, True
    if reverse in known_initiators:
        return reverse, False

    # First time we see this pair — if it's a SYN, register as initiator
    SYN = bool(pkt.flags & 0x02)
    ACK = bool(pkt.flags & 0x10)
    if SYN and not ACK:
        known_initiators.add(forward)
        return forward, True
    # Seen mid-connection (capture started after handshake); treat src as initiator
    known_initiators.add(forward)
    return forward, True


def analyze(path: str) -> list[Connection]:
    """Parse *path* and return a list of Connection objects, one per TCP flow."""
    packets = list(read_pcap(path))
    if not packets:
        return []

    connections: dict[ConnKey, Connection] = {}
    known_initiators: set[ConnKey] = set()
    conn_order: list[ConnKey] = []  # preserve encounter order

    for pkt in packets:
        key, from_initiator = _normalize_key(pkt, known_initiators)

        if key not in connections:
            idx = len(conn_order) + 1
            conn_order.append(key)
            connections[key] = Connection(key=key, index=idx)

        connections[key].process_packet(
            timestamp=pkt.timestamp,
            flags=pkt.flags,
            seq=pkt.seq,
            ack=pkt.ack,
            window=pkt.window,
            payload_len=pkt.payload_len,
            from_initiator=from_initiator,
            packet_index=pkt.index,
        )

    # Post-processing: check for half-open connections
    if packets:
        capture_end = packets[-1].timestamp
        for conn in connections.values():
            conn.check_half_open(capture_end)

    return [connections[k] for k in conn_order]
