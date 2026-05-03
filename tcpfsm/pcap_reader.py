"""
pcap_reader — parses a .pcap file with dpkt and yields normalized TCP packet records.

Only IPv4 TCP packets are processed; others are silently skipped.
"""

from __future__ import annotations

import socket
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

import dpkt


@dataclass
class TCPPacket:
    timestamp: float
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    flags: int
    seq: int
    ack: int
    window: int
    payload_len: int
    index: int          # 1-based packet index within the capture


def _ip_str(raw: bytes) -> str:
    return socket.inet_ntoa(raw)


def read_pcap(path: str | Path) -> Iterator[TCPPacket]:
    """Yield TCPPacket for every IPv4 TCP packet in the capture file."""
    path = Path(path)
    with open(path, "rb") as f:
        try:
            capture = dpkt.pcap.Reader(f)
        except Exception as exc:
            raise ValueError(f"Cannot open pcap file '{path}': {exc}") from exc

        index = 0
        for ts, raw in capture:
            index += 1
            try:
                eth = dpkt.ethernet.Ethernet(raw)
            except Exception:
                continue

            ip = getattr(eth, "data", None)
            if not isinstance(ip, dpkt.ip.IP):
                continue

            tcp = ip.data
            if not isinstance(tcp, dpkt.tcp.TCP):
                continue

            yield TCPPacket(
                timestamp=ts,
                src_ip=_ip_str(ip.src),
                src_port=tcp.sport,
                dst_ip=_ip_str(ip.dst),
                dst_port=tcp.dport,
                flags=tcp.flags,
                seq=tcp.seq,
                ack=tcp.ack,
                window=tcp.win,
                payload_len=len(tcp.data),
                index=index,
            )
