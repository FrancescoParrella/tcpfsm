from __future__ import annotations

import socket
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

import dpkt
import dpkt.sll

# DLT_LINUX_SLL = 113 (LINKTYPE_LINUX_SLL per libpcap spec).
# Older dpkt versions may not expose it as a named constant.
try:
    _DLT_LINUX_SLL: int = dpkt.pcap.DLT_LINUX_SLL  # type: ignore[attr-defined]
except AttributeError:
    _DLT_LINUX_SLL = 113


@dataclass
class Packet:
    timestamp:   float
    src_ip:      str
    src_port:    int
    dst_ip:      str
    dst_port:    int
    flags:       int
    seq:         int
    ack:         int
    window:      int
    payload_len: int   # bytes of TCP payload — payload itself is NOT stored
    index:       int   # 1-based position within the capture


# Backward-compatibility alias — analyzer.py imports TCPPacket
TCPPacket = Packet


def _ip_str(raw: bytes) -> str:
    return socket.inet_ntoa(raw)


def read_pcap(path: str | Path) -> Iterator[Packet]:
    """Yield Packet for every IPv4/TCP frame in the capture.

    Handles Ethernet (DLT_EN10MB) and Linux cooked capture (DLT_LINUX_SLL).
    Non-IPv4 and non-TCP frames are silently skipped.
    Malformed or truncated records emit a warning on stderr and are skipped.
    Raises FileNotFoundError if *path* does not exist.
    """
    path = Path(path)
    with open(path, "rb") as f:
        try:
            capture = dpkt.pcap.Reader(f)
        except Exception as exc:
            raise ValueError(f"Cannot open pcap '{path}': {exc}") from exc

        use_sll = (capture.datalink() == _DLT_LINUX_SLL)

        index = 0
        for ts, raw in capture:
            index += 1
            try:
                frame = dpkt.sll.SLL(raw) if use_sll else dpkt.ethernet.Ethernet(raw)
            except Exception as exc:
                print(
                    f"pcap_reader: warning: packet {index} at t={ts:.6f} "
                    f"malformed ({type(exc).__name__}: {exc})",
                    file=sys.stderr,
                )
                continue

            ip = getattr(frame, "data", None)
            if not isinstance(ip, dpkt.ip.IP):
                continue

            tcp = ip.data
            if not isinstance(tcp, dpkt.tcp.TCP):
                continue

            yield Packet(
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
