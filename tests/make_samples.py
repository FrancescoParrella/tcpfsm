"""
Generate synthetic .pcap sample files for testing.
Run once: python -m tests.make_samples
"""

import struct
import os
from pathlib import Path

SAMPLES_DIR = Path(__file__).parent / "samples"


def _pcap_global_header() -> bytes:
    # magic, version major/minor, thiszone, sigfigs, snaplen, network (1=Ethernet)
    return struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)


def _pcap_record(ts_sec: int, ts_usec: int, data: bytes) -> bytes:
    n = len(data)
    return struct.pack("<IIII", ts_sec, ts_usec, n, n) + data


def _eth_ip_tcp(
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    flags: int,
    seq: int,
    ack: int,
    window: int = 65535,
    payload: bytes = b"",
) -> bytes:
    import socket

    src_mac = b"\x00\x01\x02\x03\x04\x05"
    dst_mac = b"\x00\x0a\x0b\x0c\x0d\x0e"

    # TCP header (20 bytes, no options)
    tcp_hdr = struct.pack(
        "!HHIIBBHHH",
        src_port, dst_port,
        seq, ack,
        0x50,       # data offset = 5 (20 bytes), reserved
        flags,
        window,
        0,          # checksum (0 = unchecked by dpkt)
        0,          # urgent
    )
    tcp_seg = tcp_hdr + payload

    src_raw = socket.inet_aton(src_ip)
    dst_raw = socket.inet_aton(dst_ip)
    ip_len = 20 + len(tcp_seg)

    # IP header (20 bytes, no options)
    ip_hdr = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,       # version=4, IHL=5
        0,          # DSCP/ECN
        ip_len,
        0,          # id
        0,          # flags/fragment offset
        64,         # TTL
        6,          # protocol = TCP
        0,          # checksum
        src_raw,
        dst_raw,
    )
    ip_pkt = ip_hdr + tcp_seg

    # Ethernet frame: dst_mac + src_mac + ethertype 0x0800
    eth_frame = dst_mac + src_mac + b"\x08\x00" + ip_pkt
    return eth_frame


# Flag constants
SYN     = 0x02
ACK     = 0x10
SYN_ACK = 0x12
FIN     = 0x01
FIN_ACK = 0x11
RST     = 0x04
RST_ACK = 0x14


def write_pcap(filename: str, records: list[tuple[int, int, bytes]]) -> None:
    path = SAMPLES_DIR / filename
    with open(path, "wb") as f:
        f.write(_pcap_global_header())
        for ts_sec, ts_usec, data in records:
            f.write(_pcap_record(ts_sec, ts_usec, data))
    print(f"Wrote {path}")


def make_clean_handshake() -> None:
    """Clean 3-way handshake, data exchange, and graceful 4-way close."""
    C, S = "10.0.0.1", "10.0.0.2"
    CP, SP = 54321, 80
    records = [
        # Handshake
        (1, 0,      _eth_ip_tcp(C, S, CP, SP, SYN,     seq=1000, ack=0)),
        (1, 100000, _eth_ip_tcp(S, C, SP, CP, SYN_ACK, seq=2000, ack=1001)),
        (1, 200000, _eth_ip_tcp(C, S, CP, SP, ACK,     seq=1001, ack=2001)),
        # Data
        (1, 300000, _eth_ip_tcp(C, S, CP, SP, ACK,     seq=1001, ack=2001, payload=b"GET / HTTP/1.0\r\n")),
        (1, 400000, _eth_ip_tcp(S, C, SP, CP, ACK,     seq=2001, ack=1017, payload=b"HTTP/1.0 200 OK\r\n")),
        # Graceful close (active close by client)
        (2, 0,      _eth_ip_tcp(C, S, CP, SP, FIN_ACK, seq=1017, ack=2018)),
        (2, 100000, _eth_ip_tcp(S, C, SP, CP, ACK,     seq=2018, ack=1018)),
        (2, 200000, _eth_ip_tcp(S, C, SP, CP, FIN_ACK, seq=2018, ack=1018)),
        (2, 300000, _eth_ip_tcp(C, S, CP, SP, ACK,     seq=1018, ack=2019)),
    ]
    write_pcap("clean_handshake.pcap", records)


def make_retransmissions() -> None:
    """Connection with retransmitted segment."""
    C, S = "10.0.0.1", "10.0.0.2"
    CP, SP = 54322, 80
    records = [
        (1, 0,      _eth_ip_tcp(C, S, CP, SP, SYN,     seq=1000, ack=0)),
        (1, 100000, _eth_ip_tcp(S, C, SP, CP, SYN_ACK, seq=2000, ack=1001)),
        (1, 200000, _eth_ip_tcp(C, S, CP, SP, ACK,     seq=1001, ack=2001)),
        # Data segment
        (1, 300000, _eth_ip_tcp(C, S, CP, SP, ACK,     seq=1001, ack=2001, payload=b"Hello")),
        # Retransmission: same seq=1001 again
        (1, 800000, _eth_ip_tcp(C, S, CP, SP, ACK,     seq=1001, ack=2001, payload=b"Hello")),
        # Server ACK
        (1, 900000, _eth_ip_tcp(S, C, SP, CP, ACK,     seq=2001, ack=1006)),
        # Close
        (2, 0,      _eth_ip_tcp(C, S, CP, SP, FIN_ACK, seq=1006, ack=2001)),
        (2, 100000, _eth_ip_tcp(S, C, SP, CP, FIN_ACK, seq=2001, ack=1007)),
        (2, 200000, _eth_ip_tcp(C, S, CP, SP, ACK,     seq=1007, ack=2002)),
    ]
    write_pcap("retransmission.pcap", records)


def make_half_open() -> None:
    """SYN sent but no SYN-ACK ever arrives."""
    C, S = "10.0.0.1", "10.0.0.3"
    CP, SP = 54323, 9999
    records = [
        (1, 0,      _eth_ip_tcp(C, S, CP, SP, SYN, seq=5000, ack=0)),
        # No reply — capture ends 10 seconds later with an unrelated packet
        (11, 0,     _eth_ip_tcp(C, S, CP, SP, SYN, seq=5000, ack=0)),  # retry SYN
    ]
    write_pcap("half_open.pcap", records)


def make_rst_terminated() -> None:
    """Connection terminated by RST."""
    C, S = "10.0.0.1", "10.0.0.2"
    CP, SP = 54324, 80
    records = [
        (1, 0,      _eth_ip_tcp(C, S, CP, SP, SYN,     seq=3000, ack=0)),
        (1, 100000, _eth_ip_tcp(S, C, SP, CP, SYN_ACK, seq=4000, ack=3001)),
        (1, 200000, _eth_ip_tcp(C, S, CP, SP, ACK,     seq=3001, ack=4001)),
        # Data
        (1, 300000, _eth_ip_tcp(C, S, CP, SP, ACK,     seq=3001, ack=4001, payload=b"data")),
        # Server resets the connection
        (1, 400000, _eth_ip_tcp(S, C, SP, CP, RST_ACK, seq=4001, ack=3005)),
    ]
    write_pcap("rst_terminated.pcap", records)


def make_connection_refused() -> None:
    """RST in response to SYN — port closed."""
    C, S = "10.0.0.1", "10.0.0.2"
    CP, SP = 54325, 9876
    records = [
        (1, 0,      _eth_ip_tcp(C, S, CP, SP, SYN,     seq=6000, ack=0)),
        (1, 100000, _eth_ip_tcp(S, C, SP, CP, RST_ACK, seq=0,    ack=6001)),
    ]
    write_pcap("connection_refused.pcap", records)


if __name__ == "__main__":
    SAMPLES_DIR.mkdir(parents=True, exist_ok=True)
    make_clean_handshake()
    make_retransmissions()
    make_half_open()
    make_rst_terminated()
    make_connection_refused()
    print("All sample pcaps written.")
