"""
Generate synthetic .pcap sample files for testing.
Run once: python -m tests.make_samples
"""

import struct
import os
from pathlib import Path

SAMPLES_DIR = Path(__file__).parent / "samples"
SAMPLES_DIR.mkdir(parents=True, exist_ok=True)


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
        (1,  0, _eth_ip_tcp(C, S, CP, SP, SYN, seq=5000, ack=0)),
        # No reply — 35 s later a retry SYN arrives (exceeds 30 s half-open timeout)
        (36, 0, _eth_ip_tcp(C, S, CP, SP, SYN, seq=5001, ack=0)),
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


def make_showcase() -> None:
    """Five mixed connections for README demo: clean, retransmissions, RST, mid-stream, half-open."""
    records = []

    # 1 — clean handshake + graceful close (active close by client)
    C1, S1, CP1, SP1 = "10.0.0.1", "10.0.0.2", 55001, 80
    records += [
        (1, 0,      _eth_ip_tcp(C1, S1, CP1, SP1, SYN,     seq=1000, ack=0)),
        (1, 100000, _eth_ip_tcp(S1, C1, SP1, CP1, SYN_ACK, seq=2000, ack=1001)),
        (1, 200000, _eth_ip_tcp(C1, S1, CP1, SP1, ACK,     seq=1001, ack=2001)),
        (1, 300000, _eth_ip_tcp(C1, S1, CP1, SP1, ACK,     seq=1001, ack=2001, payload=b"GET / HTTP/1.0\r\n")),
        (1, 500000, _eth_ip_tcp(S1, C1, SP1, CP1, ACK,     seq=2001, ack=1017, payload=b"HTTP/1.0 200 OK\r\n")),
        (2, 0,      _eth_ip_tcp(C1, S1, CP1, SP1, FIN_ACK, seq=1017, ack=2018)),
        (2, 100000, _eth_ip_tcp(S1, C1, SP1, CP1, ACK,     seq=2018, ack=1018)),
        (2, 200000, _eth_ip_tcp(S1, C1, SP1, CP1, FIN_ACK, seq=2018, ack=1018)),
        (2, 300000, _eth_ip_tcp(C1, S1, CP1, SP1, ACK,     seq=1018, ack=2019)),
    ]

    # 2 — two retransmissions of the same segment
    C2, S2, CP2, SP2 = "10.0.0.1", "10.0.0.2", 55002, 443
    records += [
        (4, 0,      _eth_ip_tcp(C2, S2, CP2, SP2, SYN,     seq=3000, ack=0)),
        (4, 100000, _eth_ip_tcp(S2, C2, SP2, CP2, SYN_ACK, seq=4000, ack=3001)),
        (4, 200000, _eth_ip_tcp(C2, S2, CP2, SP2, ACK,     seq=3001, ack=4001)),
        (4, 300000, _eth_ip_tcp(C2, S2, CP2, SP2, ACK,     seq=3001, ack=4001, payload=b"Hello")),
        (4, 800000, _eth_ip_tcp(C2, S2, CP2, SP2, ACK,     seq=3001, ack=4001, payload=b"Hello")),  # retransmit 1
        (4, 900000, _eth_ip_tcp(C2, S2, CP2, SP2, ACK,     seq=3001, ack=4001, payload=b"Hello")),  # retransmit 2
        (5, 0,      _eth_ip_tcp(S2, C2, SP2, CP2, ACK,     seq=4001, ack=3006)),
        (5, 100000, _eth_ip_tcp(C2, S2, CP2, SP2, FIN_ACK, seq=3006, ack=4001)),
        (5, 200000, _eth_ip_tcp(S2, C2, SP2, CP2, FIN_ACK, seq=4001, ack=3007)),
        (5, 300000, _eth_ip_tcp(C2, S2, CP2, SP2, ACK,     seq=3007, ack=4002)),
    ]

    # 3 — established connection terminated by RST from server
    C3, S3, CP3, SP3 = "10.0.0.1", "10.0.0.2", 55003, 8080
    records += [
        (7, 0,      _eth_ip_tcp(C3, S3, CP3, SP3, SYN,     seq=5000, ack=0)),
        (7, 100000, _eth_ip_tcp(S3, C3, SP3, CP3, SYN_ACK, seq=6000, ack=5001)),
        (7, 200000, _eth_ip_tcp(C3, S3, CP3, SP3, ACK,     seq=5001, ack=6001)),
        (7, 300000, _eth_ip_tcp(C3, S3, CP3, SP3, ACK,     seq=5001, ack=6001, payload=b"POST /upload")),
        (7, 400000, _eth_ip_tcp(S3, C3, SP3, CP3, RST_ACK, seq=6001, ack=5013)),
    ]

    # 4 — mid-stream: capture started after handshake, data-only packets
    C4, S4, CP4, SP4 = "10.0.0.3", "10.0.0.4", 55004, 80
    records += [
        (9, 0,      _eth_ip_tcp(C4, S4, CP4, SP4, ACK, seq=7000, ack=8000, payload=b"GET /api")),
        (9, 100000, _eth_ip_tcp(S4, C4, SP4, CP4, ACK, seq=8000, ack=7008, payload=b"200 OK")),
        (9, 200000, _eth_ip_tcp(C4, S4, CP4, SP4, ACK, seq=7008, ack=8006)),
    ]

    # 5 — half-open: SYN never answered; retry SYN at t=45 triggers finalize() > 30 s timeout
    C5, S5, CP5, SP5 = "10.0.0.1", "10.0.0.5", 55005, 9999
    records += [
        (11, 0, _eth_ip_tcp(C5, S5, CP5, SP5, SYN, seq=9000, ack=0)),
        (45, 0, _eth_ip_tcp(C5, S5, CP5, SP5, SYN, seq=9001, ack=0)),
    ]

    write_pcap("showcase.pcap", records)


if __name__ == "__main__":
    SAMPLES_DIR.mkdir(parents=True, exist_ok=True)
    make_clean_handshake()
    make_retransmissions()
    make_half_open()
    make_rst_terminated()
    make_connection_refused()
    make_showcase()
    print("All sample pcaps written.")
