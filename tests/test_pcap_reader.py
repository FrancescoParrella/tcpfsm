"""Unit tests for pcap_reader — no external dependencies beyond dpkt."""

import socket
import struct
import unittest
from pathlib import Path

import dpkt

from tcpfsm.pcap_reader import Packet, TCPPacket, read_pcap

SAMPLES_DIR = Path(__file__).parent / "samples"
HANDSHAKE_PCAP = SAMPLES_DIR / "handshake.pcap"

# TCP flag constants
SYN     = 0x02
ACK     = 0x10
SYN_ACK = SYN | ACK  # 0x12

CLIENT_IP,   CLIENT_PORT = "10.0.0.1", 12345
SERVER_IP,   SERVER_PORT = "10.0.0.2", 80


# ── packet builder ────────────────────────────────────────────────────────────

def _build_frame(
    src_ip: str, dst_ip: str,
    sport: int, dport: int,
    flags: int, seq: int, ack_seq: int,
    payload: bytes = b"",
) -> bytes:
    """Build a raw Ethernet/IPv4/TCP frame via struct packing.

    Checksums are set to 0 — dpkt's reader accepts them without validation.
    """
    tcp_hdr = struct.pack(
        "!HHIIBBHHH",
        sport, dport,
        seq, ack_seq,
        0x50,     # data offset = 5 (20-byte header), reserved = 0
        flags,
        65535,    # window
        0,        # checksum
        0,        # urgent pointer
    )
    tcp_seg = tcp_hdr + payload

    ip_len = 20 + len(tcp_seg)
    ip_hdr = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0, ip_len, 0, 0,
        64, 6, 0,             # TTL=64, proto=TCP(6), checksum=0
        socket.inet_aton(src_ip),
        socket.inet_aton(dst_ip),
    )

    return (
        b"\x00\x0a\x0b\x0c\x0d\x0e"   # dst MAC
        b"\x00\x01\x02\x03\x04\x05"   # src MAC
        b"\x08\x00"                    # EtherType = IPv4
        + ip_hdr + tcp_seg
    )


# ── fixture: generate handshake.pcap once for the whole test run ──────────────

def setUpModule() -> None:   # noqa: N802  (unittest convention)
    SAMPLES_DIR.mkdir(parents=True, exist_ok=True)
    frames = [
        (1.000000, _build_frame(CLIENT_IP, SERVER_IP, CLIENT_PORT, SERVER_PORT,
                                SYN,     seq=1000, ack_seq=0)),
        (1.100000, _build_frame(SERVER_IP, CLIENT_IP, SERVER_PORT, CLIENT_PORT,
                                SYN_ACK, seq=2000, ack_seq=1001)),
        (1.200000, _build_frame(CLIENT_IP, SERVER_IP, CLIENT_PORT, SERVER_PORT,
                                ACK,     seq=1001, ack_seq=2001)),
    ]
    with open(HANDSHAKE_PCAP, "wb") as f:
        writer = dpkt.pcap.Writer(f)
        for ts, frame in frames:
            writer.writepkt(frame, ts=ts)


# ── field-level tests for the 3-packet handshake ─────────────────────────────

class TestHandshakePackets(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.packets = list(read_pcap(HANDSHAKE_PCAP))

    def test_yields_exactly_three_packets(self):
        self.assertEqual(len(self.packets), 3)

    def test_all_items_are_packet_instances(self):
        for pkt in self.packets:
            self.assertIsInstance(pkt, Packet)

    # SYN
    def test_syn_src_ip(self):
        self.assertEqual(self.packets[0].src_ip, CLIENT_IP)

    def test_syn_dst_ip(self):
        self.assertEqual(self.packets[0].dst_ip, SERVER_IP)

    def test_syn_src_port(self):
        self.assertEqual(self.packets[0].src_port, CLIENT_PORT)

    def test_syn_dst_port(self):
        self.assertEqual(self.packets[0].dst_port, SERVER_PORT)

    def test_syn_flags(self):
        self.assertEqual(self.packets[0].flags, SYN)

    def test_syn_seq(self):
        self.assertEqual(self.packets[0].seq, 1000)

    def test_syn_ack_field_is_zero(self):
        self.assertEqual(self.packets[0].ack, 0)

    def test_syn_payload_len_is_zero(self):
        self.assertEqual(self.packets[0].payload_len, 0)

    def test_syn_index_is_one(self):
        self.assertEqual(self.packets[0].index, 1)

    # SYN+ACK
    def test_synack_src_ip(self):
        self.assertEqual(self.packets[1].src_ip, SERVER_IP)

    def test_synack_dst_ip(self):
        self.assertEqual(self.packets[1].dst_ip, CLIENT_IP)

    def test_synack_flags(self):
        self.assertEqual(self.packets[1].flags, SYN_ACK)

    def test_synack_seq(self):
        self.assertEqual(self.packets[1].seq, 2000)

    def test_synack_ack(self):
        self.assertEqual(self.packets[1].ack, 1001)

    def test_synack_index_is_two(self):
        self.assertEqual(self.packets[1].index, 2)

    # ACK
    def test_ack_flags(self):
        self.assertEqual(self.packets[2].flags, ACK)

    def test_ack_seq(self):
        self.assertEqual(self.packets[2].seq, 1001)

    def test_ack_ack(self):
        self.assertEqual(self.packets[2].ack, 2001)

    def test_ack_index_is_three(self):
        self.assertEqual(self.packets[2].index, 3)

    # Cross-packet properties
    def test_timestamps_are_strictly_increasing(self):
        ts = [p.timestamp for p in self.packets]
        self.assertEqual(ts, sorted(ts))
        self.assertEqual(len(set(ts)), 3)

    def test_window_is_preserved(self):
        for pkt in self.packets:
            self.assertEqual(pkt.window, 65535)


# ── edge cases ────────────────────────────────────────────────────────────────

class TestEdgeCases(unittest.TestCase):

    def test_empty_pcap_yields_no_packets(self):
        empty_path = SAMPLES_DIR / "empty.pcap"
        with open(empty_path, "wb") as f:
            dpkt.pcap.Writer(f)   # writes global header only
        self.assertEqual(list(read_pcap(empty_path)), [])

    def test_nonexistent_file_raises_file_not_found(self):
        with self.assertRaises(FileNotFoundError):
            list(read_pcap(SAMPLES_DIR / "does_not_exist.pcap"))

    def test_non_tcp_packets_are_skipped(self):
        """UDP frame must produce no Packet."""
        src_raw = socket.inet_aton("10.0.0.1")
        dst_raw = socket.inet_aton("10.0.0.2")
        udp_payload = b"\x00\x35\x00\x35\x00\x08\x00\x00"  # minimal UDP header
        ip_len = 20 + len(udp_payload)
        ip_hdr = struct.pack(
            "!BBHHHBBH4s4s",
            0x45, 0, ip_len, 0, 0, 64,
            17, 0,          # proto=UDP
            src_raw, dst_raw,
        )
        eth = b"\x00\x0a\x0b\x0c\x0d\x0e\x00\x01\x02\x03\x04\x05\x08\x00" + ip_hdr + udp_payload

        udp_path = SAMPLES_DIR / "udp_only.pcap"
        with open(udp_path, "wb") as f:
            writer = dpkt.pcap.Writer(f)
            writer.writepkt(eth, ts=1.0)

        self.assertEqual(list(read_pcap(udp_path)), [])

    def test_payload_len_reflects_tcp_data(self):
        """Packet with 5-byte payload must report payload_len=5."""
        frame = _build_frame(
            CLIENT_IP, SERVER_IP, CLIENT_PORT, SERVER_PORT,
            ACK, seq=1001, ack_seq=2001, payload=b"hello",
        )
        data_path = SAMPLES_DIR / "payload.pcap"
        with open(data_path, "wb") as f:
            writer = dpkt.pcap.Writer(f)
            writer.writepkt(frame, ts=2.0)

        pkts = list(read_pcap(data_path))
        self.assertEqual(len(pkts), 1)
        self.assertEqual(pkts[0].payload_len, 5)


# ── backward-compat alias ─────────────────────────────────────────────────────

class TestBackwardCompatAlias(unittest.TestCase):

    def test_tcppacket_is_same_class_as_packet(self):
        self.assertIs(TCPPacket, Packet)


if __name__ == "__main__":
    unittest.main()
