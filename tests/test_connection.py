"""Integration + unit tests for Connection and ConnectionTracker.

Pcap-based tests generate synthetic files once in setUpModule.
Unit tests drive ConnectionTracker directly with Packet objects.
"""

import unittest
from pathlib import Path

import tests.make_samples as _ms
from tcpfsm.analyzer import analyze
from tcpfsm.anomaly import AnomalyKind
from tcpfsm.connection import Connection, ConnectionTracker, _identify_initiator
from tcpfsm.fsm import State
from tcpfsm.pcap_reader import Packet

SAMPLES = Path(__file__).parent / "samples"


def setUpModule() -> None:   # noqa: N802
    _ms.SAMPLES_DIR.mkdir(parents=True, exist_ok=True)
    _ms.make_clean_handshake()
    _ms.make_retransmissions()
    _ms.make_half_open()
    _ms.make_rst_terminated()
    _ms.make_connection_refused()


# ── helpers ───────────────────────────────────────────────────────────────────

def _pkt(
    src_ip: str, src_port: int,
    dst_ip: str, dst_port: int,
    flags: int,
    seq: int = 0, ack: int = 0,
    payload_len: int = 0, ts: float = 1.0, idx: int = 1,
) -> Packet:
    return Packet(
        timestamp=ts, src_ip=src_ip, src_port=src_port,
        dst_ip=dst_ip, dst_port=dst_port, flags=flags,
        seq=seq, ack=ack, window=65535, payload_len=payload_len, index=idx,
    )


SYN     = 0x02
ACK     = 0x10
SYN_ACK = 0x12
FIN_ACK = 0x11
RST_ACK = 0x14

# Client / server addresses
C, CP = "10.0.0.1", 50000   # client IP, client port
S, SP = "10.0.0.2", 80      # server IP, server port


def _run_handshake(tracker: ConnectionTracker | None = None) -> ConnectionTracker:
    """Feed a complete 3WHS into a tracker and return it."""
    t = tracker or ConnectionTracker()
    t.feed(_pkt(C, CP, S, SP, SYN,     seq=1000, ack=0,    ts=1.0, idx=1))
    t.feed(_pkt(S, SP, C, CP, SYN_ACK, seq=2000, ack=1001, ts=1.1, idx=2))
    t.feed(_pkt(C, CP, S, SP, ACK,     seq=1001, ack=2001, ts=1.2, idx=3))
    return t


# ── pcap-based integration tests ──────────────────────────────────────────────

class TestCleanHandshake(unittest.TestCase):
    def setUp(self):
        self.conns = analyze(str(SAMPLES / "clean_handshake.pcap"))

    def test_one_connection(self):
        self.assertEqual(len(self.conns), 1)

    def test_final_states(self):
        c = self.conns[0]
        self.assertEqual(c.final_state_initiator, State.TIME_WAIT)
        self.assertEqual(c.final_state_responder, State.CLOSED)

    def test_no_anomalies(self):
        self.assertEqual(self.conns[0].anomalies, [])

    def test_bytes_transferred(self):
        c = self.conns[0]
        self.assertGreater(c.init_bytes, 0)
        self.assertGreater(c.resp_bytes, 0)

    def test_duration_positive(self):
        self.assertGreater(self.conns[0].duration, 0)


class TestRetransmission(unittest.TestCase):
    def setUp(self):
        self.conns = analyze(str(SAMPLES / "retransmission.pcap"))

    def test_one_connection(self):
        self.assertEqual(len(self.conns), 1)

    def test_retransmission_anomaly_detected(self):
        kinds = {a.kind for a in self.conns[0].anomalies}
        self.assertIn(AnomalyKind.RETRANSMISSION, kinds)


class TestHalfOpen(unittest.TestCase):
    def setUp(self):
        self.conns = analyze(str(SAMPLES / "half_open.pcap"))

    def test_one_connection(self):
        self.assertEqual(len(self.conns), 1)

    def test_half_open_detected(self):
        kinds = {a.kind for a in self.conns[0].anomalies}
        self.assertIn(AnomalyKind.HALF_OPEN, kinds)

    def test_initiator_stuck_in_syn_sent(self):
        self.assertEqual(self.conns[0].final_state_initiator, State.SYN_SENT)


class TestRstTerminated(unittest.TestCase):
    def setUp(self):
        self.conns = analyze(str(SAMPLES / "rst_terminated.pcap"))

    def test_one_connection(self):
        self.assertEqual(len(self.conns), 1)

    def test_unexpected_rst_detected(self):
        kinds = {a.kind for a in self.conns[0].anomalies}
        self.assertIn(AnomalyKind.UNEXPECTED_RST, kinds)

    def test_final_state_closed(self):
        self.assertEqual(self.conns[0].final_state_initiator, State.CLOSED)


class TestConnectionRefused(unittest.TestCase):
    def setUp(self):
        self.conns = analyze(str(SAMPLES / "connection_refused.pcap"))

    def test_one_connection(self):
        self.assertEqual(len(self.conns), 1)

    def test_refused_detected(self):
        kinds = {a.kind for a in self.conns[0].anomalies}
        self.assertIn(AnomalyKind.CONNECTION_REFUSED, kinds)


# ── unit tests: ConnectionTracker ─────────────────────────────────────────────

class TestBasicTracking(unittest.TestCase):

    def test_3whs_reaches_established(self):
        t = _run_handshake()
        conn = t.connections[0]
        self.assertEqual(conn.final_state_initiator, State.ESTABLISHED)
        self.assertEqual(conn.final_state_responder, State.ESTABLISHED)

    def test_single_connection_created(self):
        self.assertEqual(len(_run_handshake().connections), 1)

    def test_bytes_counted_correctly(self):
        t = _run_handshake()
        t.feed(_pkt(C, CP, S, SP, ACK, seq=1001, ack=2001,
                    payload_len=10, ts=1.3, idx=4))
        conn = t.connections[0]
        self.assertEqual(conn.init_bytes, 10)
        self.assertEqual(conn.resp_bytes, 0)

    def test_packet_count(self):
        self.assertEqual(_run_handshake().connections[0].packet_count, 3)

    def test_duration(self):
        t = _run_handshake()
        self.assertAlmostEqual(t.connections[0].duration, 0.2, places=5)


class TestBidirectionalLookup(unittest.TestCase):

    def test_reverse_packet_reuses_same_connection(self):
        t = _run_handshake()
        # ACK from server → client (reverse direction)
        t.feed(_pkt(S, SP, C, CP, ACK, seq=2001, ack=1001, ts=1.3, idx=4))
        self.assertEqual(len(t.connections), 1)

    def test_initiator_key_is_syn_sender(self):
        conn = _run_handshake().connections[0]
        self.assertEqual(conn.src_ip,   C)
        self.assertEqual(conn.src_port, CP)
        self.assertEqual(conn.dst_ip,   S)
        self.assertEqual(conn.dst_port, SP)


class TestPortReuse(unittest.TestCase):

    def _closed_connection(self) -> ConnectionTracker:
        """Build a tracker with one fully-closed connection."""
        t = _run_handshake()
        t.feed(_pkt(C, CP, S, SP, FIN_ACK, seq=1001, ack=2001, ts=2.0, idx=4))
        t.feed(_pkt(S, SP, C, CP, ACK,     seq=2001, ack=1002, ts=2.1, idx=5))
        t.feed(_pkt(S, SP, C, CP, FIN_ACK, seq=2001, ack=1002, ts=2.2, idx=6))
        t.feed(_pkt(C, CP, S, SP, ACK,     seq=1002, ack=2002, ts=2.3, idx=7))
        t.finalize(2.3)
        return t

    def test_new_connection_after_time_wait(self):
        t = self._closed_connection()
        first = t.connections[0]
        self.assertEqual(first.final_state_initiator, State.TIME_WAIT)
        self.assertEqual(first.final_state_responder, State.CLOSED)

        # New SYN on same 4-tuple → must create a second Connection
        t.feed(_pkt(C, CP, S, SP, SYN, seq=9000, ts=130.0, idx=8))
        self.assertEqual(len(t.connections), 2)
        self.assertEqual(t.connections[1].final_state_initiator, State.SYN_SENT)

    def test_new_connection_after_rst(self):
        t = _run_handshake()
        t.feed(_pkt(S, SP, C, CP, RST_ACK, seq=2001, ack=1001, ts=2.0, idx=4))
        t.finalize(2.0)
        self.assertTrue(t.connections[0].is_closed)

        t.feed(_pkt(C, CP, S, SP, SYN, seq=9000, ts=3.0, idx=5))
        self.assertEqual(len(t.connections), 2)


class TestInvalidTransition(unittest.TestCase):

    def test_syn_in_established_produces_anomaly(self):
        t = _run_handshake()
        t.feed(_pkt(C, CP, S, SP, SYN, seq=1001, ack=2001, ts=1.3, idx=4))
        kinds = {a.kind for a in t.connections[0].anomalies}
        self.assertIn(AnomalyKind.INVALID_TRANSITION, kinds)

    def test_invalid_transition_description_contains_event_and_side(self):
        t = _run_handshake()
        t.feed(_pkt(C, CP, S, SP, SYN, seq=1001, ack=2001, ts=1.3, idx=4))
        inv = [a for a in t.connections[0].anomalies
               if a.kind == AnomalyKind.INVALID_TRANSITION]
        self.assertGreater(len(inv), 0)
        self.assertIn("SEND_SYN", inv[0].description)
        # Description must mention the side ("initiator" or "responder")
        self.assertTrue(
            "initiator" in inv[0].description or "responder" in inv[0].description
        )


class TestMidStream(unittest.TestCase):

    def test_well_known_dst_port_identifies_client(self):
        t = ConnectionTracker()
        t.feed(_pkt("192.168.1.10", 54000, "10.0.0.1", 80,
                    ACK, seq=500, ack=300, ts=1.0, idx=1))
        conn = t.connections[0]
        self.assertEqual(conn.src_ip,   "192.168.1.10")
        self.assertEqual(conn.src_port, 54000)
        self.assertTrue(conn.mid_stream)

    def test_well_known_src_port_identifies_server(self):
        t = ConnectionTracker()
        # Server (port 443) sends first — client should still be initiator
        t.feed(_pkt("10.0.0.1", 443, "192.168.1.10", 54001,
                    ACK, seq=300, ack=500, ts=1.0, idx=1))
        conn = t.connections[0]
        self.assertEqual(conn.src_port, 54001)   # initiator is the client
        self.assertTrue(conn.mid_stream)

    def test_mid_stream_fsm_starts_in_observed_established(self):
        t = ConnectionTracker()
        t.feed(_pkt("192.168.1.10", 54000, "10.0.0.1", 80,
                    ACK, seq=500, ack=300, ts=1.0, idx=1))
        conn = t.connections[0]
        self.assertEqual(conn.final_state_initiator, State.OBSERVED_ESTABLISHED)
        self.assertEqual(conn.final_state_responder, State.OBSERVED_ESTABLISHED)

    def test_identify_initiator_well_known_dst(self):
        ii, ip, ri, rp, ms = _identify_initiator("1.1.1.1", 55000, "2.2.2.2", 443, ACK)
        self.assertEqual(ii, "1.1.1.1")
        self.assertEqual(ip, 55000)
        self.assertTrue(ms)

    def test_identify_initiator_well_known_src(self):
        ii, ip, ri, rp, ms = _identify_initiator("2.2.2.2", 3306, "1.1.1.1", 55000, ACK)
        self.assertEqual(ii, "1.1.1.1")   # client is initiator
        self.assertTrue(ms)

    def test_identify_initiator_syn_overrides_heuristic(self):
        # SYN sender is always the initiator regardless of port values
        ii, ip, ri, rp, ms = _identify_initiator("1.1.1.1", 80, "2.2.2.2", 55000, SYN)
        self.assertEqual(ii, "1.1.1.1")
        self.assertEqual(ip, 80)
        self.assertFalse(ms)


class TestFinalizeHalfOpen(unittest.TestCase):

    def test_half_open_detected_after_finalize(self):
        t = ConnectionTracker(half_open_timeout=5.0)
        t.feed(_pkt(C, CP, S, SP, SYN, seq=1000, ts=1.0, idx=1))
        t.finalize(capture_end_ts=10.0)   # 9 s gap > 5 s timeout
        kinds = {a.kind for a in t.connections[0].anomalies}
        self.assertIn(AnomalyKind.HALF_OPEN, kinds)

    def test_no_half_open_if_syn_acked(self):
        t = _run_handshake()
        t.finalize(10.0)
        kinds = {a.kind for a in t.connections[0].anomalies}
        self.assertNotIn(AnomalyKind.HALF_OPEN, kinds)


if __name__ == "__main__":
    unittest.main()
