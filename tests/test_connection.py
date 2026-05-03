"""Integration tests using synthetic pcap files."""

import unittest
from pathlib import Path

from tcpfsm.analyzer import analyze
from tcpfsm.fsm import State
from tcpfsm.anomaly import AnomalyKind

SAMPLES = Path(__file__).parent / "samples"


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
        self.assertEqual(len(self.conns[0].anomalies), 0)

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
        c = self.conns[0]
        self.assertEqual(c.final_state_initiator, State.CLOSED)


class TestConnectionRefused(unittest.TestCase):
    def setUp(self):
        self.conns = analyze(str(SAMPLES / "connection_refused.pcap"))

    def test_one_connection(self):
        self.assertEqual(len(self.conns), 1)

    def test_refused_detected(self):
        kinds = {a.kind for a in self.conns[0].anomalies}
        self.assertIn(AnomalyKind.CONNECTION_REFUSED, kinds)


if __name__ == "__main__":
    unittest.main()
