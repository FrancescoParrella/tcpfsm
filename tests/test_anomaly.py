"""Unit tests for anomaly detectors."""

import unittest
from tcpfsm.anomaly import SideTracker, AnomalyKind, check_zero_window


class TestSideTracker(unittest.TestCase):

    def _tracker(self):
        return SideTracker()

    def test_no_anomaly_fresh_segments(self):
        t = self._tracker()
        self.assertEqual(t.observe(1000, 100, 1.0, 1), [])
        self.assertEqual(t.observe(1100, 100, 1.1, 2), [])
        self.assertEqual(t.observe(1200, 100, 1.2, 3), [])

    def test_retransmission_detected(self):
        t = self._tracker()
        t.observe(1000, 100, 1.0, 1)
        anomalies = t.observe(1000, 100, 1.5, 2)
        self.assertEqual(len(anomalies), 1)
        self.assertEqual(anomalies[0].kind, AnomalyKind.RETRANSMISSION)

    def test_out_of_order_detected(self):
        t = self._tracker()
        t.observe(1000, 100, 1.0, 1)
        t.observe(1100, 100, 1.1, 2)
        # Now send seq=900, which is behind max_seq_end=1200
        anomalies = t.observe(900, 100, 1.5, 3)
        self.assertEqual(len(anomalies), 1)
        self.assertEqual(anomalies[0].kind, AnomalyKind.OUT_OF_ORDER)

    def test_pure_ack_not_flagged_as_retransmission(self):
        """ACK-only packets (length=0) should not trigger retransmission."""
        t = self._tracker()
        t.observe(1000, 0, 1.0, 1)
        anomalies = t.observe(1000, 0, 1.1, 2)
        self.assertEqual(anomalies, [])

    def test_first_segment_never_anomaly(self):
        t = self._tracker()
        self.assertEqual(t.observe(0, 100, 0.0, 1), [])


class TestZeroWindow(unittest.TestCase):

    def test_zero_window_detected(self):
        a = check_zero_window(0, 1.5, 5)
        self.assertIsNotNone(a)
        self.assertEqual(a.kind, AnomalyKind.ZERO_WINDOW)

    def test_nonzero_window_ok(self):
        self.assertIsNone(check_zero_window(1024, 1.5, 5))
        self.assertIsNone(check_zero_window(65535, 1.5, 5))


if __name__ == "__main__":
    unittest.main()
