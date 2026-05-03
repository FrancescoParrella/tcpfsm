"""Tests for the CLI entry point and output renderers."""

import io
import json
import unittest
from pathlib import Path
from unittest.mock import patch

import tests.make_samples as _ms
from tcpfsm.cli import build_parser, main

SAMPLES = Path(__file__).parent / "samples"


def setUpModule() -> None:  # noqa: N802
    _ms.SAMPLES_DIR.mkdir(parents=True, exist_ok=True)
    _ms.make_clean_handshake()
    _ms.make_rst_terminated()
    _ms.make_connection_refused()


# ── parser ────────────────────────────────────────────────────────────────────

class TestParser(unittest.TestCase):

    def _parse(self, args):
        return build_parser().parse_args(args)

    def test_positional_required(self):
        with self.assertRaises(SystemExit):
            build_parser().parse_args([])

    def test_pcap_positional(self):
        self.assertEqual(self._parse(["foo.pcap"]).pcap, "foo.pcap")

    def test_connection_long(self):
        self.assertEqual(self._parse(["foo.pcap", "--connection", "3"]).connection, 3)

    def test_connection_short(self):
        self.assertEqual(self._parse(["foo.pcap", "-c", "2"]).connection, 2)

    def test_anomalies_only(self):
        self.assertTrue(self._parse(["foo.pcap", "--anomalies-only"]).anomalies_only)

    def test_json_flag(self):
        self.assertTrue(self._parse(["foo.pcap", "--json"]).json)

    def test_half_open_timeout_explicit(self):
        self.assertAlmostEqual(
            self._parse(["foo.pcap", "--half-open-timeout", "60.0"]).half_open_timeout,
            60.0,
        )

    def test_half_open_timeout_default(self):
        self.assertAlmostEqual(self._parse(["foo.pcap"]).half_open_timeout, 30.0)


# ── JSON output ───────────────────────────────────────────────────────────────

class TestJsonOutput(unittest.TestCase):

    def _run_json(self, extra_args=None):
        args = ["--json", str(SAMPLES / "clean_handshake.pcap")]
        if extra_args:
            args = extra_args + [str(SAMPLES / "clean_handshake.pcap")]
        buf = io.StringIO()
        with patch("sys.stdout", buf):
            rc = main(args)
        return rc, buf.getvalue()

    def test_returns_zero(self):
        rc, _ = self._run_json()
        self.assertEqual(rc, 0)

    def test_json_is_parseable(self):
        _, out = self._run_json()
        data = json.loads(out)
        self.assertIsInstance(data, list)
        self.assertEqual(len(data), 1)

    def test_required_fields_present(self):
        _, out = self._run_json()
        conn = json.loads(out)[0]
        for field in (
            "index", "src_ip", "src_port", "dst_ip", "dst_port",
            "mid_stream", "first_ts", "last_ts", "duration",
            "init_bytes", "resp_bytes", "packet_count",
            "final_state_initiator", "final_state_responder",
            "transitions", "anomalies",
        ):
            with self.subTest(field=field):
                self.assertIn(field, conn)

    def test_transitions_and_anomalies_are_lists(self):
        _, out = self._run_json()
        conn = json.loads(out)[0]
        self.assertIsInstance(conn["transitions"], list)
        self.assertIsInstance(conn["anomalies"], list)

    def test_connection_detail_json_is_dict(self):
        buf = io.StringIO()
        with patch("sys.stdout", buf):
            rc = main(["--json", "-c", "1", str(SAMPLES / "clean_handshake.pcap")])
        self.assertEqual(rc, 0)
        data = json.loads(buf.getvalue())
        self.assertIsInstance(data, dict)
        self.assertEqual(data["index"], 1)

    def test_anomalies_json_has_entries(self):
        buf = io.StringIO()
        with patch("sys.stdout", buf):
            rc = main(["--json", str(SAMPLES / "rst_terminated.pcap")])
        self.assertEqual(rc, 0)
        conns = json.loads(buf.getvalue())
        self.assertGreater(len(conns[0]["anomalies"]), 0)

    def test_anomalies_only_json_empty_on_clean(self):
        buf = io.StringIO()
        with patch("sys.stdout", buf):
            rc = main(["--anomalies-only", "--json",
                       str(SAMPLES / "clean_handshake.pcap")])
        self.assertEqual(rc, 0)
        data = json.loads(buf.getvalue())
        self.assertIsInstance(data, list)
        self.assertEqual(len(data), 0)


# ── human-readable output ─────────────────────────────────────────────────────

class TestHumanOutput(unittest.TestCase):

    def _stdout(self, args):
        buf = io.StringIO()
        with patch("sys.stdout", buf):
            rc = main(args)
        return rc, buf.getvalue()

    def test_summary_has_header_and_data_rows(self):
        rc, out = self._stdout([str(SAMPLES / "clean_handshake.pcap")])
        self.assertEqual(rc, 0)
        non_empty = [l for l in out.splitlines() if l.strip()]
        # header + separator + 1 data row
        self.assertGreaterEqual(len(non_empty), 3)

    def test_connection_detail_shows_index(self):
        rc, out = self._stdout(["-c", "1", str(SAMPLES / "clean_handshake.pcap")])
        self.assertEqual(rc, 0)
        self.assertIn("Connection #1", out)

    def test_connection_detail_shows_transitions(self):
        rc, out = self._stdout(["-c", "1", str(SAMPLES / "clean_handshake.pcap")])
        self.assertEqual(rc, 0)
        self.assertIn("State transitions", out)

    def test_anomalies_only_suppresses_clean_connections(self):
        rc, out = self._stdout(["--anomalies-only", str(SAMPLES / "clean_handshake.pcap")])
        self.assertEqual(rc, 0)
        self.assertIn("No TCP connections found", out)

    def test_anomalies_only_keeps_anomalous_connections(self):
        rc, out = self._stdout(["--anomalies-only", str(SAMPLES / "rst_terminated.pcap")])
        self.assertEqual(rc, 0)
        non_empty = [l for l in out.splitlines() if l.strip()]
        self.assertGreaterEqual(len(non_empty), 3)


# ── error handling ────────────────────────────────────────────────────────────

class TestErrors(unittest.TestCase):

    def test_missing_file_returns_1(self):
        self.assertEqual(main(["nonexistent_file_xyz.pcap"]), 1)

    def test_invalid_connection_index_returns_1(self):
        self.assertEqual(
            main(["-c", "99", str(SAMPLES / "clean_handshake.pcap")]),
            1,
        )

    def test_connection_refused_anomaly_detected_via_json(self):
        buf = io.StringIO()
        with patch("sys.stdout", buf):
            rc = main(["--json", str(SAMPLES / "connection_refused.pcap")])
        self.assertEqual(rc, 0)
        conns = json.loads(buf.getvalue())
        kinds = {a["kind"] for a in conns[0]["anomalies"]}
        self.assertIn("connection_refused", kinds)


if __name__ == "__main__":
    unittest.main()
