"""CLI entry point."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .analyzer import analyze
from .render import _conn_to_dict, render_human, render_json


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="tcpfsm",
        description="TCP state machine analyzer — reconstructs TCP connection lifecycles from .pcap files.",
    )
    p.add_argument("pcap", metavar="FILE", help=".pcap capture file to analyze")
    p.add_argument(
        "--connection", "-c",
        metavar="N",
        type=int,
        help="Show full timeline for connection N (1-based index)",
    )
    p.add_argument(
        "--anomalies-only", "-a",
        action="store_true",
        help="Only show connections that had at least one anomaly",
    )
    p.add_argument(
        "--json", "-j",
        action="store_true",
        help="Output in JSON format",
    )
    p.add_argument(
        "--half-open-timeout",
        metavar="SECONDS",
        type=float,
        default=30.0,
        help="Timeout (s) for half-open connection detection (default: 30.0)",
    )
    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    pcap_path = Path(args.pcap)
    if not pcap_path.exists():
        print(f"error: file not found: {pcap_path}", file=sys.stderr)
        return 1

    try:
        connections = analyze(str(pcap_path), half_open_timeout=args.half_open_timeout)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    if args.connection is not None:
        matched = [c for c in connections if c.index == args.connection]
        if not matched:
            print(f"error: no connection with index {args.connection}", file=sys.stderr)
            return 1
        if args.json:
            print(json.dumps(_conn_to_dict(matched[0]), indent=2))
        else:
            print(render_human(connections, connection=args.connection))
        return 0

    if args.anomalies_only:
        connections = [c for c in connections if c.anomalies]

    if args.json:
        print(render_json(connections))
    else:
        print(render_human(connections, anomalies_only=args.anomalies_only))
    return 0


if __name__ == "__main__":
    sys.exit(main())
