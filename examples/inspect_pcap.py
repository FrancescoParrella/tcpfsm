"""inspect_pcap.py — quick summary of a .pcap file using tcpfsm.pcap_reader.

Usage:
    python examples/inspect_pcap.py <file.pcap>

Prints:
  - total TCP packets read
  - capture time range and duration
  - packet counts by flag combination
  - unique TCP 4-tuples (flows)
"""

import sys
from collections import Counter
from pathlib import Path

# Allow running from repo root without installing
sys.path.insert(0, str(Path(__file__).parent.parent))

from tcpfsm.pcap_reader import read_pcap


_FLAG_NAMES = {
    0x02: "SYN",
    0x12: "SYN+ACK",
    0x10: "ACK",
    0x11: "FIN+ACK",
    0x01: "FIN",
    0x04: "RST",
    0x14: "RST+ACK",
    0x18: "PSH+ACK",
    0x19: "FIN+PSH+ACK",
}


def _flag_label(flags: int) -> str:
    return _FLAG_NAMES.get(flags, f"0x{flags:02x}")


def main(path: str) -> None:
    packets = list(read_pcap(path))

    if not packets:
        print(f"{path}: no IPv4/TCP packets found.")
        return

    first_ts = packets[0].timestamp
    last_ts  = packets[-1].timestamp
    duration = last_ts - first_ts

    flag_counts: Counter = Counter(_flag_label(p.flags) for p in packets)

    flows: dict = {}
    for p in packets:
        key = (p.src_ip, p.src_port, p.dst_ip, p.dst_port)
        rev = (p.dst_ip, p.dst_port, p.src_ip, p.src_port)
        if key not in flows and rev not in flows:
            flows[key] = 0
        canonical = key if key in flows else rev
        flows[canonical] += 1

    print("\n" + "-" * 60)
    print(f"  File     : {path}")
    print(f"  Packets  : {len(packets)}")
    print(f"  Time     : {first_ts:.6f}s -> {last_ts:.6f}s  ({duration:.3f}s)")
    print(f"  Flows    : {len(flows)} unique TCP 4-tuple(s)")

    print("\n  Packets by flag combination:")
    for label, count in sorted(flag_counts.items(), key=lambda x: -x[1]):
        bar = "#" * min(count, 40)
        print(f"    {label:<14} {count:>5}  {bar}")

    print("\n  TCP flows (src_ip:port -> dst_ip:port  [pkts]):")
    for (src_ip, sport, dst_ip, dport), count in sorted(flows.items(), key=lambda x: -x[1]):
        print(f"    {src_ip}:{sport:<6} -> {dst_ip}:{dport:<6}  [{count} pkts]")

    print("-" * 60 + "\n")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <file.pcap>", file=sys.stderr)
        sys.exit(1)
    main(sys.argv[1])
