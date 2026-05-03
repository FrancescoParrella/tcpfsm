"""Output formatting — plain text and JSON."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Optional

from .connection import Connection
from .anomaly import Anomaly, AnomalyKind


def _ts(ts: float) -> str:
    return f"{ts:.6f}"


def _fmt_anomaly(a: Anomaly) -> str:
    return f"  [{a.kind.value.upper()}] pkt#{a.packet_index}  t={_ts(a.timestamp)}  {a.description}"


def render_summary_table(connections: list[Connection]) -> str:
    if not connections:
        return "No TCP connections found.\n"

    header = (
        f"{'#':>4}  {'SRC':>21}  {'DST':>21}  "
        f"{'DURATION':>10}  {'TX→':>8}  {'←RX':>8}  "
        f"{'INIT STATE':>14}  {'RESP STATE':>14}  {'ANOMALIES':>9}"
    )
    sep = "-" * len(header)
    lines = [header, sep]

    for c in connections:
        src = f"{c.src_ip}:{c.src_port}"
        dst = f"{c.dst_ip}:{c.dst_port}"
        lines.append(
            f"{c.index:>4}  {src:>21}  {dst:>21}  "
            f"{c.duration:>10.3f}  {c.init_bytes:>8}  {c.resp_bytes:>8}  "
            f"{c.final_state_initiator.name:>14}  {c.final_state_responder.name:>14}  "
            f"{len(c.anomalies):>9}"
        )

    return "\n".join(lines) + "\n"


def render_connection_detail(conn: Connection) -> str:
    lines: list[str] = []
    src = f"{conn.src_ip}:{conn.src_port}"
    dst = f"{conn.dst_ip}:{conn.dst_port}"
    lines.append(f"Connection #{conn.index}  {src} → {dst}")
    lines.append(f"  Duration : {conn.duration:.3f}s")
    lines.append(f"  Packets  : {conn.packet_count}")
    lines.append(f"  TX bytes : {conn.init_bytes}  (initiator → responder)")
    lines.append(f"  RX bytes : {conn.resp_bytes}  (responder → initiator)")
    lines.append(f"  Final    : initiator={conn.final_state_initiator.name}  responder={conn.final_state_responder.name}")
    lines.append("")

    if conn.transitions:
        lines.append("  State transitions:")
        for t in conn.transitions:
            lines.append(
                f"    t={_ts(t.timestamp)}  pkt#{t.packet_index:>4}  [{t.side[:4]}]  "
                f"{t.from_state.name:>14} --{t.event.name}--> {t.to_state.name}"
            )
    else:
        lines.append("  (no state transitions recorded)")

    lines.append("")

    if conn.anomalies:
        lines.append(f"  Anomalies ({len(conn.anomalies)}):")
        for a in conn.anomalies:
            lines.append(_fmt_anomaly(a))
    else:
        lines.append("  No anomalies detected.")

    lines.append("")
    return "\n".join(lines)


def _conn_to_dict(conn: Connection) -> dict:
    return {
        "index": conn.index,
        "src_ip": conn.src_ip,
        "src_port": conn.src_port,
        "dst_ip": conn.dst_ip,
        "dst_port": conn.dst_port,
        "duration": conn.duration,
        "init_bytes": conn.init_bytes,
        "resp_bytes": conn.resp_bytes,
        "packet_count": conn.packet_count,
        "final_state_initiator": conn.final_state_initiator.name,
        "final_state_responder": conn.final_state_responder.name,
        "transitions": [
            {
                "timestamp": t.timestamp,
                "packet_index": t.packet_index,
                "event": t.event.name,
                "from_state": t.from_state.name,
                "to_state": t.to_state.name,
                "side": t.side,
            }
            for t in conn.transitions
        ],
        "anomalies": [
            {
                "kind": a.kind.value,
                "timestamp": a.timestamp,
                "packet_index": a.packet_index,
                "description": a.description,
            }
            for a in conn.anomalies
        ],
    }


def render_json(connections: list[Connection]) -> str:
    return json.dumps([_conn_to_dict(c) for c in connections], indent=2)
