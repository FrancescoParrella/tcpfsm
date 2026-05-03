"""Anomaly detectors — stateless functions that inspect per-side packet history."""

from dataclasses import dataclass, field
from enum import Enum, auto


class AnomalyKind(Enum):
    RETRANSMISSION = "retransmission"
    OUT_OF_ORDER = "out_of_order"
    UNEXPECTED_RST = "unexpected_rst"
    HALF_OPEN = "half_open"
    CONNECTION_REFUSED = "connection_refused"
    ZERO_WINDOW = "zero_window"
    INVALID_TRANSITION = "invalid_transition"


@dataclass
class Anomaly:
    kind: AnomalyKind
    timestamp: float
    description: str
    packet_index: int


class SideTracker:
    """
    Tracks per-direction sequence state for retransmission / out-of-order detection.
    Call observe(seq, length, timestamp, index) for each packet on one side.
    """

    def __init__(self) -> None:
        self._seen_seqs: set[int] = set()
        self._max_seq_end: int | None = None  # highest seq+len seen so far

    def observe(self, seq: int, length: int, timestamp: float, index: int) -> list[Anomaly]:
        anomalies: list[Anomaly] = []
        seq_end = seq + max(length, 1)  # treat pure ACKs as occupying 1 virtual byte for ordering

        if seq in self._seen_seqs and length > 0:
            anomalies.append(Anomaly(
                kind=AnomalyKind.RETRANSMISSION,
                timestamp=timestamp,
                description=f"Retransmission: seq={seq} already seen",
                packet_index=index,
            ))
        elif self._max_seq_end is not None and seq < self._max_seq_end and length > 0:
            anomalies.append(Anomaly(
                kind=AnomalyKind.OUT_OF_ORDER,
                timestamp=timestamp,
                description=f"Out-of-order: seq={seq} < max seen end={self._max_seq_end}",
                packet_index=index,
            ))

        if length > 0:
            self._seen_seqs.add(seq)
            if self._max_seq_end is None or seq_end > self._max_seq_end:
                self._max_seq_end = seq_end

        return anomalies


def check_zero_window(window: int, timestamp: float, index: int) -> Anomaly | None:
    if window == 0:
        return Anomaly(
            kind=AnomalyKind.ZERO_WINDOW,
            timestamp=timestamp,
            description="Zero receive window advertised",
            packet_index=index,
        )
    return None
