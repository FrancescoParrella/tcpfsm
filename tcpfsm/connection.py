"""
Connection — tracks a single TCP 4-tuple through the RFC 793 FSM.

Each side (initiator / responder) has its own FSM state and SideTracker.
The initiator is the side that sent the first SYN.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from .fsm import State, Event, flags_to_events, next_state
from .anomaly import Anomaly, AnomalyKind, SideTracker, check_zero_window


ConnKey = tuple[str, int, str, int]  # (src_ip, src_port, dst_ip, dst_port) — always initiator-first


@dataclass
class Transition:
    timestamp: float
    packet_index: int
    event: Event
    from_state: State
    to_state: State
    side: str  # "initiator" | "responder"


@dataclass
class Connection:
    key: ConnKey                        # (init_ip, init_port, resp_ip, resp_port)
    index: int                          # global connection index (1-based)

    # Per-side FSM states
    init_state: State = State.CLOSED
    resp_state: State = State.LISTEN    # server starts listening

    # Timeline
    transitions: list[Transition] = field(default_factory=list)
    anomalies: list[Anomaly] = field(default_factory=list)

    # Stats
    first_ts: float = 0.0
    last_ts: float = 0.0
    init_bytes: int = 0
    resp_bytes: int = 0
    packet_count: int = 0

    # Half-open detection: time of first SYN
    syn_ts: Optional[float] = None
    syn_acked: bool = False

    # Per-side sequence trackers
    _init_tracker: SideTracker = field(default_factory=SideTracker)
    _resp_tracker: SideTracker = field(default_factory=SideTracker)

    # Half-open timeout in seconds (configurable)
    half_open_timeout: float = 5.0

    def process_packet(
        self,
        timestamp: float,
        flags: int,
        seq: int,
        ack: int,
        window: int,
        payload_len: int,
        from_initiator: bool,
        packet_index: int,
    ) -> None:
        self.packet_count += 1
        if self.first_ts == 0.0:
            self.first_ts = timestamp
        self.last_ts = timestamp

        if from_initiator:
            self.init_bytes += payload_len
        else:
            self.resp_bytes += payload_len

        # --- Sequence anomalies ---
        tracker = self._init_tracker if from_initiator else self._resp_tracker
        self.anomalies.extend(tracker.observe(seq, payload_len, timestamp, packet_index))

        # --- Zero window ---
        zw = check_zero_window(window, timestamp, packet_index)
        if zw:
            self.anomalies.append(zw)

        # --- Half-open tracking ---
        SYN = bool(flags & 0x02)
        ACK = bool(flags & 0x10)
        RST = bool(flags & 0x04)

        if SYN and not ACK and from_initiator and self.syn_ts is None:
            self.syn_ts = timestamp
        if SYN and ACK and not from_initiator:
            self.syn_acked = True
        if RST and not ACK and not from_initiator and self.init_state == State.SYN_SENT:
            self.anomalies.append(Anomaly(
                kind=AnomalyKind.CONNECTION_REFUSED,
                timestamp=timestamp,
                description="Connection refused: RST received in response to SYN",
                packet_index=packet_index,
            ))

        # --- FSM transitions (apply to both sides) ---
        # from_initiator=True → initiator is the sender; for the responder it's a recv
        events_as_sender = flags_to_events(flags, is_sender=True)
        events_as_recver = flags_to_events(flags, is_sender=False)

        if from_initiator:
            # initiator perspective: sending
            for ev in events_as_sender:
                self._apply(ev, from_side="initiator", timestamp=timestamp, packet_index=packet_index)
            # responder perspective: receiving
            for ev in events_as_recver:
                self._apply(ev, from_side="responder", timestamp=timestamp, packet_index=packet_index)
        else:
            # responder perspective: sending
            for ev in events_as_sender:
                self._apply(ev, from_side="responder", timestamp=timestamp, packet_index=packet_index)
            # initiator perspective: receiving
            for ev in events_as_recver:
                self._apply(ev, from_side="initiator", timestamp=timestamp, packet_index=packet_index)

        # Unexpected RST during ESTABLISHED (after we've already transitioned — check anomaly)
        # We check the state *before* the packet was processed stored via transitions list
        if RST and len(self.transitions) >= 1:
            last_t = self.transitions[-1]
            # If we just transitioned to CLOSED from ESTABLISHED via RST
            if last_t.from_state == State.ESTABLISHED and last_t.to_state == State.CLOSED:
                self.anomalies.append(Anomaly(
                    kind=AnomalyKind.UNEXPECTED_RST,
                    timestamp=timestamp,
                    description=f"Unexpected RST during ESTABLISHED on {last_t.side} side",
                    packet_index=packet_index,
                ))

    def _apply(self, event: Event, from_side: str, timestamp: float, packet_index: int) -> None:
        if from_side == "initiator":
            current = self.init_state
            new_state, valid = next_state(current, event)
            if new_state != current:
                self.transitions.append(Transition(
                    timestamp=timestamp,
                    packet_index=packet_index,
                    event=event,
                    from_state=current,
                    to_state=new_state,
                    side="initiator",
                ))
                self.init_state = new_state
            elif not valid:
                self.anomalies.append(Anomaly(
                    kind=AnomalyKind.INVALID_TRANSITION,
                    timestamp=timestamp,
                    description=f"Invalid transition: {current.name} + {event.name} (initiator)",
                    packet_index=packet_index,
                ))
        else:
            current = self.resp_state
            new_state, valid = next_state(current, event)
            if new_state != current:
                self.transitions.append(Transition(
                    timestamp=timestamp,
                    packet_index=packet_index,
                    event=event,
                    from_state=current,
                    to_state=new_state,
                    side="responder",
                ))
                self.resp_state = new_state
            elif not valid:
                self.anomalies.append(Anomaly(
                    kind=AnomalyKind.INVALID_TRANSITION,
                    timestamp=timestamp,
                    description=f"Invalid transition: {current.name} + {event.name} (responder)",
                    packet_index=packet_index,
                ))

    def check_half_open(self, capture_end_ts: float) -> None:
        """Call after all packets processed to detect half-open connections."""
        if (
            self.syn_ts is not None
            and not self.syn_acked
            and self.init_state == State.SYN_SENT
            and (capture_end_ts - self.syn_ts) > self.half_open_timeout
        ):
            self.anomalies.append(Anomaly(
                kind=AnomalyKind.HALF_OPEN,
                timestamp=self.syn_ts,
                description=(
                    f"Half-open: SYN sent at t={self.syn_ts:.3f} with no SYN-ACK "
                    f"after {capture_end_ts - self.syn_ts:.1f}s"
                ),
                packet_index=-1,
            ))

    @property
    def duration(self) -> float:
        return self.last_ts - self.first_ts

    @property
    def final_state_initiator(self) -> State:
        return self.init_state

    @property
    def final_state_responder(self) -> State:
        return self.resp_state

    @property
    def src_ip(self) -> str:
        return self.key[0]

    @property
    def src_port(self) -> int:
        return self.key[1]

    @property
    def dst_ip(self) -> str:
        return self.key[2]

    @property
    def dst_port(self) -> int:
        return self.key[3]
