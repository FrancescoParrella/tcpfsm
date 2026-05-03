from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from .anomaly import Anomaly, AnomalyKind, SideTracker, check_zero_window
from .fsm import Event, State, TcpFsm, flags_to_events, next_state
from .pcap_reader import Packet

# (init_ip, init_port, resp_ip, resp_port) — always initiator-first
ConnKey = tuple[str, int, str, int]

# Well-known server ports for mid-stream initiator heuristic
_WELL_KNOWN_EXTRA: frozenset[int] = frozenset({
    3306, 5432, 6379, 6380, 8080, 8443, 8888,
    9200, 9300, 27017, 5672, 15672,
})


def _is_server_port(port: int) -> bool:
    return port < 1024 or port in _WELL_KNOWN_EXTRA


def _identify_initiator(
    src_ip: str, src_port: int,
    dst_ip: str, dst_port: int,
    flags: int,
) -> tuple[str, int, str, int, bool]:
    """Return (init_ip, init_port, resp_ip, resp_port, mid_stream).

    If a SYN without ACK is present, the sender is unambiguously the initiator.
    Otherwise (mid-stream): use well-known-port heuristic; fallback to first src.
    """
    if flags & 0x02 and not (flags & 0x10):   # SYN without ACK
        return src_ip, src_port, dst_ip, dst_port, False

    src_server = _is_server_port(src_port)
    dst_server = _is_server_port(dst_port)

    if dst_server and not src_server:
        return src_ip, src_port, dst_ip, dst_port, True   # src = client
    if src_server and not dst_server:
        return dst_ip, dst_port, src_ip, src_port, True   # dst = client
    return src_ip, src_port, dst_ip, dst_port, True        # fallback


# States from which a new connection must be created on the same 4-tuple
_TERMINAL_STATES: frozenset[State] = frozenset({State.CLOSED, State.TIME_WAIT})


@dataclass
class Transition:
    timestamp:    float
    packet_index: int
    event:        Event
    from_state:   State
    to_state:     State
    side:         str   # "initiator" | "responder"


@dataclass
class Connection:
    key:        ConnKey
    index:      int
    mid_stream: bool

    # Initialized by __post_init__
    init_fsm:     TcpFsm      = field(init=False)
    resp_fsm:     TcpFsm      = field(init=False)
    first_ts:     float       = field(init=False, default=0.0)
    last_ts:      float       = field(init=False, default=0.0)
    init_bytes:   int         = field(init=False, default=0)
    resp_bytes:   int         = field(init=False, default=0)
    packet_count: int         = field(init=False, default=0)
    transitions:  list        = field(init=False, default_factory=list)
    anomalies:    list        = field(init=False, default_factory=list)

    _init_tracker: SideTracker      = field(init=False, repr=False)
    _resp_tracker: SideTracker      = field(init=False, repr=False)
    _syn_ts:       Optional[float]  = field(init=False, repr=False)
    _syn_acked:    bool             = field(init=False, repr=False)

    def __post_init__(self) -> None:
        if self.mid_stream:
            self.init_fsm = TcpFsm.observed()
            self.resp_fsm = TcpFsm(initial=State.OBSERVED_ESTABLISHED, mid_stream=True)
        else:
            self.init_fsm = TcpFsm(initial=State.CLOSED)
            self.resp_fsm = TcpFsm(initial=State.LISTEN)
        self._init_tracker = SideTracker()
        self._resp_tracker = SideTracker()
        self._syn_ts   = None
        self._syn_acked = False

    # ── public packet processing ──────────────────────────────────────────────

    def process_packet(self, pkt: Packet) -> None:
        self.packet_count += 1
        if self.first_ts == 0.0:
            self.first_ts = pkt.timestamp
        self.last_ts = pkt.timestamp

        from_initiator = (pkt.src_ip == self.key[0] and pkt.src_port == self.key[1])

        if from_initiator:
            self.init_bytes += pkt.payload_len
        else:
            self.resp_bytes += pkt.payload_len

        # Sequence anomaly detection (data packets only)
        tracker = self._init_tracker if from_initiator else self._resp_tracker
        self.anomalies.extend(
            tracker.observe(pkt.seq, pkt.payload_len, pkt.timestamp, pkt.index)
        )

        # Zero-window
        zw = check_zero_window(pkt.window, pkt.timestamp, pkt.index)
        if zw:
            self.anomalies.append(zw)

        # Flag decomposition
        SYN = bool(pkt.flags & 0x02)
        ACK = bool(pkt.flags & 0x10)
        RST = bool(pkt.flags & 0x04)

        # Half-open tracking
        if SYN and not ACK and from_initiator and self._syn_ts is None:
            self._syn_ts = pkt.timestamp
        if SYN and ACK and not from_initiator:
            self._syn_acked = True

        # Save states before applying events (needed for post-event anomaly checks)
        prev_init = self.init_fsm.state
        prev_resp = self.resp_fsm.state

        # Connection refused: RST from responder while initiator is in SYN_SENT
        if RST and not from_initiator and prev_init == State.SYN_SENT:
            self.anomalies.append(Anomaly(
                kind=AnomalyKind.CONNECTION_REFUSED,
                timestamp=pkt.timestamp,
                description="Connection refused: RST received in response to SYN",
                packet_index=pkt.index,
            ))

        # Apply FSM events for both sides
        send_evs = flags_to_events(pkt.flags, is_sender=True)
        recv_evs = flags_to_events(pkt.flags, is_sender=False)

        if from_initiator:
            for ev in send_evs:
                self._apply(ev, "initiator", pkt.timestamp, pkt.index)
            for ev in recv_evs:
                self._apply(ev, "responder", pkt.timestamp, pkt.index)
        else:
            for ev in send_evs:
                self._apply(ev, "responder", pkt.timestamp, pkt.index)
            for ev in recv_evs:
                self._apply(ev, "initiator", pkt.timestamp, pkt.index)

        # Unexpected RST: either side just went ESTABLISHED → CLOSED via RST
        if RST:
            if prev_init == State.ESTABLISHED and self.init_fsm.state == State.CLOSED:
                self.anomalies.append(Anomaly(
                    kind=AnomalyKind.UNEXPECTED_RST,
                    timestamp=pkt.timestamp,
                    description="Unexpected RST during ESTABLISHED (initiator)",
                    packet_index=pkt.index,
                ))
            elif prev_resp == State.ESTABLISHED and self.resp_fsm.state == State.CLOSED:
                self.anomalies.append(Anomaly(
                    kind=AnomalyKind.UNEXPECTED_RST,
                    timestamp=pkt.timestamp,
                    description="Unexpected RST during ESTABLISHED (responder)",
                    packet_index=pkt.index,
                ))

    def finalize(self, capture_end_ts: float, half_open_timeout: float = 30.0) -> None:
        if (
            self._syn_ts is not None
            and not self._syn_acked
            and self.init_fsm.state == State.SYN_SENT
            and (capture_end_ts - self._syn_ts) > half_open_timeout
        ):
            self.anomalies.append(Anomaly(
                kind=AnomalyKind.HALF_OPEN,
                timestamp=self._syn_ts,
                description=(
                    f"Half-open: SYN at t={self._syn_ts:.3f}s, "
                    f"no SYN-ACK after {capture_end_ts - self._syn_ts:.1f}s"
                ),
                packet_index=-1,
            ))

    # ── internal FSM application ──────────────────────────────────────────────

    def _apply(self, event: Event, side: str, ts: float, idx: int) -> None:
        fsm = self.init_fsm if side == "initiator" else self.resp_fsm
        prev = fsm.state
        new, valid = fsm.process(event)
        if new != prev:
            self.transitions.append(Transition(
                timestamp=ts, packet_index=idx,
                event=event, from_state=prev, to_state=new, side=side,
            ))
        elif not valid:
            self.anomalies.append(Anomaly(
                kind=AnomalyKind.INVALID_TRANSITION,
                timestamp=ts,
                description=f"Invalid: {prev.name} + {event.name} ({side})",
                packet_index=idx,
            ))

    # ── public properties ─────────────────────────────────────────────────────

    @property
    def is_closed(self) -> bool:
        return (self.init_fsm.state == State.CLOSED
                and self.resp_fsm.state == State.CLOSED)

    @property
    def duration(self) -> float:
        return self.last_ts - self.first_ts

    @property
    def final_state_initiator(self) -> State:
        return self.init_fsm.state

    @property
    def final_state_responder(self) -> State:
        return self.resp_fsm.state

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


class ConnectionTracker:
    """Stateful tracker: accepts a stream of Packets, manages Connection objects."""

    def __init__(self, half_open_timeout: float = 30.0) -> None:
        self._half_open_timeout = half_open_timeout
        self._conns: list[Connection] = []
        # frozenset({(src_ip, src_port), (dst_ip, dst_port)}) → Connection (active only)
        self._active: dict[frozenset, Connection] = {}

    # ── public interface ──────────────────────────────────────────────────────

    def feed(self, pkt: Packet) -> None:
        conn = self._get_or_create(pkt)
        conn.process_packet(pkt)

    def finalize(self, capture_end_ts: float) -> None:
        for conn in self._conns:
            conn.finalize(capture_end_ts, self._half_open_timeout)

    @property
    def connections(self) -> list[Connection]:
        return list(self._conns)

    # ── internal helpers ──────────────────────────────────────────────────────

    @staticmethod
    def _lookup_key(pkt: Packet) -> frozenset:
        return frozenset({(pkt.src_ip, pkt.src_port), (pkt.dst_ip, pkt.dst_port)})

    @staticmethod
    def _is_terminal(conn: Connection) -> bool:
        return (conn.init_fsm.state in _TERMINAL_STATES
                and conn.resp_fsm.state in _TERMINAL_STATES)

    def _get_or_create(self, pkt: Packet) -> Connection:
        key = self._lookup_key(pkt)
        existing = self._active.get(key)

        if existing is not None and not self._is_terminal(existing):
            return existing

        # Terminal or new: create a fresh Connection
        if existing is not None:
            del self._active[key]

        init_ip, init_port, resp_ip, resp_port, mid_stream = _identify_initiator(
            pkt.src_ip, pkt.src_port, pkt.dst_ip, pkt.dst_port, pkt.flags,
        )
        conn = Connection(
            key=(init_ip, init_port, resp_ip, resp_port),
            index=len(self._conns) + 1,
            mid_stream=mid_stream,
        )
        self._conns.append(conn)
        self._active[key] = conn
        return conn
