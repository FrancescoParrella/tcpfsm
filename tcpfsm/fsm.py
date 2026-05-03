from enum import Enum, auto


class State(Enum):
    CLOSED               = auto()
    LISTEN               = auto()
    SYN_SENT             = auto()
    SYN_RECEIVED         = auto()
    ESTABLISHED          = auto()
    OBSERVED_ESTABLISHED = auto()  # mid-stream: handshake not captured
    FIN_WAIT_1           = auto()
    FIN_WAIT_2           = auto()
    CLOSE_WAIT           = auto()
    CLOSING              = auto()
    LAST_ACK             = auto()
    TIME_WAIT            = auto()


class Event(Enum):
    # Sent by tracked side
    SEND_SYN     = auto()
    SEND_SYN_ACK = auto()
    SEND_ACK     = auto()
    SEND_FIN     = auto()
    SEND_FIN_ACK = auto()
    SEND_RST     = auto()
    # Received by tracked side
    RECV_SYN     = auto()
    RECV_SYN_ACK = auto()
    RECV_ACK     = auto()
    RECV_FIN     = auto()
    RECV_FIN_ACK = auto()  # FIN+ACK that also ACKs our in-flight FIN (RFC 793 §3.5 shortcut)
    RECV_RST     = auto()
    # Timer
    TIMEOUT      = auto()  # 2MSL expiry (TIME_WAIT) or connect timeout (SYN_SENT)


# (current_state, event) -> next_state
# Omitted entries are invalid/no-op (state unchanged, anomaly flag set by caller).
TRANSITIONS: dict[tuple[State, Event], State] = {

    # ── CLOSED ───────────────────────────────────────────────────────────────
    (State.CLOSED,               Event.SEND_SYN):     State.SYN_SENT,
    (State.CLOSED,               Event.RECV_SYN):     State.SYN_RECEIVED,   # pcap: skip LISTEN

    # ── LISTEN ───────────────────────────────────────────────────────────────
    (State.LISTEN,               Event.RECV_SYN):     State.SYN_RECEIVED,

    # ── SYN_SENT ─────────────────────────────────────────────────────────────
    (State.SYN_SENT,             Event.RECV_SYN_ACK): State.ESTABLISHED,    # normal 3WHS
    (State.SYN_SENT,             Event.RECV_SYN):     State.SYN_RECEIVED,   # simultaneous open
    (State.SYN_SENT,             Event.RECV_RST):     State.CLOSED,
    (State.SYN_SENT,             Event.TIMEOUT):      State.CLOSED,         # no response / refused

    # ── SYN_RECEIVED ─────────────────────────────────────────────────────────
    (State.SYN_RECEIVED,         Event.RECV_ACK):     State.ESTABLISHED,    # normal 3WHS
    (State.SYN_RECEIVED,         Event.RECV_SYN_ACK): State.ESTABLISHED,   # simultaneous open
    (State.SYN_RECEIVED,         Event.SEND_FIN):     State.FIN_WAIT_1,    # abort before ESTABLISHED
    (State.SYN_RECEIVED,         Event.RECV_FIN):     State.CLOSE_WAIT,    # RFC edge: FIN before ACK
    (State.SYN_RECEIVED,         Event.RECV_RST):     State.CLOSED,

    # ── ESTABLISHED ──────────────────────────────────────────────────────────
    (State.ESTABLISHED,          Event.SEND_FIN):     State.FIN_WAIT_1,
    (State.ESTABLISHED,          Event.SEND_FIN_ACK): State.FIN_WAIT_1,
    (State.ESTABLISHED,          Event.RECV_FIN):     State.CLOSE_WAIT,
    (State.ESTABLISHED,          Event.RECV_FIN_ACK): State.CLOSE_WAIT,
    (State.ESTABLISHED,          Event.RECV_RST):     State.CLOSED,
    (State.ESTABLISHED,          Event.SEND_RST):     State.CLOSED,

    # ── OBSERVED_ESTABLISHED ─────────────────────────────────────────────────
    # Mid-stream connections where the handshake was not captured.
    # Identical transitions to ESTABLISHED; TcpFsm.mid_stream=True is set at creation.
    (State.OBSERVED_ESTABLISHED, Event.SEND_FIN):     State.FIN_WAIT_1,
    (State.OBSERVED_ESTABLISHED, Event.SEND_FIN_ACK): State.FIN_WAIT_1,
    (State.OBSERVED_ESTABLISHED, Event.RECV_FIN):     State.CLOSE_WAIT,
    (State.OBSERVED_ESTABLISHED, Event.RECV_FIN_ACK): State.CLOSE_WAIT,
    (State.OBSERVED_ESTABLISHED, Event.RECV_RST):     State.CLOSED,
    (State.OBSERVED_ESTABLISHED, Event.SEND_RST):     State.CLOSED,

    # ── FIN_WAIT_1 ────────────────────────────────────────────────────────────
    (State.FIN_WAIT_1,           Event.RECV_ACK):     State.FIN_WAIT_2,    # our FIN ACKed
    (State.FIN_WAIT_1,           Event.RECV_FIN):     State.CLOSING,       # simultaneous close
    (State.FIN_WAIT_1,           Event.RECV_FIN_ACK): State.TIME_WAIT,     # RFC 793 §3.5 shortcut
    (State.FIN_WAIT_1,           Event.RECV_RST):     State.CLOSED,

    # ── FIN_WAIT_2 ────────────────────────────────────────────────────────────
    (State.FIN_WAIT_2,           Event.RECV_FIN):     State.TIME_WAIT,
    (State.FIN_WAIT_2,           Event.RECV_FIN_ACK): State.TIME_WAIT,
    (State.FIN_WAIT_2,           Event.RECV_RST):     State.CLOSED,

    # ── CLOSE_WAIT ────────────────────────────────────────────────────────────
    (State.CLOSE_WAIT,           Event.SEND_FIN):     State.LAST_ACK,
    (State.CLOSE_WAIT,           Event.SEND_FIN_ACK): State.LAST_ACK,
    (State.CLOSE_WAIT,           Event.RECV_RST):     State.CLOSED,

    # ── CLOSING ───────────────────────────────────────────────────────────────
    (State.CLOSING,              Event.RECV_ACK):     State.TIME_WAIT,
    (State.CLOSING,              Event.RECV_RST):     State.CLOSED,

    # ── LAST_ACK ──────────────────────────────────────────────────────────────
    (State.LAST_ACK,             Event.RECV_ACK):     State.CLOSED,
    (State.LAST_ACK,             Event.RECV_RST):     State.CLOSED,

    # ── TIME_WAIT ─────────────────────────────────────────────────────────────
    (State.TIME_WAIT,            Event.TIMEOUT):      State.CLOSED,        # 2MSL expired
    (State.TIME_WAIT,            Event.RECV_RST):     State.CLOSED,
    (State.TIME_WAIT,            Event.RECV_SYN):     State.SYN_RECEIVED,  # port reuse
    (State.TIME_WAIT,            Event.SEND_ACK):     State.TIME_WAIT,     # ACK of peer FIN

    # ── Self-loops: events that are valid but don't change state ──────────────
    # Needed so that normal data-flow ACKs and server SYN-ACK output don't
    # generate spurious INVALID_TRANSITION anomalies in the connection tracker.
    (State.SYN_RECEIVED,         Event.SEND_SYN_ACK): State.SYN_RECEIVED,  # server 3WHS output
    (State.ESTABLISHED,          Event.SEND_ACK):     State.ESTABLISHED,   # data ack
    (State.ESTABLISHED,          Event.RECV_ACK):     State.ESTABLISHED,   # data ack
    (State.OBSERVED_ESTABLISHED, Event.SEND_ACK):     State.OBSERVED_ESTABLISHED,
    (State.OBSERVED_ESTABLISHED, Event.RECV_ACK):     State.OBSERVED_ESTABLISHED,
    (State.CLOSE_WAIT,           Event.SEND_ACK):     State.CLOSE_WAIT,    # ACK of peer FIN
    (State.FIN_WAIT_1,           Event.SEND_ACK):     State.FIN_WAIT_1,    # piggybacked ACK
    (State.FIN_WAIT_2,           Event.SEND_ACK):     State.FIN_WAIT_2,

    # ── SEND_RST from all remaining active states ─────────────────────────────
    (State.SYN_SENT,             Event.SEND_RST):     State.CLOSED,
    (State.SYN_RECEIVED,         Event.SEND_RST):     State.CLOSED,
    (State.FIN_WAIT_1,           Event.SEND_RST):     State.CLOSED,
    (State.FIN_WAIT_2,           Event.SEND_RST):     State.CLOSED,
    (State.CLOSE_WAIT,           Event.SEND_RST):     State.CLOSED,
    (State.CLOSING,              Event.SEND_RST):     State.CLOSED,
    (State.LAST_ACK,             Event.SEND_RST):     State.CLOSED,
    (State.TIME_WAIT,            Event.SEND_RST):     State.CLOSED,
}


def next_state(current: State, event: Event) -> tuple[State, bool]:
    """Return (new_state, was_valid_transition).

    Unknown (state, event) pairs return current state with was_valid=False.
    """
    result = TRANSITIONS.get((current, event))
    if result is None:
        return current, False
    return result, True


class TcpFsm:
    """Stateful wrapper around the transition table for a single TCP endpoint."""

    def __init__(self, initial: State = State.CLOSED, mid_stream: bool = False) -> None:
        self.state = initial
        self.mid_stream = mid_stream

    def process(self, event: Event) -> tuple[State, bool]:
        self.state, valid = next_state(self.state, event)
        return self.state, valid

    @classmethod
    def observed(cls) -> "TcpFsm":
        """FSM for connections whose handshake was not present in the capture."""
        return cls(initial=State.OBSERVED_ESTABLISHED, mid_stream=True)


def flags_to_events(flags: int, is_sender: bool) -> list[Event]:
    """Derive FSM event(s) from raw TCP flags and packet direction.

    is_sender=True  → packet was sent by the tracked side
    is_sender=False → packet was received by the tracked side
    """
    SYN = bool(flags & 0x02)
    ACK = bool(flags & 0x10)
    FIN = bool(flags & 0x01)
    RST = bool(flags & 0x04)

    if RST:
        return [Event.SEND_RST if is_sender else Event.RECV_RST]

    if SYN and ACK:
        return [Event.SEND_SYN_ACK if is_sender else Event.RECV_SYN_ACK]
    if SYN:
        return [Event.SEND_SYN if is_sender else Event.RECV_SYN]
    if FIN and ACK:
        return [Event.SEND_FIN_ACK if is_sender else Event.RECV_FIN_ACK]
    if FIN:
        return [Event.SEND_FIN if is_sender else Event.RECV_FIN]
    if ACK:
        return [Event.SEND_ACK if is_sender else Event.RECV_ACK]

    return []
