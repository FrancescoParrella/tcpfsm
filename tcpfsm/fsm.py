"""
TCP Finite State Machine — table-driven per RFC 793.

Events are derived from TCP flag combinations and packet direction (initiator/responder).
Each connection is tracked from both sides independently; the FSM state here
represents the *initiator's* local TCP state. The responder side is a mirror.

State names match RFC 793 exactly.
"""

from enum import Enum, auto


class State(Enum):
    CLOSED = auto()
    LISTEN = auto()
    SYN_SENT = auto()
    SYN_RECEIVED = auto()
    ESTABLISHED = auto()
    FIN_WAIT_1 = auto()
    FIN_WAIT_2 = auto()
    CLOSE_WAIT = auto()
    CLOSING = auto()
    LAST_ACK = auto()
    TIME_WAIT = auto()


class Event(Enum):
    # Sent by this side
    SEND_SYN = auto()
    SEND_SYN_ACK = auto()
    SEND_ACK = auto()
    SEND_FIN = auto()
    SEND_FIN_ACK = auto()
    SEND_RST = auto()
    # Received by this side
    RECV_SYN = auto()
    RECV_SYN_ACK = auto()
    RECV_ACK = auto()
    RECV_FIN = auto()
    RECV_FIN_ACK = auto()
    RECV_RST = auto()


# Sentinel: RST closes the connection regardless of current state
RST_EVENTS = {Event.RECV_RST, Event.SEND_RST}

# (current_state, event) -> next_state
# Omitted entries are invalid transitions (anomaly, state unchanged)
TRANSITIONS: dict[tuple[State, Event], State] = {
    # --- Active open (initiator / client side) ---
    (State.CLOSED,         Event.SEND_SYN):      State.SYN_SENT,
    (State.SYN_SENT,       Event.RECV_SYN_ACK):  State.ESTABLISHED,
    # Simultaneous open: both sides send SYN at the same time
    (State.SYN_SENT,       Event.RECV_SYN):       State.SYN_RECEIVED,

    # --- Passive open (responder / server side) ---
    (State.LISTEN,         Event.RECV_SYN):       State.SYN_RECEIVED,
    (State.SYN_RECEIVED,   Event.SEND_SYN_ACK):   State.SYN_RECEIVED,  # SYN-ACK sent, still waiting for ACK
    (State.SYN_RECEIVED,   Event.RECV_ACK):        State.ESTABLISHED,
    # Simultaneous open: SYN_RECEIVED receives SYN-ACK from peer
    (State.SYN_RECEIVED,   Event.RECV_SYN_ACK):   State.ESTABLISHED,

    # --- Active close (initiator of close) ---
    (State.ESTABLISHED,    Event.SEND_FIN):        State.FIN_WAIT_1,
    (State.ESTABLISHED,    Event.SEND_FIN_ACK):    State.FIN_WAIT_1,
    (State.FIN_WAIT_1,     Event.RECV_ACK):         State.FIN_WAIT_2,
    (State.FIN_WAIT_1,     Event.RECV_FIN):         State.CLOSING,       # simultaneous close
    (State.FIN_WAIT_1,     Event.RECV_FIN_ACK):    State.TIME_WAIT,      # FIN+ACK together
    (State.FIN_WAIT_2,     Event.RECV_FIN):         State.TIME_WAIT,
    (State.FIN_WAIT_2,     Event.RECV_FIN_ACK):    State.TIME_WAIT,
    (State.CLOSING,        Event.RECV_ACK):         State.TIME_WAIT,
    (State.TIME_WAIT,      Event.SEND_ACK):         State.TIME_WAIT,     # ACK of peer's FIN

    # --- Passive close (receiver of first FIN) ---
    (State.ESTABLISHED,    Event.RECV_FIN):         State.CLOSE_WAIT,
    (State.ESTABLISHED,    Event.RECV_FIN_ACK):    State.CLOSE_WAIT,
    (State.CLOSE_WAIT,     Event.SEND_FIN):         State.LAST_ACK,
    (State.CLOSE_WAIT,     Event.SEND_FIN_ACK):    State.LAST_ACK,
    (State.LAST_ACK,       Event.RECV_ACK):         State.CLOSED,

    # --- RST handling: any state can receive RST → CLOSED ---
    # (handled separately via RST_EVENTS sentinel to avoid enumerating every state)

    # --- SYN_RECEIVED can also transition back to LISTEN on RST (server-side reset) ---
    (State.SYN_RECEIVED,   Event.RECV_RST):        State.LISTEN,
}


def next_state(current: State, event: Event) -> tuple[State, bool]:
    """
    Return (new_state, was_valid_transition).

    RST always moves to CLOSED (except from CLOSED itself, which stays CLOSED).
    Unknown transitions return current state with was_valid=False.
    """
    if event in RST_EVENTS:
        # SYN_RECEIVED → LISTEN on server RST is already in table; handle all other cases
        result = TRANSITIONS.get((current, event))
        if result is not None:
            return result, True
        return State.CLOSED, current != State.CLOSED

    result = TRANSITIONS.get((current, event))
    if result is None:
        return current, False
    return result, True


def flags_to_events(flags: int, is_sender: bool) -> list[Event]:
    """
    Derive FSM event(s) from raw TCP flags and direction.

    is_sender=True  → this packet was sent by the side whose state we're tracking
    is_sender=False → this packet was received by that side

    Returns a list because a single packet can carry e.g. FIN+ACK.
    We collapse flag combos to the most specific event first (SYN_ACK > SYN, FIN_ACK > FIN).
    """
    SYN = bool(flags & 0x02)
    ACK = bool(flags & 0x10)
    FIN = bool(flags & 0x01)
    RST = bool(flags & 0x04)

    if RST:
        return [Event.SEND_RST if is_sender else Event.RECV_RST]

    events = []
    if SYN and ACK:
        events.append(Event.SEND_SYN_ACK if is_sender else Event.RECV_SYN_ACK)
    elif SYN:
        events.append(Event.SEND_SYN if is_sender else Event.RECV_SYN)
    elif FIN and ACK:
        events.append(Event.SEND_FIN_ACK if is_sender else Event.RECV_FIN_ACK)
    elif FIN:
        events.append(Event.SEND_FIN if is_sender else Event.RECV_FIN)
    elif ACK:
        events.append(Event.SEND_ACK if is_sender else Event.RECV_ACK)

    return events
