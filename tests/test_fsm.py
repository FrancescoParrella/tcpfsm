"""Unit tests for the TCP FSM — no pcap required, stdlib only."""

import unittest
from tcpfsm.fsm import Event, State, TcpFsm, TRANSITIONS, next_state, flags_to_events


_ACTIVE_STATES = [
    State.SYN_SENT,
    State.SYN_RECEIVED,
    State.ESTABLISHED,
    State.OBSERVED_ESTABLISHED,
    State.FIN_WAIT_1,
    State.FIN_WAIT_2,
    State.CLOSE_WAIT,
    State.CLOSING,
    State.LAST_ACK,
    State.TIME_WAIT,
]


def _drive(events: list, initial: State = State.CLOSED) -> TcpFsm:
    fsm = TcpFsm(initial=initial)
    for e in events:
        fsm.process(e)
    return fsm


class TestEveryTransition(unittest.TestCase):
    """One subTest per entry in TRANSITIONS — exhaustive table coverage."""

    def test_every_defined_transition(self):
        for (state, event), expected in TRANSITIONS.items():
            with self.subTest(state=state.name, event=event.name):
                fsm = TcpFsm(initial=state)
                new_state, valid = fsm.process(event)
                self.assertEqual(new_state, expected)
                self.assertTrue(valid)

    def test_no_duplicate_keys(self):
        self.assertEqual(len(TRANSITIONS), len(set(TRANSITIONS.keys())))

    def test_all_values_are_states(self):
        for (state, event), nxt in TRANSITIONS.items():
            with self.subTest(state=state.name, event=event.name):
                self.assertIsInstance(nxt, State)


class TestSpecialCases(unittest.TestCase):

    # Case 1: FIN_WAIT_1 → TIME_WAIT shortcut (RFC 793 §3.5)
    def test_fin_wait_1_recv_fin_ack_shortcuts_to_time_wait(self):
        """Linux commonly sends FIN+ACK: must skip FIN_WAIT_2 entirely."""
        fsm = TcpFsm(initial=State.FIN_WAIT_1)
        state, valid = fsm.process(Event.RECV_FIN_ACK)
        self.assertEqual(state, State.TIME_WAIT)
        self.assertTrue(valid)

    def test_fin_wait_1_two_packet_path_still_works(self):
        """Normal path: ACK → FIN_WAIT_2, then FIN → TIME_WAIT."""
        fsm = TcpFsm(initial=State.FIN_WAIT_1)
        fsm.process(Event.RECV_ACK)
        self.assertEqual(fsm.state, State.FIN_WAIT_2)
        fsm.process(Event.RECV_FIN)
        self.assertEqual(fsm.state, State.TIME_WAIT)

    # Case 4: SYN_SENT timeout
    def test_syn_sent_timeout_closes(self):
        """No SYN-ACK within timeout → CLOSED."""
        fsm = TcpFsm(initial=State.SYN_SENT)
        state, valid = fsm.process(Event.TIMEOUT)
        self.assertEqual(state, State.CLOSED)
        self.assertTrue(valid)

    # Case 5: SYN_RECEIVED receives FIN directly
    def test_syn_received_recv_fin_goes_to_close_wait(self):
        """RFC edge: peer sends FIN before our SYN-ACK is ACKed."""
        fsm = TcpFsm(initial=State.SYN_RECEIVED)
        state, valid = fsm.process(Event.RECV_FIN)
        self.assertEqual(state, State.CLOSE_WAIT)
        self.assertTrue(valid)

    # Case 6: OBSERVED_ESTABLISHED mid-stream pseudo-state
    def test_observed_established_initial_state_and_flag(self):
        fsm = TcpFsm.observed()
        self.assertEqual(fsm.state, State.OBSERVED_ESTABLISHED)
        self.assertTrue(fsm.mid_stream)

    def test_observed_established_mirrors_established_transitions(self):
        pairs = [
            (Event.SEND_FIN,     State.FIN_WAIT_1),
            (Event.SEND_FIN_ACK, State.FIN_WAIT_1),
            (Event.RECV_FIN,     State.CLOSE_WAIT),
            (Event.RECV_FIN_ACK, State.CLOSE_WAIT),
            (Event.RECV_RST,     State.CLOSED),
            (Event.SEND_RST,     State.CLOSED),
        ]
        for event, expected in pairs:
            with self.subTest(event=event.name):
                fsm = TcpFsm.observed()
                fsm.process(event)
                self.assertEqual(fsm.state, expected)

    def test_mid_stream_flag_persists_through_close(self):
        fsm = TcpFsm.observed()
        for e in [Event.RECV_FIN, Event.SEND_FIN, Event.RECV_ACK]:
            fsm.process(e)
        self.assertEqual(fsm.state, State.CLOSED)
        self.assertTrue(fsm.mid_stream)


class TestEndToEndFlows(unittest.TestCase):

    def test_client_3whs(self):
        fsm = _drive([Event.SEND_SYN, Event.RECV_SYN_ACK])
        self.assertEqual(fsm.state, State.ESTABLISHED)

    def test_server_3whs(self):
        fsm = _drive([Event.RECV_SYN, Event.RECV_ACK])
        self.assertEqual(fsm.state, State.ESTABLISHED)

    def test_simultaneous_open(self):
        fsm = _drive([Event.SEND_SYN, Event.RECV_SYN, Event.RECV_SYN_ACK])
        self.assertEqual(fsm.state, State.ESTABLISHED)

    def test_active_close_two_packet(self):
        """Peer sends ACK, then FIN as separate packets."""
        fsm = _drive([
            Event.SEND_SYN, Event.RECV_SYN_ACK,
            Event.SEND_FIN, Event.RECV_ACK, Event.RECV_FIN,
        ])
        self.assertEqual(fsm.state, State.TIME_WAIT)

    def test_active_close_one_packet_shortcut(self):
        """Peer sends FIN+ACK in a single packet (RFC 793 §3.5)."""
        fsm = _drive([
            Event.SEND_SYN, Event.RECV_SYN_ACK,
            Event.SEND_FIN, Event.RECV_FIN_ACK,
        ])
        self.assertEqual(fsm.state, State.TIME_WAIT)

    def test_passive_close(self):
        fsm = _drive([
            Event.RECV_SYN, Event.RECV_ACK,
            Event.RECV_FIN, Event.SEND_FIN, Event.RECV_ACK,
        ])
        self.assertEqual(fsm.state, State.CLOSED)

    def test_simultaneous_close(self):
        fsm = _drive([
            Event.SEND_SYN, Event.RECV_SYN_ACK,
            Event.SEND_FIN, Event.RECV_FIN, Event.RECV_ACK,
        ])
        self.assertEqual(fsm.state, State.TIME_WAIT)

    def test_2msl_timeout_closes(self):
        fsm = _drive([
            Event.SEND_SYN, Event.RECV_SYN_ACK,
            Event.SEND_FIN, Event.RECV_FIN_ACK,
            Event.TIMEOUT,
        ])
        self.assertEqual(fsm.state, State.CLOSED)

    def test_rst_aborts_established(self):
        fsm = _drive([Event.SEND_SYN, Event.RECV_SYN_ACK, Event.RECV_RST])
        self.assertEqual(fsm.state, State.CLOSED)

    def test_time_wait_port_reuse(self):
        fsm = _drive([
            Event.SEND_SYN, Event.RECV_SYN_ACK,
            Event.SEND_FIN, Event.RECV_FIN_ACK,
        ])
        self.assertEqual(fsm.state, State.TIME_WAIT)
        fsm.process(Event.RECV_SYN)
        self.assertEqual(fsm.state, State.SYN_RECEIVED)

    def test_mid_stream_passive_close(self):
        fsm = TcpFsm.observed()
        for e in [Event.RECV_FIN, Event.SEND_FIN, Event.RECV_ACK]:
            fsm.process(e)
        self.assertEqual(fsm.state, State.CLOSED)
        self.assertTrue(fsm.mid_stream)


class TestNegative(unittest.TestCase):

    def test_unknown_transition_returns_false_and_keeps_state(self):
        fsm = TcpFsm(initial=State.ESTABLISHED)
        _, valid = fsm.process(Event.SEND_SYN)
        self.assertEqual(fsm.state, State.ESTABLISHED)
        self.assertFalse(valid)

    def test_next_state_unknown_returns_current_and_false(self):
        state, valid = next_state(State.CLOSED, Event.SEND_FIN)
        self.assertEqual(state, State.CLOSED)
        self.assertFalse(valid)

    def test_recv_rst_from_all_active_states_closes(self):
        for state in _ACTIVE_STATES:
            with self.subTest(state=state.name):
                fsm = TcpFsm(initial=state)
                fsm.process(Event.RECV_RST)
                self.assertEqual(fsm.state, State.CLOSED)

    def test_established_send_ack_is_valid_self_loop(self):
        """SEND_ACK from ESTABLISHED must be a valid no-op, not an invalid transition."""
        fsm = TcpFsm(initial=State.ESTABLISHED)
        new_state, valid = fsm.process(Event.SEND_ACK)
        self.assertEqual(new_state, State.ESTABLISHED)
        self.assertTrue(valid)

    def test_send_rst_from_all_active_states_closes(self):
        """SEND_RST must close the connection from every active state."""
        for state in _ACTIVE_STATES:
            with self.subTest(state=state.name):
                fsm = TcpFsm(initial=state)
                new_state, valid = fsm.process(Event.SEND_RST)
                self.assertEqual(new_state, State.CLOSED)
                self.assertTrue(valid)


class TestFlagsToEvents(unittest.TestCase):

    def test_syn_sender(self):
        self.assertEqual(flags_to_events(0x02, True),  [Event.SEND_SYN])

    def test_syn_receiver(self):
        self.assertEqual(flags_to_events(0x02, False), [Event.RECV_SYN])

    def test_syn_ack_sender(self):
        self.assertEqual(flags_to_events(0x12, True),  [Event.SEND_SYN_ACK])

    def test_syn_ack_receiver(self):
        self.assertEqual(flags_to_events(0x12, False), [Event.RECV_SYN_ACK])

    def test_fin_ack_sender(self):
        self.assertEqual(flags_to_events(0x11, True),  [Event.SEND_FIN_ACK])

    def test_fin_ack_receiver(self):
        self.assertEqual(flags_to_events(0x11, False), [Event.RECV_FIN_ACK])

    def test_fin_only_sender(self):
        self.assertEqual(flags_to_events(0x01, True),  [Event.SEND_FIN])

    def test_fin_only_receiver(self):
        self.assertEqual(flags_to_events(0x01, False), [Event.RECV_FIN])

    def test_ack_only_sender(self):
        self.assertEqual(flags_to_events(0x10, True),  [Event.SEND_ACK])

    def test_ack_only_receiver(self):
        self.assertEqual(flags_to_events(0x10, False), [Event.RECV_ACK])

    def test_rst_sender(self):
        self.assertEqual(flags_to_events(0x04, True),  [Event.SEND_RST])

    def test_rst_receiver(self):
        self.assertEqual(flags_to_events(0x04, False), [Event.RECV_RST])

    def test_pure_data_no_flags(self):
        self.assertEqual(flags_to_events(0x00, True),  [])
        self.assertEqual(flags_to_events(0x00, False), [])


if __name__ == "__main__":
    unittest.main()
