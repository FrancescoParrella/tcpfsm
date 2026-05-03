"""Unit tests for the FSM transition table — no pcap required."""

import unittest
from tcpfsm.fsm import State, Event, next_state, flags_to_events, TRANSITIONS


class TestNextState(unittest.TestCase):

    def test_active_open_sequence(self):
        """Client-side normal 3-way handshake open."""
        s = State.CLOSED
        s, ok = next_state(s, Event.SEND_SYN)
        self.assertEqual(s, State.SYN_SENT)
        self.assertTrue(ok)

        s, ok = next_state(s, Event.RECV_SYN_ACK)
        self.assertEqual(s, State.ESTABLISHED)
        self.assertTrue(ok)

    def test_passive_open_sequence(self):
        """Server-side normal 3-way handshake open."""
        s = State.LISTEN
        s, ok = next_state(s, Event.RECV_SYN)
        self.assertEqual(s, State.SYN_RECEIVED)
        self.assertTrue(ok)

        s, ok = next_state(s, Event.SEND_SYN_ACK)
        self.assertEqual(s, State.SYN_RECEIVED)  # still waiting for ACK
        self.assertTrue(ok)

        s, ok = next_state(s, Event.RECV_ACK)
        self.assertEqual(s, State.ESTABLISHED)
        self.assertTrue(ok)

    def test_active_close_sequence(self):
        """Initiator-of-close side."""
        s = State.ESTABLISHED
        s, ok = next_state(s, Event.SEND_FIN)
        self.assertEqual(s, State.FIN_WAIT_1)
        self.assertTrue(ok)

        s, ok = next_state(s, Event.RECV_ACK)
        self.assertEqual(s, State.FIN_WAIT_2)

        s, ok = next_state(s, Event.RECV_FIN)
        self.assertEqual(s, State.TIME_WAIT)

    def test_passive_close_sequence(self):
        """Receiver-of-FIN side."""
        s = State.ESTABLISHED
        s, ok = next_state(s, Event.RECV_FIN)
        self.assertEqual(s, State.CLOSE_WAIT)

        s, ok = next_state(s, Event.SEND_FIN)
        self.assertEqual(s, State.LAST_ACK)

        s, ok = next_state(s, Event.RECV_ACK)
        self.assertEqual(s, State.CLOSED)

    def test_rst_from_established_goes_to_closed(self):
        s = State.ESTABLISHED
        s, ok = next_state(s, Event.RECV_RST)
        self.assertEqual(s, State.CLOSED)
        self.assertTrue(ok)

    def test_rst_from_closed_stays_closed(self):
        s = State.CLOSED
        s, ok = next_state(s, Event.RECV_RST)
        self.assertEqual(s, State.CLOSED)
        self.assertFalse(ok)  # already closed — not a meaningful transition

    def test_invalid_transition_returns_false(self):
        # Can't send a FIN from CLOSED
        s = State.CLOSED
        new_s, ok = next_state(s, Event.SEND_FIN)
        self.assertEqual(new_s, State.CLOSED)
        self.assertFalse(ok)

    def test_simultaneous_close(self):
        """Both sides send FIN simultaneously → CLOSING → TIME_WAIT."""
        s = State.FIN_WAIT_1
        s, ok = next_state(s, Event.RECV_FIN)
        self.assertEqual(s, State.CLOSING)

        s, ok = next_state(s, Event.RECV_ACK)
        self.assertEqual(s, State.TIME_WAIT)

    def test_simultaneous_open(self):
        """SYN_SENT receives SYN (not SYN-ACK) → SYN_RECEIVED."""
        s = State.SYN_SENT
        s, ok = next_state(s, Event.RECV_SYN)
        self.assertEqual(s, State.SYN_RECEIVED)

    def test_fin_ack_from_fin_wait_1_goes_to_time_wait(self):
        """FIN+ACK received while in FIN_WAIT_1 shortcuts to TIME_WAIT."""
        s = State.FIN_WAIT_1
        s, ok = next_state(s, Event.RECV_FIN_ACK)
        self.assertEqual(s, State.TIME_WAIT)

    def test_syn_received_rst_goes_to_listen(self):
        """Server resets a half-open back to LISTEN."""
        s = State.SYN_RECEIVED
        s, ok = next_state(s, Event.RECV_RST)
        self.assertEqual(s, State.LISTEN)
        self.assertTrue(ok)


class TestFlagsToEvents(unittest.TestCase):

    def test_syn_sender(self):
        events = flags_to_events(0x02, is_sender=True)
        self.assertEqual(events, [Event.SEND_SYN])

    def test_syn_receiver(self):
        events = flags_to_events(0x02, is_sender=False)
        self.assertEqual(events, [Event.RECV_SYN])

    def test_syn_ack(self):
        events = flags_to_events(0x12, is_sender=True)   # SYN=0x02, ACK=0x10
        self.assertEqual(events, [Event.SEND_SYN_ACK])

    def test_fin_ack(self):
        events = flags_to_events(0x11, is_sender=False)  # FIN=0x01, ACK=0x10
        self.assertEqual(events, [Event.RECV_FIN_ACK])

    def test_rst(self):
        events = flags_to_events(0x04, is_sender=True)
        self.assertEqual(events, [Event.SEND_RST])

    def test_ack_only(self):
        events = flags_to_events(0x10, is_sender=False)
        self.assertEqual(events, [Event.RECV_ACK])

    def test_pure_data_no_flags(self):
        # No control flags set → no events
        events = flags_to_events(0x00, is_sender=True)
        self.assertEqual(events, [])


class TestTransitionTableCompleteness(unittest.TestCase):

    def test_no_duplicate_keys(self):
        """All keys in TRANSITIONS are unique (dict guarantees this, but be explicit)."""
        self.assertEqual(len(TRANSITIONS), len(set(TRANSITIONS.keys())))

    def test_all_values_are_states(self):
        for (state, event), next_s in TRANSITIONS.items():
            self.assertIsInstance(next_s, State, f"Bad value for ({state}, {event})")

    def test_all_keys_use_valid_states_and_events(self):
        for state, event in TRANSITIONS.keys():
            self.assertIsInstance(state, State)
            self.assertIsInstance(event, Event)


if __name__ == "__main__":
    unittest.main()
