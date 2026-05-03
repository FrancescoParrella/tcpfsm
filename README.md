# tcpfsm

**TCP state machine analyzer** — reconstructs the full RFC 793 lifecycle of every TCP connection from a `.pcap` capture file.

**Tests:** 131 passing &nbsp;|&nbsp; **Python:** 3.10+ &nbsp;|&nbsp; **License:** MIT &nbsp;|&nbsp; **Deps:** `dpkt` only

---

## What it does

Tools like Wireshark show you individual packets. `tcpfsm` shows you what those packets *mean*: for each TCP flow it reconstructs the initiator and responder state machines step by step, then reports the final state, byte counts, and any anomalies detected along the way.

The state machine follows RFC 793 exactly — 12 states, a table-driven transition function, and explicit handling of every flag combination including the FIN+ACK shortcut (§3.5), simultaneous open and close, and RST from every active state. Anomaly detection runs as a side effect of state tracking: retransmissions, half-open connections, unexpected resets, connection refusals, and invalid transitions are all flagged automatically with timestamps and packet indices.

Captures that start mid-flow are handled too. When no SYN is visible, the initiator is identified via well-known port heuristics and both FSMs start in `OBSERVED_ESTABLISHED`, then track any subsequent close sequence normally.

---

## Install

```
git clone https://github.com/FrancescoParrella/tcpfsm
cd tcpfsm
pip install -e .
```

Requires Python 3.10+ and `dpkt`. No other dependencies.

---

## Quick start

```
python -m tcpfsm capture.pcap
```

Sample output on the five-connection showcase file included in `tests/samples/showcase.pcap`:

```
   #                    SRC                    DST    DURATION      TX->      <-RX     INIT STATE     RESP STATE  ANOMALIES
---------------------------------------------------------------------------------------------------------------------------
   1         10.0.0.1:55001            10.0.0.2:80       1.300        16        17      TIME_WAIT         CLOSED          0
   2         10.0.0.1:55002           10.0.0.2:443       1.300        15         0      TIME_WAIT         CLOSED          2
   3         10.0.0.1:55003          10.0.0.2:8080       0.400        12         0         CLOSED         CLOSED          1
   4         10.0.0.3:55004            10.0.0.4:80       0.200         8         6       OBSERVED       OBSERVED          0
   5         10.0.0.1:55005          10.0.0.5:9999      34.000         0         0       SYN_SENT   SYN_RECEIVED          3
```

Columns: index, source and destination endpoints, duration in seconds, bytes sent by each side, final FSM state for initiator and responder (`OBSERVED` = `OBSERVED_ESTABLISHED`), anomaly count.

---

## Usage

### Summary table (default)

```
python -m tcpfsm capture.pcap
```

### Full timeline for one connection

```
python -m tcpfsm capture.pcap --connection 1
```

```
Connection #1  10.0.0.1:55001 -> 10.0.0.2:80
  Duration : 1.300s
  Packets  : 9
  TX bytes : 16  (initiator -> responder)
  RX bytes : 17  (responder -> initiator)
  Final    : initiator=TIME_WAIT  responder=CLOSED

  State transitions:
    t=1.000000  pkt#   1  [init]          CLOSED --SEND_SYN--> SYN_SENT
    t=1.000000  pkt#   1  [resp]          LISTEN --RECV_SYN--> SYN_RECEIVED
    t=1.100000  pkt#   2  [init]        SYN_SENT --RECV_SYN_ACK--> ESTABLISHED
    t=1.200000  pkt#   3  [resp]    SYN_RECEIVED --RECV_ACK--> ESTABLISHED
    t=2.000000  pkt#   6  [init]     ESTABLISHED --SEND_FIN_ACK--> FIN_WAIT_1
    t=2.000000  pkt#   6  [resp]     ESTABLISHED --RECV_FIN_ACK--> CLOSE_WAIT
    t=2.100000  pkt#   7  [init]      FIN_WAIT_1 --RECV_ACK--> FIN_WAIT_2
    t=2.200000  pkt#   8  [resp]      CLOSE_WAIT --SEND_FIN_ACK--> LAST_ACK
    t=2.200000  pkt#   8  [init]      FIN_WAIT_2 --RECV_FIN_ACK--> TIME_WAIT
    t=2.300000  pkt#   9  [resp]        LAST_ACK --RECV_ACK--> CLOSED

  No anomalies detected.
```

### Only connections with anomalies

```
python -m tcpfsm capture.pcap --anomalies-only
```

```
   #                    SRC                    DST    DURATION      TX->      <-RX     INIT STATE     RESP STATE  ANOMALIES
---------------------------------------------------------------------------------------------------------------------------
   2         10.0.0.1:55002           10.0.0.2:443       1.300        15         0      TIME_WAIT         CLOSED          2
   3         10.0.0.1:55003          10.0.0.2:8080       0.400        12         0         CLOSED         CLOSED          1
   5         10.0.0.1:55005          10.0.0.5:9999      34.000         0         0       SYN_SENT   SYN_RECEIVED          3
```

### Machine-readable JSON

```
python -m tcpfsm capture.pcap --json
python -m tcpfsm capture.pcap --json --anomalies-only
python -m tcpfsm capture.pcap --json --connection 2
```

Each connection object contains: `index`, `src_ip`, `src_port`, `dst_ip`, `dst_port`, `mid_stream`, `first_ts`, `last_ts`, `duration`, `init_bytes`, `resp_bytes`, `packet_count`, `final_state_initiator`, `final_state_responder`, `transitions` (array), `anomalies` (array).

### Half-open timeout

```
python -m tcpfsm capture.pcap --half-open-timeout 60.0
```

Default is 30 seconds. A SYN with no SYN-ACK reply seen within this window is flagged as `HALF_OPEN` when `finalize()` runs at the end of the capture.

---

## Coverage

| Feature | Status |
|---|---|
| TCP FSM — RFC 793, table-driven, 12 states | complete |
| Anomaly: retransmission | complete |
| Anomaly: out-of-order segment | complete |
| Anomaly: half-open connection | complete |
| Anomaly: connection refused (RST reply to SYN) | complete |
| Anomaly: unexpected RST during ESTABLISHED | complete |
| Anomaly: zero-window stall | complete |
| Anomaly: invalid FSM transition | complete |
| pcap format: Ethernet + IPv4 | complete |
| pcap format: Linux SLL (DLT 113) | complete |
| pcap format: malformed-packet tolerant | complete |
| Mid-stream connections (no SYN captured) | complete |
| Port reuse (new SYN after TIME_WAIT or CLOSED) | complete |
| Bidirectional flow tracking — 2 FSMs per connection | complete |
| JSON output | complete |

---

## Architecture

**FSM (`tcpfsm/fsm.py`)** — a `dict`-based transition table keyed by `(State, Event)` pairs. Two `TcpFsm` instances run per connection: one for the initiator side, one for the responder. Events are derived from the packet's TCP flags and the direction it travels (`SEND_*` vs `RECV_*`). Invalid transitions are recorded as anomalies rather than raising exceptions, so analysis of the remaining packets continues uninterrupted.

**pcap reader (`tcpfsm/pcap_reader.py`)** — thin wrapper around `dpkt` that yields typed `Packet` dataclass objects. Handles Ethernet (DLT 1) and Linux SLL (DLT 113) link types, skips non-TCP and malformed frames with a stderr warning, and raises a meaningful `FileNotFoundError` on missing files.

**Connection tracker (`tcpfsm/connection.py`)** — `ConnectionTracker` uses a `frozenset`-keyed dict so both directions of a flow map to the same `Connection` without any key normalization. A new `Connection` is created when the current one reaches a terminal state (`CLOSED` or `TIME_WAIT`), enabling correct port-reuse handling. Per-connection `SideTracker` instances track sequence numbers to detect retransmissions and out-of-order segments.

**CLI and renderer (`tcpfsm/cli.py`, `tcpfsm/render.py`)** — `argparse`-based entry point calls `analyze()` and dispatches to either the human-readable table/detail renderer or the JSON serializer. Rendering is decoupled from argument parsing so it can be tested and reused independently.

---

## Limitations

- **No live capture.** Input must be an offline `.pcap` file. Live capture via `libpcap`/`npcap` is not supported.
- **IPv4 only.** IPv6 packets are silently skipped.
- **No payload reassembly.** Byte counts are tracked per side but the payload is not buffered or decoded.
- **No TCP options parsing.** SACK, timestamps, and window scaling are present in the wire format but not interpreted.
- **No VLAN tagging.** 802.1Q and QinQ frames are not parsed and will be skipped as malformed.
- **Sequence number wrap-around.** The retransmission detector does not handle 32-bit sequence space wrap on very long-lived connections.

---

## Future work

- Live capture via `libpcap`/`npcap`
- IPv6 support
- 802.1Q VLAN and QinQ frame parsing
- SACK-aware retransmission detection
- Window scaling option parsing
- ML-based anomaly classification on top of the FSM event stream

---

## Development

```
# run all 131 tests
python -m unittest discover tests

# inspect a pcap packet by packet
python examples/inspect_pcap.py capture.pcap
```

**Dependencies:** Python 3.10+, `dpkt` (pcap parsing only). Tests use the standard library exclusively (`unittest`, `io`, `json`, `struct`, `socket`).

**Project layout:**

```
tcpfsm/
  fsm.py           RFC 793 state machine
  pcap_reader.py   dpkt wrapper, Packet dataclass
  anomaly.py       AnomalyKind enum, SideTracker, Anomaly dataclass
  connection.py    Connection, ConnectionTracker
  analyzer.py      top-level analyze() function
  render.py        human-readable and JSON renderers
  cli.py           argparse entry point
  __main__.py      python -m tcpfsm support

tests/
  test_fsm.py          39 FSM unit tests
  test_pcap_reader.py  28 pcap reader tests
  test_connection.py   34 connection tracking tests
  test_cli.py          23 CLI and renderer tests
  test_anomaly.py       7 anomaly detector tests
  make_samples.py      synthetic pcap generator
```

---

## License

MIT. See [LICENSE](LICENSE).
