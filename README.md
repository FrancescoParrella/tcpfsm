# tcpfsm

TCP state machine analyzer — reads `.pcap` files and reconstructs the lifecycle of every TCP connection, tracing each through the RFC 793 finite state machine and flagging anomalies.

**v0.1 — offline analysis only. No live capture.**

## Installation

```bash
pip install dpkt          # only external dependency
pip install -e .          # install tcpfsm CLI
```

## Usage

```bash
# Summary of all connections
tcpfsm capture.pcap

# Full timeline for connection #3
tcpfsm capture.pcap --connection 3

# Only connections with anomalies
tcpfsm capture.pcap --anomalies-only

# Machine-readable output
tcpfsm capture.pcap --json
tcpfsm capture.pcap --connection 3 --json
```

### Example output

```
   #                    SRC                    DST    DURATION       TX→       ←RX    INIT STATE    RESP STATE  ANOMALIES
---------------------------------------------------------------------------------------------------------------------------
   1        10.0.0.1:54321         10.0.0.2:80       1.300     16          17       TIME_WAIT          CLOSED          0
   2        10.0.0.1:54322         10.0.0.2:80       1.200      5           0       TIME_WAIT          CLOSED          1
```

```
Connection #2  10.0.0.1:54322 → 10.0.0.2:80
  Duration : 1.200s
  Packets  : 9
  TX bytes : 5  (initiator → responder)
  RX bytes : 0  (responder → initiator)
  Final    : initiator=TIME_WAIT  responder=CLOSED

  State transitions:
    t=1.000000  pkt#   1  [init]           CLOSED --SEND_SYN--> SYN_SENT
    t=1.000000  pkt#   1  [resp]           LISTEN --RECV_SYN--> SYN_RECEIVED
    ...

  Anomalies (1):
  [RETRANSMISSION] pkt#5  t=1.800000  Retransmission: seq=1001 already seen
```

## TCP FSM (RFC 793)

```
                              +---------+
                              | CLOSED  |<---------+
                              +---------+          |
                    passive      |    ^             |
                    open /       |    | close /     | RST /
                    LISTEN       v    | --           | --
                              +---------+          |
                              | LISTEN  |          |
                              +---------+          |
                 rcv SYN /       |    ^             |
                 snd SYN,ACK     |    |             |
                                 v    |             |
                           +-----------+            |
                           |SYN_RCVD   |            |
                           +-----------+            |
          rcv ACK /              |                  |
          --                     v                  |
                           +-----------+   snd FIN  |  rcv FIN /
          snd SYN /        |ESTABLISHED|--------+   |  snd ACK
          rcv SYN,ACK -->  +-----------+        |   |
     +-----------+               |              v   |
     | SYN_SENT  |    rcv FIN /  |      +-----------+
     +-----------+    snd ACK    +----->|FIN_WAIT_1 |
                                        +-----------+
                     rcv FIN /               |    |
                     snd ACK          rcv    |    | rcv ACK /
                          +------+    FIN,   |    | --
                          |CLOSING|  ACK /   |    v
                          +------+  snd ACK  | +-----------+
                               |             | |FIN_WAIT_2 |
                  rcv ACK /    |             | +-----------+
                  --           v             |      |
                         +-----------+       |      | rcv FIN /
                         | TIME_WAIT |<------+      | snd ACK
                         +-----------+<-------------+
                               |
                  2MSL timeout |
                               v
                           +---------+
                           | CLOSED  |
                           +---------+

  CLOSE_WAIT --> LAST_ACK (passive close side, after app calls close)
  LAST_ACK   --> CLOSED   (on receipt of final ACK)
```

## Detected anomalies

| Anomaly | Description |
|---|---|
| `retransmission` | Same sequence number seen twice from the same side |
| `out_of_order` | Sequence number lower than the highest previously seen |
| `unexpected_rst` | RST received while connection was ESTABLISHED |
| `half_open` | SYN sent with no SYN-ACK reply within the capture window |
| `connection_refused` | RST received in response to SYN |
| `zero_window` | Receive window of 0 advertised |
| `invalid_transition` | Packet caused an FSM transition not in RFC 793 |

## Known limitations

- **No live capture** — offline `.pcap` files only (v0.1)
- **IPv4 only** — IPv6 TCP not yet supported
- **No TCP payload reassembly** — bytes are counted but content is not reconstructed
- **No SACK tracking** — selective ACK blocks are not parsed; only basic retransmission detection via sequence numbers
- **No IP fragmentation handling** — fragmented IP packets are skipped
- **Sequence number wrap-around** — 32-bit sequence wrap is not handled (affects very long, high-throughput connections)
- **Capture-start mid-connection** — connections in progress at capture start are tracked from the first seen packet; their initial handshake is not reconstructed

## Running tests

```bash
# Generate sample pcaps first
python -m tests.make_samples

# Run all tests
python -m unittest discover -s tests
```
