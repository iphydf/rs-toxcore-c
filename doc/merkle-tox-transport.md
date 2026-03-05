# Merkle-Tox Sub-Design: Transport Layer (`tox-sequenced`)

## Overview

Tox custom packets are lossy and have a limited MTU (~1.3KB). The
`tox-sequenced` layer provides **congestion-controlled datagram delivery**
over these packets.

tox-sequenced controls the **rate** of transmission (congestion control,
pacing, prioritization). It does NOT provide reliability or ordering —
those are the application's responsibility, because the application has
semantic knowledge the transport lacks (content addressing, DAG structure,
chunk bitmasks).

The custom-packet substrate this layer rides on is **transport-binding
dependent**: either direct friend connections
(`tox.friend.send_lossy_packet`) or NGC custom packets
(`gc_send_custom_private_packet`, with `lossless=false`). The binding
is selected per Merkle-Tox conversation and is orthogonal to the
congestion control described here. In both cases the substrate is
*lossy* per [Principle 9](merkle-tox-principles.md) — Tox lossless
modes are not used at any layer of the Merkle-Tox stack. See
[merkle-tox-ngc.md](merkle-tox-ngc.md) for the NGC binding
(`ConversationId == chat_id`, multi-device pseudonymity,
`PeerIntroduction` records, sync gating, and membership
reconciliation).

### Design Rationale

Previous versions of tox-sequenced provided full reliable delivery
(fragmentation, selective ACKs, per-fragment retransmission). This
created problems for bulk data:

-   **Head-of-line blocking**: A 64KB message fragmented into 49 pieces
    stalls entirely if one fragment is lost.
-   **Delayed feedback**: The sender gets no delivery signal until all 49
    fragments arrive, starving congestion control of samples.
-   **Redundant reliability**: The application already tracks what data
    is missing (DAG sync knows missing nodes, CAS knows missing chunks).
    Transport-level retransmission duplicates this work blindly.

The redesigned transport provides datagrams with congestion feedback.
The application decides what to (re)send based on its own semantics.

## 1. Transport Header

Every custom packet is serialized as a **MessagePack Positional Array**.
The first element is the `packet_type` discriminator.

**Packet Types:**

Index | Data (0x00) | Ack (0x01) | Ping (0x02) | Pong (0x03) | Fragment (0x04)
:---- | :---------- | :--------- | :---------- | :---------- | :--------------
0     | `0x00`      | `0x01`     | `0x02`      | `0x03`      | `0x04`
1     | `[Payload]` | `[Payload]`| `t1`        | `[Payload]` | `[Payload]`

**Payload Structure:**

Type     | Field 0      | Field 1      | Field 2        | Field 3     | Field 4
:------- | :----------- | :----------- | :------------- | :---------- | :------
Data     | `seq`        | `msg_type`   | `data`         | -           | -
Ack      | `base_seq`   | `recv_bytes` | `sack_ranges`  | -           | -
Ping     | `t1`         | -            | -              | -           | -
Pong     | `t1`         | `t2`         | `t3`           | -           | -
Fragment | `frag_id`    | `frag_index` | `frag_total`   | `msg_type`  | `data`

**Overhead:** MessagePack array framing (~2-3 bytes) + integer varints.
**Remaining Space:** ~1350 bytes for payload (`data`).

## 2. Packet Types

### `DATA` (0x00) — Sequenced Datagram

The primary send path for all protocol messages. Every DATA packet
carries a sequence number for congestion control tracking.

-   `seq: u32` — Monotonically increasing sequence number. Used by the
    receiver to build ACK bitmaps for congestion control feedback.
    NOT used for ordering or reliability.
-   `msg_type: u8` — Application-level message type (see Section 5).
-   `data: bytes` — Payload (≤ ~1350 bytes).

All single-packet messages use DATA, including bulk data (BlobData).
This gives the congestion controller per-packet loss visibility across
all traffic, which is critical for accurate bandwidth estimation on
variable-quality P2P connections.

### `ACK` (0x01) — Cumulative + SACK Delivery Feedback

Periodic feedback from receiver to sender for congestion control. Sent
at least once per poll cycle when data has been received. Bounded by
design: cumulative fields are fixed-size, and the SACK list is capped
at `MAX_SACK_RANGES` entries — the ACK packet always fits well within
`MAX_DATAGRAM_SIZE` regardless of traffic volume or loss pattern.

All three ACK fields are wire-tagged `Untrusted<T>` and must be
sanitised against sender-side state before use:

-   `base_seq: Untrusted<u32>` — The next contiguous sequence number
    expected by the receiver. All seqs strictly less than `base_seq`
    have been received (cumulative ack). Sender rejects values
    strictly ahead of its own `next_seq` (peer cannot have received
    a seq that was never sent).
-   `recv_bytes: Untrusted<u64>` — Cumulative total bytes received
    from this peer. Used for delivery rate estimation. Sender clamps
    at `bytes_sent` (peer cannot have received more than was sent).
-   `sack_ranges: Untrusted<SmallVec<(u32, u32), 8>>` — A bounded list
    of `(start_seq, length)` pairs reporting non-contiguous
    *above-base* receipts. Each range covers seqs
    `[start, start + length)` that the receiver has seen even though
    `base_seq` could not advance past them (e.g., a persistent gap
    behind the range). This is the equivalent of TCP SACK blocks.
    Capped at 8 entries; per-range length capped at
    `MAX_SACK_RANGE_LENGTH = 65536`. Sender additionally validates
    each range as in-bounds, ascending, and non-overlapping; out-of-
    spec entries are silently ignored.

ACKs are for **congestion control only**. The transport never
retransmits based on ACK content. The application receives
`DatagramLost(seq)` events and decides whether to retransmit.

The sender resolves `sent_datagrams` entries via two paths from each
ACK: cumulative resolution (entries with `seq < base_seq`) and
selective resolution (entries covered by a `sack_ranges` entry). Any
remaining unresolved entries are aged out by the RTO timer in
Section 3.

**Anti-fingerprint.** Like PONG timestamps (see
`merkle-tox-clock.md` §3.3), implementations SHOULD apply small random
jitter to ACK *transmission timing* to smooth observable patterns of
when receipts arrive. The range *content* is not jittered — it
truthfully reports what the receiver has seen.

### `PING` (0x02) — RTT Probe

NTP-style timestamp for RTT and clock offset calculation.

-   `t1: i64` — Transmit timestamp (milliseconds, sender's clock).

### `PONG` (0x03) — RTT Response

-   `t1: i64` — Copied from PING.
-   `t2: i64` — Receive timestamp of the PING.
-   `t3: i64` — Transmit timestamp of the PONG.

### `FRAGMENT` (0x04) — Message Fragment

For messages too large to fit in a single packet (e.g., MerkleNode with
large content, SyncSketch). Fragments are reassembled at the receiver.
If any fragment is lost, the entire message is silently dropped after a
timeout. The application is responsible for retrying if needed.

-   `frag_id: u32` — Identifies which message this fragment belongs to.
-   `frag_index: u16` — Fragment index within the message.
-   `frag_total: u16` — Total fragments for this message.
-   `msg_type: u8` — Application-level message type. Present in **every**
    fragment (not just fragment 0) to keep the positional array layout
    uniform. The receiver MAY verify that all fragments for the same
    `frag_id` carry the same `msg_type`.
-   `data: bytes` — Fragment payload.

**Reassembly semantics:**
-   Receiver allocates a reassembly buffer on the first fragment.
-   If all fragments arrive within `REASSEMBLY_TIMEOUT` (5 seconds),
    the message is delivered to the application.
-   If any fragment is missing after the timeout, the entire message is
    dropped. The application receives `MessageDropped(frag_id)`.

**Congestion control:** Each FRAGMENT packet contributes to `recv_bytes`
in the receiver's ACK, so the congestion controller accounts for fragment
traffic. However, individual fragments do not carry a `seq` number and
are not tracked in the ACK bitmap. Loss detection for fragments relies on
the reassembly timeout, not on per-packet ACKs.

## 3. Congestion Control

tox-sequenced implements congestion control to avoid overwhelming the
network and the peer. The controller estimates available bandwidth and
paces outgoing packets accordingly.

### Delivery Rate Estimation

The sender tracks:
-   Cumulative bytes sent.
-   Cumulative bytes acknowledged (from `recv_bytes` in ACK packets).
-   Time between ACK arrivals.

Delivery rate = `delta_recv_bytes / delta_time`. This feeds the
congestion controller (BBR or AIMD) to set the pacing rate.

The raw ratio is *not* trusted as-is. Two artefacts inflate it
pathologically and would otherwise drive the pacer to tens of Gbps in
startup, overrunning the bottleneck queue and triggering loss-driven
backoff:

1.  **Cumulative-base catch-up.** `recv_bytes` advances only when the
    receiver's cumulative `base` advances. A SACK ACK can describe
    above-base receipts without moving `base`; when a missing seq
    eventually fills, `base` jumps and `recv_bytes` jumps with it —
    multiple MB at a time. The bytes were *received* gradually, but
    they're *reported* in one delta.
2.  **ACK batching.** The receiver coalesces ACKs to one every
    `ACK_INTERVAL` (10 ms with ±5 ms jitter). When two ACKs land
    closely on the sender, `delta_time` between them can be sub-RTT,
    and a moderate `delta_recv_bytes` reads as wildly high bandwidth.

The BBR-family controllers therefore floor `sample.duration` at the
established `min_rtt` (the smallest meaningful measurement window for
delivery rate) and clamp the resulting bandwidth at a hard ceiling
(`MAX_BW_CEILING = 1 Gbps` — covers LAN-gigabit deployments without
admitting the multi-Gbps spike readings produced by sub-RTT samples).
The same ceiling is applied to the final `pacing_rate()` output to
defend against cwnd-floor formulas that divide by `min_rtt` and could
otherwise overrule the bandwidth-based pacing target.

### Pacing

Outgoing datagrams are paced at the estimated delivery rate. When the
application calls `send()`, the datagram is queued and released at the
pacing interval. This prevents bursty sends that would overflow the
peer's UDP receive buffer.

### Send Window

The sender maintains a send window (in bytes) limiting outstanding data.
`outstanding = bytes_sent - bytes_acknowledged`, where `bytes_acknowledged`
comes from the peer's `recv_bytes` counter. If `outstanding >= window`,
new sends are blocked until further ACKs arrive.

The window size is set by the congestion controller based on estimated
bandwidth-delay product.

### RTT Measurement

Sampled in two places, both feeding the same RFC 6298 estimator
(`srtt` smoothed RTT with α = 0.125; `rttvar` mean deviation with
β = 0.25):

1.  **PING/PONG exchanges** (every 10 s while traffic is active,
    every 60 s while idle) — establishes RTT during long idle
    periods or when no DATA is in flight.
2.  **DATA ACKs** — every ACK that resolves at least one
    previously-unresolved datagram contributes one sample, computed
    as `now - sent_time` of the *freshest* newly-resolved entry in
    the ACK. Pinning to the freshest entry minimises the
    contribution of receiver `ACK_INTERVAL` batching to the
    measurement, since older entries in the same ACK necessarily
    sat in the pipeline longer.

Per-ACK sampling is essential: PING/PONG alone updates SRTT only
once every 10 s of active traffic, which leaves short flows
anchored to `INITIAL_SRTT = 200 ms` regardless of the true link RTT.
That stale figure then pollutes the BBR-family controllers'
`min_rtt` floor and inflates BDP / cwnd / pacing-rate calculations
proportionally.

Karn's ambiguity (RTT samples from retransmitted segments are
untrustworthy) does not apply here: every entry in `sent_datagrams`
corresponds to exactly one transmission. Loss is signalled to the
upper layer via `DatagramLost`; any retry surfaces as a new seq.

The estimator is used for:
-   Computing the loss-detection RTO (see below).
-   Congestion controller input (delivery samples, bandwidth-delay
    product).

### Loss Detection

The sender tracks each sent DATA packet in a per-session ring along
with its send time. A sent packet is resolved in one of four ways,
in priority order:

1.  **Cumulative ACK**: when `seq < base_seq` after an ACK arrives, the
    packet is implicitly delivered. Covers seqs the receiver got
    contiguously.
2.  **Selective ACK (SACK)**: when an ACK arrives carrying
    `sack_ranges`, any unresolved entry whose seq falls in a range is
    marked delivered. Covers above-base receipts that cumulative alone
    cannot describe — the common case under any non-zero loss.
3.  **Timer-based loss (RTO)**: when `now - sent_time >= rto()` and the
    packet is still unresolved, the transport emits
    `DatagramLost(seq)` and signals `on_loss` to the congestion
    controller. RTO is computed per RFC 6298 as
    `rto = clamp(srtt + 4 * rttvar, MIN_RTO, MAX_RTO)`, with
    `MIN_RTO = 200 ms` and `MAX_RTO = 5000 ms`. There is no
    consecutive-loss RTO backoff: backoff in TCP/QUIC throttles
    *retransmission* rate, but tox-sequenced does not retransmit at
    this layer — the RTO timer is purely a loss *signal*, and slowing
    that signal would only delay the CC's reaction to congestion
    without buying anything for the upper-layer retry path (which
    drives off semantic state, not `DatagramLost` events). With SACK
    present, this path fires only for genuinely lost packets (or the
    tail of a transfer where no further ACK can cover them).
4.  **Hard expiry**: a 30-second backstop on tracked entries to bound
    memory regardless of CC state.

The transport does NOT retransmit — the application receives
`DatagramLost(seq)` events and decides what (if anything) to retry,
using its own semantic state (CAS bitmasks, sync DAG, etc.).

The cwnd gate in `flush()` reads `outstanding_bytes` as the *local*
sum of unresolved `sent_datagrams` byte sizes, not as
`bytes_sent − bytes_acked`. Once an entry is resolved (delivered via
ACK or marked lost via timer), it stops contributing to outstanding,
letting the cwnd gate reopen even before the peer's `recv_bytes`
counter advances. BBR's delivery-rate sampling continues to use
`delta_recv_bytes` from the peer's counter (the authoritative wire
delivery signal).

Reordered packets are tolerated: SACK reports them as received
within their first ACK round-trip, before the RTO timer would have
fired. The RFC 6298 variance term (`4 × rttvar`) and 200 ms floor
provide a backstop for jitter even when SACK is unavailable.

## 4. Priority Scheduling

tox-sequenced uses Deficit Round Robin (DRR) across priority levels to
ensure control messages are not starved by bulk data.

| Level | Priority   | Quantum | Members (`MessageType::priority()`)                                                                                                                                              |
| :---- | :--------- | :------ | :--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| 0     | Critical   | 5200    | `CapsAnnounce`, `CapsAck`                                                                                                                                                        |
| 1     | High       | 3900    | `SyncHeads`, `FetchBatchReq`, `SyncSketch`, `SyncReconFail`, `SyncShardChecksums`, `SyncRateLimited`, `ReconPowChallenge`, `ReconPowSolution`, `HandshakeError`, `KeywrapAck`, `ReinclusionRequest`, `ReinclusionResponse`, `AdminGossip` |
| 2     | Standard   | 2600    | `MerkleNode`                                                                                                                                                                     |
| 3     | Low        | 1400    | `BlobQuery`, `BlobAvail`, `BlobReq`, `BlobFetch`, `BlobProgress`, `BlobCancel`                                                                                                   |
| 4     | Bulk       | 67650   | `BlobData`                                                                                                                                                                       |

Higher-priority queues are serviced first. Within a priority level,
messages are serviced round-robin with the quantum determining how many
bytes each message can send per round.

## 5. Application Message Types

The `msg_type` field identifies the application-level protocol message.

| ID     | Message Type           | Transport    | Description                  |
| :----- | :--------------------- | :----------- | :--------------------------- |
| `0x01` | `CAPS_ANNOUNCE`        | Data         | Handshake / Features         |
| `0x02` | `CAPS_ACK`             | Data         | Handshake Acknowledgment     |
| `0x03` | `SYNC_HEADS`           | Data/Frag    | DAG tips + CAS Inventory     |
| `0x04` | `FETCH_BATCH_REQ`      | Data         | Request multiple nodes       |
| `0x05` | `MERKLE_NODE`          | Fragment     | A single DAG node            |
| `0x06` | `BLOB_QUERY`           | Data         | "Do you have this hash?"     |
| `0x07` | `BLOB_AVAIL`           | Data/Frag    | "I have it, size = X"        |
| `0x08` | `BLOB_REQ`             | Data         | Request specific piece       |
| `0x09` | `BLOB_DATA`            | Data         | Blob data piece (~1300B)     |
| `0x0A` | `SYNC_SKETCH`          | Fragment     | IBLT Set Reconciliation      |
| `0x0B` | `SYNC_RECON_FAIL`      | Data         | IBLT Decoding Failure        |
| `0x0C` | `SYNC_SHARD_CHECKSUMS` | Data/Frag    | Shard Checksums              |
| `0x0D` | `HANDSHAKE_ERROR`      | Data         | Invalid pre-key signal       |
| `0x0E` | `SYNC_RATE_LIMITED`    | Data         | CPU budget exhausted         |
| `0x0F` | `KEYWRAP_ACK`          | Data         | WrappedKey decryption ACK    |
| `0x10` | `RECON_POW_CHALLENGE`  | Data         | PoW challenge for recon      |
| `0x11` | `RECON_POW_SOLUTION`   | Data         | PoW solution                 |
| `0x12` | `REINCLUSION_REQ`      | Data         | Reinclusion request          |
| `0x13` | `REINCLUSION_RESP`     | Data         | Reinclusion response         |
| `0x14` | `ADMIN_GOSSIP`         | Data         | Admin node gossip            |
| `0x15` | `BLOB_FETCH`           | Data/Frag    | Request push streaming       |
| `0x16` | `BLOB_PROGRESS`        | Data/Frag    | Receiver progress update     |
| `0x17` | `BLOB_CANCEL`          | Data         | Cancel push stream           |

**Transport column:**
-   **Data** — single-packet sequenced datagram. Every packet gets a
    sequence number for congestion control tracking.
-   **Data/Frag** — sent as a single DATA packet when the serialized
    message fits within the MTU (~1350B). Falls back to FRAGMENT when
    it exceeds the MTU (e.g., large `completed_ranges` in BLOB_PROGRESS,
    or SyncHeads with many conversation tips). Most instances fit in one
    packet; fragmentation is a rare-case fallback.
-   **Fragment** — always multi-packet. Used for messages that routinely
    exceed the MTU (MerkleNode, SyncSketch). Reassembled at the receiver;
    dropped on timeout if incomplete.

## 6. Session Events

The transport emits events to the application:

-   `DatagramDelivered(seq)` — Sequence was acknowledged by peer.
-   `DatagramLost(seq)` — Sequence remained unresolved past the
    RFC 6298 RTO (`clamp(srtt + 4·rttvar, MIN_RTO, MAX_RTO)`); see §3
    Loss Detection.
-   `MessageCompleted(frag_id, msg_type, data)` — Fragmented message
    fully reassembled.
-   `MessageDropped(frag_id)` — Fragmented message timed out (missing
    fragments).
-   `ReadyToSend` — Send window has capacity for new datagrams.

The application uses these events to drive its own retry logic:
-   Control messages: retry on `DatagramLost` or response timeout.
-   DAG nodes: no retry needed; sync protocol self-heals.
-   Blob data: no retry needed; CAS bitmask drives retransmission.

## 7. Heartbeats & Keep-alive

-   **Mandatory PING**: At least once every **60 seconds** if idle.
-   **Active Transfer**: Reduced to **10 seconds** during sync or bulk
    transfer.
-   **Session Timeout**: **5 minutes** without any valid packet.

## 8. Hard Limits and Constraints

| Constant                  | Value   | Description                        |
| :------------------------ | :------ | :--------------------------------- |
| `MAX_DATAGRAM_SIZE`       | ~1350B  | Single-packet payload limit        |
| `MAX_FRAGMENT_MESSAGE`    | 1 MB    | Maximum reassembled fragment size  |
| `MAX_CONCURRENT_REASSEMBLY` | 32   | Concurrent fragmented messages     |
| `REASSEMBLY_TIMEOUT`     | 5s      | Drop incomplete fragments after    |
| `MIN_RTO` / `MAX_RTO`     | 200ms / 5000ms | RFC 6298 RTO bounds for loss timer |
| `MAX_SACK_RANGES`         | 8       | Max `(start, length)` pairs per ACK |
| `MAX_SACK_RANGE_LENGTH`   | 65536   | Max seqs covered by one SACK range  |
| `MIN_PACING_INTERVAL`    | 200us   | Minimum gap between sends          |
| `INITIAL_WINDOW`         | 256 KB  | Initial send window                |
| `MAX_WINDOW`             | 1 MB    | Maximum send window                |
| `MAX_BW_CEILING`         | 1 Gbps  | Pacing-rate ceiling (covers LAN gigabit) |
