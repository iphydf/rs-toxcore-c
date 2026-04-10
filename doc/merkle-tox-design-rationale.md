# Merkle-Tox Design Rationale & Dismissed Considerations

Records architectural decisions and rejected paths to prevent re-introducing
known vulnerabilities or redundancies.

## 1. SyncKey Obfuscation (Dismissed)

*   **Original Proposal**: Derive a `SyncKey = KDF(ConversationID)` to hide the
    room ID from network observers.
*   **Decision**: Dismissed as redundant.
*   **Rationale**:
    1.  **Transport Blinding**: Merkle-Tox runs inside an encrypted Tox tunnel.
        Observers on the internet already see only encrypted noise.
    2.  **Stable Identifiers**: An untrusted peer (SyncBot) needs a unique
        handle to identify the room. Whether it is the `ID` or `Hash(ID)`, it
        remains a stable identifier that allows relationship mapping.
    3.  **Opaque by Default**: The `ConversationID` is already a 32-byte Blake3
        hash of the Genesis node. It carries no semantic meaning.
*   **Result**: Use `ConversationID` directly in all protocol messages to
    simplify implementation and mapping tables.

## 2. Cleartext epoch in WireNode (Dismissed)

*   **Original Proposal**: Add a cleartext `epoch` field to the `WireNode`
    header to allow instant filtering and decryption without trial-and-error.
*   **Decision**: Dismissed for security and protocol integrity.
*   **Rationale**:
    1.  **Metadata Leakage**: Exposing the epoch allows untrusted peers (e.g.,
        SyncBots) to observe key rotation frequency and interaction patterns.
    2.  **Ghost Content**: Decrypting nodes before their parents arrive (using
        the epoch hint) would allow "floating" messages that have no verifiable
        topological context, compromising the Merkle trust model.
    3.  **Redundancy**: In a high-end topological sync, the "Active Epoch" is a
        property of the verified state. The system inherently knows the correct
        key to apply to the next logical child.
*   **Result**: Remove the `epoch` field from the wire header. Mandate
    **Topological Anchor Verification** as a prerequisite for decryption.

## 3. Cleartext network_timestamp in WireNode (Dismissed)

*   **Original Proposal**: Keep `network_timestamp` in the cleartext header of
    the `WireNode` for easy "Future Quarantine" checks.
*   **Decision**: Dismissed for security (Traffic Analysis protection).
*   **Rationale**: Exposing the wall-clock timestamp allows a peer (e.g., a
    SyncBot) to perform authoring-pattern analysis (learning the user's active
    hours).
*   **Result**: Move the timestamp inside the encrypted payload. Use the
    cleartext `topological_rank` for synchronization and eviction priority
    instead.

## 4. FIFO Eviction in Opaque Store (Dismissed)

*   **Original Proposal**: Use First-In-First-Out (FIFO) to manage the 100MB
    Opaque Store buffer.
*   **Decision**: Dismissed due to the **Rank-Padding Attack**.
*   **Rationale**: An attacker could flood the buffer with "Future" high-rank
    junk to push out legitimate historical nodes.
*   **Result**: Use **Contiguity-based Eviction**. Prioritize nodes close to the
    Local Low-Water Mark (LLWM), forcing an attacker to possess the room's
    history to maintain their nodes in the victim's buffer.

## 5. Unbound Structural Vouching (Dismissed)

*   **Original Proposal**: Any node listed as a parent of a verified Admin node
    is automatically vouched for (fetchable from blind relays).
*   **Decision**: Dismissed due to **Buffer Exhaustion** risks.
*   **Rationale**: A single valid Admin node could be used to vouch for an
    infinite chain of junk history, filling the victim's quota instantly.
*   **Result**: Implement a **500-hop Ancestry Cap**. Structural trust must be
    "re-anchored" by a new verified Admin node every 400 levels.

## 6. Blocking 1-on-1 Pulse (Dismissed)

*   **Original Proposal**: If only a "Last Resort" key is available for a peer,
    block sending and wait for a fresh handshake.
*   **Decision**: Dismissed for UX (Availability).
*   **Rationale**: Blocking the UI until a peer comes online to provide fresh
    keys breaks asynchronous store-and-forward.
*   **Result**: Use **Opportunistic Handshakes** for 1-on-1. Send the first
    message using the Last Resort key but attach a `HandshakePulse` to force a
    secure rotation immediately.

## 7. Unified Opaque/Blob Storage Logic (Dismissed)

*   **Original Proposal**: Treat encrypted nodes and large binary files as the
    same "Blob" type in the storage engine.
*   **Decision**: Dismissed for performance.
*   **Rationale**: Opaque nodes are small (256B), high-frequency, and require
    complex eviction logic. Blobs are large (MBs) and are fetched lazily.
    Storing them in the same backend (e.g., SQLite) leads to excessive DB bloat
    or poor I/O performance.
*   **Result**: Use a unified **logical trait** (`ObjectStore`) but keep
    separate **physical backends** (SQLite for nodes, raw Filesystem for blobs).

## 8. Global DAG Merging Ratchets (Dismissed)

*   **Original Proposal**: Use a single global ratchet state for the
    conversation that "merges" cryptographically whenever the DAG branches join.
*   **Decision**: Dismissed due to **State Explosion** and **Race Conditions**.
*   **Rationale**: A global state that branches creates "siblings" that require
    the same parent key simultaneously. To support merges, the system would need
    to keep old keys "just in case," violating strict Forward Secrecy or
    creating complex caching deadlocks.
*   **Result**: Use **Per-Sender Linear Ratchets**. Each device maintains its
    own linear hash chain. DAG merges remain logical (sync/integrity) but not
    cryptographic (encryption), achieving Signal-grade Forward Secrecy with zero
    race conditions.

## 9. Application-Layer Time Sync (Dismissed)

*   **Original Proposal**: Perform time synchronization via high-level protocol
    messages (TIME_SYNC_REQ/RES) over the application protocol.
*   **Decision**: Dismissed to avoid **retransmission jitter**.
*   **Rationale**: If time sync messages are subject to application-level retry
    logic, retransmissions introduce variable and unpredictable delays, making
    accurate RTT and offset calculations impossible. By measuring time at the
    transport layer via heartbeats (PING/PONG), we get "free" measurements that
    reflect the pure wire latency.
*   **Result**: Move time measurement to the `tox-sequenced` transport layer.
    The logic layer now only handles the **Median Consensus** and **Slewing**.

## 10. Admin-Only Anchoring (Dismissed)

*   **Original Proposal**: Require Admin nodes every 500 hops. If no Admin is
    online, the room stalls for blind relays, requiring an "always-on" Admin
    Bot.
*   **Decision**: Dismissed in favor of Level 2 `SoftAnchor`s.
*   **Rationale**: Centralized bots violate decentralization. Sacrificing a
    small amount of "presence deniability" (L2 users signing a SoftAnchor with
    their permanent key) is an acceptable trade-off to guarantee decentralized
    availability. The "Hop Reset Topology" (where SoftAnchors only parent the
    previous Admin node) ensures actual message *content* remains deniable.
*   **Result**: Introduced `SoftAnchor` with a 3-chain cap and parallel topology
    to maintain availability without Centralized Admin Bots.

## 11. Deterministic Tie-Breakers for Soft Anchors (Dismissed)

*   **Original Proposal**: When 400 hops are reached, use a deterministic rule
    (e.g., mathematical distance of `device_pk` to `basis_hash`) to select one
    Level 2 user to author the `SoftAnchor`, preventing a "thundering herd".
*   **Decision**: Dismissed in favor of probabilistic jitter.
*   **Rationale**: In a lossy, asynchronous network like Tox, you never have a
    complete view of *who* is currently online. If the "mathematically chosen"
    user happens to be offline or partitioned, the whole room would stall
    waiting for them.
*   **Result**: Clients trigger `SoftAnchor` creation at a uniformly randomized
    interval between 400 and 450 hops, effectively trading a small amount of
    network noise for guaranteed robustness.

## 12. Proof-of-Work for Extending Ancestry Cap (Dismissed)

*   **Original Proposal**: Allow any node to extend the 500-hop buffer
    exhaustion cap by computing a heavy Proof-of-Work (PoW), avoiding the need
    for `SoftAnchor` signatures entirely.
*   **Decision**: Dismissed for mobile performance and effectiveness.
*   **Rationale**: PoW drains mobile batteries and proves only CPU time
    expenditure, not history legitimacy. A determined attacker with server
    resources could still trivially overwhelm the buffer limit of honest nodes.
*   **Result**: Relied on cryptographic authentication (`SoftAnchor`
    Anti-Branching rule) which is computationally cheap to verify ($O(1)$) and
    bounds the attack surface.

## 13. Transport-Level Reliable Delivery for Blob Data (Dismissed)

*   **Original Proposal**: Send blob data as reliable, fragmented messages
    through the `tox-sequenced` transport layer (the same path used for control
    messages like SyncHeads and MerkleNode). A 64KB blob chunk would be
    fragmented into ~49 transport fragments, reassembled at the receiver, and
    ACKed as a single message.
*   **Decision**: Dismissed due to **head-of-line blocking** and **feedback
    starvation**.
*   **Rationale**:
    1.  **Head-of-line blocking**: A 64KB message fragmented into 49 pieces
        stalls entirely if one fragment is lost. The receiver cannot use any of
        the 48 successfully received fragments until the missing one arrives.
        With a 200ms retransmission timeout, one lost fragment delays 64KB of
        data by at least 200ms.
    2.  **Feedback starvation**: The sender receives no delivery signal until
        all 49 fragments arrive and the receiver sends a message-level ACK.
        This delays congestion control feedback by the time it takes to
        complete an entire message (~200ms with 20ms polling), preventing the
        bandwidth estimator from converging.
    3.  **Redundant reliability**: The CAS layer already tracks which blob
        pieces are missing (via bitmask) and can request retransmission
        precisely. Transport-level retransmission duplicates this with less
        information — it retransmits fragments, not content-addressed pieces.
    4.  **Spurious retransmissions**: With many concurrent large messages
        sharing a small congestion window, individual messages take longer to
        complete than the retransmission timeout, triggering unnecessary
        retransmissions that waste 2-3× bandwidth.
*   **Result**: Blob data is sent as single-packet sequenced DATA packets
    (~1300 bytes each). The transport tracks delivery for congestion control
    but does NOT retransmit — the CAS layer handles retransmission via
    `BLOB_PROGRESS` bitmask feedback and credit-based flow control. See
    `merkle-tox-cas.md` Section 4.

## 14. Removing Fragment Reassembly from Transport (Dismissed)

*   **Original Proposal**: Eliminate the FRAGMENT packet type entirely.
    Require all protocol messages to fit in a single packet (~1350 bytes), or
    handle splitting at the application layer per message type.
*   **Decision**: Dismissed due to **complexity duplication**.
*   **Rationale**: Several protocol messages legitimately exceed the packet
    MTU — SyncSketch (IBLT cells, 3-49KB), large MerkleNodes (KeyWrap with
    many recipients, Snapshot with many members), and SyncShardChecksums
    (48KB for large archives). These messages are atomic units: an IBLT
    requires all cells to decode, a WireNode requires all fields to verify
    its signature. Without transport-level fragmentation, each message type
    would need its own `(message_id, part_index, total_parts, data)` framing
    and reassembly buffer — reimplementing FRAGMENT at the application layer,
    duplicated across handlers.
*   **Alternatives considered**:
    -   *Reduce FetchBatchReq size*: MAX_BATCH_SIZE can be reduced from 64 to
        ~38 hashes to fit in one packet. This avoids fragmentation for batch
        requests specifically, but does not help SyncSketch or MerkleNode.
    -   *Split IBLT across datagrams*: Send individual cells and accept that
        loss → decode failure → fallback to shard checksums. Wastes a
        reconciliation round on every lost cell.
    -   *Application-level generic fragmenter*: A reusable split/reassemble
        utility in merkle-tox-core. This is just FRAGMENT in a different
        layer, with no benefit.
*   **Result**: Keep FRAGMENT (0x04) in the transport as a minimal
    reassembly mechanism. It provides multi-packet framing with a 5-second
    timeout — no reliability, no retransmission. If any fragment is lost, the
    entire message is dropped and the application's self-healing protocols
    (sync reconciliation, re-request) handle the miss.

## 15. All-Datagram Transport — No Reliable Messages (Adopted)

*   **Original Proposal**: `tox-sequenced` provided TCP-like reliable delivery
    with per-fragment ACKs, selective retransmission, and message-level
    completion guarantees. All protocol messages (control, DAG nodes, blob
    data) used the same reliable message path.
*   **Decision**: Redesign `tox-sequenced` as a **congestion-controlled
    datagram transport** with no reliability.
*   **Rationale**: The transport should control the **rate** (congestion
    control, pacing). The application should control the **content** (what to
    send and retry). The application has semantic knowledge the transport
    lacks:
    -   **DAG nodes are content-addressed**: the sync protocol knows which
        nodes are missing and re-requests them. Transport retransmission is
        redundant.
    -   **Blob chunks are unordered**: any piece is independently useful.
        Bitmask-based CAS tracking is more efficient than per-fragment ACKs.
    -   **Control messages are request/response**: the application knows when
        a response is overdue and can retry with updated state, rather than
        blindly retransmitting a stale request.
*   **Result**: Two transport primitives:
    1.  **DATA** (sequenced datagram): single-packet, tracked by ACK bitmaps
        for congestion control. Used for all single-packet messages including
        bulk blob data. The CC gets per-packet loss visibility across all
        traffic.
    2.  **FRAGMENT** (multi-packet): reassembly with timeout, no reliability.
        Used for oversized protocol messages (SyncSketch, large MerkleNode).
    The transport emits `DatagramLost`/`DatagramDelivered` events. The
    application decides whether to retransmit based on its semantics.

## 16. Unsequenced Datagrams for Blob Data (Dismissed)

*   **Original Proposal**: Add a separate DATAGRAM (unsequenced) packet type
    for blob data, without sequence numbers or ACK bitmap tracking. The CAS
    layer would handle all feedback via BLOB_PROGRESS bitmasks, and the
    transport would be unaware of individual blob packet delivery.
*   **Decision**: Dismissed. All packets use sequenced DATA.
*   **Rationale**: On a P2P network with variable connection quality (NAT
    traversal, UDP hole punching, TCP relay fallback), the congestion
    controller needs *some* per-packet loss signal to distinguish "sending
    too fast" from "slow but lossless link." Without sequence numbers, the
    sender has no way to identify which specific packet was lost or to time
    a per-packet RTO. Bandwidth estimation can run on cumulative byte
    counters, but loss-driven CC reactions (AIMD halving, BBR's loss-rate
    threshold) need a per-packet anchor.
*   **Result**: Kept sequence numbers on every DATA packet. The transport
    knows what it sent and when, and can detect loss via timer (Section 17).
    The application still handles reliability — the transport never
    retransmits, it only reports loss via `DatagramLost(seq)` events.

## 17. ACK Encoding: Bounded SACK Ranges (Final Shape)

The ACK packet went through three iterations on the way to its final
shape. This section records the journey because each step taught
something the next one needed.

### 17a. Iteration 1 — Unbounded bitmap (original; dismissed)

The receiver maintained a sliding-window bitmap of received sequence
numbers and sent it on the wire in every ACK. The sender resolved
individual `sent_datagrams` entries against the bitmap; gaps older
than `2 × RTT` triggered `DatagramLost(seq)` events.

**Failure**: under sustained loss with a non-contiguous receive
pattern, `advance_base` could not advance past the oldest gap. The
bitmap grew without bound, eventually exceeding `MAX_DATAGRAM_SIZE`
and causing every ACK send to fail with
`TOX_ERR_FRIEND_CUSTOM_PACKET_TOO_LONG`. The connection then wedged
permanently — no acks reached the sender, `bytes_acked` stayed
pinned, the send window stayed closed.

### 17b. Iteration 2 — Cumulative-only ACK (intermediate; abandoned)

To make the ACK fixed-size, we considered a TCP Tahoe-style
cumulative-only ACK: `{base_seq, recv_bytes}`. Loss detection moved
entirely to a sender-side RFC 6298 RTO timer.

**Failure**: in real-loss conditions, the receiver's `base_seq`
anchors at the oldest unfilled gap, while seqs above the gap may be
arriving fine. The sender has no way to know about those above-base
receipts; from its perspective they're just unresolved entries
aging past RTO. We measured **~92% false-positive loss** under 4 %
real wire loss in the e2e bench. The CC reacted by collapsing cwnd,
throughput dropped to ~3 Mbps. Architecturally correct (ack channel
no longer wedges), but not viable in practice.

A separate flaw exposed during this iteration: `outstanding_bytes`
was defined as `bytes_sent − bytes_acked`, peer-driven. After cwnd
collapse, `bytes_acked` couldn't advance until alice resumed
sending, but alice couldn't send because the cwnd gate read
`outstanding` as still-pinned. **Fix retained** in the final shape:
`outstanding_bytes` now sums unresolved `sent_datagrams` entry sizes
(local view), so resolved-as-lost entries free up window without
waiting for the peer's recv counter.

### 17c. Iteration 3 — Cumulative + bounded SACK ranges (adopted)

The ACK now carries
`{base_seq, recv_bytes, sack_ranges: SmallVec<(u32, u32), 8>}`. SACK
ranges report above-base receipts compactly: each
`(start_seq, length)` pair covers a run of received seqs that the
sender can resolve immediately. Capped at 8 ranges, ~80 bytes
maximum on the wire — the wedge from §17a remains structurally
impossible.

**Why this is the right shape**:

-   **Wedge-safe by construction.** The SACK list size is bounded
    independent of loss pattern, traffic volume, or window size.
-   **Accurate under loss.** SACK tells the sender exactly which
    above-base seqs arrived, eliminating the false-positive loss
    storm of §17b. End-to-end measurement: 11× fewer loss events on
    a 100 MB transfer.
-   **No application-layer regression.** CAS retransmission still
    runs off `BLOB_PROGRESS` bitmasks (~100 ms cadence). The transport
    just emits more accurate `DatagramDelivered`/`DatagramLost`
    timing.
-   **CC integration unchanged.** BBR/AIMD/Cubic continue to consume
    `(rtt, sample, bytes_acked, in_flight)`. Critically, the
    delivery-rate sample's `bytes_delivered` field comes from
    `delta_recv_bytes` (the peer's authoritative recv counter), NOT
    from SACK-resolved bytes. SACK accelerates *resolution* of
    `sent_datagrams`; it does not feed the bandwidth estimator.
    Re-counting SACK bytes there would double-count and produce
    fabricated throughput estimates.
-   **Backstop preserved.** The RFC 6298 RTO timer remains as a
    fallback for tail loss (last few seqs of a burst, peer goes
    silent) and any other condition SACK can't cover. With SACK
    present it fires only for genuinely lost packets.

**What it costs**:

-   ~80 bytes per ACK in the worst case (vs. 12 bytes for cumulative
    only). Negligible vs. data packet sizes.
-   Per-seq receipt info is now visible to the peer. This weakens
    transport-metadata privacy slightly (loss patterns are
    inferable). The implementation applies ±5 ms random jitter to
    ACK *transmission timing* (constant `ACK_JITTER_MS` in
    `tox-sequenced/src/session.rs`), matching the PONG timestamp
    jitter in `merkle-tox-clock.md` §3.3. The jitter is regenerated
    on every flush call and bounds observable inter-ACK timing
    variation without changing the averaged emission cadence.

### Summary

ACK packet: `{base_seq, recv_bytes, sack_ranges}`. The sender
resolves `sent_datagrams` entries via cumulative ack (seq < base),
selective ack (covered by a SACK range), and timer-based loss (RTO).
The cwnd gate uses local-view `outstanding_bytes`. The receiver
maintains a bounded `RecvTracker` (1024-bit internal bitmap + base)
purely as runtime state — never serialized to the wire — used only
to compute `base_seq` and the next SACK range list at flush time.
