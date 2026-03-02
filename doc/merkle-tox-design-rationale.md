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
    messages (TIME_SYNC_REQ/RES) over the reliable ARQ transport.
*   **Decision**: Dismissed to avoid **ARQ Jitter**.
*   **Rationale**: ARQ transports retransmit lost packets, which introduces
    variable and unpredictable delays, making accurate RTT and offset
    calculations impossible. By moving time sync to the transport-layer
    heartbeats (PING/PONG), we get "free" measurements that bypass
    retransmission buffers and reflect the pure wire latency.
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
