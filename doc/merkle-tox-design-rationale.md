# Merkle-Tox Design Rationale & Dismissed Considerations

This document records the architectural decisions made during the design of
Merkle-Tox v1. It specifically focuses on "rejected" paths or simplifications to
prevent future redesigns from re-introducing known vulnerabilities or
redundancies.

## 1. SyncKey Obfuscation (Dismissed)

*   **Original Proposal**: Derive a `SyncKey = KDF(ConversationID)` to hide the
    room ID from network observers.
*   **Decision**: Dismissed as mathematically redundant.
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
    header to allow for instant filtering and decryption without
    trial-and-error.
*   **Decision**: Dismissed for security and protocol integrity.
*   **Rationale**:
    1.  **Metadata Leakage**: Exposing the epoch allows untrusted peers (e.g.,
        SyncBots) to observe key rotation frequency and interaction patterns.
    2.  **Ghost Content**: Decrypting nodes before their parents arrive (using
        the epoch hint) would allow for "floating" messages that have no
        verifiable topological context, compromising the Merkle trust model.
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
    Local Low-Water Mark (LLWM). This forces an attacker to possess the room's
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
    keys destroys the "Instant Messaging" feel and breaks asynchronous
    store-and-forward.
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
    own strictly linear hash chain. DAG merges remain logical (sync/integrity)
    but not cryptographic (encryption). This achieves Signal-grade Forward
    Secrecy with zero race conditions.

## 9. Application-Layer Time Sync (Dismissed)

*   **Original Proposal**: Perform time synchronization via high-level protocol
    messages (TIME_SYNC_REQ/RES) over the reliable ARQ transport.
*   **Decision**: Dismissed to avoid **ARQ Jitter**.
*   **Rationale**: ARQ transports retransmit lost packets, which introduces
    variable and unpredictable delays. This makes accurate RTT and offset
    calculations impossible. By moving time sync to the transport-layer
    heartbeats (PING/PONG), we get "free" measurements that bypass
    retransmission buffers and reflect the pure wire latency.
*   **Result**: Move time measurement to the `tox-sequenced` transport layer.
    The logic layer now only handles the **Median Consensus** and **Slewing**.
