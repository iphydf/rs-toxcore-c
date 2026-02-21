# Merkle-Tox Production Roadmap

This document outlines the architectural and implementation improvements
required to bring the Merkle-Tox prototype to production quality.

## 1. Persistence & Storage Architecture

The storage layer must provide abstractions to properly support two primary
backends: a zero-dependency filesystem backend (`fs`) and a transactional
database engine (`sqlite`).

-   **Transactional Consistency:** Redesign the `NodeStore` and
    `process_effects` loop to support atomic multi-operation transactions across
    both SQL and custom FS backends. A sequence of engine effects (e.g., writing
    a node and updating heads) must be committed atomically.
-   **Dual Backends:** Fully implement and optimize both the SQLite backend and
    the Filesystem backend (incorporating the Bloom filters, fanout tables, and
    incremental compaction defined in `merkle-tox-storage-format.md`).
-   **Indexing:** Ensure $O(1)$ or $O(\log N)$ lookups without exhausting RAM.
    For the FS backend, finalize the Bloom Filter and Fanout Table
    implementation; for the SQLite backend, ensure SQL indices are maintained.
-   **Durability Primitives:** Add `fsync` / `fdatasync` support and coalesced
    durability barriers to the Virtual Filesystem (VFS) to prevent data loss on
    power failure while minimizing flash wear.
-   **Schema & Format Migration:** Implement a migration system (e.g., using
    `rusqlite_migrations` for SQL and versioned pack structures for FS) to
    handle upgrades without losing user data.
-   **Startup Integrity Check:** Implement a recovery mode on startup for both
    backends that identifies and cleans up "orphaned" or unverified nodes left
    by partial syncs or interrupted compactions.

## 2. Engine Scalability & Performance

The engine must support conversations with high message volumes and multiple
concurrent devices without linear performance degradation.

-   **Incremental State Loading:** Refactor `load_conversation_state` to avoid
    loading the conversation history into RAM. Use checkpoints for identity and
    permission states.
-   **Fine-Grained Locking:** Move away from the single, coarse-grained mutex
    around `MerkleToxNode`. Implement granular locking (e.g., per-session or
    actor-based) to enable parallel processing.
-   **Permission Checks:** Replace recursive delegation walks with a flattened
    permission cache or a graph-based lookup.
-   **Zero-Copy Hotpath:** Reduce heap allocations in the packet processing
    pipeline by using reference-counted buffers (`Bytes`) instead of frequent
    `.clone()` calls on nodes.
-   **Pagination support:** Enable the engine and UI to load and display only
    the most recent N messages while maintaining background synchronization of
    the full DAG.

## 3. Asynchronous I/O & Backpressure

Decouple the network processing loop from blocking disk I/O to maintain
responsiveness under load.

-   **Async Storage API:** Redesign the `NodeStore` and `BlobStore` traits to be
    asynchronous, allowing storage operations to be offloaded to a dedicated
    thread pool.
-   **Flow Control & Backpressure:** Implement a mechanism to signal peers to
    slow down when local storage or the processing pipeline is overwhelmed.
-   **Pacing & Congestion Control:** Validate and tune the `tox-sequenced`
    congestion control algorithms (AIMD/Cubic/BBR) against real-world network
    conditions.

## 4. Protocol Evolution & Versioning

The protocol must be able to evolve without breaking the existing network.

-   **Versioned Wire Format:** Add version fields to `WireNode` and `MerkleNode`
    to support backward-incompatible changes in the future.
-   **Cross-Conversation Integrity:** Mandate that all parents of a node must
    belong to the same conversation ID to prevent cross-room sync attacks or
    accidental data leakage.
-   **Feature Negotiation:** Expand the `CapsAnnounce` handshake to include a
    bitset of supported sub-protocols and features (e.g., compression methods,
    privacy enhancements).

## 5. State Pruning & Garbage Collection

Manage the long-term growth of the local database to prevent disk exhaustion.

-   **Snapshot-Based Pruning:** Implement logic to handle
    `ControlAction::Snapshot` by deleting historical nodes and metadata that
    precede the snapshot basis hash.
-   **Retention Policies:** Introduce TTL (Time-To-Live) for ephemeral data and
    a mechanism to "forget" devices or peers that have been offline for an
    extended period.

## 6. Privacy & Metadata Protection

Harden the wire format and sync process against passive and active network
observers.

-   **Obfuscate DAG Structure:** Encrypt or hash the `parents` field in
    `WireNode` to prevent observers from mapping conversation graphs.
-   **Encrypt Headers & Payloads (Rationale #2 & #3):** Move `network_timestamp`
    and `author_pk` from the `WireNode` header into the encrypted payload.
    Ensure `encrypted_routing` header is properly applied to `sender_pk` and
    `sequence_number`. (Note: `Admin` and `KeyWrap` must remain plaintext for
    onboarding).
-   **Revert to Linear Ratchets:** Replace the "DAG-based merge ratchet"
    implementation in `conversation.rs` and `crypto.rs` with the documented
    **Per-Sender Linear Ratchets**. This eliminates the brittle
    `historical_chains` cache and the risk of becoming "cryptographically stuck"
    during large forks.
-   **Metadata-Private Sync:** Investigate Private Information Retrieval (PIR)
    or oblivious synchronization techniques to reduce metadata leakage during
    the IBLT reconciliation process.

## 7. Security & Denial-of-Service Protection

Protect the node against malicious peers and resource exhaustion attacks.

-   **Ancestry Trust Cap (Rationale #5):** Implement the 500-hop structural
    trust cap. Mandate that content chains must be re-anchored by a verified
    Admin node every 400 levels to prevent "infinite junk" history attacks.
-   **Contiguity-Based Eviction (Rationale #4):** Implement the Opaque Store
    eviction policy. Prioritize keeping nodes close to the Local Low-Water Mark
    (LLWM) to mitigate Rank-Padding attacks.
-   **Nonce Hardening:** Audit and harden nonce derivation in `crypto.rs` to
    guarantee unique, cryptographically strong nonces for every encryption
    operation, especially for KeyWrap.
-   **Opportunistic Handshake Completion (Rationale #6):** Implement the
    `HandshakePulse` authoring logic to ensure 1-on-1 conversations rotate away
    from "Last Resort" keys immediately upon the peer coming online. This MUST
    include a debounce mechanism (e.g., ignoring pulses if a `KeyWrap` was
    authored within the last 5 minutes) to prevent "KeyWrap Storms" when
    processing large batches of offline messages.
-   **Bounded Allocations:** Fix `tox-proto` to enforce maximum limits on
    collection sizes during deserialization.
-   **CPU DoS Protection:** Harden auto-generated deserialization code to avoid
    long-running loops when skipping extra fields.
-   **IBLT Size Limits:** Enforce strict maximum cell counts for `SyncSketch`
    messages at the deserialization layer to prevent memory-exhaustion attacks
    during reconciliation.
-   **Resource Quotas:** Implement global and per-identity limits on peer
    sessions and reassembly buffers.
-   **Peer Reputation & Attribution:** Track validation failures per peer and
    implement automated punishment.

## 8. API & Code Quality

Ensure the library is easy to use safely and meets high standards for
correctness.

-   **Secure Defaults:** Refactor constructors to use secure, entropy-seeded
    RNGs (`OsRng`) by default. Deterministic injection must be a specialized
    testing-only feature.
-   **Error Propagation:** Eliminate `unwrap()` and `expect()` calls in the
    library. Replace them with `Result` handling.
-   **FFI Safety Audit:** Perform a safety review of the `toxcore` FFI wrapper
    and `tox-proto` unsafe optimizations (e.g., `transmute`).
-   **Standardized Logging:** Implement structured tracing tags across all
    components to improve sync troubleshooting in production environments.

## 9. Tooling, Backup & Documentation

Provide the necessary ecosystem for users and developers.

-   **Documentation Integrity:** Ensure `doc/merkle-tox-ratchet.md` and
    `doc/merkle-tox-design-rationale.md` remain the source of truth for the
    linear ratchet model once the implementation is reverted.
-   **Formal Specification:** Create a formal specification of the binary wire
    format and protocol state machine transitions.
-   **Integrated Backup Tool:** Develop a utility for creating consistent
    snapshots of identity seeds and conversation history for user migration.
-   **Network Simulation:** Expand the `VirtualHub` to simulate high-latency,
    low-bandwidth, and lossy environments to ensure protocol robustness.
-   **Development Tool Isolation:** Ensure that developer tools like
    `merkle-tox-workbench` and test mocks are strictly separated from production
    builds.

## 10. Legacy Interoperability

Bridge the gap between Merkle-Tox and standard Tox to ensure a smooth transition
for the ecosystem.

-   **Legacy Bridge Implementation:** Implement the `Content::LegacyBridge` node
    type and the notary logic in `merkle-tox-tox`.
-   **Multi-Device Deduplication:** Integrate the `NetworkClock` with the
    deduplication hashing strategy defined in `merkle-tox-legacy-bridge.md`.
-   **UI Materialization:** Update `merkle-tox-client` to project bridged
    messages and handle duplicate witness suppression.
-   **Quorum Witnessing Logic:** Add logic to the client to prefer bridged nodes
    that have been "witnessed" by multiple members (if available) to increase
    confidence in the validity of bridged legacy data.
-   **Fallback Signaling:** Automatically detect when a peer does not support
    Merkle-Tox and initiate the legacy bridge mode for that conversation.
