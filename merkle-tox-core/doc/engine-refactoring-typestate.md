# Merkle-Tox Engine Architecture (Level 7 Implemented)

This document defines the architecture of the `MerkleToxEngine`, which has been
refactored from a procedural "God Module" into a **Type-Driven State Machine**.
This design leverages Rust's type system to enforce protocol correctness,
eliminate illegal state transitions at compile-time, and provide a formal
structure for cryptographic evidence.

## Core Architectural Principles

1.  **Protocol Correctness:** Using Typestates to ensure that protocol logic
    (e.g., history reconciliation) is only accessible when the peer session is
    in the correct state (e.g., `Active`).
2.  **Evidence-Based Processing:** Utilizing "Verified Wrappers"
    (`VerifiedNode<T>`) to ensure that side-effects are only applied to nodes
    that have passed cryptographic and identity checks.
3.  **Functional Decomposition:** Separating "Policy" (decision making) from
    "Mechanism" (node creation, verification, storage).
4.  **State Isolation:** Isolating transient peer-specific state from
    persistent, conversation-wide state.
5.  **Pure Effect System (Level 7 Vision):** The engine acts as an "Oblivious
    Brain," emitting declarative intents (`Effect`) rather than performing IO.

--------------------------------------------------------------------------------

## 1. The Modular Structure (Level 6 Status: Complete)

The engine is decomposed into high-cohesion sub-modules under
`merkle-tox-core/src/engine/`:

### 1.1. The Coordinator (`mod.rs`)

The `MerkleToxEngine` struct serves as a thin coordination layer. It owns the
registries of peer sessions and conversation managers.

### 1.2. Typestate Peer Sessions (`session/`)

The `SyncSession` is a state machine where transitions consume the previous state.
`session.activate(features)` consumes a `Handshake` session and returns an
`Active` session.

### 1.3. Conversation Typestates (`conversation.rs`)

The `Conversation<S>` typestates manage conversation-wide state:
-   **`Conversation<Pending>`**: Handles received speculative nodes while keys
    are missing.
-   **`Conversation<Established>`**: Manages active `ConversationKeys` and the
    per-message ratchet (`head_chains`).
- **Transition Rule**: Establishing a conversation triggers an immediate
    **Re-verification Sweep** across all speculative nodes, promoting valid
    history.

### 1.4. The Evidence Pipeline (`processor/`)

- **`VerifiedNode<T>`**: A wrapper ensuring a node passed all checks.
- **Strict Centralization**: All nodes (including self-authored) pass through
    identical verification paths in `handle_node`, preventing authorship privilege.
- **Side Effects**: Ratchet advancement, head management, and identity updates
    are triggered only after successful verification.

### 1.5. The Authoring Module (`authoring.rs`)

A pure factory for raw `MerkleNode` objects. It handles deterministic parent
selection and PoW for Genesis.

--------------------------------------------------------------------------------

## 2. Level 7 Evolution: Pure Effect Systems (Status: Complete)

The engine has been refactored to act as an "Oblivious Brain," emitting declarative intents (`Effect`) rather than performing IO.

### 2.1. Declarative Intents

The engine emits effects instead of mutating external state:

```rust
pub enum Effect {
    SendPacket(PublicKey, ProtocolMessage),
    WriteStore(Hash, MerkleNode, bool),
    WriteRatchetKey(Hash, Hash, [u8; 32]),
    DeleteRatchetKey(Hash, Hash),
    UpdateHeads(Hash, Vec<Hash>, bool), // cid, heads, is_admin
    WriteConversationKey(Hash, u64, [u8; 32]),
    WriteEpochMetadata(Hash, u32, i64),
    WriteBlobInfo(BlobInfo),
    WriteChunk(Hash, Hash, u64, Vec<u8>, Option<Vec<u8>>),
    EmitEvent(NodeEvent),
    ScheduleWakeup(Task, Instant),
}
```

### 2.2. Gaps Closed

1.  **Functional Processor**: `apply_side_effects` and `update_heads` now return `Vec<Effect>`.
2.  **Synchronous Consistency**: The `MerkleToxNode` orchestrator processes effects in strict sequence, ensuring consistency even in async environments.
3.  **Expanded Coverage**: Added effects for ratchet key deletion, head management, and blob storage.
4.  **Double-IO Removal**: The engine utilizes a transient `PendingCache` and `EngineStore` overlay to maintain internal consistency during complex operations without performing direct IO.

### 2.3. Current Status (Level 7 Complete)

- **Completed:** Level 6 Typestates, Level 7 Effect Emission.
- **Pattern:** All state-changing operations in the engine return `Effect`s.
- **Internal Consistency:** The `PendingCache` acts as "working memory," allowing the engine to validate nodes against its own uncommitted changes.

### 2.4. Future Roadmap (Next Steps)

1.  **Transactional Storage:** Add `start_transaction` and `commit` methods to the `NodeStore` trait. This will allow the `MerkleToxNode` orchestrator to wrap `process_effects` in a real DB transaction, providing absolute atomicity and rollback capability for effect batches.
2.  **Shallow Sync State Persistence:** Currently, `SyncSession` limits (min\_rank, min\_timestamp) are transient. Persisting these per-peer would allow resuming "thin" syncs after a restart without re-scanning the entire history.
3.  **Blob Expiry Policy:** Implement an effect or background task for pruning `BlobData` from the `ObjectStore` once all referencing `MerkleNode`s have been deleted or a retention period has passed.

--------------------------------------------------------------------------------

## 3. Implementation Progress (Status: Level 7+ Complete)

The engine and orchestrator have reached a high degree of maturity regarding state safety and persistence.

- **Identity Reconstruction**: COMPLETED. `load_conversation_state` now reconstructs the `IdentityManager` by scanning the DAG.
- **Effect Atomicity**: COMPLETED. `MerkleToxNode` processes effects as batches and clears the `PendingCache` only on successful commitment.
- **Pure Effect System**: COMPLETED. All IO-bound operations are emitted as declarative `Effect` variants.
- **Forward Secrecy**: COMPLETED. `DeleteRatchetKey` effects are strictly honored by SQLite and FS backends.


### 3.1. Proved vs. Tested

With Level 6, many unit tests have become redundant. We no longer test "Does the
engine reject a sync request during handshake?" because that code **will not
compile**. We trade hundreds of lines of "negative testing" for a few lines of
type definition.

### 3.2. Property-Based Testing

The explicit state machine allows us to use `proptest` to generate arbitrary
sequences of valid and invalid protocol messages.

-   **Robustness Invariant**: The engine must never panic, regardless of the
    message sequence.
-   **State Invariant**: A session must only enter the `Active` state after a
    valid `CapsAnnounce` or `CapsAck`.

### 3.3. Deterministic Simulation

By isolating the `Processor` and `Authoring` logic, the `Merkle-Tox Workbench`
can simulate massive swarms (100+ nodes) with high-fidelity network impairments,
proving convergence properties at scale.

### 3.4. Complexity vs. Safety Trade-offs

| Feature               | Complexity Add       | Safety/Resilience Gain     |
| :-------------------- | :------------------- | :------------------------- |
| **Strict Evidence**   | 🟢 Low (Refactor)     | 🔴 High (Prevents local     |
:                       :                      : "hallucination")           :
| **Specialized Nodes** | 🟢 Low (Generics)     | 🔴 High (Prevents           |
:                       :                      : type-confusion)            :
| **Effect Scheduler**  | 🟡 Medium (PQ Logic)  | 🟡 Medium (Clean background |
:                       :                      : tasks)                     :
| **Store-as-State**    | 🔴 High (Persistence) | 🔴 High (Absolute           |
:                       :                      : crash-resilience)          :