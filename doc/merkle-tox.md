# Merkle-Tox: High-Level Overview

## Introduction

Merkle-Tox is a persistent, decentralized history synchronization system for the
Tox ecosystem. It replaces the "message push" model with a "state
synchronization" model, ensuring participants converge on the same immutable
history across multiple devices and offline periods.

## Concept: History DAG

Merkle-Tox represents a conversation as a **Directed Acyclic Graph (DAG)** of
signed nodes.

-   Each message includes its predecessors' hashes as parents.
-   This structure detects gaps, merges concurrent branches, and verifies
    history integrity back to a "Genesis" event.

## System Layers

The project is divided into three layers:

1.  **Reliability Layer (`tox-sequenced`)**: Provides ordered transport over
    lossy Tox custom packets. It handles fragmentation, acknowledgments, and
    retransmission.

2.  **Logic Layer (`merkle-tox-core`)**: Manages the DAG structure, calculates
    hashes, verifies signatures, and runs the synchronization state machine.

3.  **Persistence Layer (`merkle-tox-sqlite`)**: Handles storage of the DAG and
    large binary assets using SQLite.

## Features

-   **Persistent History**: Messages are stored locally and synced automatically
    upon connection.
-   **Multi-Device Support**: Devices fetch the history DAG to synchronize
    state.
-   **Multi-Source Swarm Sync**: History and files are fetched from multiple
    peers simultaneously, ensuring availability if the original sender is
    offline.
-   **Content-Addressable Storage (CAS)**: Large files are hashed and stored
    separately for deduplication and background downloading.
-   **Integrity & Security**: Every event is signed by its author. The Merkle
    structure prevents historical alteration.
-   **Legacy Interoperability**: Messages from standard Tox protocols are
    bridged into the DAG as "witnessed" events.
-   **Deniability**: DARE (Deniable Authenticated Range/Exchange) ensures
    private content cannot be cryptographically proven to a third party.

## Security & Threat Model

See **`merkle-tox-threat-model.md`** for the formal threat model, adversary
models, attack vectors, and design trade-offs.

## Protocol Constants

The following limits ensure system stability and DoS resistance:

-   **MAX_PARENTS**: 16 (Maximum number of parents a single node can have).
-   **MAX_GROUP_DEVICES**: 4096 (Maximum authorized physical devices per
    conversation, keeping KeyWrap within MTU).
-   **MAX_DEVICES_PER_IDENTITY**: 32 (Maximum authorized devices per logical
    ID).
-   **MAX_METADATA_SIZE**: 32KB (Maximum size of the optional metadata field).
-   **MAX_MESSAGE_SIZE**: 1MB (Maximum reassembled message size for transport).
-   **MAX_INFLIGHT_MESSAGES**: 32 (Maximum concurrent reassemblies per peer).
-   **MAX_HEADS_SYNC**: 64 (Maximum heads advertised in `SYNC_HEADS`).
-   **BASELINE_POW_DIFFICULTY**: 20 bits (Leading zeros for Genesis entry; ~1–2s
    on a smartphone via pre-signature Blake3 hashing).
-   **SKETCH_CPU_BUDGET_MS**: 500 (Per-peer IBLT decoding time budget in
    milliseconds per `SKETCH_CPU_WINDOW_MS` window).
-   **SKETCH_CPU_WINDOW_MS**: 60,000 (1 minute; token bucket refill window for
    per-peer sketch CPU budgets).
-   **KEYWRAP_ACK_TIMEOUT_MS**: 30,000 (30 seconds; 1-on-1 initiator retries
    KeyWrap with a different OPK if no ACK is received within this window).
-   **HANDSHAKE_PULSE_DEBOUNCE_MS**: 300,000 (5 minutes; a device ignores a
    `HandshakePulse` if it has already authored a KeyWrap rotation within this
    window, or if it has already responded to a topologically newer or
    concurrent pulse from the same peer in the current sync batch).
-   **BLOB_CHUNK_SIZE**: 64KB (Standard size for CAS blob requests).

## Baseline Protocol (Version 1)

Version 1 implementations MUST support the following primitives:

-   **Forward Secrecy**: Bounded 30-day epoch via **Signed ECIES Pre-keys**,
    which securely distribute the root of the **Symmetric Hash Ratchet**.
-   **Handshake**: Decentralized **Signed ECIES** using ephemeral pre-keys
    published in **Announcement Nodes**.
-   **Metadata Privacy**: **ISO/IEC 7816-4 Padding** to Power-of-2 boundaries
    and obfuscated `sender_pk`.
-   **Hashing (DAG/CAS)**: **Blake3**.
-   **Symmetric Encryption**: **ChaCha20-IETF** (payload) and
    **ChaCha20-Poly1305** (AEAD for routing headers and key wrapping).
-   **Message Authentication (Content)**: **Ephemeral Ed25519 Signatures** with
    key disclosure (DARE).
-   **Digital Signatures (Admin)**: **Ed25519**.

## Optional Features

Extended capabilities can be negotiated via the `features` bitmask during the
handshake (see `merkle-tox-capabilities.md`):

-   **Snapshots**: Summarized state for shallow sync.
-   **CAS (Blobs)**: Support for large binary assets and swarm-sync.
-   **Compression**: ZSTD-based payload compression.
-   **Advanced Sync**: IBLT-based set reconciliation (`tox-reconcile`).
