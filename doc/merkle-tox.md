# Merkle-Tox: High-Level Overview

## Introduction

Merkle-Tox is a persistent, decentralized history synchronization system for the
Tox ecosystem. It shifts from a "message push" model to a "state
synchronization" model, ensuring that all participants in a conversation
eventually converge on the same immutable history, even across multiple devices
and offline periods.

## Core Concept: History as a DAG

Instead of a linear stream of messages, Merkle-Tox represents a conversation as
a **Directed Acyclic Graph (DAG)** of cryptographically signed nodes.

-   Each message "acknowledges" its predecessors by including their hashes as
    parents.
-   This structure allows the protocol to detect gaps, handle concurrent
    branches (merging), and verify the integrity of the entire history back to a
    "Genesis" event.

## System Layers

The project is divided into three decoupled layers to ensure maintainability and
reusability:

1.  **Reliability Layer (`tox-sequenced`)**: Provides a reliable, ordered
    transport over lossy Tox custom packets. It handles fragmentation of large
    data blocks and ensures chunks are acknowledged and retransmitted if lost.

2.  **Logic Layer (`merkle-tox-core`)**: The "brains" of the system. It manages
    the DAG structure, calculates hashes, verifies signatures, and runs the
    synchronization state machine to reconcile history between peers.

3.  **Persistence Layer (`merkle-tox-sqlite`)**: Handles the long-term storage
    of the DAG and large binary assets (images/files) using SQLite.

## Key Features

-   **Persistent History**: Messages are stored locally and synced automatically
    upon connection.
-   **Multi-Device Support**: A user can join a conversation from a new device
    and "catch up" by fetching the history DAG.
-   **Multi-Source Swarm Sync**: History and files are fetched from multiple
    peers simultaneously (BitTorrent-style), saturating bandwidth and ensuring
    availability even if the original sender is offline.
-   **Content-Addressable Storage (CAS)**: Large files are hashed and stored
    separately, allowing for deduplication and "lazy" background downloading.
-   **Integrity & Security**: Every event is signed by its author. The Merkle
    structure ensures that past history cannot be altered without breaking the
    hash chain.
-   **Deniability**: Uses DARE (Deniable Authenticated Range/Exchange) to ensure
    private content cannot be cryptographically proven to a third party.

## Security & Threat Model

Merkle-Tox maintains a formal **Threat Model** and security analysis. For a
detailed breakdown of adversary models, attack vectors (such as KCI), and design
trade-offs, see **`merkle-tox-threat-model.md`**.

## Protocol Constants

The following limits are enforced to ensure system stability and DoS resistance:

-   **MAX_PARENTS**: 16 (Maximum number of parents a single node can have).
-   **MAX_DEVICES_PER_IDENTITY**: 32 (Maximum authorized devices per logical
    ID).
-   **MAX_METADATA_SIZE**: 32KB (Maximum size of the optional metadata field).
-   **MAX_MESSAGE_SIZE**: 1MB (Maximum reassembled message size for transport).
-   **MAX_INFLIGHT_MESSAGES**: 32 (Maximum concurrent reassemblies per peer).
-   **MAX_HEADS_SYNC**: 64 (Maximum heads advertised in `SYNC_HEADS`).
-   **BASELINE_POW_DIFFICULTY**: 12 bits (Leading zeros for Genesis entry).
-   **ADAPTIVE_POW_LIMIT**: ±1 bit / 24h (Max slew rate for difficulty
    consensus).
-   **BLOB_CHUNK_SIZE**: 64KB (Standard size for CAS blob requests).

## Baseline Protocol (Version 1)

All Merkle-Tox implementations claiming Version 1 compliance MUST support the
following security and synchronization primitives by default:

-   **Forward Secrecy**: Per-message via **Symmetric Hash Ratchet** and
    per-handshake via **X3DH**.
-   **Handshake**: Decentralized **X3DH** using ephemeral pre-keys published in
    **Announcement Nodes**.
-   **Metadata Privacy**: **ISO/IEC 7816-4 Padding** to Power-of-2 boundaries
    and obfuscated `sender_pk`.
-   **Hashing (DAG/CAS)**: **Blake3**.
-   **Symmetric Encryption**: **ChaCha20** (IETF version).
-   **Message Authentication (Content)**: **Blake3-MAC**.
-   **Digital Signatures (Admin)**: **Ed25519**.

## Optional Features

Extended capabilities can be negotiated via the `features` bitmask during the
handshake (see `merkle-tox-capabilities.md`):

-   **Snapshots**: Summarized state for shallow sync.
-   **CAS (Blobs)**: Support for large binary assets and swarm-sync.
-   **Compression**: ZSTD-based payload compression.
-   **Advanced Sync**: IBLT-based set reconciliation (`tox-reconcile`).

## Implementation Roadmap

1.  **[x] Reliable Transport**: Built the sequencing and ARQ mechanism.
2.  **[x] Core Sync Logic**: Implemented the DAG traversal and reconciliation
    protocol.
3.  **[x] Persistence**: SQLite and Filesystem storage engine implementations.
4.  **[x] Client Layer**: High-level orchestration, materialized views, and
    auto-authorization.
5.  **[ ] Application Integration**: Adding Merkle-Tox support to the `toxxi`
    client.
