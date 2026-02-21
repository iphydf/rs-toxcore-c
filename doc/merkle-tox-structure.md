# Merkle-Tox Sub-Design: Project Structure & Bazel Integration

## Overview

This document outlines the directory structure and Bazel targets for the
Merkle-Tox project. The project is split into three libraries located within the
`rs-toxcore-c` directory, following the established pattern of sibling projects
like `toxcore` and `toxxi`.

## 1. Directory Layout

```text
rs-toxcore-c/
├── tox-proto/               # Layer 0: Serialization & Protocol Primitives
├── tox-proto-derive/        # Layer 0 (Macro): Positional Serialization
├── tox-sequenced/           # Layer 1: Reliability & ARQ
├── merkle-tox-core/         # Layer 2: DAG, CAS, & Sync Logic (Mechanisms)
├── merkle-tox-client/       # Layer 3: Orchestration & High-Level API (Policy)
├── merkle-tox-sqlite/       # Layer 4: SQLite Persistence
├── merkle-tox-fs/           # Layer 4: Filesystem (Git-style) Persistence
├── merkle-tox-tox/          # Layer 5: Tox Integration Bridge
├── merkle-tox-workbench/    # Swarm Simulation & Chaos Lab (MVU pattern)
├── apps/                    # Sample Apps (groupbot, vaultbot, etc)
├── doc/                     # Centralized Design Documents
└── ...
```

## 2. Bazel Targets

### `//rs-toxcore-c/tox-proto:tox-proto`

-   **Type**: `rust_library`
-   **Responsibilities**: Positional serialization using MessagePack.
-   **Dependencies**: `@crates//:rmp-serde`, `@crates//:serde`,
    `@crates//:serde_bytes`.
-   **Macros**: `//rs-toxcore-c/tox-proto-derive`.

### `//rs-toxcore-c/tox-sequenced:tox-sequenced`

-   **Type**: `rust_library`
-   **Responsibilities**: Reliable delivery over lossy Tox custom packets.
-   **Dependencies**: `//rs-toxcore-c/tox-proto:tox-proto`, `@crates//:serde`.

### `//rs-toxcore-c/merkle-tox-core:merkle-tox-core`

-   **Type**: `rust_library`
-   **Responsibilities**: DAG management, synchronization logic, and
    cryptographic verification.
-   **Dependencies**:
    -   `//rs-toxcore-c/tox-proto:tox-proto`
    -   `//rs-toxcore-c/tox-sequenced:tox-sequenced`
    -   `@crates//:blake3`
    -   `@crates//:ed25519-dalek`
    -   `@crates//:serde`

### `//rs-toxcore-c/merkle-tox-sqlite:merkle-tox-sqlite`

-   **Type**: `rust_library`
-   **Responsibilities**: SQLite persistence for nodes and blobs.
-   **Dependencies**:
    -   `//rs-toxcore-c/merkle-tox-core:merkle-tox-core`
    -   `@crates//:rusqlite`
    -   `@crates//:serde`

### `//rs-toxcore-c/merkle-tox-fs:merkle-tox-fs`

-   **Type**: `rust_library`
-   **Responsibilities**: Filesystem-based persistence (Git-style) for nodes and
    blobs.
-   **Dependencies**:
    -   `//rs-toxcore-c/merkle-tox-core:merkle-tox-core`
    -   `@crates//:serde`
    -   `@crates//:rmp-serde`

### `//rs-toxcore-c/merkle-tox-tox:merkle-tox-tox`

-   **Type**: `rust_library`
-   **Responsibilities**: Bridge between `toxcore` and `merkle-tox-core`.
    Handles packet dispatch and Tox event processing.
-   **Dependencies**:
    -   `//rs-toxcore-c:toxcore`
    -   `//rs-toxcore-c/merkle-tox-core:merkle-tox-core`
    -   `//rs-toxcore-c/tox-sequenced:tox-sequenced`

## 3. Implementation Workflow

1.  **[x] `tox-sequenced`**: Establish reliability and fragmentation.
2.  **[x] `merkle-tox-core`**: Build the pure-logic sync engine.
3.  **[x] `merkle-tox-sqlite`**: Add the database storage layer.
4.  **[ ] `toxxi` Integration**: Update the UI client to use these crates for
    message storage and sync.
