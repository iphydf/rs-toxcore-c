# Merkle-Tox: Type-System Hardening Plan (Level 8)

## Overview

This document outlines the plan to move Merkle-Tox from **Level 7 (Pure Effect
Systems)** to **Level 8 (Semantic & Data Safety)**. The goal is to eliminate
remaining classes of logic errors (such as ID confusion or bit-masking mistakes)
by utilizing Rust's type system to enforce semantic invariants.

--------------------------------------------------------------------------------

## Phase 1: Semantic Labeling & Encapsulation (Newtypes)

We have replaced raw `[u8; 32]` with distinct Newtypes and made their internal
fields private to prevent accidental cross-usage or type-punning.

### 1.1. Identification Types

-   **`NodeHash`**: Identifies a specific Merkle Node.
-   **`ConversationId`**: Identifies a specific conversation.
-   **`ShardHash`**: Checksum for a sync shard.
-   **`PowNonce`**: Proof-of-work challenge nonce.

### 1.2. Identity Types

-   **`LogicalIdentityPk`**: Ed25519 master public key.
-   **`PhysicalDevicePk`**: Ed25519 device public key.
-   **`EphemeralX25519Pk`**: Short-lived keys for X3DH.

### 1.3. Cryptographic Key Types

-   **`MessageKey`**: Per-message symmetric encryption.
-   **`SharedSecretKey`**: Result of DH/X3DH.
-   **`EncryptionKey` / `MacKey`**: Derived from conversation root.
-   **`KConv`**: Conversation epoch root key.
-   **`ChainKey`**: Current ratchet state.

**Status:** COMPLETED. Fields are private. Semantic conversion methods (e.g.,
`to_physical()`, `to_logical()`, `to_node_hash()`) are implemented in
`tox-proto/src/lib.rs`. All call-sites in the core, client, and storage layers
have been migrated.

--------------------------------------------------------------------------------

## Phase 2: Permission Safety (Bitflags)

Replace raw `u32` bit-masks for permissions with structured types using the
`bitflags` crate.

### 2.1. Invariants

-   Enforce the **Intersection Rule** (Device A cannot delegate more than it
    has) via type-safe set operations.
-   Explicitly distinguish between **Requested Permissions** (in a certificate)
    and **Effective Permissions** (after trust-path resolution).

**Status:** Planned. Focus on `identity.rs` and `processor/verification.rs`.

--------------------------------------------------------------------------------

## Phase 3: Cryptographic Hygiene (Zeroize)

Ensure that sensitive keys and ratchet material are wiped from memory
immediately upon deletion or drop.

### 3.1. Sensitive Containers

-   **`SecretKey`**: Wraps [u8; 32] with `Zeroize`.
-   **`ChainKey`**: Wraps the current ratchet state.
-   **`KConv`**: Wraps the epoch root keys.

**Status:** Planned. Requires adding the `zeroize` crate to `merkle-tox-core`.

--------------------------------------------------------------------------------

## Phase 4: Atomic Effect Bundling

Prevent partial state updates by bundling effects that are logically
inseparable.

### 4.1. DAG State Atomic

Instead of separate `WriteStore` and `UpdateHeads` effects, introduce a
`CommitNode` effect:

```rust
struct CommitNode {
    hash: NodeHash,
    node: MerkleNode,
    is_verified: bool,
    heads_update: Option<HeadsUpdate>,
}
```

### 4.2. Ratchet State Atomic

Bundle `WriteRatchetKey` and `DeleteRatchetKey` to ensure the "Forward" move is
a single transaction.

**Status:** Planned. Requires refactoring `engine/mod.rs` and `node.rs`.

--------------------------------------------------------------------------------

## Phase 5: Refined Evidence Sub-types

Specialize `VerifiedNode<T>` into distinct types for Admin and Content tracks.

### 5.1. Specialized Wrappers

-   **`VerifiedAdminNode`**: Guaranteed to contain `Content::Control`. Used by
    `IdentityManager`.
-   **`VerifiedContentNode`**: Guaranteed to contain non-control content. Used
    by the Ratchet and UI.

### 5.2. Compilation Safety

Functions like `apply_side_effects` will be split into track-specific handlers
that accept these specialized types, eliminating the need for internal "is this
an admin node?" checks.

--------------------------------------------------------------------------------

## Phase 6: Nested Content Enums

Refactor the `Content` enum to be hierarchical.

### 6.1. Structure

-   `Content::Admin(AdminAction)`
-   `Content::Message(MessageData)`
-   `Content::System(SystemAction)`

**Status:** Long-term. Enhances pattern matching exhaustiveness.

--------------------------------------------------------------------------------

## Summary of Hardening Goals

Threat Class            | Mitigation (Level 8)       | Tool
:---------------------- | :------------------------- | :---------------------
**Identity Confusion**  | Newtypes for PK variants   | Struct Wrappers
**Bit-mask Errors**     | Typed Bitflags             | `bitflags` crate
**Memory Forensics**    | Zero-on-drop               | `zeroize` crate
**State Inconsistency** | Atomic Effect Bundles      | Type Composition
**Logic Branching**     | Refined Evidence Sub-types | Generic Specialization
