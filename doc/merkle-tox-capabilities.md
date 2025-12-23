# Merkle-Tox Sub-Design: Capabilities & Handshake

## Overview

To ensure interoperability and backward compatibility, Merkle-Tox peers must
negotiate their capabilities before initiating a synchronization session. This
prevents protocol mismatches and allows the system to evolve without breaking
existing clients.

## 1. Capability Discovery

Merkle-Tox uses the `tox-sequenced` reliability layer for all communications,
including the initial handshake. This ensures that even the capability exchange
is robust against packet loss.

### Discovery via Custom Packet

1.  Upon connection, a client sends a `CAPS_ANNOUNCE` message via a
    `tox-sequenced` DATA packet (using custom lossy packets as the carrier).
2.  If the peer supports Merkle-Tox, they will respond with their own
    `CAPS_ANNOUNCE`.

## 2. Capability Negotiation

Merkle-Tox separates capabilities into two categories to ensure that history
remains readable even when synced via blind relays and that parsing-critical
features are committed to the DAG.

### A. Network-Intrinsic (Ephemeral)

These are negotiated per-session via the `CAPS_ANNOUNCE` packet. They describe
how the current peer wants to communicate.

Serialized via MessagePack:

```rust
struct CapsAnnounce {
    /// Protocol version (e.g., 1).
    version: u32,
    /// Bitmask of optional transport features:
    /// 0x01: Multi-Source Swarm Sync (merkle-tox-cas.md)
    /// 0x02: Advanced Set Reconciliation (IBLT / tox-reconcile)
    /// 0x04: Large Batch Support (> 100 nodes per FETCH_BATCH_REQ)
    features: u64,
}
```

### B. Data-Intrinsic (Persistent / Baseline)

These are mandatory for Version 1 and are committed to the DAG (in the **Genesis
Node** or **Announcement Nodes**). Every member of the conversation MUST support
these to parse the history.

*   **X3DH Handshake**: Mandatory for initial $K_{conv}$ establishment.
*   **Symmetric Ratcheting**: Mandatory for per-message forward secrecy.
*   **Power-of-2 Padding**: Mandatory ISO/IEC 7816-4 anti-traffic analysis.
*   **Compression**: (e.g., Zstd) If used by an author, it must be supported by
    all readers.

**Principle**: Data-Intrinsic features are immutable properties of the
conversation's history. A peer MUST NOT author a node using an optional
Data-Intrinsic feature (like compression) unless that feature was enabled in the
room's Genesis parameters.

### `CAPS_ACK` (Packet Content)

Peer B responds with its own `CapsAnnounce` struct using the `CAPS_ACK` message
type (0x02). This completes the 2-way handshake. Once both sides have exchanged
these, the `merkle-tox-sync` state machine begins.

## 3. Post-Handshake Procedures

Immediately following a successful `CAPS_ACK`, the following procedures are
initiated:

1.  **Head Exchange**: Both peers send `SYNC_HEADS` to begin history
    reconciliation.
2.  **Continuous Clock Sync**: Peers monitor transport-layer PING/PONG
    timestamps to maintain network time offsets.
