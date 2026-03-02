# Merkle-Tox Sub-Design: Capabilities & Handshake

## Overview

Peers MUST negotiate capabilities before synchronizing to prevent protocol
mismatches.

## 1. Capability Discovery

The handshake uses `tox-sequenced`.

### Discovery via Custom Packet

1.  Upon connection, a client sends `CAPS_ANNOUNCE` via a `tox-sequenced` DATA
    packet.
2.  Peers supporting Merkle-Tox respond with `CAPS_ANNOUNCE`.

## 2. Capability Negotiation

### A. Network-Intrinsic (Ephemeral)

Negotiated per-session via `CAPS_ANNOUNCE`.

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

Mandatory for Version 1. Committed to the DAG (**Genesis Node** or
**Announcement Nodes**). Every member MUST support these to parse history.

*   **Signed ECIES Handshake**: Mandatory for initial $K_{conv}$.
*   **Symmetric Ratcheting**: Mandatory for post-compromise security and hash
    chaining.
*   **Power-of-2 Padding**: Mandatory ISO/IEC 7816-4 anti-traffic analysis.
*   **Compression**: (e.g., Zstd) If used, all readers must support it.

**Principle**: Data-Intrinsic features are immutable. A peer MUST NOT author
nodes using optional features unless enabled in Genesis.

### `CAPS_ACK` (Packet Content)

Peer B responds with `CAPS_ACK` (0x02) containing `CapsAnnounce`, completing the
handshake and starting `merkle-tox-sync`.

## 3. Post-Handshake Procedures

After `CAPS_ACK`:

1.  **Head Exchange**: Both peers send `SYNC_HEADS` to begin reconciliation.
2.  **Continuous Clock Sync**: Peers monitor PING/PONG timestamps to maintain
    time offsets.
