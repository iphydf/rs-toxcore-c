# Merkle-Tox Sub-Design: Symmetric Key Ratcheting

## Overview

To provide granular **Forward Secrecy (FS)** for every message without the
complexity of DAG-merge races, Merkle-Tox uses **Per-Sender Linear Ratchets**.
Each physical device in a conversation maintains a strictly linear hash chain
that is independent of other devices' branches.

## 1. The Per-Sender Hash Chain

Every physical device ($sender_pk$) authors messages in a sequential order
defined by its `sequence_number`. This sequence forms a linear cryptographic
chain.

### A. Initialization (Sender Key)

When a device is first authorized or needs to establish Post-Compromise
Security, it generates a random 32-byte `SenderKey`. This key becomes the
initial chain key:

*   $K_{chain, 0} = SenderKey$

The device distributes this `SenderKey` to all other authorized devices in the
room via a `SenderKeyDistribution` node (encrypted individually for each
recipient using X3DH).

### B. Step Function

For every message authored by the device, the chain advances:

*   $K_{chain, i+1} = ext{Blake3-KDF}( ext{context: "merkle-tox v1
    ratchet-step"}, K_{chain, i})$
*   $K_{msg, i} = ext{Blake3-KDF}( ext{context: "merkle-tox v1 message-key"},
    K_{chain, i})$

The message is encrypted with $K_{msg, i}$. After the step, $K_{chain, i}$ is
immediately deleted.

## 2. Decoupling Encryption from DAG Merges

In Merkle-Tox, the DAG and the Ratchet serve distinct purposes:

1.  **The DAG (Logical Layer)**: Manages **Synchronization and Integrity**.
    Nodes include hashes of parents from *any* device to form the global graph.
2.  **The Ratchet (Cryptographic Layer)**: Manages **Confidentiality**. A node's
    encryption key depends **only** on the previous node from the **same
    sender**.

### Rationale: Zero-Race Condition

By making the ratchet linear per-sender, the protocol eliminates the race
conditions where a single parent key might be needed for multiple concurrent
siblings. Each $sender_pk$ can only be in one cryptographic state at any given
`sequence_number`.

## 3. Post-Compromise Security (PCS)

While the linear ratchet provides Forward Secrecy, it does not provide
**Post-Compromise Security (PCS)**. Merkle-Tox achieves PCS through **Periodic
Sender Key Rotations**.

### A. Rotation Boundaries

Instead of an Admin bottlenecking the room by rekeying everyone simultaneously,
PCS is handled *per-device*. Every 5,000 messages or 7 days, a device performs a
"Sender Rekey":

1.  **Revocation Check**: The device verifies the current member list against
    the DAG.
2.  **New Root**: The device generates a new `SenderKey` ($K_{chain, 0}$).
3.  **Distribution**: It authors a `SenderKeyDistribution` node, encrypting the
    new key via X3DH for all currently authorized members.

### B. Self-Healing

Once a new `SenderKey` is established and distributed, an attacker who
previously had access to the device's old chain is "kicked out" of the future
key space. The computational burden of key rotation ($O(N)$ encryptions) is
distributed across all active participants, enabling scaling for rooms with 200+
users.

## 4. Implementation Rules

1.  **Forward Skipping (Out-of-Order Support)**: A recipient MUST support
    skipping forward in the ratchet if a message arrives out of order. The
    recipient iteratively advances the chain, deriving and caching the $K_{msg,
    i}$ for all skipped `sequence_number`s up to the received message. To
    prevent memory- exhaustion DoS attacks, a strict skip limit
    (`MAX_RATCHET_SKIPS = 2000`) MUST be enforced. Messages jumping further
    ahead are buffered in the **Opaque Store**.
2.  **Immediate Deletion**: Implementations MUST overwrite old chain keys
    ($K_{chain, i}$) with zeros in memory as soon as the ratchet advances to the
    next sequence.
3.  **Storage Isolation**: The current $K_{chain}$ and the cache of skipped
    message keys SHOULD be stored in a separate, encrypted table to prevent
    leakage.
4.  **Key Cache & Replay Protection**: When a delayed out-of-order message
    arrives, it is decrypted using its cached $K_{msg, i}$. Upon successful
    decryption, that key MUST be immediately deleted from the cache.
    -   **Strict TTL (Forward Secrecy)**: To minimize the vulnerability window
        where a seized device might leak cached keys from RAM, any key remaining
        in the skipped cache MUST be permanently deleted after a strict
        Time-To-Live (`RATCHET_CACHE_TTL_MS = 86400000`), even if the
        corresponding delayed message never arrived.
    -   A client MUST NOT accept a message with a `sequence_number` lower than
        the current chain index UNLESS its corresponding key is present in the
        skipped message cache (preventing replays).
