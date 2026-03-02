# Merkle-Tox Sub-Design: Symmetric Key Ratcheting

## Overview

To provide **Forward Secrecy (FS)** for every message without DAG-merge races,
Merkle-Tox uses **Per-Sender Linear Ratchets**. Each physical device maintains a
linear hash chain independent of other devices.

## 1. The Per-Sender Hash Chain

Every physical device ($sender_pk$) authors messages in a sequential order
defined by its `sequence_number`, forming a linear cryptographic chain.

### A. Initialization (Sender Key)

Upon authorization or to establish Post-Compromise Security, a device generates
a random 32-byte `SenderKey` (initial chain key):

*   $K_{chain, 0} = SenderKey$

The device distributes this `SenderKey` to all other authorized devices in the
room via a `SenderKeyDistribution` node (encrypted individually for each
recipient device using ECIES against their current SPK; see `merkle-tox-dag.md`
`WrappedKey`).

### B. Just-In-Time (JIT) Piggybacking (New Member Onboarding)

Upon processing a new `AuthorizeDevice` or `Invite` node, existing members do
**not** immediately author key material. Merkle-Tox uses **Just-In-Time (JIT)
Piggybacking**:

*   **Trigger**: When a device is preparing to author a **new `Content` node**
    (e.g., sending a text message), it MUST first check the current verified
    Admin track for any authorized devices that are not present in its local
    `SharedKeys` cache for the current epoch.
*   **Distribution**: If un-shared devices exist, the device MUST first author a
    `SenderKeyDistribution` node containing `WrappedKey` entries exclusively for
    those new devices, followed immediately by the intended `Content` node.
    *   **Forward Secrecy Constraint**: The sender MUST NOT distribute the root
        `SenderKey`. They MUST distribute a 3-tuple containing: their **current
        chain key** ($K_{chain, i}$), their **current sequence number** ($i$),
        and the **epoch routing key** (`K_header_epoch_n`). The new member uses
        the epoch routing key to decrypt envelopes, and derives the payload
        ratchet starting from message $i$.
*   **Historical Access**: The new device relies on the Admin's `HistoryExport`
    (Content ID 3) for past context. New devices do not need historical
    `SenderKey`s.
*   **Offline Members**: When offline members come online and author a message,
    the JIT check detects the new member and piggybacks the distribution.

### C. Step Function

For every message authored by the device that requires payload encryption via
$K_{msg, i}$ (i.e., standard Content nodes), the chain advances:

*   $K_{chain, i+1} = \text{Blake3-KDF}(\text{context: "merkle-tox v1
    ratchet-step"},\; K_{chain, i})$
*   $K_{msg, i} = \text{Blake3-KDF}(\text{context: "merkle-tox v1
    message-key"},\; K_{chain, i})$

The message is encrypted with $K_{msg, i}$. After the step, $K_{chain, i}$ is
immediately deleted.

**Exception Nodes**: Nodes that are sent in cleartext or use dedicated room-wide
keys (Admin, `KeyWrap`, `SenderKeyDistribution`, `HistoryExport`, and
`SoftAnchor` nodes) do NOT consume a ratchet step or advance the
`sequence_number`. The chain only advances when $K_{msg, i}$ is required.

## 2. Decoupling Encryption from DAG Merges

In Merkle-Tox, the DAG and the Ratchet serve distinct purposes:

1.  **The DAG (Logical Layer)**: Manages **Synchronization and Integrity**.
    Nodes include hashes of parents from *any* device to form the global graph.
2.  **The Ratchet (Cryptographic Layer)**: Manages **Confidentiality**. A node's
    encryption key depends **only** on the previous node from the **same
    sender**.

### Rationale: Zero-Race Condition

Each $sender_pk$ can only be in one cryptographic state at any given
`sequence_number`.

## 3. Post-Compromise Security (PCS)

Merkle-Tox achieves Post-Compromise Security (PCS) through **Periodic Sender Key
Rotations**.

### A. Rotation Boundaries

PCS is handled *per-device*. Every 5,000 messages or 7 days, a device performs a
"Sender Rekey":

1.  **Revocation Check**: The device verifies the current member list against
    the DAG.
2.  **New Root**: The device generates a new `SenderKey` ($K_{chain, 0}$) and a
    fresh ephemeral Ed25519 key pair for content signing.
3.  **Distribution**: It authors a `SenderKeyDistribution` node containing the
    new `SenderKey` (encrypted for each device via ECIES against their current
    SPK), the new `ephemeral_signing_pk`, and the previous epoch's
    `ephemeral_signing_sk` in `disclosed_keys` (see `merkle-tox-dag.md` and
    `merkle-tox-deniability.md`).

### B. Self-Healing

Once a new `SenderKey` is established and distributed, an attacker with access
to the old chain cannot access future keys. The $O(N)$ computational burden of
key rotation is distributed across all active participants.

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
    message keys MUST be persisted to the `ratchet.bin` checkpoint during every
    durability barrier (see `merkle-tox-storage-format.md` §5.2). If the skipped
    cache is only held in RAM, a client restart permanently destroys the cached
    keys. Since the old $K_{chain, i}$ values have already been overwritten
    (Rule 2), the delayed messages become undecryptable. The persisted cache
    SHOULD be stored in an encrypted table to prevent leakage.
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
