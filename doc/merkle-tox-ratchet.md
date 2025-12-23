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

### A. Initialization (Chain Seed)

When a device is first authorized or a new epoch begins, its initial chain key
is derived from the conversation's shared key ($K_{conv}$):

*   $K_{chain, 0} = ext{Blake3-KDF}( ext{context: "merkle-tox v1 sender-seed"},
    K_{conv} || sender_pk)$

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

## 3. Epochs and Post-Compromise Security (PCS)

While the linear ratchet provides Forward Secrecy, it does not provide
**Post-Compromise Security (PCS)**. Merkle-Tox achieves PCS through **Epoch
Rotations**.

### A. Epoch Boundaries

Every 5,000 messages or 7 days, the group performs a "Rekey" event.

1.  **Revocation Check**: The admin verifies the member list against the latest
    DAG revocations.
2.  **New Root**: A new $K_{epoch}$ is generated and distributed via `KeyWrap`
    nodes.
3.  **Reset**: All per-sender ratchets are **wiped and re-initialized** using
    the new $K_{epoch}$ as the seed (see Section 1.A).

### B. Self-Healing

Once a new epoch is established and old keys are deleted, an attacker who
previously had access to a device's chain is "kicked out" of the future key
space.

## 4. Implementation Rules

1.  **Sequential Processing**: A recipient MUST process messages from a specific
    $sender_pk$ in strict `sequence_number` order to maintain the ratchet. Out-
    of-order messages are buffered in the **Opaque Store**.
2.  **Immediate Deletion**: Implementations MUST overwrite old chain keys with
    zeros in memory as soon as the ratchet advances to the next sequence.
3.  **Storage Isolation**: The current $K_{chain}$ for each active sender SHOULD
    be stored in a separate, encrypted table to prevent leakage.
4.  **Monotonicity**: A client MUST NOT accept a message with a
    `sequence_number` lower than the current known ratchet index for that
    sender.
