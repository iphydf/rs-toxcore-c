# Merkle-Tox: Threat Model & Security Analysis

## 1. Overview

This document provides an exhaustive analysis of the security properties,
adversary models, and known trade-offs in the Merkle-Tox system. It bridges the
gap between the high-level design and the specific cryptographic sub-designs.

## 2. Adversary Models

We categorize attackers based on their capabilities and proximity to the
synchronization swarm:

*   **Global Passive Observer (GPO):** Can monitor all network traffic between
    nodes but cannot modify, drop, or inject packets (e.g., an ISP or a
    state-level monitoring entity).
*   **Local Active Attacker (LAA):** Can inject, drop, or modify packets on the
    local network segments.
*   **Malicious Relay/Peer:** A participant in the Tox network who may withhold
    data, relay invalid nodes, or attempt to manipulate the sync state machine.
*   **Compromised Participant:** An authorized member of a conversation whose
    device or Master Seed has been compromised by an adversary.

## 3. Attack Analysis

### 3.1. Key Compromise Impersonation (KCI)

*   **Status**: **Possible (by Design)**
*   **Description**: If an attacker steals User A's Master Seed, they can derive
    the shared conversation key $K_{conv}$ for any room A is in. Because
    Merkle-Tox uses symmetric MACs (DARE) for content nodes, the attacker can
    use A's own key to craft messages that appear to come from User B.
*   **Rationale**: This is a fundamental trade-off required for **Plausible
    Deniability**. For User A to be able to repudiate their own messages ("Bob
    could have forged this to frame me"), the protocol must allow any
    participant with $K_{conv}$ to be mathematically capable of forging any
    message in the room. KCI resistance would require asymmetric signatures on
    every message, which would destroy deniability.
*   **Boundaries**: KCI only applies to **Content Nodes**. **Admin Nodes** (like
    `RevokeDevice`) require Ed25519 signatures from the specific author and are
    therefore KCI-resistant.

### 3.2. Denial of Service (DoS) - Speculative Flooding

*   **Status**: **Mitigated**
*   **Description**: An attacker can flood a peer with validly-hashed but
    unverified Content nodes. Since these cannot be verified without $K_{conv}$,
    the peer must store them speculatively.
*   **Mitigation**:
    1.  **Authorized Vouching**: Clients only download or store `WireNodes` that
        are advertised by an **Authorized Peer** (a member verified via the
        Admin track). This limits the attack surface to members already in the
        conversation.
    2.  **Opaque Quotas**: Clients enforce a strict 100MB limit on the `Opaque
        Store`.
    3.  **Vouching Logic**: Nodes that are not "vouched for" by a trusted peer's
        authenticated heads are prioritized for deletion.

### 3.3. Denial of Service (DoS) - IBLT Peeling

*   **Status**: **Mitigated**
*   **Description**: An attacker sends a "garbage" IBLT sketch designed to
    trigger worst-case CPU usage during the iterative peeling process.
*   **Mitigation**: The `tox-reconcile` library enforces a maximum iteration
    count proportional to the sketch size and validates cell `HashSum` values to
    detect tampering early.

### 3.4. Traffic Analysis (Metadata Leakage)

*   **Status**: **Partially Mitigated**
*   **Description**: An observer monitors the timing, frequency, and size of
    packets to map social graphs and activity patterns.
*   **Mitigation**:
    1.  **Padding**: **ISO/IEC 7816-4 Padding** to Power-of-2 boundaries hides
        exact message lengths (`merkle-tox-wire-format.md`).
    2.  **Residual Leakage**: Timing analysis (observing *when* packets are
        sent) remains an open challenge inherent to the underlying Tox
        transport.

### 3.5. Clock Manipulation (Nudging)

*   **Status**: **Resistant**
*   **Description**: Using Sybil identities to skew the Median Consensus Clock,
    potentially causing legitimate nodes to be quarantined.
*   **Mitigation**: Only **authorized** peers (those with a valid trust path to
    the Genesis node) contribute to the median calculation. An attacker must
    control $>50\%$ of the authorized identities in a room to shift the clock.

### 3.6. Partitioning Attacks

*   **Status**: **Possible**
*   **Description**: An attacker isolates a group of peers, preventing them from
    seeing the global "Heads."
*   **Mitigation**: Merkle-Tox is **Eventually Consistent**. As soon as a single
    honest peer bridges the partition, the branches are automatically merged via
    the DAG structure.

### 3.7. Ghost Permissions / Escalation Attempts

*   **Status**: **Mitigated**
*   **Description**: A malicious user or compromised device injects a
    `DelegationCertificate` into the DAG that claims higher permissions than the
    issuer possesses (e.g., a device with `MESSAGE` trying to authorize an Admin
    with `ADMIN`).
*   **Mitigation**: Merkle-Tox uses **Dynamic Enforcement**. The sync engine
    does not blindly trust the claims in a certificate. Instead, it
    re-calculates effective power as the recursive intersection of the trust
    path at use-time. Escalated claims are cryptographically valid (signed) but
    logically ignored by the protocol.

## 4. Summary of Trade-offs

| Feature               | Design Choice        | Security Trade-off            |
| :-------------------- | :------------------- | :---------------------------- |
| **Authentication**    | Symmetric MAC (DARE) | **Gains**: Plausible          |
:                       :                      : Deniability. **Loses**\: KCI  :
:                       :                      : resistance for content.       :
| **History Sync**      | Authorized Vouching  | **Gains**: Protection against |
:                       :                      : anonymous DoS. **Loses**\:    :
:                       :                      : Latency when joining high-    :
:                       :                      : spam rooms.                   :
| **Time Sync**         | Weighted Median      | **Gains**: Byzantine fault    |
:                       :                      : tolerance. **Loses**\:        :
:                       :                      : Sensitivity to authorized     :
:                       :                      : Sybils.                       :
| **Serialization**     | Positional Arrays    | **Gains**: Maximum wire       |
:                       :                      : efficiency. **Loses**\:       :
:                       :                      : Schema flexibility.           :
| **Blob Verification** | Bao (Merkle Tree)    | **Gains**: Incremental 64KB   |
:                       :                      : verification. **Loses**\: CPU :
:                       :                      : overhead for proof            :
:                       :                      : generation.                   :
| **Permission Eval**   | Dynamic Intersection | **Gains**: Retroactive        |
:                       :                      : revocation and escalation     :
:                       :                      : resistance. **Loses**\:       :
:                       :                      : Complexity in indexing and    :
:                       :                      : possible UX confusion.        :

### 3.8. Join Deadlock (Shallow Sync)

*   **Status**: **Mitigated**
*   **Description**: A new member receives a `KeyWrap` but cannot verify the
    sender's authority because they are missing the historical Admin nodes that
    authorized that device. This creates a deadlock where the user has the key
    but refuses to use it.
*   **Mitigation**: **Speculative Decryption & Identity Pending Status**.
    1.  The client uses the `PairwiseMac` to verify the integrity of the
        `KeyWrap`.
    2.  If the MAC is valid, the client tentatively accepts the key and decrypts
        the Opaque Store.
    3.  Messages are displayed with an **"Identity Pending"** warning. This
        breaks the deadlock by allowing the user to read history immediately
        while the background sync completes the Admin track verification.
