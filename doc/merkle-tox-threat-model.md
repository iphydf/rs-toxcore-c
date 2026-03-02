# Merkle-Tox: Threat Model & Security Analysis

## 1. Overview

Security analysis of Merkle-Tox.

## 2. Adversary Models

Attackers are categorized by capabilities and proximity:

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

*   **Status**: **Mitigated (Ephemeral Signatures)**
*   **Description**: If an attacker steals User A's Master Seed, they derive the
    shared $K_{conv}$. However, because Merkle-Tox uses **Ephemeral Signatures**
    (not symmetric MACs), the attacker cannot forge messages as User B without
    also compromising User B's current `ephemeral_signing_sk`.
*   **Active Epoch**: During the active epoch, content nodes are signed with an
    ephemeral Ed25519 key held exclusively by the sender. An attacker with
    $K_{conv}$ alone cannot produce a valid signature for another sender,
    providing **Internal Authentication**.
*   **After Disclosure**: Once the sender rotates their SenderKey and discloses
    the old `ephemeral_signing_sk`, signatures from the previous epoch become
    forgeable by any authorized member, restoring **Plausible Deniability**.
*   **Residual Risk**: An attacker who compromises a device gains that device's
    *current* `ephemeral_signing_sk` and can forge content as that device until
    the next SenderKey rotation (at most 7 days / 5,000 messages).
*   **Boundaries**: Admin Nodes use permanent Ed25519 signatures from the device
    key and are always KCI-resistant.

### 3.2. Denial of Service (DoS) - Speculative Flooding

*   **Status**: **Mitigated**
*   **Description**: An attacker can flood a peer with validly-hashed but
    unverified Content nodes. Lacking $K_{conv}$, the peer must store them
    speculatively.
*   **Mitigation**:
    1.  **Authorized Vouching**: Clients only download `WireNodes` advertised by
        an **Authorized Peer** (verified via the Admin track).
    2.  **Opaque Quotas**: Clients enforce a 100MB limit on the `Opaque Store`.
    3.  **Vouching Logic**: Nodes not "vouched for" by a trusted peer's
        authenticated heads are prioritized for deletion.

### 3.3. Denial of Service (DoS) - IBLT Peeling

*   **Status**: **Prevented**
*   **Description**: An attacker sends a "garbage" IBLT sketch designed to
    trigger worst-case CPU usage during peeling.
*   **Mitigation**: The **Queue-Based (Linear) Peeling Algorithm**
    (`merkle-tox-reconcile.md` §1.C) guarantees O(m) worst-case CPU. The
    **Extracted Capacity Cap** ($D_{max}$) bounds output size and memory. Cell
    `HashSum` values (keyed with $K_{iblt}$) detect external tampering on the
    first extracted element.

### 3.3b. Denial of Service (DoS) - IBLT Sketch Spam (Volume)

*   **Status**: **Mitigated**
*   **Description**: An authorized attacker floods a peer with a high volume of
    Medium/Large IBLT sketch requests. The aggregate CPU cost of peeling
    overwhelms the target.
*   **Mitigation**: **Per-Peer CPU Budget** (`merkle-tox-reconcile.md` §3.C).
    Each responder enforces a strict token bucket of `SKETCH_CPU_BUDGET_MS`
    (500ms) of IBLT decoding time per peer per minute. When the budget exhausts,
    subsequent sketches are discarded with `SYNC_RATE_LIMITED`. Peers whose
    sketches consistently fail decoding are subject to exponential blacklist
    escalation (`merkle-tox-sync.md` §2).
*   **Design Rationale**: A token bucket provides a hard cap on the receiver's
    CPU consumption regardless of the attacker's resources, whereas PoW only
    provides a probabilistic deterrent. No global consensus is needed.

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
*   **Description**: Sybil identities skew the Median Consensus Clock,
    potentially causing legitimate nodes to be quarantined.
*   **Mitigation**: Only **authorized** peers contribute to the median
    calculation. Offsets are grouped by **Logical Identity** before the median
    is computed (see `merkle-tox-clock.md` §1, Step 3), preventing an attacker
    from amplifying their vote with multiple devices. An attacker must control
    $>50\%$ of the distinct authorized **identities** in a room to shift the
    clock.

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
    re-calculates effective power as the recursive intersection of the trust
    path at use-time. Escalated claims are cryptographically valid (signed) but
    logically ignored.

## 4. Summary of Trade-offs

| Feature               | Design Choice          | Security Trade-off          |
| :-------------------- | :--------------------- | :-------------------------- |
| **Authentication**    | Ephemeral Signatures + | **Gains**: Internal         |
:                       : Key Disclosure (DARE)  : authentication AND          :
:                       :                        : plausible deniability.      :
:                       :                        : **Loses**\: Deniability is  :
:                       :                        : delayed until epoch         :
:                       :                        : rotation (≤7 days).         :
| **History Sync**      | Authorized Vouching    | **Gains**: Protection       |
:                       :                        : against anonymous DoS.      :
:                       :                        : **Loses**\: Latency when    :
:                       :                        : joining high- spam rooms.   :
| **Time Sync**         | Weighted Median        | **Gains**: Byzantine fault  |
:                       :                        : tolerance. **Loses**\:      :
:                       :                        : Sensitivity to authorized   :
:                       :                        : Sybils.                     :
| **Serialization**     | Positional Arrays      | **Gains**: Maximum wire     |
:                       :                        : efficiency. **Loses**\:     :
:                       :                        : Schema flexibility.         :
| **Blob Verification** | Bao (Merkle Tree)      | **Gains**: Incremental 64KB |
:                       :                        : verification. **Loses**\:   :
:                       :                        : CPU overhead for proof      :
:                       :                        : generation.                 :
| **Permission Eval**   | Dynamic Intersection   | **Gains**: Retroactive      |
:                       :                        : revocation and escalation   :
:                       :                        : resistance. **Loses**\:     :
:                       :                        : Complexity in indexing and  :
:                       :                        : possible UX confusion.      :
| **Sketch DoS**        | Per-Peer CPU Budget    | **Gains**: Hard cap on      |
:                       : (Token Bucket)         : defender CPU, no            :
:                       :                        : coordination needed, honest :
:                       :                        : peers unaffected.           :
:                       :                        : **Loses**\: No room-wide    :
:                       :                        : awareness of ongoing        :
:                       :                        : attacks.                    :

### 3.8. OPK Collision History Erasure

*   **Status**: **Prevented**
*   **Description**: An attacker (Eve) observes a victim's (Alice's) `KeyWrap`
    node in the DAG, extracts the `opk_id`, and authors a competing `KeyWrap`
    using the same OPK. If the collision resolution rule uses a grindable value
    (such as the initiator's ephemeral key $E_a$), Eve can guarantee she wins,
    orphaning Alice's `KeyWrap` and all content nodes descending from it. This
    is a targeted retroactive history erasure attack.
*   **Mitigation**:
    1.  **Non-Grindable Tie-Breaker**: The collision resolution rule uses
        **Admin Seniority** (group chats) or **Device Public Key** (1-on-1
        chats) (immutable historical values that cannot be varied
        per-collision). See `merkle-tox-handshake-ecies.md` §5.
    2.  **Per-Entry Collision Scope**: The `opk_id` field is per-`WrappedKey`
        entry, not per-`KeyWrap` node. A collision only invalidates the specific
        recipient entry, not the entire `KeyWrap`.
    3.  **Delivery Confirmation (1-on-1)**: In 1-on-1 chats where the two
        `KeyWrap` nodes contain different $K_{conv}$ values, the losing
        initiator's key is never delivered. The `KEYWRAP_ACK` protocol
        (`merkle-tox-handshake-ecies.md` §2.A) prevents the initiator from
        authoring content before delivery is confirmed, ensuring no unreadable
        messages enter the DAG. In group chats, both Admins wrap the same
        $K_{conv}$, so the collision is harmless.

### 3.9. Join Deadlock (Shallow Sync)

*   **Status**: **Mitigated**
*   **Description**: A new member receives a `KeyWrap` but lacks the historical
    Admin nodes that authorized the sender, creating a deadlock.
*   **Mitigation**: **Speculative Decryption & Identity Pending Status**.
    1.  The client uses the Admin's `Signature` to verify the `KeyWrap`
        integrity.
    2.  If valid, the client tentatively accepts the key and decrypts the Opaque
        Store.
    3.  Messages display an **"Identity Pending"** warning, allowing history to
        be read while background sync completes Admin track verification.

### 3.10. Equivocation (Split-View Attack)

*   **Status**: **Prevented**
*   **Description**: A compromised member sends different messages to different
    subgroups.
*   **Mitigation**: Because all nodes are committed to a global DAG with
    content-addressable hashes, any peer who syncs with both subgroups will
    detect the inconsistency (two different nodes with the same sequence number
    from the same sender). The DAG makes equivocation detectable, and the
    ratchet makes it impossible (the same sequence number cannot produce two
    valid encryption keys).

### 3.11. Selective Data Withholding

*   **Status**: **Mitigated**
*   **Description**: A compromised member advertises heads but refuses to serve
    requested nodes to stall the sync process.
*   **Mitigation**: Mitigated by the bounded voucher set
    (`MAX_VOUCHERS_PER_HASH = 3`) combined with timeout-based rotation
    (`VOUCHER_TIMEOUT_MS`) and multi-peer fetching (detailed in
    `merkle-tox-sync.md`). If the primary peer fails to provide the requested
    node, the engine penalizes them and immediately requests from the next
    authorized peer.

### 3.12. Rapid Authorization Churn

*   **Status**: **Mitigated**
*   **Description**: A compromised admin rapidly issues and revokes certificates
    to create confusion, fork the state, or exhaust resources.
*   **Mitigation**: Mitigated by the **Admin Seniority** tie-breaker (concurrent
    actions are deterministically serialized) and **Transitive Revocation**
    (revoking the compromised admin immediately invalidates all their downstream
    actions and ghost authorizations).
