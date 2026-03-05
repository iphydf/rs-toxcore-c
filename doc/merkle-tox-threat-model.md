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
*   **NGC Peer (Non-Member):** When a Merkle-Tox conversation is transported
    over an NGC (see [merkle-tox-ngc.md](merkle-tox-ngc.md)), this adversary
    is a participant in the underlying NGC who has not been authorized at the
    Merkle-Tox layer (no `LogicalIdentityPk` in `MemberInfo`, or no valid
    `PeerIntroduction` binding). They observe NGC routing metadata but are
    gated out of Merkle-Tox sync responses. Specific deltas analysed in
    [merkle-tox-ngc.md §7](merkle-tox-ngc.md).

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
*   **Transport-binding deltas**: For NGC-transported conversations, a passive
    DHT observer who knows the `chat_id` of a *public* NGC can enumerate
    currently-announced NGC peer keys; private NGCs do not self-announce. NGC
    peer keys are per-chat ephemerals unrelated to long-term Tox identity and
    cannot be linked across NGCs from the keys alone. See
    [merkle-tox-ngc.md §7](merkle-tox-ngc.md) for the full per-binding
    threat-model delta.

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
| **Blob Verification** | Chunk-Merkle Tree      | **Gains**: Incremental 64KB |
:                       : (domain-separated      : chunk verification with     :
:                       : blake3)                : proofs sized to fit in one  :
:                       :                        : datagram. **Loses**\:       :
:                       :                        : Modest CPU for tree build.  :
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

### 3.13. Nonce Reuse / Two-Time Pad in KeyWrap

*   **Status**: **Prevented**
*   **Description**: If `KeyWrap` AEAD reused a nonce across epoch rotations
    (for example, a fixed zero nonce combined with a reused `k_wrap`), an
    attacker could XOR two ciphertexts to recover plaintext via classical
    two-time-pad analysis.
*   **Mitigation**: Each `WrappedKey` derives a fresh `k_wrap` from
    `ECDH(ephemeral_sk, recipient_spk)` (plus an OPK contribution when
    present). The ephemeral sender key rotates per `KeyWrap` node, so even
    a zero AEAD nonce is safe — `(k_wrap, nonce)` is unique per entry.
    Regression-guarded by `adversarial_keywrap_test.rs::test_key_wrap_two_time_pad_vulnerability`.

### 3.14. Skipped-Key Expiry (Forward-Secrecy Window)

*   **Status**: **Prevented**
*   **Description**: Out-of-order message delivery forces a receiver to retain
    skipped message keys for later decryption. If those keys were held
    indefinitely, a late-arriving forgery — or a compromise of the storage
    — could decrypt messages well outside the intended forward-secrecy
    window.
*   **Mitigation**: Skipped keys are tagged with a wall-clock timestamp and
    evicted proactively during `poll()` once they exceed 24 hours
    (`86_400_000` ms). A message arriving after TTL expiry is rejected even
    if its sequence number falls within the recorded skip range.
    Regression-guarded by `adversarial_auth_test.rs::test_skipped_key_ttl_expiry_rejects_late_message`.

### 3.15. Membership Poisoning via `Snapshot`

*   **Status**: **Prevented**
*   **Description**: A compromised admin authors a `Snapshot` node with a
    tampered `members` field (for example, an empty list or a list that
    omits specific targets). A receiver that imported the `members` list
    blindly could be tricked into dropping authorized members, breaking
    sync or silently denying them access.
*   **Mitigation**: `ControlAction::Snapshot` side-effects only update
    `latest_anchor_hashes`; they do NOT import `data.members`. Member-list
    updates are restricted to `ControlAction::AnchorSnapshot`, which
    requires a founder-signed delegation certificate with `ADMIN`
    permission (checked via the `skip_generic_path` gate in the
    verification phase). A plain `Snapshot` therefore cannot mutate the
    membership view.
    Regression-guarded by `adversarial_identity_test.rs::test_malicious_snapshot_poisoning`.

### 3.16. Ratchet Key Persistence Leak

*   **Status**: **Prevented**
*   **Description**: Long-lived retention of ratchet chain keys,
    `SenderKey`s, or message keys in engine state or on-disk storage
    would undermine post-compromise security — an attacker who later
    extracted the state could decrypt historical messages that should be
    protected by the ratchet step.
*   **Mitigation**: All secret newtypes (`ChainKey`, `MessageKey`,
    `KConv`, `HeaderKey`, etc.) derive `ZeroizeOnDrop` via the
    `merkle_tox_newtype!(...secret)` macro in `tox-proto/src/lib.rs`. On
    ratchet advance, a `DeleteRatchetKey` effect is emitted
    (`side_effects.rs`) so the storage layer purges the prior chain key
    along with the in-memory zeroization. No ratchet key is retained past
    the step that consumes it.
    Regression-guarded by `memory_hardening_test.rs::test_engine_ratchet_key_persistence_leak`.

### 3.17. Bootstrap-Exception Trust Hijack

*   **Status**: **Mitigated**
*   **Description**: Several content types are *bootstrap exceptions* in
    the verifier — they are admitted via paths that intentionally
    bypass the parent-not-verified and unauthorized-without-vouches
    quarantines (`engine/processor/verification.rs`, the `is_bootstrap`
    set), because a first-of-its-kind node has no verified parents and
    the authoring device may not yet be in `authorized_devices`. The
    set is enumerated:

    -   `Content::Control(ControlAction::Genesis { … })`
    -   `Content::Control(ControlAction::AuthorizeDevice { … })`
    -   `Content::Control(ControlAction::AnchorSnapshot { … })`
    -   `Content::KeyWrap { … }`
    -   `Content::HistoryExport { … }`
    -   `Content::SenderKeyDistribution { … }`

    Without explicit invariants, each exception is an opportunity for
    the *speculative-trust path to apply state mutations whose
    invariants the speculative check doesn't enforce* — a class of
    bug realized concretely by the second-Genesis injection
    (`d67212d`) and the AnchorSnapshot member-list founder
    displacement (`8470145`).
*   **Invariants enforced**:

    1.  **Genesis uniqueness.** At most one Genesis per conversation.
        Enforced at the verifier entry (`verification.rs`, top of
        `handle_node_internal_ext`): a Genesis whose hash differs from
        the existing `latest_anchor_hashes[conv_id]` is dropped before
        any state mutation. Without this, any peer who knows a
        `conversation_id` could mint a second Genesis with themselves
        as creator (the `is_authorized` self-bind shortcut at
        `identity.rs:622` admits the self-author binding) and have
        `apply_side_effects` register them as a co-founder.
    2.  **Founder slot immutability.** Role=0 is established by
        Genesis only and cannot be reassigned. Enforced at two
        layers: (a) verifier rejects any AnchorSnapshot whose
        `data.members` introduces a new role-0 logical_pk or demotes
        the existing founder to a different role; (b) defense-in-depth
        in `IdentityManager::add_member` (`identity.rs`) silently
        refuses role=0 inserts that conflict with the existing
        founder, plus refuses non-zero role on the existing founder.
        Without this, a (legitimate or stale-cert) admin could mint
        an AnchorSnapshot listing an attacker-controlled
        `LogicalIdentityPk` with role=0; combined with `get_founder`'s
        lex-smallest `BTreeMap` selection, the attacker would
        supplant the founder for every downstream `verify_delegation`
        check.
    3.  **`conv_id` is opaque to the wire layer; user opt-in for new
        conversations.** No wire-level message can introduce a new
        conversation into `MerkleToxEngine::conversations`. Every
        handler arm whose state mutation is keyed by `conv_id` —
        `MerkleNode`, `SyncHeads`, `SyncSketch`, `SyncShardChecksums`,
        `HandshakeError`, `BlobAvail`, `BlobFetch`, `BlobReq`,
        `FetchBatchReq` — is gated behind
        `self.conversations.contains_key(&conv_id)` (or the
        equivalent `blob_conversations + sessions` check for blob
        handlers). New conversations enter the engine only via
        user-initiated paths (`start_sync`,
        `load_conversation_state`). Consequence: even though
        `conv_id` has no structural binding to the Genesis hash at
        the protocol level (it is an application-supplied 32-byte
        label), an attacker who picks a `conv_id` cannot inject
        state into a victim's engine for that `conv_id` without the
        victim's user-level acceptance.
    4.  **OPK pre-claim closure.** `consumed_opk_ids` records OPK
        consumption only after a successful ECIES unwrap, with one
        exception for the §3.8 collision tiebreaker (where the prior
        entry already proved the OPK was consumable, so a senior-wins
        overwrite is recorded without the second decryption attempt).
        Without this, any authorised peer could ship a KeyWrap with
        junk ciphertext, "consume" any OPK they had observed in an
        Announcement, and via the seniority tiebreaker deny K_conv
        distribution from legitimate senders for the same OPK.
*   **Regression-guarded by**:
    `tests/adversarial_genesis_injection_test.rs` (§GI-1/2/3),
    `tests/adversarial_anchor_snapshot_member_test.rs` (§AS-1/2),
    `tests/adversarial_unknown_conversation_test.rs` (§UC-1/2/3/4/5),
    `tests/adversarial_keywrap_preclaim_test.rs` (§KW-PRE-1).
*   **Residual risk / out-of-scope**:
    -   The protocol layer does *not* bind `conv_id` to the Genesis
        hash. The application is responsible for managing `conv_id`
        provenance during invitations (e.g., shipping
        `(conv_id, k_conv)` together as a single invitation token).
        Future protocol revisions may consider adopting
        `conv_id := Genesis.hash()` as a structural invariant; today
        it is enforced only by user opt-in at the wire boundary.
    -   `verify_delegation` (`identity.rs`) checks signature +
        expiry only and does *not* consult `revoked_devices`. A
        late-joiner who has not yet replayed the admin chain past a
        revocation may speculatively trust an AnchorSnapshot or
        SoftAnchor signed by a now-revoked admin. Impact today is
        bounded to `latest_anchor_hashes` overwrite and the §3.17
        invariant 2 founder-slot protection limits the worst case;
        full revocation-aware speculative trust is a separate fix.
