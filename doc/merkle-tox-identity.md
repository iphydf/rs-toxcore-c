# Merkle-Tox Sub-Design: Hierarchical Identity & Device Management

## Overview

Merkle-Tox decouples the **Logical Identity** (the User) from the **Physical
Identity** (the Tox ID of a device) using a 3-level trust hierarchy.

## 1. Trust Hierarchy

### Level 0: Master Seed ("Root")

-   **Storage**: Offline (e.g., a 24-word BIP-39 mnemonic phrase on paper).
-   **Capability**: Can authorize "Admin" devices and perform emergency
    recovery.
-   **Power**: Absolute. A revocation signed by the Master Seed overrides any
    other action in the DAG.
-   **Identity PK ($I_{pk}$)**: The Ed25519 public key derived from the Master
    Seed, acting as the "User ID" shared with friends.

### Level 1: Admin Devices ("Executive")

-   **Storage**: Online (e.g., the user's primary Laptop or Phone).
-   **Capability**: Can authorize Level 2 devices, revoke other devices, and
    manage conversation settings.
-   **Constraint**: Before authorizing new devices or rotating keys, the Admin
    MUST ensure their local view of the DAG does not contain any valid
    `RevokeDevice` nodes targeting the current members.
-   **Delegation**: Holds a `DelegationCertificate` signed by the Master Seed.
-   **Risk**: If an Admin device is compromised, it can disrupt the account, but
    the Master Seed can still revoke it.

### Level 2: Basic Devices ("Participant")

-   **Storage**: Online (e.g., a shared tablet, a work computer, or a "burner"
    phone).
-   **Capability**: Can send/receive messages and sync history. Cannot authorize
    or revoke other devices.
-   **Delegation**: Holds a `DelegationCertificate` signed by an Admin Device
    (Level 1).

## 2. Permissions & Delegation Rules

Merkle-Tox enforces dynamic delegation rules:

-   **Cryptographic Validity**: A `DelegationCertificate` is cryptographically
    valid if it is correctly signed by an issuer who was authorized at the
    moment of the certificate's creation (determined by causal ancestry).
-   **Effective Permissions (Dynamic Intersection)**: A device's actual power is
    the **intersection** of its certificate's claims and the issuer's power at
    the causal history point of the node being verified. If an issuer oversteps
    their authority (e.g., granting `ADMIN` when they only have `MESSAGE`), the
    escalated permission is ignored.
-   **Expiration**: A device's authorization is only valid until the earliest
    `expires_at` timestamp in its trust path.

## 3. Dynamic Trust & Recursive Validation

Merkle-Tox uses **Recursive Topological Validation** to prevent revoked devices
from acting.

### The Rule of Contextual Validity

A `MerkleNode` is only valid if its author (the `sender_pk`) was authorized at
the exact moment of its creation, represented by its **Admin Frontier**.

1.  **Admin Frontier**: Each node evaluates its Admin Frontier (the set of most
    recent, mutually concurrent Admin nodes in its ancestry) to efficiently
    compute permissions.
    -   `Frontier(N) = Prune( Union(Frontier(P) for P in N.parents) U {N if N is
        Admin} )`
    -   **Pruning**: The `Prune()` operation MUST remove any hash from the set
        that is a topological ancestor of another hash in the set. This enforces
        chronological time, ensuring only the absolute latest causal actions
        remain.
2.  **State Lookup**: The client verifies that the `sender_pk` holds a valid
    `DelegationCertificate` within the evaluated state of this Admin Frontier.
3.  **Concurrent Admin Resolution (Tie-Breaker)**: If a Frontier contains
    multiple concurrent Admin nodes (e.g., conflicting `RevokeDevice` and
    `AuthorizeDevice` actions), the system MUST deterministically serialize the
    actions to compute the merged state. Concurrent Admin nodes are sorted by
    **Admin Seniority**:
    1.  The `topological_rank` of the `AuthorizeDevice` node that granted the
        author's Admin status (older/lower rank wins).
    2.  If authorized at the exact same rank, tie-break using the
        lexicographical Blake3 `hash` of that same historical `AuthorizeDevice`
        node. Because the sorting relies on *historical, immutable* data, an
        attacker cannot "grind" the hash of their new `RevokeDevice` node to
        artificially win the tie-breaker. The junior Admin's action is evaluated
        second, and if they were just revoked by the senior Admin, their action
        is discarded as invalid.
    3.  *Crucially, Admin Seniority is ONLY used to resolve conflicts between
        concurrent nodes remaining in the pruned Frontier. It MUST NOT be used
        to override a true topological descendant, ensuring Hierarchy does not
        overwrite Time.*
4.  **Transitive Revocation**: If Admin A is revoked by node R, all Level 2
    devices authorized *only* by Admin A automatically lose their authority to
    author any node that descends from R.
    -   **Concurrent Node Resolution**: Because network time is not used, an
        attacker might attempt to author nodes concurrently with their
        revocation (i.e., the revocation is not an ancestor of the new node).
        These concurrent nodes are accepted as valid, as the author possessed
        the keys at that logical moment.
    -   **Cryptographic Isolation**: To definitively cut off a revoked attacker,
        the revocation MUST be immediately followed by a `KeyWrap` node rotating
        the global metadata key ($K_{conv}$). The attacker does not receive the
        new key, making them incapable of generating valid Payload MACs or
        Header Encryptions for new messages. Their parallel branch physically
        dies.

### Logical vs. Cryptographic Validity

Merkle-Tox separates the *act of authorization* (writing a certificate to the
DAG) from the *presence of power*.

-   **Dormant Paths**: An `AuthorizeDevice` node can be accepted into the DAG
    even if the issuer currently has zero permissions (e.g., they are currently
    revoked).
-   **Healing**: If the issuer's power is later restored (e.g., by a snapshot
    that overwrites a malicious revocation), all sub-devices in that path
    automatically regain their power without needing fresh certificates,
    ensuring the trust graph is resilient and decoupled from transient
    partitioning or malicious Admin track manipulation.

### Post-Revocation Cleanup

When an Admin is revoked, the remaining Admins SHOULD author a new `Snapshot` or
`KeyWrap` node to explicitly formalize the new set of authorized devices and
rotate the conversation metadata key ($K_{conv}$), physically excluding the
revoked branch from future actions.

### Trust-Restored, Key-Pending State

The **Healing** mechanism can restore a device's trust path after a revocation
is overwritten by a Snapshot. Key material does not heal automatically: the
revoked device never received the $K_{conv}$ rotation that excluded it. A healed
device enters a **Trust-Restored, Key-Pending** state.

```
Revoked
  → [Healing Snapshot accepted]
  → Trust-Restored, Key-Pending
      - MAY verify and read history using old K_conv generation(s) it holds
      - MUST NOT author any new nodes (enforced Observer Mode)
      - MUST NOT share the conversation key with other devices
      - MUST NOT provide structural vouches for new nodes
      → [Re-inclusion KeyWrap received]
      → Fully Active
      OR
      → [30-day expiry with no Re-inclusion KeyWrap received]
      → Revoked  (state resets; device must be re-authorized from scratch)
```

#### Re-inclusion Protocol (Device-Initiated, Off-DAG)

Because the healed device lacks $K_{conv}$, it cannot produce a valid
authenticator. The re-inclusion signal is sent **off-DAG** via `tox-sequenced`:

1.  The healed device sends a `REINCLUSION_REQUEST` message directly to any
    online Admin it can reach via the Tox transport. The message contains the
    device's `sender_pk` and the hash of the healing Snapshot that restored its
    trust path.
2.  The Admin verifies the device's trust path against the current DAG state
    (confirming the healing Snapshot is valid and the device is not expired).
3.  Upon verification, the Admin MUST issue a fresh `KeyWrap` that includes the
    healed device's identity in the `wrapped_keys` list, following the normal
    `KeyWrap` authoring rules (valid unexpired pre-keys required; see
    `merkle-tox-handshake-ecies.md`).

This off-DAG approach respects the Observer Mode constraint (no new DAG nodes)
and avoids the circular dependency of needing $K_{conv}$ to author an
authenticated node.

#### Expiry

If no Re-inclusion `KeyWrap` is received within **30 days** of the healing
Snapshot being accepted, the device reverts to the **Revoked** state, preventing
zombie trust states from accumulating in long-running groups where the healing
event may have been accidental or contested. The device must then be
re-authorized via a fresh `AuthorizeDevice` Admin node.

--------------------------------------------------------------------------------

## 4. Multi-Device History Synchronization

Because Merkle-Tox provides strict Forward Secrecy, a newly authorized device
cannot decrypt historical messages since past `SenderKey`s are ratcheted and
deleted. The protocol uses a **History Export** mechanism built on top of the
CAS to synchronize historical messages.

**Note on KeyWrap and Per-Device Addressing**: `KeyWrap` and
`SenderKeyDistribution` nodes wrap keys once per **physical device**
(sender_pk), not once per logical identity. Each `WrappedKey` entry uses ECIES
against the recipient device's current Signed Pre-Key (SPK) from their
Announcement node. This ensures any device can wrap for any other device,
enabling `SenderKeyDistribution` to be authored by non-Admin devices. **Forward
Secrecy** is bounded by the SPK rotation interval (30 days): once the recipient
deletes the SPK secret key after rotation, past wrappings become undecryptable.
The O(N_members × N_devices) scaling cost is the price of per-device forward
secrecy. See `merkle-tox-dag.md` for the `WrappedKey` structure definition.

**Invariant**: Historical encryption keys (past $K_{conv}$ generations, past
`SenderKey` seeds, ratchet chain keys) are NEVER included in the export. These
keys are deleted per the ratchet's forward secrecy rules
(`merkle-tox-ratchet.md` §4). The exporting device only has access to
already-decrypted message content in its local database, ensuring Forward
Secrecy and Post-Compromise Security claims are not undermined by history
synchronization.

1.  **Periodic Snapshot Generation**: To preserve CAS deduplication and minimize
    upload bandwidth, the room SHOULD periodically author a generic **Encrypted
    History Snapshot** blob (e.g., every 5,000 messages). The author compiles
    the already-decrypted message content from its local database and encrypts
    it with a random, static $K_{snapshot}$. No historical encryption keys are
    included.
2.  **CAS Upload**: The author uploads the snapshot as a standard Blob to the
    Content-Addressable Storage (CAS) swarm, deriving a `blob_hash`.
3.  **Key Distribution (Invite/Export)**: When Device A authorizes Device B,
    Device A does NOT generate a unique blob. Instead, Device A authors a
    `HistoryExport` node to the DAG referencing the most recent existing
    snapshot. This node contains the existing `blob_hash` and the existing
    $K_{snapshot}$ wrapped for Device B via the standard `WrappedKey` ECIES
    construction. This ensures $O(1)$ CAS deduplication for history exports.
    -   *Edge Case (Re-inviting Revoked Members)*: If a user was revoked and
        later re-invited, sending them the generic snapshot might expose
        messages authored during the period they were revoked. If an Admin
        wishes to enforce strict cryptoperiod boundaries upon re-inviting a
        user, the client MUST fall back to generating a bespoke, curated history
        export blob rather than reusing the generic snapshot.
4.  **Asynchronous Catch-Up**: Device B syncs the DAG structure instantly, then
    asynchronously downloads the encrypted content blob from blind relays. Once
    decrypted, Device B can display the historical messages. Device B receives
    plaintext content only. It cannot cryptographically verify or forge
    authorship of historical messages, consistent with the DARE deniability
    model.
5.  **Deniability**: Because no signing keys or SenderKeys are transferred,
    exported history lacks cryptographic capabilities. If the CAS blob is
    compromised, the attacker gains message content but no cryptographic
    capabilities (cannot derive future keys, verify MACs, or forge messages).
6.  **Forward Secrecy of Snapshots**: The $K_{snapshot}$ key distributed in the
    `HistoryExport` node is wrapped using ECIES against the recipient's Signed
    Pre-Key (SPK). When the recipient rotates their SPK (every 30 days) and
    securely deletes the old private key, they can no longer decrypt the
    `HistoryExport` node to recover $K_{snapshot}$. Therefore, if a device is
    seized months later, the historical CAS blob remains cryptographically
    protected, preserving the 30-day bounded forward secrecy.

--------------------------------------------------------------------------------

## 5. Speculative Decryption & Unverified Silence

To resolve deadlocks where a user has a new $K_{conv}$ but has not yet verified
the Admin Track that authorized the sender, Merkle-Tox allows **Speculative
Decryption** under a strict **Observer Mode**.

1.  **Integrity Check**: If a `KeyWrap` node is validly authenticated via its
    **Signature**, the enclosed $K_{conv}$ is considered tentatively valid.
2.  **Promotion**: The client uses this $K_{conv}$ to decrypt history buffered
    in the Opaque Store.
3.  **Identity Pending State**: Decrypted nodes are moved to the database but
    marked as **Identity Pending**.
    -   **Observer Mode**: While in this state, the client MUST NOT author any
        new nodes (Content or Admin), share the conversation key with other
        devices, or provide structural vouches for the speculative nodes,
        preventing data leakage if the "Anchor" is later found to be a traitor.
    -   **Display**: Nodes are displayed in the UI (e.g., with an "Unverified
        Author" icon).
4.  **Healing & Finalization**:
    -   **Heal**: If the Admin track sync reveals a revocation that invalidates
        the anchor, all "Identity Pending" nodes and the associated key are
        wiped.
    -   **Seal**: If the recursive trust path is verified back to the Genesis
        Node, the nodes are promoted to **Fully Verified** and the client
        transitions to **Full Member Mode**, enabling authoring.

--------------------------------------------------------------------------------

## 6. Speculative Trust (Anchor Snapshots)

To break the deadlock during **Shallow Sync** (where a user needs a Snapshot to
avoid history, but needs history to verify the Snapshot), Merkle-Tox defines
**Anchor Snapshots**.

### The Deadlock

A standard `Snapshot` node relies on the **Recursive Topological Validation**
rule (Section 3). To verify the snapshot author's authority deep in the DAG, a
client must walk the Admin Track back to Genesis, negating the performance
benefits of the snapshot.

### The Solution: Anchor Snapshots

An `AnchorSnapshot` is a special `ControlAction` that allows for *speculative*
validation through an **Authority Chain**.

-   **Requirement**: MUST be signed by a **Level 1 Admin Device** and MUST
    include that device's **Delegation Certificate** signed by the **Founder**.
-   **Verification**: The client verifies the Founder's public key from the
    **Genesis Node**, uses it to verify the Admin's Certificate, and then uses
    the Admin's key to verify the Snapshot.
-   **Speculative Trust**: This allows a joiner to establish a *tentative* root
    of trust immediately using only two nodes: Genesis and AnchorSnapshot. The
    conversation enters **Identity Pending** mode.
-   **Security**: While it enables instant viewing of history, the client MUST
    background-sync the full Admin Track back to Genesis to cryptographically
    prove the Anchor's Admin was never revoked. If a revocation is found, the
    Anchor is discarded and the speculative history is wiped.

--------------------------------------------------------------------------------

## 7. Deniability vs. Identity

Merkle-Tox uses the **DARE** model.

-   **Admin/Identity Nodes** are cryptographically signed with permanent device
    keys (Non-repudiable).
-   **Content Nodes** use ephemeral Ed25519 signatures. During the active epoch,
    signatures provide internal authentication. After epoch rotation, the
    signing key is disclosed, making past signatures forgeable (Deniable).
-   **Timestamps**: All logical timestamps (joins, expirations) use **Network
    Time** to ensure consensus-wide consistency.

See **`merkle-tox-deniability.md`** for the full rationale and security
properties.

## 8. Security & Privacy

### Device Accountability

Every message includes the `sender_pk` of the device that claims to have
authored it.

-   **Internal Authentication**: During the active epoch, content nodes are
    signed with an ephemeral Ed25519 key held exclusively by the sender.
    Participants can cryptographically verify *which specific device* sent a
    message. No other member can forge a valid signature as another member in
    real time.
-   **External Deniability**: After epoch rotation, the sender discloses the old
    `ephemeral_signing_sk`. Any authorized member could then produce valid
    signatures from that epoch. To an outsider, the `sender_pk` and `content`
    are not permanently linked in a non-repudiable way.

### Sybil Protection

An attacker must have a valid `DelegationCertificate` pathing back to the Master
Seed to join an identity. Knowing the `Master_PK` alone is insufficient.

### Metadata

Friends only need to know the `Master_PK`. The internal complexity of which
device is currently active is handled by the Merkle-Tox sync engine, keeping the
user's "Logical" presence consistent.

### Identity Privacy & Ephemeral Pre-Keys

Merkle-Tox supports **Ephemeral Pre-keys** published via **Announcement Nodes**,
alongside the device's Tox Public Key for `sender_pk`.

-   **Announcement Nodes**: Devices MUST publish new signed X25519 pre-keys to
    the DAG every 30 days or after 100 successful handshakes.
-   **Anonymity**: This allows a device to participate in multiple conversations
    using different ephemeral keys, further decoupling the physical hardware
    from the persistent logical history and preventing cross-conversation
    tracking by relays.

See **`merkle-tox-handshake-ecies.md`** for the protocol details.
