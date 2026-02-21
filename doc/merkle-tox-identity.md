# Merkle-Tox Sub-Design: Hierarchical Identity & Device Management

## Overview

Merkle-Tox decouples the **Logical Identity** (the User) from the **Physical
Identity** (the Tox ID of a device). This allows a single user to chat from
multiple devices (Phone, Laptop, Desktop) while appearing as a single consistent
entity to their friends.

The system uses a 3-level trust hierarchy to balance security, resilience, and
usability.

## 1. Trust Hierarchy

### Level 0: Master Seed ("Root")

-   **Storage**: Offline (e.g., a 24-word BIP-39 mnemonic phrase on paper).
-   **Capability**: Can authorize "Admin" devices and perform emergency
    recovery.
-   **Power**: Absolute. A revocation signed by the Master Seed overrides any
    other action in the DAG.
-   **Identity PK ($I_{pk}$)**: The Ed25519 public key derived from the Master
    Seed. This is the "User ID" shared with friends.

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

To ensure security and prevent privilege escalation, Merkle-Tox enforces dynamic
delegation rules:

-   **Cryptographic Validity**: A `DelegationCertificate` is cryptographically
    valid if it is correctly signed by an issuer who was authorized at the
    moment of the certificate's creation (determined by causal ancestry).
-   **Effective Permissions (Dynamic Intersection)**: A device's actual power is
    the **intersection** of its certificate's claims and the issuer's actual
    power at the point in causal history of the node being verified. If an
    issuer oversteps their authority (e.g., granting `ADMIN` when they only have
    `MESSAGE`), the escalated permission is ignored by the engine.
-   **Expiration**: A device's authorization is only valid until the earliest
    `expires_at` timestamp in its trust path.

## 3. Dynamic Trust & Recursive Validation

To prevent "Zombie" devices (devices authorized by an Admin who has since been
revoked) from continuing to disrupt a conversation, Merkle-Tox uses **Recursive
Topological Validation**.

### The Rule of Contextual Validity

A `MerkleNode` is only valid if its author (the `sender_pk`) was authorized at
the moment of creation.

1.  **Pathing**: Every node must be linked to a valid `DelegationCertificate`.
2.  **Recursive Check**: When validating a node **N**, the client must verify
    that:
    -   The `sender_pk` holds a certificate signed by an Admin.
    -   **Crucially**: The Admin's own authorization was not revoked by any node
        that is a **topological ancestor** of N.
    -   **Concurrent Admin Resolution (Tie-Breaker)**: If the DAG contains
        concurrent `RevokeDevice` nodes that target each other's authors (a
        "mutually assured destruction" scenario where a compromised Admin tries
        to drag down honest Admins), the system MUST deterministically serialize
        the Admin track before evaluation. Concurrent Admin nodes are sorted by
        **Admin Seniority**:
        1.  The `topological_rank` of the `AuthorizeDevice` node that granted
            the author's Admin status (older/lower rank wins).
        2.  If authorized at the exact same rank, tie-break using the
            lexicographical Blake3 `hash` of that same historical
            `AuthorizeDevice` node. Because the sorting relies entirely on
            *historical, immutable* data, an attacker cannot "grind" the hash of
            their new `RevokeDevice` node to artificially win the tie-breaker.
            The junior Admin's revocation is evaluated second, and because they
            were just revoked by the senior Admin, their action is discarded as
            invalid.
3.  **Transitive Revocation**: If Admin A is revoked by node R, all Level 2
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
        new key, making them mathematically incapable of generating valid MACs
        or Header Encryptions for new messages. Their parallel branch physically
        dies.

### Logical vs. Cryptographic Validity

Merkle-Tox separates the *act of authorization* (writing a certificate to the
DAG) from the *presence of power*.

-   **Dormant Paths**: An `AuthorizeDevice` node can be accepted into the DAG
    even if the issuer currently has zero permissions (e.g., they are currently
    revoked).
-   **Healing**: If the issuer's power is later restored (e.g., by a snapshot
    that overwrites a malicious revocation), all sub-devices in that path
    automatically regain their power without needing fresh certificates. This
    ensures that the trust graph is resilient and decoupled from transient
    partitioning or malicious Admin track manipulation.

### Post-Revocation Cleanup

When an Admin is revoked, the remaining Admins SHOULD author a new `Snapshot` or
`KeyWrap` node to explicitly formalize the new set of authorized devices and
rotate the conversation metadata key ($K_{conv}$), physically excluding the
revoked branch from future actions.

--------------------------------------------------------------------------------

## 4. Multi-Device History Synchronization

Because Merkle-Tox provides strict Forward Secrecy, a newly authorized device
cannot mathematically decrypt historical messages because the past `SenderKey`s
have been ratcheted and deleted. To fulfill the promise of allowing users to
"catch up" from new devices, the protocol uses a **History Key Export**
mechanism built on top of the CAS.

1.  **Export & Encrypt**: When Device A authorizes Device B, Device A compiles
    its local repository of all known historical keys (past $K_{conv}$
    generations and past `SenderKey` seeds). Device A encrypts this repository
    with a newly generated symmetric $K_{export}$.
2.  **CAS Upload**: Device A uploads the encrypted repository as a standard Blob
    to the Content-Addressable Storage (CAS) swarm, deriving a `blob_hash`.
3.  **Key Distribution**: Device A authors a `HistoryKeyExport` node to the DAG.
    This node contains the `blob_hash` and the $K_{export}$ encrypted
    specifically for Device B (using X3DH).
4.  **Asynchronous Catch-Up**: Because the encrypted keys are stored in the CAS
    rather than bloating the DAG, Device B can sync the entire DAG architecture
    instantly, and then asynchronously download the key repository from blind
    relays in the background. Once decrypted, Device B instantly regains access
    to the user's entire historical chat record.

--------------------------------------------------------------------------------

## 5. Speculative Decryption & Unverified Silence

To resolve deadlocks during initial synchronization (where a user has a new
$K_{conv}$ but has not yet verified the Admin Track that authorized the sender),
Merkle-Tox allows **Speculative Decryption** under a strict **Observer Mode**.

1.  **Integrity Check**: If a `KeyWrap` node is validly authenticated via its
    **Signature**, the enclosed $K_{conv}$ is considered tentatively valid.
2.  **Promotion**: The client uses this $K_{conv}$ to decrypt history buffered
    in the Opaque Store.
3.  **Identity Pending State**: Decrypted nodes are moved to the database but
    marked as **Identity Pending**.
    -   **Observer Mode**: While in this state, the client MUST NOT author any
        new nodes (Content or Admin), share the conversation key with other
        devices, or provide structural vouches for the speculative nodes. This
        prevents data leakage if the "Anchor" is later found to be a traitor.
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

## 5. Speculative Trust (Anchor Snapshots)

To break the deadlock during **Shallow Sync** (where a user needs a Snapshot to
avoid history, but needs history to verify the Snapshot), Merkle-Tox defines
**Anchor Snapshots**.

### The Deadlock

A standard `Snapshot` node relies on the **Recursive Topological Validation**
rule (Section 3). To verify the snapshot author's authority deep in the DAG, a
client must walk the Admin Track back to Genesis. This negates the performance
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

## 6. Deniability vs. Identity

To balance the need for a **Sound Identity** with **Plausible Deniability**,
Merkle-Tox uses the **DARE** model.

-   **Admin/Identity Nodes** are cryptographically signed (Non-repudiable).
-   **Content Nodes** use symmetric MACs (Deniable).
-   **Timestamps**: All logical timestamps (joins, expirations) use **Network
    Time** to ensure consensus-wide consistency.

See **`merkle-tox-deniability.md`** for the full rationale and security
properties.

## 7. Security & Privacy

### Device Accountability

Every message includes the `sender_pk` of the device that claims to have
authored it.

-   **Group Authentication**: Within the group, participants can verify that a
    message was sent by *someone* in the room (via the shared $K_{conv}$ MAC).
    However, because the MAC is symmetric, **Internal Accountability**
    (cryptographically proving *which* specific device sent a message) is
    mathematically impossible. Any authorized member can forge the `sender_pk`
    field of a Content node to frame another member.
-   **External Deniability**: Because the content uses DARE MACs, this group
    authentication is only visible to those who hold the shared conversation
    key. To an outsider, the `sender_pk` and `content` are not cryptographically
    linked in a non-repudiable way.

### Sybil Protection

An attacker cannot "join" your identity by just knowing your `Master_PK`. They
must have a valid `DelegationCertificate` that paths back to your Master Seed.

### Metadata

Friends only need to know the `Master_PK`. The internal complexity of which
device is currently active is handled by the Merkle-Tox sync engine, keeping the
user's "Logical" presence consistent.

### Identity Privacy & Ephemeral Pre-Keys

While the current design uses the device's Tox Public Key for `sender_pk`,
Merkle-Tox supports **Ephemeral Pre-keys** published via **Announcement Nodes**.

-   **Announcement Nodes**: Devices MUST publish new signed X25519 pre-keys to
    the DAG every 30 days or after 100 successful handshakes.
-   **Anonymity**: This allows a device to participate in multiple conversations
    using different ephemeral keys, further decoupling the physical hardware
    from the persistent logical history and preventing cross-conversation
    tracking by relays.

See **`merkle-tox-handshake-x3dh.md`** for the protocol details.
