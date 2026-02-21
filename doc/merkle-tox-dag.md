# Merkle-Tox Sub-Design: DAG & Schema

## Overview

This document defines the cryptographic structure of the Merkle-Tox history and
the data formats used for messages and control actions.

## 1. Merkle Node

A `MerkleNode` is the atomic unit of the DAG. It is serialized using
**MessagePack** and identified by its **Blake3** hash.

**Serialization Note**: To ensure maximum compactness, all structures and enums
in Merkle-Tox are serialized as **MessagePack Arrays (Positional)** using the
`#[derive(ToxProto)]` macro. Field names are not sent on the wire; the receiver
must know the field order defined below.

```rust
struct MerkleNode {
    /// Hashes of parent nodes (the "Heads" known to the author).
    /// RULE: If this is an Admin node, parents MUST only be other Admin nodes.
    /// LIMIT: MAX_PARENTS (see merkle-tox.md).
    parents: Vec<[u8; 32]>,

    /// Logical Identity PK (The "User" this message belongs to).
    /// Note: In Tox-based swarms, this is the conversation-local Public Key
    /// to prevent cross-room tracking.
    author_pk: [u8; 32],

    /// Physical Device PK (The Tox Public Key of the device that signed this).
    /// Note: Encrypted in the wire header to prevent metadata leaks to relays.
    sender_pk: [u8; 32],

    /// Monotonic counter per-device for gap detection.
    /// Note: Encrypted in the wire header to prevent metadata leaks to relays.
    sequence_number: u64,

    /// Logical depth in the DAG (max(parent_ranks) + 1).
    topological_rank: u64,

    /// Consensus Network Time (milliseconds).
    network_timestamp: i64,

    /// Actual content (Text, Blob, Reaction, Control, etc).
    content: Content,

    /// Optional metadata (Thumbnails, custom tags, etc).
    metadata: Vec<u8>,

    /// Authenticator: Either a 32-byte DARE MAC or a 64-byte Ed25519 Signature.
    authentication: NodeAuth,
}

enum NodeAuth {
    /// For standard content nodes: Blake3-MAC(K_mac, NodeData).
    /// K_mac is derived from the global K_conv.
    Mac([u8; 32]),

    /// For administrative and KeyWrap nodes: Ed25519-Sig(Sender_SK, NodeData).
    /// Because KeyWrap is an administrative action distributing keys, it MUST
    /// be signed by the Admin to prevent spoofing.
    Signature([u8; 64]),
}
```

## 2. Wire Format vs. Logical Format

To ensure metadata privacy (hiding which device sent which message), Content
nodes obfuscate the `sender_pk` and `sequence_number` on the wire.

### Logical View (In-Memory & Database)

The structure defined in Section 1 is the **Logical View**. This is what the
application logic sees after decryption and what is stored in the database for
indexing.

### Wire View (`WireNode`)

On the wire, the node is serialized as a `WireNode` struct (MessagePack Array):

1.  `parents`: `Vec<[u8; 32]>`
2.  `author_pk`: `[u8; 32]`
3.  `encrypted_routing`: `Vec<u8>`
    -   Contains: `[sender_pk, sequence_number]`.
    -   **ENCRYPTION**: ChaCha20 encrypted using $K_{header}$ (derived from
        $K_{conv}$) to hide metadata from blind relays. Authorized members
        decrypt this first to identify the sender's ratchet.
    -   **EXCEPTION**: `KeyWrap` nodes and **Admin Nodes** send these fields in
        **cleartext** (as `[sender_pk, sequence_number]`) to allow
        onboarding/validation by peers who do not yet have $K_{conv}$.
4.  `payload_data`: `Vec<u8>` (Optionally encrypted and/or compressed)
    -   Contains: `[network_timestamp, content, metadata]`
    -   **ENCRYPTION**: This field is **ChaCha20 encrypted** with the sender's
        ratchet key ($K_{msg\_i}$) for standard Content nodes.
    -   **EXCEPTION**: `KeyWrap` nodes (Content ID 7) and **Admin Nodes** are
        sent in **cleartext** (but still padded and optionally compressed) to
        allow for immediate validation and onboarding.
5.  `topological_rank`: `u64`
6.  `flags`: `u32` (Bitmask, e.g., 0x01 = Compressed)
7.  `authentication`: `NodeAuth`

**Note**: Admin nodes do NOT encrypt their payload on the wire to allow for
immediate validation by any peer, even those without the conversation key.

## 3. Multi-Device Coordination

Merkle-Tox uses a hierarchical trust model where a **Logical Identity** (the
author) delegates signing power to multiple **Physical Devices** (the senders).

### Validation Rule

A node is only considered valid if:

1.  The `authentication` is valid:
    -   **Admin and KeyWrap Nodes**: MUST use `NodeAuth::Signature`.
    -   **Content Nodes**: MUST use `NodeAuth::Mac`.
2.  **Chain Isolation**: Admin nodes MUST ONLY reference other Admin nodes as
    parents. Content nodes may reference both. (See `merkle-tox-deniability.md`
    for the security rationale).
3.  A valid **Trust Path** exists from the `sender_pk` back to the `author_pk`
    (the Master Seed).
4.  **Causality-Dependent Authorization**: Permissions are recalculated for
    every node based on the strictly linearized causal history of the DAG. A
    Trust Path is only valid if it has not been invalidated by a `RevokeDevice`
    node that is a **topological ancestor** of the node being verified. (Note:
    Network time is NEVER used for cryptographic authorization boundaries, as it
    is manipulable by attackers backdating nodes).
5.  **Limits**: See `merkle-tox.md` for `MAX_PARENTS` and other hard limits.

## 4. Content Types

Content is represented as a flattened enum for protocol efficiency.

```rust
enum Content {
    /// ID 0: Standard text
    Text(String),

    /// ID 1: File/Image reference in the CAS
    Blob {
        hash: [u8; 32],      // Blake3 hash of the file content
        name: String,        // Filename
        mime_type: String,
        size: u64,
        metadata: Vec<u8>,
    },

    /// ID 2: Emoji/Reaction
    Reaction {
        target_hash: [u8; 32],
        emoji: EmojiSource,
    },

    /// ID 3: Geo-location
    Location {
        latitude: f64,
        longitude: f64,
        title: Option<String>,
    },

    /// ID 4: Admin/Room actions
    Control(ControlAction),

    /// ID 5: Removes the content of a previous node from display.
    Redaction {
        target_hash: [u8; 32],
        reason: String,
    },

    /// ID 6: Opaque/Experimental for client-specific features.
    Other {
        tag_id: u32,
        data: Vec<u8>,
    },

    /// ID 7: Batch of keys for distributing the global metadata/DARE key (K_conv).
    /// Used when adding/revoking members. Does NOT encrypt content.
    KeyWrap {
        generation: u64,
        /// Hash of the Anchor Snapshot or Genesis Node that proves the
        /// sender's authority. Required for new joiners to trust the key.
        anchor_hash: [u8; 32],
        wrapped_keys: Vec<WrappedKey>,
    },

    /// ID 8: Encrypted cache of historical keys to allow newly authorized devices to decrypt past history.
    /// The key database is uploaded as a Blob to the CAS. This node distributes the decryption key.
    HistoryKeyExport {
        /// Hash of the encrypted Key Cache Blob in the CAS.
        blob_hash: [u8; 32],
        /// The symmetric key used to encrypt the blob, wrapped for the new device.
        wrapped_keys: Vec<WrappedKey>,
    },

    /// ID 9: Bridged from legacy Tox transport.
    LegacyBridge {
        /// The original stable Tox Public Key of the legacy sender.
        source_pk: [u8; 32],
        /// The message content (Text).
        text: String,
        /// The legacy message type (0: Normal, 1: Action).
        message_type: u8,
        /// Deterministic ID for cross-device deduplication.
        dedup_id: [u8; 32],
    },

    /// ID 10: Distributes a device's unique SenderKey for payload encryption.
    /// Provides scalable Forward Secrecy and PCS without Admin bottlenecks.
    SenderKeyDistribution {
        wrapped_keys: Vec<WrappedKey>,
    },
}

```

## 4. Control Actions

Control actions manage the state of the conversation.

```rust
enum ControlAction {
    /// Room Settings
    SetTitle(String),
    SetTopic(String),

    /// Membership
    Invite(InviteAction),
    Leave([u8; 32]),

    /// Identity Hierarchy (merkle-tox-identity.md)
    AuthorizeDevice {
        cert: DelegationCertificate,
    },
    RevokeDevice {
        target_device_pk: [u8; 32],
        reason: String,
    },

    /// X3DH Pre-key Announcement (merkle-tox-handshake-x3dh.md)
    Announcement {
        pre_keys: Vec<SignedPreKey>,
        last_resort_key: SignedPreKey,
    },

    /// Requests a peer to publish fresh pre-keys.
    /// Used primarily in 1-on-1 chats to compel a full KeyWrap rotation of $K_{conv}$
    /// after relying on a Last Resort key.
    HandshakePulse,

    /// A "Snapshot" node to allow shallow sync by summarizing state.
    /// REQUIRES: Full Admin Track verification up to basis_hash.
    Snapshot(SnapshotData),

    /// A "Speculative" Snapshot for shallow sync.
    /// AUTH: MUST be signed by a Level 1 Admin.
    /// RULE: This node acts as a speculative trust anchor and can be initially
    /// verified using the Founder's key (from Genesis) + the enclosed Certificate.
    /// It MUST be followed by a background sync of the Admin Track to verify
    /// that the Admin was not revoked prior to the snapshot.
    AnchorSnapshot {
        data: SnapshotData,
        cert: DelegationCertificate,
    },
}

struct SnapshotData {
    basis_hash: [u8; 32],
    members: Vec<MemberInfo>,
    last_seq_numbers: Vec<([u8; 32], u64)>,
}

struct InviteAction {
    invitee_pk: [u8; 32],
    role: u8,
}

struct MemberInfo {
    public_key: [u8; 32],
    role: u8,
    /// Network Time (ms) when this member joined.
    joined_at: i64,
}

struct SignedPreKey {
    /// Ephemeral X25519 Public Key.
    public_key: [u8; 32],
    /// Ed25519 Signature of public_key by the Identity Master Seed.
    signature: [u8; 64],
    /// Expiration timestamp (Network Time).
    expires_at: i64,
}

enum EmojiSource {
    Unicode(String),
    Custom {
        hash: [u8; 32],
        shortcode: String,
    },
}

struct DelegationCertificate {
    /// Tox Public Key of the device being authorized.
    device_pk: [u8; 32],
    /// Bitmask of permissions (ADMIN, MESSAGE, SYNC).
    permissions: u32,
    /// Network Time (ms) when this authorization expires.
    expires_at: i64,
    /// Signature of the above by a higher-level key (Master or Admin).
    signature: [u8; 64],
}

struct WrappedKey {
    /// PK of the recipient member device.
    /// Note: While earlier designs attempted to hide this via trial decryption,
    /// room membership is already public to relays via cleartext `AuthorizeDevice`
    /// Admin nodes. Therefore, including the `recipient_pk` here avoids the
    /// massive CPU overhead of trial decryption in 200+ user groups.
    recipient_pk: [u8; 32],
    /// New K_conv or SenderKey, encrypted with the pairwise X3DH secret.
    ciphertext: Vec<u8>,
}
```

## 5. Genesis Node

The first node in any conversation is the **Genesis Node**.

-   Its hash is used as the `Conversation ID`.
-   It defines the initial parameters of the room.
-   A node is only valid if a path exists from it back to the Genesis Node.

### Recommendation: Standardized 1-on-1 Genesis

To ensure that multi-device synchronization functions correctly for 1-on-1
chats, the "Deterministic Genesis" based on device-specific `crypto_box` secrets
is NOT used.

-   1-on-1 chats use the exact same **Group Genesis** procedure as larger
    groups.
-   The initiator generates a random $K_{conv}$ and authors the Genesis Node.
-   The initiator then uses the **X3DH Handshake** to securely wrap and deliver
    the new $K_{conv}$ to the recipient's logical identity, allowing both users
    to sync the conversation across all their authorized devices.

### Recommendation: Group Genesis

For group chats, the Genesis Node is created by the founder and contains:

-   `title`: Initial room name.
-   `creator_pk`: The founder's public key.
-   `permissions`: Initial capability set.
-   `flags`: A `u64` bitmask for room-wide rules:
    -   `0x01`: `FLAG_ADMIN_ONLY_INVITE` (Only Admins can invite).
    -   `0x02`: `FLAG_MEMBER_INVITE` (Any member can invite).
-   `created_at`: The Genesis timestamp (Network Time, ms).
-   `pow_nonce`: A `u64` used to satisfy the Proof-of-Work requirement.
-   **Authentication**: Must be **signed** by the creator's Master Seed OR a
    Level 1 Admin Device.

**Proof-of-Work (Hashcash)**: To prevent Genesis spam, the Blake3 hash of the
serialized Genesis Node MUST start with $N$ leading zero bits.

-   **Target Difficulty**: 12 bits (requires 4,096 hashes on average).
-   **Tuning**: This provides a baseline cost to deter automated spam while
    remaining feasible for mobile devices.
