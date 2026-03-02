# Merkle-Tox Sub-Design: DAG & Schema

## Overview

Defines the cryptographic structure of the Merkle-Tox history and data formats
for messages and control actions.

## 1. Merkle Node

`MerkleNode` is the atomic unit of the DAG, serialized using **MessagePack** and
identified by its **Blake3** hash.

**Hash Scope**: Computed over the **complete** serialized `WireNode`,
**including** the `authentication` field, ensuring nodes with identical content
but different authenticators produce distinct hashes.

**Serialization Note**: Structures and enums are serialized as **MessagePack
Arrays (Positional)** via `#[derive(ToxProto)]`. Field names are omitted;
receivers MUST know the defined field order.

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

    /// Authenticator: Either a 64-byte Ephemeral Signature or a 64-byte
    /// Ed25519 Signature (Admin/KeyWrap).
    authentication: NodeAuth,
}

enum NodeAuth {
    /// For standard content nodes: Ed25519-Sig(ephemeral_signing_sk, NodeData).
    /// The ephemeral signing key is distributed via SenderKeyDistribution and
    /// disclosed after epoch rotation. During the active epoch, only the sender
    /// holds the private key (internal authentication). After disclosure, the
    /// signature becomes forgeable (external deniability).
    EphemeralSignature([u8; 64]),

    /// For administrative and KeyWrap nodes: Ed25519-Sig(Sender_SK, NodeData).
    /// MUST be signed by the Admin to prevent spoofing of keys or permissions.
    Signature([u8; 64]),
}
```

## 2. Wire Format vs. Logical Format

Content nodes obfuscate the `sender_pk` and `sequence_number` on the wire.

### Logical View (In-Memory & Database)

The structure defined in Section 1 is the **Logical View**.

### Wire View (`WireNode`)

On the wire, the node is serialized as a `WireNode` struct (MessagePack Array):

1.  `parents`: `Vec<[u8; 32]>`
2.  `sender_hint`: `[u8; 4]`
    -   A 4-byte per-message fingerprint used for O(1) sender identification.
    -   The user's Logical Identity (`author_pk`) is omitted from the wire
        format to prevent relays from grouping messages by user. Authorized
        recipients infer the `author_pk` by looking up the decrypted `sender_pk`
        in their verified Admin Track hierarchy.
    -   Computed as the first 4 bytes of: `Blake3-KDF("merkle-tox v1 hint",
        K_msg_i)`, where $K_{msg\_i}$ is the sender's per-message ratchet key
        for this specific message.
    -   Because $K_{msg\_i}$ is unique per message, the hint changes every
        message. To a blind relay, consecutive hints from the same sender are
        indistinguishable from random, preventing passive traffic analysis
        (message grouping by sender).
    -   **PCS**: The ratchet chain is seeded from the sender's `SenderKey`,
        which rotates every 7 days / 5,000 messages. An attacker rotated out of
        the `SenderKey` cannot derive future $K_{msg\_i}$ values and therefore
        cannot compute future hints.
    -   **Lookup**: Authorized recipients maintain a `{sender_hint → (sender_pk,
        ratchet_index)}` lookup table built from their ratchet state (next
        expected key + cached skipped keys per sender). On table miss (e.g.,
        during batch sync), the recipient falls back to O(N) trial decryption of
        `encrypted_routing`. See `merkle-tox-deniability.md` §2 (Verification
        Order) for the full procedure.
    -   **EXCEPTION**: `KeyWrap` (Content ID 1), `SenderKeyDistribution` (ID 2),
        **Admin Nodes**, and `SoftAnchor` nodes set this field to `[0x00, 0x00,
        0x00, 0x00]` (the `sender_pk` is already in cleartext for these node
        types). `HistoryExport` (ID 3) also sets this to `[0x00, 0x00, 0x00,
        0x00]` but encrypts its routing header using a room-wide key (see
        below).
3.  `encrypted_routing`: `Vec<u8>`
    -   Contains: `nonce (12B) || ciphertext` where the plaintext is
        `[sequence_number]`. (The `sender_pk` is omitted here to save 32 bytes
        per message; successful trial-decryption via Poly1305 inherently
        identifies the sender).
    -   **ENCRYPTION**: The sender generates a random 12-byte nonce per message
        and prepends it to the ChaCha20-Poly1305 ciphertext. The key is the
        current $K_{header\_epoch\_n}$ (see `merkle-tox-deniability.md`). The
        recipient reads the first 12 bytes as the nonce and decrypts the
        remaining bytes.
    -   **EXCEPTION (Cleartext)**: `KeyWrap` (Content ID 1),
        `SenderKeyDistribution` (ID 2), **Admin Nodes**, and `SoftAnchor` nodes
        send these fields in **cleartext** (as `[sender_pk, sequence_number]`,
        without nonce prefix). The cleartext `sender_pk` is mandatory here to
        allow new peers to lookup the key and verify the outer signature before
        they possess any routing keys.
    -   **EXCEPTION (HistoryExport)**: `HistoryExport` (ID 3) nodes encrypt this
        field using a room-wide key: `K_header_export = Blake3-KDF("merkle-tox
        v1 header-export", K_conv)`. The plaintext is `[sender_pk,
        sequence_number]`. This hides the device-to-device export relationship
        from relays while allowing the new device (which just received `K_conv`
        via `KeyWrap`) to decrypt the routing header without needing
        `K_header_epoch_n`.
4.  `payload_data`: `Vec<u8>` (Optionally encrypted and/or compressed)
    -   Contains: `[network_timestamp, content, metadata]`
    -   **ENCRYPTION**: This field is **ChaCha20-IETF encrypted** with the
        sender's ratchet key ($K_{msg\_i}$) and a random 12-byte nonce for
        standard Content nodes. The nonce is prepended to the ciphertext: `nonce
        (12B) || ciphertext`. A random nonce prevents catastrophic $K_{msg\_i}$
        reuse if ratchet state rewinds (e.g., db restore, crash, VM clone).
    -   **EXCEPTION (Cleartext)**: `KeyWrap` (Content ID 1),
        `SenderKeyDistribution` (ID 2), **Admin Nodes**, and `SoftAnchor` nodes
        are sent in **cleartext** (but still padded and optionally compressed)
        to allow immediate validation without circular key dependencies.
    -   **EXCEPTION (HistoryExport)**: `HistoryExport` (ID 3) nodes encrypt
        their payload using a distinct room-wide key: `K_payload_export =
        Blake3-KDF("merkle-tox v1 payload-export", K_conv)` and a random 12-byte
        nonce. This hides the `recipient_pk` of the exported history from
        relays, while obeying the Key Separation Principle (distinct keys for
        routing vs. payload).
5.  `topological_rank`: `u64`
6.  `flags`: `u32` (Bitmask, e.g., 0x01 = Compressed)
7.  `authentication`: `NodeAuth`

**Note**: Admin nodes do NOT encrypt their payload on the wire to allow
immediate validation by any peer, even those without the conversation key.

## 3. Multi-Device Coordination

Merkle-Tox uses a hierarchical trust model where a **Logical Identity** (the
author) delegates signing power to multiple **Physical Devices** (the senders).

### Definition: Admin Node

A `MerkleNode` is formally classified as an "Admin Node" if and only if its
`authentication` is `NodeAuth::Signature` **AND** its `content` variant is one
of the following:

-   `Content::KeyWrap` (ID 1)
-   `Content::Control` (ID 4) containing an Admin-restricted `ControlAction`
    (e.g., `Genesis`, `AuthorizeDevice`, `RevokeDevice`, `Snapshot`,
    `AnchorSnapshot`).
-   *(Note: `SoftAnchor` nodes are evaluated identically to Admin nodes for
    ancestry bounding, but are authored by L2 Participants).*

### Validation Rule

A node MUST satisfy the following to be valid:

1.  The `authentication` is valid:

    -   **Admin, KeyWrap, and SoftAnchor Nodes**: MUST use
        `NodeAuth::Signature`.
    -   **SenderKeyDistribution Nodes**: For the initial distribution (epoch 0),
        MUST use `NodeAuth::Signature` (no ephemeral key has been established
        yet). For subsequent epochs, MUST use `NodeAuth::EphemeralSignature`
        signed by the current epoch's ephemeral signing key.
    -   **Content Nodes**: MUST use `NodeAuth::EphemeralSignature`.
    -   **Canonical Ephemeral Signature Input**: The signature for a Content
        Node is computed as:

        ```
        Node_Contents = ToxProto::serialize([
            parents,               // Vec<[u8; 32]>
            sender_hint,           // [u8; 4]
            encrypted_routing,     // Vec<u8>  ← CIPHERTEXT
            payload_data,          // Vec<u8>  ← CIPHERTEXT
            topological_rank,      // u64
            flags,                 // u32
        ])
        Ed25519_Sign(ephemeral_signing_sk, "merkle-tox v1 content-sig" || Node_Contents)
        ```

        The signature covers the **ciphertext** of `encrypted_routing` and
        `payload_data` (Encrypt-then-Sign). It also covers `topological_rank`
        and `flags`, preventing relay manipulation of either field. The
        `ephemeral_signing_sk` is the private key of the ephemeral signing key
        pair distributed via the sender's current `SenderKeyDistribution` (see
        below). Recipients verify using the corresponding
        `ephemeral_signing_pk`.

    -   **Canonical Signature Input (Admin/KeyWrap)**: For signed nodes, the
        `Node_Contents` is the same positional serialization of fields 1–6, but
        `encrypted_routing` contains the **plaintext** `[sender_pk,
        sequence_number]` and `sender_hint` is `[0x00, 0x00, 0x00, 0x00]`.

        ```
        Ed25519_Sign(sender_sk, "merkle-tox v1 admin-sig" || Node_Contents)
        ```

2.  **Chain Isolation**: Admin and `SoftAnchor` nodes MUST ONLY reference other
    Admin or `SoftAnchor` nodes as parents. Content nodes may reference both.
    (See `merkle-tox-deniability.md` for the security rationale).

3.  A valid **Trust Path** exists from the `sender_pk` back to the `author_pk`
    (the Master Seed).

4.  **Causality-Dependent Authorization**: Permissions are recalculated for
    every node based on the linearized causal history of the DAG. A Trust Path
    is only valid if it has not been invalidated by a `RevokeDevice` node that
    is a **topological ancestor** of the node being verified. (Note: Network
    time is NEVER used for cryptographic authorization boundaries, as it is
    manipulable by attackers backdating nodes).

5.  **Limits**: See `merkle-tox.md` for `MAX_PARENTS` and other hard limits.

## 4. Content Types

Content is represented as a flattened enum for protocol efficiency.

```rust
enum Content {
    /// ID 0: Opaque/Experimental for client-specific features.
    Custom {
        tag_id: u32,
        data: Vec<u8>,
    },

    /// ID 1: Batch of keys for distributing the global metadata/DARE key (K_conv).
    /// Used when adding/revoking members. Does NOT encrypt content.
    KeyWrap {
        generation: u64,
        /// Hash of the Anchor Snapshot or Genesis Node that proves the
        /// sender's authority. Required for new joiners to trust the key.
        anchor_hash: [u8; 32],
        /// Single ephemeral X25519 public key used for all WrappedKey entries.
        /// The sender generates one keypair (e, E) per node, computes
        /// DH(e, SPK_i) for each recipient, and deletes e after all entries
        /// are derived. See WrappedKey.ciphertext for the per-entry derivation.
        ephemeral_pk: [u8; 32],
        wrapped_keys: Vec<WrappedKey>,
    },

    /// ID 2: Distributes a device's unique SenderKey for payload encryption
    /// and the ephemeral signing public key for content authentication.
    /// Provides scalable Forward Secrecy and PCS without Admin bottlenecks.
    SenderKeyDistribution {
        /// Single ephemeral X25519 public key (see KeyWrap.ephemeral_pk).
        ephemeral_pk: [u8; 32],
        wrapped_keys: Vec<WrappedKey>,
        /// The Ed25519 public key that recipients use to verify content nodes
        /// from this sender during the current epoch. The corresponding private
        /// key is held only by the sender until the next epoch rotation.
        ephemeral_signing_pk: [u8; 32],
        /// Disclosed private keys from previous epochs. Including the old
        /// ephemeral_signing_sk makes all signatures from that epoch forgeable
        /// by anyone, restoring deniability (analogous to OTR MAC disclosure).
        /// Empty for the initial distribution (epoch 0).
        disclosed_keys: Vec<[u8; 32]>,
    },

    /// ID 3: Encrypted export of decrypted message history for newly authorized devices.
    /// The exporting device encrypts plaintext local content with a fresh symmetric key
    /// and uploads it as a Blob to the CAS. Historical encryption keys (K_conv generations,
    /// SenderKey seeds, ratchet chain keys) are NEVER included. The new device receives
    /// plaintext content only, preserving deniability (no signing keys are transferred).
    HistoryExport {
        /// Hash of the encrypted content Blob in the CAS.
        blob_hash: [u8; 32],
        /// Single ephemeral X25519 public key (see KeyWrap.ephemeral_pk).
        ephemeral_pk: [u8; 32],
        /// The symmetric key used to encrypt the blob, wrapped for the new device.
        wrapped_keys: Vec<WrappedKey>,
    },

    /// ID 4: Admin/Room actions
    Control(ControlAction),

    /// ID 5: Standard text
    Text(String),

    /// ID 6: File/Image reference in the CAS
    Blob {
        hash: [u8; 32],      // Bao root hash of the file content (see merkle-tox-cas.md)
        name: String,        // Filename
        mime_type: String,
        size: u64,
        metadata: Vec<u8>,
    },

    /// ID 7: Geo-location
    Location {
        latitude: f64,
        longitude: f64,
        title: Option<String>,
    },

    /// ID 8: Replaces the text content of a previous message inline.
    Edit {
        /// The Blake3 hash of the original Content::Text node.
        target_hash: [u8; 32],
        /// The corrected text content.
        new_text: String,
    },

    /// ID 9: Emoji/Reaction
    Reaction {
        target_hash: [u8; 32],
        emoji: EmojiSource,
    },

    /// ID 10: Removes the content of a previous node from display.
    Redaction {
        target_hash: [u8; 32],
        reason: String,
    },

    /// ID 11: Bridged from legacy Tox transport.
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
}
```

**Edit Node Rules**:

-   **Immutability:** The original `Content::Text` node is never deleted or
    modified on disk.
-   **Authorization:** The `author_pk` of the `Edit` node MUST match the
    `author_pk` of the target node.
-   **Target Restriction:** The `target_hash` MUST reference a `Content::Text`
    node specifically. Edits targeting other content types (including other
    `Edit` nodes) are invalid.
-   **Materialized View:** UIs SHOULD render the message at its original
    topological position but display the `new_text` from the latest valid `Edit`
    node (with an indicator like "(edited)").
-   **Concurrent Edits:** If multiple valid `Edit` nodes target the same
    `Content::Text` node and are DAG-concurrent (neither is an ancestor of the
    other), the UI MUST display the one with the lexicographically smaller
    `NodeHash`.
-   **Redaction Precedence:** A `Redaction` node takes precedence over any
    `Edit` targeting the same node. Once redacted, subsequent `Edit`s are
    accepted into the DAG but MUST NOT restore the content to display.
-   **Referential Integrity:** Replies made prior to the edit continue to
    reference the original message hash.

**Unknown Content Rules (Forward Compatibility)**:

-   **Unrecognized IDs:** If a client receives a `MerkleNode` with an
    unrecognized `Content` ID (e.g., ID 12 from a newer protocol version), the
    client **MUST** cryptographically verify the node's signature, store the
    node in its local database, and actively relay it to peers just like any
    known content.
-   **Display:** The UI **SHOULD** display the node as an "Unsupported message".
    It **MUST NOT** reject the node or drop the connection, provided the
    signature and DAG requirements are valid. This ensures the Merkle-DAG
    structure remains intact and can be synced across older relays.

## 4. Control Actions

Control actions manage the state of the conversation.

```rust
enum ControlAction {
    /// Conversation Bootstrap (merkle-tox-dag.md §5)
    Genesis {
        title: String,
        creator_pk: [u8; 32],
        permissions: u32,
        flags: u64,
        created_at: i64,
        /// Proof of Work nonce, ground before the node is signed.
        pow_nonce: u64,
    },

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

    /// Signed ECIES Pre-key Announcement (merkle-tox-handshake-ecies.md)
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
    /// RULE: Acts as a speculative trust anchor, initially verified using the
    /// Founder's key (from Genesis) + the enclosed Certificate. MUST be followed
    /// by background sync of the Admin Track to verify the Admin was not revoked
    /// prior to the snapshot.
    AnchorSnapshot {
        data: SnapshotData,
        cert: DelegationCertificate,
    },

    /// A checkpoint authored by a Level 2 Participant.
    /// Resets the structural vouching hop-counter for blind relays.
    /// AUTH: MUST be signed by the author's permanent device key.
    /// Note on Deniability: Authoring a SoftAnchor uses the permanent device key,
    /// providing non-repudiable proof of the author's presence in the conversation
    /// at this topological point. The content of their messages, however, remains
    /// protected by ephemeral signatures.
    SoftAnchor {
        /// The hash of the preceding Admin or SoftAnchor node.
        basis_hash: [u8; 32],
        /// Authorization proof, allowing blind relays to verify membership
        /// without full DAG context.
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
    /// Ed25519 Signature of public_key by the Device Key (sender_pk).
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
    /// Format version (currently 1).
    version: u32,
    /// The specific conversation this certificate applies to.
    conversation_id: [u8; 32],
    /// Tox Public Key of the device being authorized.
    device_pk: [u8; 32],
    /// Bitmask of permissions (ADMIN, MESSAGE, SYNC).
    permissions: u32,
    /// Network Time (ms) when this authorization expires.
    expires_at: i64,
    /// Signature of the above fields by a higher-level key (Master or Admin).
    signature: [u8; 64],
}

struct WrappedKey {
    /// Tox Public Key (Ed25519) of the recipient **device**.
    ///
    /// Keys are wrapped per physical device using ECIES against the
    /// recipient device's current Signed Pre-Key (SPK) from their
    /// Announcement node. The construction works uniformly for both
    /// `KeyWrap` (Admin-authored) and `SenderKeyDistribution` (any
    /// device), since every device publishes pre-keys via Announcement
    /// nodes that any other device can use.
    ///
    /// **Forward Secrecy**: Bounded by the SPK rotation interval
    /// (ANNOUNCEMENT_ROTATION_INTERVAL = 30 days). Once the recipient
    /// deletes the SPK secret key after rotation, past wrappings become
    /// undecryptable. Per-identity wrapping against a static key derived
    /// from the Master Seed is explicitly forbidden: compromise of that
    /// single key would expose all historical K_conv generations, all
    /// SenderKeys, and transitively all ratchet chains.
    ///
    /// The O(N_members × N_devices) scaling cost is the price of
    /// per-device forward secrecy.
    recipient_pk: [u8; 32],
    /// Blake3 hash of the One-Time Pre-Key (OPK) from the recipient's
    /// Announcement node that was consumed in this wrapping. Used for
    /// OPK collision detection (see merkle-tox-handshake-ecies.md §5).
    /// Set to [0u8; 32] when no OPK was consumed (e.g., post-revocation
    /// re-keying, SenderKeyDistribution, or when only the SPK is used).
    ///
    /// Placing the OPK context per-entry (rather than per-KeyWrap node)
    /// ensures that an OPK collision only affects the specific recipient
    /// entry, not the entire KeyWrap. The rest of the node's wrapped_keys
    /// remain valid, eliminating the blast radius of OPK collision attacks.
    opk_id: [u8; 32],
    /// New K_conv or SenderKey, encrypted via ECIES against recipient SPK
    /// (and optionally OPK for additional forward secrecy).
    ///
    /// The ephemeral public key E is stored once in the parent node's
    /// `ephemeral_pk` field, NOT repeated per entry. Per-entry key derivation:
    ///   1. shared_spk = DH(e, recipient_spk)
    ///      where recipient_spk is the recipient device's current SPK
    ///      from their latest Announcement node.
    ///   2. If opk_id != [0u8; 32]:
    ///        shared_opk = DH(e, recipient_opk)
    ///        key = Blake3-KDF("merkle-tox v1 keywrap", shared_spk || shared_opk)
    ///      Else:
    ///        key = Blake3-KDF("merkle-tox v1 keywrap", shared_spk)
    ///   3. Encrypt: ChaCha20-Poly1305(key, [0u8; 12], plaintext).
    ///      The zero nonce is safe because `key` is unique per entry
    ///      (each device has a unique SPK, producing a unique DH output).
    ///      Poly1305 is REQUIRED to prevent decryption DoS and ensure payload integrity.
    /// Forward secrecy comes from deleting `e` after all entries are
    /// computed. When an OPK is consumed, it provides additional per-entry
    /// forward secrecy beyond the 30-day SPK rotation window.
    ciphertext: Vec<u8>,
}
```

## 5. Genesis Node

The first node in any conversation is the **Genesis Node**.

-   Its hash is used as the `Conversation ID`.
-   It defines the initial parameters of the room.
-   A node is only valid if a path exists from it back to the Genesis Node.

### Standardized 1-on-1 Genesis

"Deterministic Genesis" based on device-specific `crypto_box` secrets is NOT
used.

-   1-on-1 chats use the exact same **Group Genesis** procedure as larger
    groups.
-   The initiator generates a random $K_{conv}$ and authors the Genesis Node.
-   The initiator uses the **Signed ECIES Handshake** to wrap and deliver
    $K_{conv}$ to each of the recipient's authorized devices, enabling
    multi-device sync.

### Group Genesis

The Genesis Node is created by the founder and contains:

-   `title`: Initial room name.
-   `creator_pk`: The founder's public key.
-   `permissions`: Initial capability set.
-   `flags`: A `u64` bitmask for room-wide rules:
    -   `0x01`: `FLAG_ADMIN_ONLY_INVITE` (Only Admins can invite).
    -   `0x02`: `FLAG_MEMBER_INVITE` (Any member can invite).
-   `created_at`: The Genesis timestamp (Network Time, ms).
-   `pow_nonce`: A 64-bit integer ground to satisfy the Proof-of-Work
    constraint.
-   **Authentication**: Must be **signed** by the creator's Master Seed OR a
    Level 1 Admin Device.

**Contextual Proof-of-Work**: To prevent Genesis spam, the room creator must
compute a PoW before signing the Genesis node.

-   **Target Difficulty**: 20 bits (requires ~1,048,576 attempts on average).
-   **PoW Scope**: The creator constructs the `ControlAction::Genesis` structure
    and grinds its internal `pow_nonce` field such that `Blake3(creator_pk ||
    ToxProto::serialize(genesis_action))` has 20 leading zeros. This ensures the
    PoW is robustly bound to all Genesis parameters.
-   **Pre-Signature Grinding**: Because the `pow_nonce` is inside the payload,
    it is ground *before* the Ed25519 `NodeAuth::Signature` is computed. The
    creator then embeds this `pow_nonce` directly into the
    `ControlAction::Genesis` struct, serializes the complete `WireNode`, and
    applies the signature once.
-   **Security**: A malicious relay cannot alter the `pow_nonce` to fragment the
    room because it is covered by the creator's signature. `NodeHash` and
    `ConversationID` remain identical.
-   **Validation**: Relays and clients MUST verify both the Ed25519 signature
    and the PoW before accepting the node.
-   **Cost Model**: Grinding uses pure Blake3 hashing over a few bytes. At ~1M
    Blake3 hashes/sec on a smartphone, the expected cost is **~1 second**, while
    maintaining resistance to relay tampering.
