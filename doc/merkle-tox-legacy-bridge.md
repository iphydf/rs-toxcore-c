# Merkle-Tox Sub-Design: Legacy Bridge

## Overview

The Legacy Bridge enables synchronization of history from standard Tox (legacy)
1:1 and Group chats into the Merkle-Tox DAG. It ensures that users in a
multi-device setup maintain a consistent, persistent history even when
interacting with peers who have not yet upgraded to Merkle-Tox.

## 1. Content Definition

Legacy messages are wrapped in a `MerkleNode` using the `Content::LegacyBridge`
variant (**ID 9**). To maintain **Principle #1 (Deniability)**, these nodes use
a **Symmetric MAC** for authentication, exactly like native content nodes.

*   **Bridging Identity**: The signature of the bridging event belongs to the
    **bridging device** (via its participation in the DARE MAC chain), but is
    cryptographically deniable to third parties.
*   **Privacy**: Although the `source_pk` is stored in the payload, it remains
    **encrypted at rest** and **blinded on the wire** (Principle #2), as it is
    contained within the encrypted `WireNode` payload.

```rust
pub enum Content {
    // ...
    /// ID 9: Bridged from legacy Tox transport.
    LegacyBridge {
        /// The original stable Tox Public Key of the legacy sender.
        source_pk: PublicKey,
        /// The message content (Text).
        text: String,
        /// The legacy message type (0: Normal, 1: Action).
        message_type: u8,
        /// Deterministic ID for cross-device deduplication.
        dedup_id: [u8; 32],
    },
}
```

### 1.1 Context Identification

To ensure all devices agree on which DAG a legacy message belongs to:

*   **1:1 Chats**: The `ConversationId` is derived deterministically from the
    sorted pair of Tox Public Keys using keyed Blake3: `ConversationId =
    blake3::keyed_hash(sort(PkA, PkB), b"MerkleToxLegacy1on1Bridge\0\0\0\0")`.
    *(Note: This differs from native Merkle-Tox 1:1 chats which use a random
    Genesis Hash to support multi-device, but is necessary here to map the
    legacy Tox stable identifiers.)*
*   **Legacy Groups (DHT)**: The `ConversationId` is derived deterministically
    from the stable `ChatId` using keyed Blake3: `ConversationId =
    blake3::keyed_hash(ChatId, b"MerkleToxLegacyGroupBridge\0\0\0\0")`.
*   **Legacy Conferences (Friend-based)**: The `ConversationId` is derived
    deterministically from the stable `ConferenceId` using keyed Blake3:
    `ConversationId = blake3::keyed_hash(ConferenceId,
    b"MerkleToxLegacyConfBridge\0\0\0\0")`.

This ensures all Merkle-Tox-capable devices in a legacy conversation
automatically synchronize their witnessed history into the same DAG.

## 2. Deterministic Deduplication

In a multi-device setup, multiple devices may receive the same legacy message
(specifically in legacy Group Chats/Conferences). To prevent flooding the DAG
with redundant nodes, devices use a deterministic `dedup_id`.

### The Dedup Hash

The `dedup_id` is calculated using the following fields, serialized in their
canonical `ToxProto` binary format in order:

1.  **Conversation ID** (32 bytes).
2.  **Source PK** (32 bytes).
3.  **Text Length** (u32-BE).
4.  **Text** (UTF-8 bytes).
5.  **Message Type** (u8).
6.  **Windowed Network Time** (u64-BE): The current **Merkle-Tox Network Time**
    rounded to a 10-second window.

```rust
// Rounding to 10s buckets accounts for network jitter and minor clock skew.
let window_bucket = network_time_ms / 10_000;
let dedup_id = blake3::hash(conversation_id + source_pk + text + message_type + window_bucket);
```

### 2.1 Bucket Boundary Races

If a message is received by two devices right at the edge of a 10-second bucket
(e.g., Device A at 09:999 and Device B at 10:001), they will generate different
`dedup_id`s.

*   **Safe Failure**: This results in a duplicate message appearing in the UI. A
    10-second window is chosen to balance **Collision Risk** (identical messages
    from the same user) against **Skew Tolerance** (disagreement on the bucket).
*   **Fuzzy UI Matching**: To further mitigate bucket splits, UIs SHOULD perform
    fuzzy deduplication during display. If two `LegacyBridge` nodes from the
    same `source_pk` have identical `text` and their timestamps are within **±12
    seconds**, the UI should treat them as duplicates and only display one.

### 2.2 Content Collisions

If a sender transmits multiple messages with identical content and type within
the same 10-second window, the bridge will treat them as duplicates and only
record the first one.

## 3. The Notary Workflow

The client acts as a "Notary" for legacy events, promoting them from the
ephemeral legacy transport into the persistent Merkle DAG.

1.  **Intercept**: A legacy message is received by the Tox transport layer.
2.  **Calculate**: The client generates the `dedup_id` using the current
    consensus network time.
3.  **Pre-emptive Check**: The client queries the local `NodeStore` for any
    existing `LegacyBridge` node containing this `dedup_id`.
4.  **Author**:
    *   **If Found**: Another of the user's devices (or another group member)
        has already bridged the message. The event is ignored.
    *   **If Not Found**: The client authors a new `MerkleNode` with
        `Content::LegacyBridge`.

## 4. Conflict Resolution (Duplicate Witnesses)

If two devices are partitioned or sync is delayed, they may both author a
`LegacyBridge` node for the same legacy event before seeing each other's work.

*   **DAG Structure**: The DAG will temporarily contain two distinct nodes with
    the same `dedup_id`. This is topologically valid.
*   **UI Projection**: The materialized view (`ChatState`) MUST track processed
    `dedup_id`s for the current session. It displays only the first node
    encountered for a specific `dedup_id` and suppresses subsequent "witnesses."

## 5. Trust & Verification

### Verification

A `LegacyBridge` node is authenticated via MAC by the **bridging device**.

*   **`MerkleNode.author_pk`**: The Logical Identity of the user who bridged the
    message.
*   **`MerkleNode.sender_pk`**: The Physical Device PK of the specific device
    that performed the bridge.

### Trust Model

Members of a conversation trust `LegacyBridge` nodes because the bridging author
is a **verified member** of the Merkle-Tox room.

*   **Collective Witnessing**: In groups, multiple members may bridge the same
    legacy message. This creates a distributed "notary" record. UIs MAY use the
    count of distinct witnesses to indicate the "veracity" of a bridged event.

### UI Representation & Identity

UIs SHOULD distinguish bridged messages from native Merkle-Tox messages:

*   **Badge**: A "Bridged" or "Imported" badge should be shown.
*   **External Identity**: If the `source_pk` is not a verified member of the
    Merkle-Tox DAG, the UI MUST still display the message but mark it as
    "Legacy/External" to distinguish it from cryptographically proven members.
*   **Witness Verification**: Native messages are cryptographically proven by
    the original author. Bridged messages are proven only by the bridging member
    (witness).

## 6. Outgoing Bridging ("Best-Effort" Self-Sync)

To ensure the user's other devices see messages they send via legacy clients:

*   When a client sends a legacy message (Fallback Mode), it SHOULD immediately
    author a `LegacyBridge` node for that outgoing message.
*   **Self-Sync Workflow**:
    1.  The client authors the `LegacyBridge` node and stores it locally with a
        `MessageStatus::Pending` state.
    2.  The node is synced to the user's other devices via Merkle-Tox.
    3.  Once the legacy transport confirms delivery (e.g., via 1:1 receipt), the
        originating device updates the node's status to `Sent`.
*   **Legacy-Only Clients**: If a user sends a message from a legacy client
    (e.g., uTox) to a Merkle-Tox-capable recipient, the recipient's bridge node
    will sync back to the user's other Merkle-Tox devices. This provides a
    "best-effort" history sync even for software that has not been upgraded.

## 7. Advanced Bridging Features

### 7.1 Administrative Promotion

The bridge SHOULD promote legacy administrative events, respecting the
Merkle-Tox permission model:

*   **Admin Promotion**: If the bridging device has `ADMIN` permissions in the
    DAG, it authors a native `ControlAction::SetTitle` or `SetTopic` node.
*   **Informational Promotion**: If the bridging device is NOT an admin, it
    authors an informational Content node using `Content::Other` with **`tag_id:
    0x01`** (`LegacyEventInfo`). The payload contains a MessagePack-encoded
    description of the legacy event (e.g., "Alice changed the title to 'New
    Title'").
*   **Membership Events**: Legacy Join/Leave/Kick events are bridged as
    informational nodes to maintain history context.

### 7.2 File Transfer Promotion

While legacy file transfers are stream-based and incompatible with the CAS swarm
protocol, they can be "upgraded" upon completion:

*   **Promotion**: If a legacy file transfer completes successfully on a
    bridging device, that device SHOULD author a standard `Content::Blob` node
    referencing the file's hash in its local CAS store.
*   **Swarm Availability**: This allows the user's other devices to download the
    file using the native Merkle-Tox CAS protocol, even though it was originally
    received via legacy Tox.

## 8. Limitations & Exclusions

### Limitations

*   **No Retroactive Sync**: Only messages received while at least one
    Merkle-Tox-capable device is online can be bridged. History that exists only
    in a legacy client's local cache cannot be automatically recovered.

### Exclusions (Not Bridged)

To maintain DAG performance and avoid complexity, the following legacy events
are **NOT** bridged into the Merkle DAG:

*   **Typing Indicators**: Ephemeral and high-frequency.
*   **Read Receipts**: Handled natively by Merkle-Tox for native messages.
*   **File Transfers**: Legacy stream-based transfers are incompatible with the
    Merkle-Tox CAS model.
*   **Call Notifications**: Ephemeral signaling.
*   **Status/Name Changes**: These should be handled by the client's local
    contact database, not the message history DAG.
