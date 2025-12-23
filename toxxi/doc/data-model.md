# Toxxi Data Model Specification

## 1. Overview
Toxxi uses an **Event-Sourced** data architecture. The single source of truth is an append-only **Event Log** stored in an encrypted SQLite database. All other tables (Contacts, Conversations, Message History) are **Projections** derived from this log.

For details on the underlying protocol primitives (e.g., `ConversationId`, `NodeHash`, `KConv`), see the [Merkle-Tox Design Documents](../../doc/merkle-tox.md).

### 1.1 Core Principles
*   **Immutability:** The Event Log is append-only. Past events are never modified.
*   **Derivability:** All UI-facing tables can be reconstructed by replaying the Event Log.
*   **Encrypted at Rest:** The database uses `SQLCipher` for full-disk encryption, matching Tox's security expectations.
*   **Stable Identifiers:** Events use Public Keys or 32-byte UIDs, never transient database IDs.

---

## 2. The Source of Truth: `event_log`
Every interaction, network event, or user action is serialized into the `event_log` table.

### 2.1 Database Schema (SQL)
```sql
CREATE TABLE event_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    profile_id BLOB,         -- The Public Key of the local profile
    timestamp INTEGER,       -- Unix timestamp (milliseconds)
    event_type TEXT,         -- Enum discriminator (e.g., "MessageReceived")
    data BLOB                -- Msgpack serialized event payload
);
```

### 2.2 Event Schema (Msgpack / Rust Enum)
Using `tox-proto` for efficient binary serialization.

```rust
pub enum ToxEvent {
    // Profile Management
    ProfileCreated { name: String, tox_data: Vec<u8> },
    ProfileStatusChanged { status: UserStatus, message: String },
    
    // Contact Management
    FriendRequestReceived { pk: PublicKey, message: String },
    FriendAdded { pk: PublicKey, alias: Option<String> },
    FriendRemoved { pk: PublicKey },
    
    // Communication (Legacy & Merkle)
    MessageReceived { 
        target: TargetId, 
        sender: PublicKey, 
        content: MessageContent,
        protocol: ProtocolType,
        merkle_hash: Option<Hash> // Only for Merkle-Tox groups
    },
    MessageSent { 
        target: TargetId, 
        content: MessageContent,
        protocol: ProtocolType
    },
    
    // Merkle-Tox Specific Events
    MerkleNodeVerified { hash: NodeHash, node_type: NodeType },
    MerkleSyncCompleted { target: TargetId, head_hash: NodeHash },

    // File Transfers (Native & CAS Swarm)
    FileOffer { 
        target: TargetId, 
        file_id: u32, // Native ID or index
        name: String, 
        size: u64,
        protocol: ProtocolType,
        blob_hash: Option<NodeHash> 
    },
    FileProgress { file_id: u32, bytes_received: u64 },
    
    // Games
    GameStarted { target: TargetId, game_type: String, session_id: Uuid },
    GameMove { session_id: Uuid, move_data: Vec<u8> }, // msgpack within msgpack
    GameEnded { session_id: Uuid, result: String },
}

pub enum ProtocolType {
    Native,    // Standard Tox 1:1 / Conference
    MerkleTox, // DHT-based Merkle Groups (see [doc/merkle-tox.md](../../doc/merkle-tox.md))
}

pub enum TargetId {
    Friend(PhysicalDevicePk),   // See [doc/merkle-tox-identity.md](../../doc/merkle-tox-identity.md)
    Group(ConversationId),      // See [doc/merkle-tox-dag.md](../../doc/merkle-tox-dag.md)
    Conference(ConversationId), // Legacy mapping
}

pub enum MessageContent {
    Text(String),
    Action(String),      // /me style
    Custom(Vec<u8>),     // For extensible plugins
}
```

---

## 3. The Projections (Derived Tables)
These tables are optimized for UI performance (searching, sorting, and lazy loading).

### 3.1 `conversations`
Used to populate the Sidebar and Quick Switcher.
*   `id`: Primary Key.
*   `profile_id`: Local owner.
*   `target_id`: Remote PK or Group UID.
*   `target_type`: (1:1, Group, Conference).
*   `protocol_type`: (Native, MerkleTox).
*   `last_message_at`: For sorting by recent activity.
*   `unread_count`: (Calculated on the fly or cached).

### 3.2 `messages`
The flat list of messages for the chat view.
*   `id`: Primary Key.
*   `conversation_id`: Foreign key to `conversations`.
*   `sender_pk`: Who sent it.
*   `timestamp`: When it arrived.
*   `content_type`: Discriminator.
*   `text_content`: Plain string (if applicable) for fast display.
*   `metadata`: Msgpack blob for non-text details (invites, file info).

### 3.3 `fts_messages` (FTS5)
A virtual table for full-text search.
*   `rowid`: Matches `messages.id`.
*   `body`: The text content of the message.
*   `profile_id`: To allow for profile-specific or global filtering.

---

## 4. Blob Storage
To keep the database performant, large data is offloaded to the filesystem following the Content-Addressable Storage (CAS) model (see [doc/merkle-tox-cas.md](../../doc/merkle-tox-cas.md)).

*   **Location:** `<app_data>/blobs/<profile_hash>/<year>/<month>/`
*   **Security:** These files should be encrypted or at least restricted by FS permissions.
*   **Usage:**
    *   Completed file transfers.
    *   Incoming/Outgoing images.
    *   Large game assets or state snapshots.

---

## 5. Concurrency & Data Flow
Toxxi uses a multi-actor model to handle data safely.

### 5.1 The Database Actor (The Projectionist)
The Database Actor is the sole owner of the SQLite connection.
1.  **Receive Event:** Receives `ToxEvent` from a Tox Actor.
2.  **Log:** Appends the event to `event_log`.
3.  **Project:** Updates derived tables (`messages`, `conversations`) in the same transaction.
4.  **Notify:** Broadcasts a `DataChanged(ConversationId)` signal to the UI Actor.

### 5.2 The UI Actor (The Reader)
The UI Actor reads from the derived tables.
*   **Lazy Loading:** Queries `messages` with `LIMIT` and `OFFSET` based on the scroll position.
*   **Fuzzy Search:** Queries `fts_messages` when the user opens the Quick Switcher or uses `/search`.

---

## 6. Migration and Schema Evolution
Since the `event_log` is the source of truth:
*   **Minor Changes:** Standard `ALTER TABLE` on derived tables.
*   **Major Changes:** If the derived schema changes significantly, Toxxi can:
    1.  Delete the derived tables.
    2.  Re-play the `event_log` from the beginning.
    3.  Repopulate the tables with the new schema.
*   **Version Check:** A `user_version` pragma in SQLite tracks the current projection version.

---

## 7. Performance Optimizations
*   **Batch Writing:** Events are collected for up to 100ms or 50 events before being committed to the database to reduce IOPS.
*   **Indexing:** `conversations` is indexed by `last_message_at`. `messages` is indexed by `(conversation_id, timestamp)`.
*   **Zstd Compression:** The `data` blob in `event_log` or `metadata` in `messages` can be transparently compressed with `zstd` if they exceed a certain size (e.g., 1KB).

---

## 8. Summary Table: Data Lifecycle

| Data Type | Source | Persistence | Source of Truth |
|-----------|--------|-------------|-----------------|
| Text Message | Network | `messages` table | `event_log` |
| Friend Status | Network | Memory Only | N/A |
| Game Move | Network | `event_log` | `event_log` |
| File Chunk | Network | `blobs/` | `event_log` (metadata) |
| Profile Info | Disk (Save) | `event_log` | `event_log` |

(End of Document)
