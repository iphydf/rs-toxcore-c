# Merkle-Tox Sub-Design: Synchronization Protocol

## Overview

The synchronization protocol ensures that two peers eventually hold the same set
of DAG nodes for a conversation.

## 1. Reconciliation Process

Sync is "Heads-based". Instead of pushing every new message, peers reconcile the
differences between their known "tips".

### Prerequisites

Before any synchronization can occur, peers MUST complete the **Capability
Handshake** defined in `merkle-tox-capabilities.md`. This establishes:

1.  Protocol version compatibility.
2.  Mutual support for required baseline features (X3DH, Ratcheting).
3.  Initial Network Time offset (via transport PING/PONG).

### Step 1: Announcement

Upon connection, peers exchange `SYNC_HEADS` packets.

-   Contains the **`ConversationID`** (Genesis Hash) and a list of hashes
    representing the latest nodes they have for the conversation.
-   **Anchor Ad**: Members MUST also include the hash of their **Earliest Known
    Admin Head** (the oldest Snapshot or Rekey node they have verified). This
    acts as an **Explicit Vouch** for the chain of nodes between that anchor and
    the current heads, allowing joiners to bridge gaps larger than 500 hops
    using data from blind relays.
-   **CAS Inventory Flag**: A bitmask or boolean indicating if the peer is
    available to seed blobs for this conversation.

### Step 2: Identification

-   Peer A compares received Heads from Peer B with its local database.
-   If Peer B has a Head unknown to Peer A, Peer A enters "Fetching Mode" for
    that hash.

### Step 3: Batch Fetching

To maximize throughput and avoid round-trip stalls, peers use `FETCH_BATCH_REQ`.

-   **Request**: The **`ConversationID`** and a list of up to $N$ hashes.
-   **Prioritization**: Clients SHOULD prioritize fetching the **Admin Track**
    (nodes with `node_type = Admin`) to establish the current trust hierarchy
    and member list before processing content.
-   **Blob Triggering**: As the client reassembles `MerkleNode`s containing
    `Content::Blob`, it cross-references the `hash` with its `cas_blobs` table.
    If the blob is missing, it triggers the swarm logic defined in
    `merkle-tox-cas.md` to fetch chunks from all peers who signaled inventory.
-   **Response**: A series of `DATA` packets from the `tox-sequenced` layer.
-   **Queueing**: Peer A inspects the `parents` of received nodes and adds
    unknown ones to the next batch request.

### Step 4: Key Establishment (Interactive X3DH)

If, during the synchronization process, a client determines that it does not
possess the conversation key ($K_{conv}$) and there are no valid ephemeral
pre-keys available for the author:

1.  **Pulse**: The client authors a `ControlAction::HandshakePulse` node.
2.  **Await**: The client waits for the author to respond with a fresh
    `ControlAction::Announcement` node containing new ephemeral keys.
3.  **Establish**: The client performs the X3DH exchange as defined in
    `merkle-tox-handshake-x3dh.md` to establish $K_{conv, 0}$.
4.  **Decrypt**: Once the key is established, the client bulk-verifies and
    decrypts all previously synced "Speculative" content nodes.

## 2. Tiered Reconciliation (IBLT)

For large groups, heads-based sync is augmented by IBLT sketches. To prevent
DoS, this is tiered and uses **Adaptive PoW Consensus**:

1.  **Tiny/Small Sketches**: Exchanged automatically for recent history.
2.  **Medium/Large Sketches**: Require a unique **Proof-of-Work (PoW)** solution
    from the requester to prevent CPU exhaustion on the responder.
3.  **Dynamic Scaling**: The difficulty of the PoW scales based on the group's
    collective observation of spam pressure (the weighted median of member
    recommendations). See `merkle-tox-reconcile.md` for the consensus details.
4.  **Poisoning Protection (Blacklisting)**: If a peer provides a poisoned IBLT
    sketch (one that fails decoding or exceeds CPU limits despite a valid PoW),
    the client MUST **Blacklist** that peer for that specific `SyncRange`.
    -   **Escalation**: To deter persistent attackers, the blacklist duration
        MUST increase exponentially with each repeated offense within a 24-hour
        period (e.g., 10 minutes, 1 hour, 24 hours). This prevents state machine
        deadlocks while penalizing repeat offenders.

## 3. Adaptive Genesis PoW

To prevent room-creation spam and history-flood attacks, the **Genesis Node**
and the initial **`SYNC_HEADS`** handshake are protected by a two-stage PoW:

1.  **Stage 1: Baseline Entry (Hardcoded)**:
    -   A new client wishing to join or sync a conversation must solve a fixed,
        baseline PoW (e.g., 12 bits).
    -   This allows the client to receive the `SYNC_HEADS` and the **Current
        Consensus Difficulty** from authorized members.
2.  **Stage 2: Adaptive Top-up (Dynamic)**:
    -   If the room is currently under high spam pressure, the authorized
        members may demand a "Top-up PoW" (the difference between Baseline and
        Consensus) before allowing a full batch fetch or deep reconciliation.
3.  **Byzantine Security**: Since the consensus difficulty is the **median** of
    existing member votes, an attacker cannot lock out new users by jacking the
    difficulty to impossible levels unless they control >50% of the room.

## 4. Shallow Sync & Depth

New members or devices joining a conversation with a long history can perform a
"Shallow Sync" to reach a usable state quickly.

### Depth-Limited Fetching

Clients can request a sync up to a specific **logical depth**:

-   **Immediate**: Fetch nodes within the last $X$ network-time units (e.g.,
    last 24 hours).
-   **Recent**: Fetch the last $N$ messages following the parent chain back from
    the current Heads.
-   **Snapshot-Based**: If a `ControlAction::Snapshot` node is encountered, the
    client can choose to trust the member list and sequence numbers within that
    snapshot as a "checkpoint", stopping the backfill until the user requests
    "More History".

## 5. Speculative Sync & Authorized Vouching

Under the DARE model, a client may receive nodes from a relay peer before it has
established a shared secret with the author or group. To prevent Denial of
Service (DoS) while maintaining metadata privacy, Merkle-Tox uses **Authorized
Vouching**.

### The Vouching Rule

A client will only download or store an encrypted `WireNode` if it is **Vouched
For**:

1.  **Implicit Vouch (Admin)**: All Admin nodes (Control Actions) are sent in
    cleartext and signed. They are vouched for by their valid signature.
    -   **Persistence**: A structural vouch remains valid even if the Admin node
        is later **Redacted**. Redaction only affects display logic, not the
        cryptographic trust path established by the node's signature.
    -   **Quarantine**: A node in the **Quarantine** state (e.g., future-dated)
        **MUST** still provide a structural vouch for its parents. This prevents
        an attacker from "hiding" legitimate history by referencing it from a
        future-dated node.
2.  **Explicit Vouch (Member)**: A `WireNode` hash is vouched for if it is
    advertised in a `SYNC_HEADS` or `SYNC_SKETCH` by a peer who has already been
    authorized via an `AuthorizeDevice` node in the DAG.
    -   **Single-Voucher Optimization**: To minimize memory usage on resource-
        constrained devices, the engine only needs to track the **first**
        authorized peer who vouched for a specific hash. If that peer fails to
        provide the data, the hash is marked as "Orphaned" until another peer
        re-vouches for it. This reduces memory complexity from $O(Nodes \times
        Peers)$ to $O(Nodes)$.
3.  **Structural Vouch (Ancestry Cap)**: If a verified node (Admin OR Content)
    lists a hash as a parent or basis, that hash is automatically vouched for.
    -   **Cap**: This transitive vouching is limited to **500 hops** to prevent
        deep buffer exhaustion while still allowing normal conversation flow.
    -   **Periodic Re-anchoring**: To ensure blind relays can serve long
        histories, Admins MUST author a lightweight `Snapshot` or `Rekey` node
        at least once every 400 messages. This resets the hop counter and
        provides a signed trust anchor for the next segment of history.

### Speculative Quota & Opaque Storage

Vouched-for but undecryptable `WireNodes` are stored in the **Opaque Store**:

-   **Quota**: 100MB per conversation.
-   **Per-Peer Fetch Quota**: To mitigate **Anchor Spoofing**, the sync engine
    limits the number of outstanding Opaque requests per voucher (e.g., max 500
    nodes). A voucher only regains quota as their provided nodes are promoted or
    successfully decrypted.
-   **Vouch Purging**: When a member's device is revoked via a `RevokeDevice`
    node, the system MUST immediately purge all entries from the **Vouch
    Registry** associated with that device identity. This makes the associated
    junk nodes in the Opaque Store eligible for immediate eviction.
-   **Tiered Priority (Hot/Cold Sync)**: To prevent a "Sync Trap" where a stale
    head forces the client to prioritize ancient history over new messages, the
    engine uses a tiered priority system.
    -   **Hot Sync Window**: Defined as all nodes with a rank within **1,000**
        of the highest known verified head.
    -   **Cold Sync Window**: All nodes older than the Hot Sync Window.
    -   **Priority Rule**: The sync engine MUST prioritize fetching and
        retaining nodes in the **Hot Sync Window**. This ensures the user always
        sees the latest conversation state.
    -   **Local Low-Water Mark (LLWM)**: The minimum rank of all current
        verified local heads. The engine attempts to advance this mark by
        backfilling the contiguous history.
-   **Eviction Policy**:
    -   **Cold first**: If the quota is exceeded, nodes in the Cold Sync Window
        are evicted before any node in the Hot Sync Window.
    -   **Furthest first**: Within a window, nodes furthest from the LLWM (or
        too far in the future) are evicted first.
    -   **Promotion Lock**: Any node currently being processed by an active
        **Promotion Flow** MUST be "Locked" and is exempt from eviction until
        the promotion batch is finalized.
-   **Anti-Thrashing**: This prevents an attacker from "trapping" a victim in
    the past by keeping a stale branch alive or flooding the buffer with
    high-rank garbage.

### Promotion Flow

Once a `KeyWrap` or initial $K_{conv}$ is established:

1.  **Anchor Identification**: The client inspects the `anchor_hash` field of
    the `KeyWrap`. If the anchor is not yet verified, the sync engine MUST
    prioritize fetching and verifying that specific **Anchor Snapshot**.
2.  **Promotion Batch**: The client identifies `WireNodes` in the Opaque Store
    whose **parents are already verified** in the main store. These nodes are
    marked as **Locked**.
    -   **Topological Anchor**: A content node MUST NOT be decrypted or promoted
        until its cryptographic ancestry is anchored to a verified Admin node or
        a previously promoted content node.
3.  **Trial Decryption**: The client attempts to decrypt the locked nodes using
    the current and recent conversation keys ($K_{epoch}, K_{epoch-1}$).
    -   **De-duplication**: If a promotion is already in progress for a specific
        branch, incoming redundant `KeyWrap` nodes for that same epoch MUST be
        ignored to prevent a "Promotion Storm" DoS.
4.  **Verification**: The client validates sequence numbers and DAG structure.
5.  **Speculative Promotion (Identity Pending)**: If a `KeyWrap` is
    authenticated (via Pairwise MAC) but the sender's authorization cannot be
    verified yet (due to missing Admin track nodes), the key is used to decrypt
    the Opaque Store tentatively.
    -   Content is moved to the **Verified Store** but marked as **"Identity
        Pending"**.
    -   UI should display these messages with a warning until the Admin Track
        catches up.
6.  **Safety & Recovery**: To prevent data loss during a crash, the Promotion
    Flow **MUST be idempotent**.
    -   A node MUST NOT be unlocked or deleted from the Opaque Store until it
        has been successfully persisted in the main Verified/Speculative Store.
    -   If a client restarts during a promotion, it re-runs the flow for all
        remaining Opaque nodes.
7.  **Final Promotion**: Once the Admin Track is complete, "Identity Pending"
    nodes are fully verified or discarded.

## 6. Security & Privacy

### Peer-Level Metadata Privacy

While the Tox transport layer hides traffic from network observers, Merkle-Tox
implements additional protections against inquisitive peers (SyncBots):

-   **Opaque Identifiers**: The `ConversationID` is a hash of the Genesis node.
    It does not leak the room name or membership to a peer who does not already
    possess the Genesis node.
-   **Sequence/Identity Obfuscation**: The `sender_pk` and `sequence_number` are
    encrypted, preventing a relay from mapping the room's social graph.
-   **Temporal Privacy**: The `network_timestamp` is encrypted, preventing a
    relay from performing activity-pattern analysis on authors.

### Authentication Verification

-   A node is only added to the local DAG if its `authentication` (MAC or
    Signature) is valid for the `sender_pk`.
-   If a node's parents are invalid, the node itself is rejected.

### High-Priority Admin Gossip

To minimize the "Window of Harassment" and ensure rapid propagation of
membership changes (Revocations, Leaves, Invites):

-   **Priority**: Admin nodes MUST be treated as **High Priority Data** by the
    sync engine and the transport layer.
-   **Gossip**: Upon receiving or authoring a new verified Admin node, a client
    SHOULD immediately **multicast** the node hash to all connected peers in the
    conversation, bypassing the normal tiered reconciliation queue.
-   **Fetch**: Peers receiving a high-priority advertisement SHOULD prioritize
    fetching the associated Admin node before continuing with content
    synchronization.

## 7. Conflict Resolution (Branching)

Because the history is a DAG, concurrent messages do not "conflict" in the
traditional sense; they create multiple Heads.

-   When a user writes a new message, their client must include **all current
    local Heads** as parents.
-   This "Merges" the branches back into a single tip.
