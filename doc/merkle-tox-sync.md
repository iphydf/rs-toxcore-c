# Merkle-Tox Sub-Design: Synchronization Protocol

## Overview

The synchronization protocol ensures peers eventually hold the same set of DAG
nodes for a conversation.

## 1. Reconciliation Process

Peers reconcile differences between their known "tips" (Heads).

### Prerequisites

Peers MUST complete the **Capability Handshake** (`merkle-tox-capabilities.md`),
establishing:

1.  Protocol version compatibility.
2.  Mutual support for required baseline features (Signed ECIES, Ratcheting).
3.  Initial Network Time offset (via transport PING/PONG).

### Step 1: Announcement

Upon connection, peers exchange `SYNC_HEADS` packets.

-   Contains the **`ConversationID`** (Genesis Hash) and a list of hashes
    representing the latest nodes.
-   **Anchor Ad**: Members MUST also include the hash of their **Earliest Known
    Admin Head** (the oldest Snapshot or KeyWrap node they have verified),
    acting as an **Explicit Vouch** for the chain of nodes between that anchor
    and the current heads, bridging gaps >500 hops via blind relays.
-   **CAS Inventory Flag**: A bitmask or boolean indicating if the peer is
    available to seed blobs for this conversation.

### Step 2: Identification

-   Peer A compares received Heads from Peer B with its local database.
-   If Peer B has an unknown Head, Peer A enters "Fetching Mode" for that hash.

### Step 3: Batch Fetching

Peers request nodes using `FETCH_BATCH_REQ`.

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

### Step 4: Key Establishment (Interactive ECIES)

If a client determines it lacks the conversation key ($K_{conv}$) and there are
no valid ephemeral pre-keys available for the author:

1.  **Pulse**: The client authors a `ControlAction::HandshakePulse` node.
2.  **Await**: The client waits for the author to respond with a fresh
    `ControlAction::Announcement` node containing new ephemeral keys.
3.  **Establish**: The client performs the ECIES exchange as defined in
    `merkle-tox-handshake-ecies.md` to establish $K_{conv, 0}$.
4.  **Decrypt**: Once the key is established, the client bulk-verifies and
    decrypts all previously synced "Speculative" content nodes.

## 2. Tiered Reconciliation (IBLT)

For large groups, heads-based sync is augmented by IBLT sketches. To prevent
DoS, this is tiered and uses **Per-Peer CPU Budgets**:

1.  **Tiny/Small Sketches**: Exchanged automatically for recent history.
    Negligible decoding cost; effectively free under the budget.
2.  **Medium/Large Sketches**: Non-trivial decoding cost. Each authorized peer
    is assigned a strict token bucket of `SKETCH_CPU_BUDGET_MS` (500ms) of
    decoding time per minute. If the budget is exhausted, the responder replies
    with `SYNC_RATE_LIMITED` and discards the sketch. See
    `merkle-tox-reconcile.md` §3.C for the budget rules.
3.  **Poisoning Protection (Blacklisting)**: If a peer provides a poisoned IBLT
    sketch (one that fails decoding or exceeds the capacity cap), the client
    MUST **Blacklist** that peer for that specific `SyncRange`.
    -   **Escalation**: To deter persistent attackers, the blacklist duration
        MUST increase exponentially with each repeated offense within a 24-hour
        period (`BLACKLIST_TIER_1_MS = 600000`, `BLACKLIST_TIER_2_MS = 3600000`,
        `BLACKLIST_TIER_3_MS = 86400000`), preventing state machine deadlocks
        while penalizing repeat offenders.

## 3. Genesis PoW

The **Genesis Node** requires a one-time Proof-of-Work to deter room-creation
spam:

-   A new client creating a conversation must solve a fixed PoW
    (`BASELINE_POW_DIFFICULTY = 20`).
-   The PoW uses **Contextual Hashcash**. The `pow_nonce` is an explicit field
    in the `ControlAction::Genesis` payload. The creator grinds the `pow_nonce`
    such that `Blake3(creator_pk || ToxProto::serialize(genesis_action))` has 20
    leading zeros.
-   Because the grinding occurs *before* the node is serialized and signed, it
    requires pure Blake3 hashing. At ~1M Blake3 hashes/sec on a smartphone, 20
    bits (~1M attempts) costs **~1 second**, keeping room creation fast while
    maintaining security against relay tampering (the nonce is covered by the
    creator's signature).
-   **Note**: Once a peer is authorized and syncing, sketch DoS is handled by
    the per-peer CPU budget (§2), not by PoW. PoW is only for the
    unauthenticated Genesis creation step where there is no identity to
    rate-limit against.

## 4. Shallow Sync & Depth

New members or devices perform a "Shallow Sync" to reach a usable state quickly
without full history.

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

Under the DARE model, a client may receive nodes before establishing a shared
secret. To prevent DoS while maintaining metadata privacy, Merkle-Tox uses
**Authorized Vouching**.

### The Vouching Rule

A client will only download or store an encrypted `WireNode` if it is **Vouched
For**:

1.  **Implicit Vouch (Admin)**: All Admin nodes (Control Actions) are sent in
    cleartext and signed. They are vouched for by their valid signature.
    -   **Persistence**: A structural vouch remains valid even if the Admin node
        is later **Redacted**. Redaction only affects display logic, not the
        cryptographic trust path established by the node's signature.
    -   **Quarantine**: A node in the **Quarantine** state (e.g., future-dated)
        **MUST** still provide a structural vouch for its parents, preventing an
        attacker from "hiding" legitimate history by referencing it from a
        future-dated node.
2.  **Explicit Vouch (Member)**: A `WireNode` hash is vouched for if it is
    advertised in a `SYNC_HEADS` or `SYNC_SKETCH` by a peer who has already been
    authorized via an `AuthorizeDevice` node in the DAG.
    -   **Bounded Voucher Set**: To prevent a malicious peer from advertising
        hashes and refusing to serve the data (Data Withholding), the engine
        tracks a bounded set of authorized peers (`MAX_VOUCHERS_PER_HASH = 3`)
        who vouched for a specific hash.
        -   **Rotation**: If the primary peer fails to provide the requested
            node within the timeout (`VOUCHER_TIMEOUT_MS = 10000`) or
            disconnects, the engine penalizes that peer and immediately requests
            the node from the next peer in the voucher set.
        -   This ensures continuous synchronization while keeping memory
            complexity bounded at $O(Nodes)$ rather than $O(Nodes \times
            Peers)$.
3.  **Structural Vouch (Ancestry Cap)**: If a verified node (Admin OR Content)
    lists a hash as a parent or basis, that hash is automatically vouched for.
    -   **Cap**: This transitive vouching is limited to **500 hops** to prevent
        deep buffer exhaustion while still allowing normal conversation flow.
    -   **Periodic Re-anchoring (Admins)**: Admins MUST author a `Snapshot` or
        `KeyWrap` node at least once every 400 messages to reset the hop
        counter.
    -   **Soft Anchoring (Level 2 Fallback)**: If a conversation reaches 400
        hops without an Admin node, any authorized Level 2 Participant SHOULD
        author a `ControlAction::SoftAnchor` node. To prevent a thundering herd
        where all online members simultaneously author anchors, clients SHOULD
        trigger the SoftAnchor creation at a uniformly randomized interval
        between 400 and 450 hops.
        -   **Chaining Cap (Max 3)**: Blind relays MUST accept `SoftAnchor`
            nodes to reset the 500-hop counter, but MUST reject more than 3
            consecutive `SoftAnchor` nodes in a single ancestry chain. This caps
            maximum offline depth at 2,000 hops before an Admin node is
            required.
        -   **Anti-Branching**: Relays MUST accept only one `SoftAnchor` per
            `device_pk` per `basis_hash`. Duplicates are dropped. Even if a
            relay is unaware of a recent revocation, the Anti-Branching rule
            bounds a revoked attacker to injecting one invalid SoftAnchor per
            basis_hash, preventing buffer exhaustion.
        -   **Self-Proving Validation**: Blind relays MUST verify the
            `SoftAnchor` signature against the attached
            `DelegationCertificate`'s public key, and verify the certificate is
            validly signed by an Admin key present in the relay's cached Admin
            Track. Upon validating a SoftAnchor, the blind relay MUST reset its
            vouching counter and accept up to 500 hops of history descending
            from the `SoftAnchor` itself. The `basis_hash` is used for
            Anti-Branching deduplication.
        -   **Strict Chain Isolation**: To prevent Transitive Non-Repudiation, a
            `SoftAnchor` MUST ONLY reference the `basis_hash` (the previous
            Admin node) in its `parents` array. It MUST NOT reference Content
            nodes.
        -   **Hop Reset Topology**: The subsequent `Content` node authored in
            the conversation will include both the previous Content heads and
            the new `SoftAnchor` in its `parents`. Because blind relays
            calculate the 500-hop limit using the shortest path to any valid
            anchor, this new Content node evaluates as 1 hop away from the
            `SoftAnchor`, successfully resetting the relay's buffer limit while
            preserving the plausible deniability of the Content chain.
        -   **Surgical Pruning**: Admins MAY prune spam originating from a
            `SoftAnchor` in $O(1)$ by revoking the device and dropping the
            descending branch.

### Speculative Quota & Opaque Storage

Vouched-for but undecryptable `WireNodes` are stored in the **Opaque Store**:

-   **Quota**: 100MB per conversation.
-   **Per-Peer Fetch Quota**: To mitigate **Anchor Spoofing**, the sync engine
    limits the number of outstanding Opaque requests per voucher
    (`MAX_OPAQUE_REQUESTS_PER_VOUCHER = 500`). A voucher regains quota when
    their provided nodes are removed from the Opaque Store (whether by
    promotion, decryption, or **eviction**).
-   **Vouch Purging**: When a member's device is revoked via a `RevokeDevice`
    node, the system MUST immediately purge all entries from the **in-memory
    voucher set** associated with that device identity and deprioritize any
    opaque nodes whose persisted `voucher_pk` matches the revoked device for
    eviction.
-   **Tiered Priority (Hot/Cold Sync)**: To prevent a "Sync Trap" where a stale
    head forces the client to prioritize ancient history over new messages, the
    engine uses a tiered priority system.
    -   **Hot Sync Window**: Defined as all nodes with a rank within **1,000**
        of the highest known verified head.
    -   **Cold Sync Window**: All nodes older than the Hot Sync Window.
    -   **Priority Rule**: The sync engine MUST prioritize fetching and
        retaining nodes in the **Hot Sync Window**, ensuring the user always
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
3.  **Trial Decryption**: The client attempts to decrypt the locked nodes. It
    first uses $K_{header}$ to decrypt the routing info, identifying the sender.
    It then uses that sender's current `SenderKey` (or a recent historical step)
    to decrypt the payload.
    -   **De-duplication**: If a promotion is already in progress for a specific
        branch, incoming redundant `SenderKeyDistribution` nodes for that same
        generation MUST be ignored to prevent a "Promotion Storm" DoS.
4.  **Verification**: The client validates sequence numbers and DAG structure.
5.  **Speculative Promotion (Identity Pending)**: If a `KeyWrap` is
    authenticated via Signature but the sender's authorization cannot be
    verified yet (missing Admin track nodes), the key tentatively decrypts the
    Opaque Store.
    -   Content is moved to the **Verified Store** but marked **"Identity
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
    nodes are verified or discarded.

## 6. Security & Privacy

### Peer-Level Metadata Privacy

Merkle-Tox implements additional protections against inquisitive peers
(SyncBots):

-   **Opaque Identifiers**: The `ConversationID` is a hash of the Genesis node.
    It does not leak the room name or membership to a peer who does not already
    possess the Genesis node.
-   **Sequence/Identity Obfuscation**: The `sender_pk` and `sequence_number` are
    encrypted, preventing a relay from mapping the room's social graph.
-   **Temporal Privacy**: The `network_timestamp` is encrypted, preventing a
    relay from performing activity-pattern analysis on authors.

### Authentication Verification

-   A node is only added to the local DAG if its `authentication`
    (EphemeralSignature or Signature) is valid for the `sender_pk`.
-   If a node's parents are invalid, the node itself is rejected.

### High-Priority Admin Gossip

To ensure rapid propagation of membership changes (Revocations, Leaves,
Invites):

-   **Priority**: Admin nodes MUST be treated as **High Priority Data** by the
    sync engine and the transport layer.
-   **Gossip**: Upon receiving or authoring a new verified Admin node, a client
    SHOULD immediately **multicast** the node hash to all connected peers in the
    conversation, bypassing the normal tiered reconciliation queue.
-   **Fetch**: Peers receiving a high-priority advertisement SHOULD prioritize
    fetching the associated Admin node before continuing with content
    synchronization.

## 7. Conflict Resolution (Branching)

Because history is a DAG, concurrent messages do not conflict; they create
multiple Heads.

-   When a user writes a new message, their client must include **all current
    local Heads** as parents.
-   This "Merges" the branches back into a single tip.
