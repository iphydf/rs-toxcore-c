# Merkle-Tox Sub-Design: Deniable Authentication (DARE)

## Overview

Merkle-Tox prioritizes **Plausible Deniability**, a tenet of the Tox ecosystem.
While traditional Merkle-DAGs use digital signatures (providing
non-repudiation), Merkle-Tox employs **Deniable Authenticated Range/Exchange
(DARE)** logic using Message Authentication Codes (MACs) and shared secrets.

This ensures that while participants *inside* a conversation can verify the
authenticity and integrity of messages, a third party *outside* the conversation
cannot cryptographically prove who authored a specific node.

## 1. DARE Authentication Model

### Shared Conversation Key ($K_{conv}$)

Every conversation (1:1 or Group) establishes a symmetric **Shared Conversation
Key**.

-   In **1:1 chats**, this is derived from the Tox `crypto_box` shared secret.
-   In **Group chats**, this is a rotating symmetric key shared among all
    authorized devices of all participants.

### From Signatures to MACs

Instead of an asymmetric signature, each `MerkleNode` contains an
**Authenticator**:

-   `Authenticator = Blake3_MAC(K_mac, Node_Contents)`
-   `Header_Encryption = ChaCha20(K_header, Routing_Info)`
-   `Payload_Encryption = ChaCha20(K_msg_i, Content)`

Where `K_mac` and `K_header` are derived from $K_{conv}$ using **Blake3-KDF**,
ensuring global deniability and preventing metadata leakage to relays. `K_msg_i`
is derived from the sender's current **Ratchet Chain Key**, ensuring Forward
Secrecy. See **`merkle-tox.md`** for the full cryptographic suite.

### Plausible Deniability

Because every participant in the conversation possesses $K_{conv}$, any of them
could have theoretically authored any node in the DAG.

-   **Internal Trust**: When Peer A receives a node from Peer B, they know it's
    authentic because it's valid under $K_{conv}$ and follows Peer B's
    `sequence_number` chain.
-   **External Repudiation**: If the DAG is leaked, Peer B can plausibly claim
    that Peer A (or any other participant) forged the node to frame them.

> **Note on KCI**: This design explicitly accepts **Key Compromise Impersonation
> (KCI)** for content nodes as a trade-off for deniability. If a user's key is
> compromised, the attacker can impersonate others *to that user*. For a full
> analysis, see **`merkle-tox-threat-model.md`**.

## 2. Key Agreement & Rotation

### Initial Handshake: X3DH

Merkle-Tox uses a decentralized **Extended Triple Diffie-Hellman (X3DH)**
handshake to establish the initial conversation key ($K_{conv, 0}$).

1.  **Announcement Nodes**: Users publish signed ephemeral "Pre-keys" to the
    DAG.
2.  **Exchange**: To start a chat or join a group, a user fetches the
    recipient's latest pre-key and performs a 4-part DH exchange.
3.  **Result**: This establishes a shared secret with **Forward Secrecy** from
    the first message.

See **`merkle-tox-handshake-x3dh.md`** for the full handshake protocol.

### Per-Message Forward Secrecy: Symmetric Ratchet

Once $K_{conv, 0}$ is established, it seeds a **Symmetric Key Ratchet** (Hash
Chain).

-   Every message is encrypted with a unique, one-way derived key.
-   Keys are deleted immediately after use, ensuring that compromising the
    current state does not expose past messages.
-   The ratchet handles the non-linear nature of the DAG by merging parent chain
    keys during branch joins.

See **`merkle-tox-ratchet.md`** for the ratchet implementation details.

### Post-Compromise Security (PCS)

To "heal" a conversation after a device has been compromised, Merkle-Tox
performs periodic **Epoch Rotations**.

1.  **Triggers**: Rotation occurs every **5,000 messages** or **7 days**.
2.  **Mechanism**: A new root $K_{epoch}$ is generated and distributed via
    ephemeral-static DH (KeyWrap) to all authorized members.
3.  **Result**: This provides **Post-Compromise Security**, ensuring that an
    attacker who has stolen a previous key is eventually rotated out of the
    conversation.

## 3. "Lazy Consensus" Fallback

In scenarios where $K_{conv}$ is not yet known (e.g., syncing history from a
third-party relay before meeting the author):

1.  **Speculative Sync**: The client downloads nodes and validates their `hash`
    (integrity) but marks them as `Unverified`.
2.  **Attestation (Vouching)**: If Peer C (whom you trust) has included a node
    from Peer B as a parent in their own authenticated nodes, your confidence in
    that node increases.
3.  **Finalization**: Once you perform a DARE handshake with Peer B (or any
    participant who has the key), the historical DAG is validated.

## 4. Identity vs. Content (Two-Stage Onboarding)

To maintain the security of the **Identity Model** (`merkle-tox-identity.md`)
while keeping messages deniable, Merkle-Tox uses a **Two-Stage Onboarding**
process.

### Stage 1: Non-Repudiable Authorization (Hard Identity)

Nodes that manage the membership and capabilities of the room are **signed** and
transparent.

-   **Admin/Control Nodes**: Authorize/revoke devices, change room title, or
    invite members.
-   **Security**: These nodes use **Ed25519 signatures**. This provides
    non-repudiable proof that an Admin performed a specific management action.
-   **Privacy**: These nodes do **not** contain private user content. They only
    establish *who* is allowed to participate.

### Stage 2: Deniable Communication (DARE)

Once authorized, all actual conversation content is protected by the symmetric
DARE model.

-   **Content Nodes**: All messages, files, and reactions **MUST** use the DARE
    MAC approach.
-   **Deniability**: Because the content uses symmetric MACs derived from the
    $K_{conv}$, any authorized member could have forged a message. An outsider
    cannot prove who authored a specific `Content::Text` node.
-   **Strict Encryption**: Clients MUST use "Encrypt-then-MAC" for the `content`
    and `metadata` fields. In Content nodes, the `sender_pk` and
    `sequence_number` MUST be encrypted into an `encrypted_routing` header using
    $K_{header}$ (derived from $K_{conv}$) to prevent metadata leakage to blind
    relays.
    -   **EXCEPTION (KeyWrap)**: `KeyWrap` nodes (Content ID 7) are sent in
        **cleartext** (and signed with an Ed25519 Signature) to allow new
        members to receive the conversation keys. For these nodes, the
        `sender_pk` MUST NOT be encrypted, enabling joiners to verify the "Chain
        of Custody" back to a verified Admin. The internal `WrappedKey` payloads
        use pairwise authenticated encryption.

### Transitive Rationale

By separating the **Authority to Speak** (Signed) from the **Act of Speaking**
(MAC'd), we ensure that a user's digital signature on a room-management task
never "anchors" the hash of a private message into a non-repudiable record. Even
if your presence in a room is proven, your specific messages remain plausibly
deniable.

## 5. Control Chain Isolation

To prevent "Transitive Non-Repudiation," Merkle-Tox enforces a strict separation
between Admin and Content nodes:

-   **Admin nodes** (which are signed) can only reference other Admin nodes as
    parents.
-   **Content nodes** (which are MAC'd) can reference both Admin and Content
    nodes.

This ensures that a user's digital signature on a room-management task (like
changing a topic) never "anchors" the hash of a private message into a
non-repudiable record. Even if a user's signed presence in a room is proven,
their specific messages remain plausibly deniable.

## 6. Summary of Security Properties

-   **Integrity**: Guaranteed by the Merkle-DAG (Blake3 hashes).
-   **Authenticity**: Guaranteed to participants who hold the shared key.
-   **Deniability**: Provided by the symmetric nature of the MAC (DARE).
-   **Forward Secrecy**: Provided by the symmetric ratchet (per-message) and
    X3DH (per-handshake).
-   **Post-Compromise Security**: Provided by periodic epoch rotations and
    re-keying.
