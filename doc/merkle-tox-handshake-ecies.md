# Merkle-Tox Sub-Design: Signed ECIES Handshake & Announcement Nodes

## Overview

Merkle-Tox implements a decentralized **Signed ECIES (Ephemeral-Static
Diffie-Hellman)** handshake for **Forward Secrecy**.

The DAG publishes and distributes ephemeral keys, replacing centralized "Pre-key
Servers".

## 1. Announcement Nodes

Every user MUST author a new **Announcement Node** in the DAG at a defined
interval (`ANNOUNCEMENT_ROTATION_INTERVAL = 30 days` or
`ANNOUNCEMENT_MAX_HANDSHAKES = 100`).

### A. Structure

```rust
struct Announcement {
    /// The user's Identity Public Key (Ed25519).
    pub identity_pk: [u8; 32],

    /// A signed "Pre-key bundle" containing multiple ephemeral keys.
    pub pre_keys: Vec<SignedPreKey>,

    /// A single "Last Resort" pre-key that is never rotated (for long-term offline use).
    pub last_resort_key: SignedPreKey,
}

struct SignedPreKey {
    /// The ephemeral X25519 Public Key.
    pub public_key: [u8; 32],
    /// The Ed25519 Signature by the identity_pk.
    pub signature: [u8; 64],
    /// Expiration timestamp (Network Time).
    pub expires_at: i64,
}
```

## 2. The ECIES Exchange

The ECIES exchange establishes the initial conversation key ($K_{conv, 0}$). The
strictness of the handshake depends on the conversation type.

### A. 1-on-1 Conversations (Opportunistic)

1-on-1 chats prioritize availability over strict synchronous keying.

1.  **Fetch**: User A fetches User B's latest `Announcement` node.
2.  **Select**:
    -   If valid `pre_keys` exist, User A uses one and performs the ECIES
        exchange.
    -   If the initiator uses the `last_resort_key` **OR** performs an SPK-only
        handshake (where no One-Time Pre-Key was available or consumed), they
        **MAY** proceed but **MUST** attach a `HandshakePulse` to their first
        message.
3.  **Delivery Confirmation (OPK Use Only)**: If the initiator used a One-Time
    Pre-Key (OPK), they enter a **KeyWrap Pending** state and MUST NOT author
    content nodes for this conversation until a `KEYWRAP_ACK` is received from
    the recipient (see §5, Losing Entry Handling). Messages composed during this
    window are buffered locally.
    -   **Timeout**: If no `KEYWRAP_ACK` arrives within `KEYWRAP_ACK_TIMEOUT_MS`
        (30,000 = 30 seconds), the initiator SHOULD retry with a different OPK
        (or SPK-only) and reset the timer.
    -   **Offline Recipient (No OPK)**: If the initiator used the
        `last_resort_key` or SPK-only (no OPK consumed), there is no risk of OPK
        collision. The initiator DOES NOT wait for a `KEYWRAP_ACK` and MAY
        immediately author and broadcast content nodes.
4.  **Forward Secrecy**: The `last_resort_key` provides limited forward secrecy.
    The `HandshakePulse` forces User B, upon reconnecting, to execute a
    `KeyWrap` rotation using fresh ephemeral keys, establishing a new $K_{conv}$
    and compelling `SenderKey` rotations, restoring full Forward Secrecy and
    Post-Compromise Security.
5.  **Debounce (KeyWrap Storm Prevention)**: To prevent a "KeyWrap Storm" if
    User B comes online after receiving multiple offline messages containing a
    `HandshakePulse`, a node **MUST** ignore a `HandshakePulse` if it has
    already authored a `KeyWrap` rotation within `HANDSHAKE_PULSE_DEBOUNCE_MS`
    (300,000 = 5 minutes), or if it has already responded to a topologically
    newer or concurrent pulse from the same peer in the current sync batch.

### B. Group Conversations (Strict)

Groups prioritize security and Post-Compromise Security (PCS).

1.  **Onboarding**: New members fetch the Group Genesis and the current Admin
    track.
2.  **Strict Keying**: Content nodes (messages) are ignored and stored only in
    the **Opaque Store** until a `KeyWrap` is received from an authorized Admin.
3.  **Key Delivery**: Admins MUST use valid, unexpired ephemeral keys to wrap
    $K_{conv}$ for new members.
4.  **SenderKey Delivery**: Receiving $K_{conv}$ alone is insufficient. Each
    existing member's client MUST author a supplementary `SenderKeyDistribution`
    using **Just-In-Time (JIT) Piggybacking** right before they author their
    next message (see `merkle-tox-ratchet.md` §1.B).
5.  **No Last Resort Keys (with Revocation Exception)**: Admins SHOULD NOT
    author a `KeyWrap` for a user if that user only has a `last_resort_key`
    published. Using a Last Resort Key for group onboarding compromises the
    forward secrecy of the entire group's $K_{conv}$ and `SenderKey`s if that
    long-term key were ever forensically recovered.
    -   *Operational Resolution (Invites)*: If an Admin wishes to invite an
        offline user who lacks fresh keys, the Admin's client SHOULD send an
        off-DAG 1-on-1 `HandshakePulse` to wake the user up. The Admin client
        automatically buffers the group invite and authors the `KeyWrap` only
        after the user comes online and publishes fresh ephemeral keys.
    -   *Mandatory Key Rotations (Revocation Exception)*: If the `KeyWrap` is
        being authored to rotate keys following a `RevokeDevice` event, the
        Admin **MUST** proceed with the rotation immediately, even if some
        remaining valid members only have a `last_resort_key`. The immediate
        security threat of a compromised device remaining in the room outweighs
        the theoretical risk of a long-term key compromise.

### C. The DH Exchange (Logic)

Once a fresh `Announcement` is available:

-   User A generates a **single** one-time ephemeral X25519 key pair ($E_a,
    e_a$) for the entire `KeyWrap` or `SenderKeyDistribution` node. $E_a$ is
    stored once in the node header (see `merkle-tox-dag.md`
    `KeyWrap.ephemeral_pk`), not repeated per entry.
-   For each recipient device's `WrappedKey` entry, User A computes:
    -   $shared_{spk} = \text{ECDH}(e_a, SPK_b)$
    -   $shared_{opk} = \text{ECDH}(e_a, OPK_b)$ (if OPK consumed)
    -   Each entry derives a unique encryption key because each device has a
        unique $SPK_b$ (and unique $OPK_b$ when consumed). Forward secrecy
        derives from deleting $e_a$ after computing all entries.
-   **Authentication**: Mutual authentication is provided by Ed25519 signatures
    (the `KeyWrap` is signed by the Admin; the recipient's SPK is signed by
    their identity key), not by identity-key DH operations.
*   **Wrap & Send**: User A generates a random $K_{conv, 0}$ and authors a
    `KeyWrap` node. The node's `ephemeral_pk` field contains $E_a$; each
    `WrappedKey` entry derives its encryption key from $DH(e_a, SPK_b)$ (and
    optionally $DH(e_a, OPK_b)$ when `opk_id` is non-zero).
    -   **1:1 Chats**: $K_{conv, 0}$ is generated randomly by the initiator and
        delivered via the `WrappedKey` ECIES construction.
    -   **Group Onboarding**: The Admin already has the group's $K_{conv}$.
        $K_{conv}$ is delivered to each new device via a `WrappedKey` entry with
        the new member's OPK consumed (`opk_id` set). Multiple members can be
        onboarded in a single `KeyWrap` node, each with their own `WrappedKey`
        entry and independent `opk_id`.
    -   **Anchor Hint**: The `KeyWrap` node MUST include the `anchor_hash` of
        the latest **Anchor Snapshot** (or Genesis Node) known to the author.
    -   **Authentication**: The `KeyWrap` MUST be authenticated using a
        `Signature` (Ed25519) by the authoring Admin.

## 3. Forward Secrecy & Deniability

### A. Forward Secrecy

Ephemeral pre-keys and `HandshakePulse` ensure `last_resort_key` is only used
for non-critical signals or interactive handshakes. $K_{conv, 0}$ is always
protected by ephemeral keys deleted after use.

### B. Two-Stage Deniability (DARE Model)

Merkle-Tox operates on a decentralized DAG requiring strict membership
authentication. The `KeyWrap` node establishing $K_{conv}$ is
**non-repudiable**, requiring an Admin's permanent `Signature`.

This is the **Two-Stage Onboarding** model (`merkle-tox-deniability.md`): 1.
**Stage 1 (Identity)**: Inviting a device and establishing room keys is
transparent and non-repudiable. An Admin cannot deny adding a user. 2. **Stage 2
(Content)**: Once keys are established, conversation content is authenticated
via **Ephemeral Signatures**. These signatures are disclosed after epoch
rotation, providing full **Plausible Deniability** for messages sent within the
room.

## 4. Lifecycle Management

-   **Rotation**: Users SHOULD publish a new `Announcement` node every 30 days
    or after 100 successful handshakes.
-   **Cleanup**: Once a new `Announcement` is acknowledged by > 50% of a user's
    peers, the old ephemeral private keys SHOULD be securely erased.
-   **Handshake Retry (OPK Exhausted)**: If Bob receives a handshake request
    using an OPK that has already been used and erased, he MUST respond with a
    `HANDSHAKE_ERROR`.
    -   **Retry Cap**: The initiator MUST NOT retry more than **3 times** per
        peer per 10-minute window.
    -   **Backoff**: Successive retries MUST use exponential backoff starting at
        a base of 2 seconds, doubling each time, up to a ceiling of 8 seconds
        (`HANDSHAKE_RETRY_BASE_MS = 2000`, `HANDSHAKE_RETRY_MAX_MS = 8000`).

## 5. OPK Collision Resolution

In the decentralized DAG, two initiators may simultaneously use the same OPK
from a recipient's `Announcement` node before either's `KeyWrap` propagates.
Because each initiator uses a different ephemeral key, they derive different
wrapping keys. A resolution rule is required because the recipient cannot
process both (the OPK private key is consumed on first use).

### Detection

Each `WrappedKey` entry includes an `opk_id` field (Blake3 hash of the OPK
public key consumed in the ECIES exchange). A peer detects a collision when two
`WrappedKey` entries (in different `KeyWrap` nodes) reference the same `opk_id`
for the same recipient.

Because `opk_id` is per-entry (not per-`KeyWrap` node), a collision only affects
the specific recipient entry. All other entries in both `KeyWrap` nodes remain
valid, eliminating the blast radius of OPK collision attacks.

### Resolution Rule: Admin Seniority / Device Key

The tie-breaker MUST use ungrindable, immutable historical context. Ephemeral
values MUST NOT be used because an attacker can generate thousands of keypairs
per second to guarantee they win, enabling targeted history erasure (see
Security Rationale below).

-   **Group Chats**: The winner is the initiator whose **Admin Seniority** is
    higher. Admin Seniority is determined by the `AuthorizeDevice` node that
    granted the author's Admin status: specifically the tuple
    `(topological_rank, auth_node_hash)`, where lower rank wins and
    lexicographic hash breaks ties at the same rank, reusing the seniority rule
    defined in `merkle-tox-identity.md` §3 for concurrent revocation resolution.
-   **1-on-1 Chats**: The winner is the initiator whose `sender_pk` (the
    device's long-term Ed25519 public key) is lexicographically smaller.
-   **Why these values are safe**: Admin Seniority is an immutable historical
    fact recorded in the DAG. Device public keys are long-term commitments.
    Neither can be varied per-collision. An attacker cannot grind their identity
    or retroactively change when they were authorized.
-   **Determinism & First Seen (The Race Condition Reality)**: The deterministic
    rules above resolve collisions for **offline** recipients who receive both
    KeyWraps simultaneously in a sync batch. However, for **online** recipients,
    "First Seen" is the ONLY physically enforceable rule: the first KeyWrap to
    arrive is decrypted and the OPK private key MUST be immediately destroyed
    for Forward Secrecy. If a KeyWrap arrives later with the same OPK, the
    recipient MUST discard it (even if it has higher deterministic seniority)
    because they physically cannot decrypt it. The deterministic tie-breaker
    applies ONLY to simultaneous batch evaluation. In a First-Seen race, the
    losing initiator's `KEYWRAP_ACK_TIMEOUT` will force them to retry, resolving
    the branch naturally.

### Losing Entry Handling

The losing `WrappedKey` entry is discarded. The **`KeyWrap` node itself is NOT
invalidated**. Only the specific colliding entry is affected:

1.  The recipient cannot decrypt the losing entry (OPK private key was consumed
    by the winning entry).
2.  The recipient processes the winning entry normally and receives the key.
3.  The losing `KeyWrap` node remains valid for all its other `wrapped_keys`
    entries.

**Recovery (Group Chats)**: Both Admins wrap the same $K_{conv}$. The recipient
gets the key from the winning entry. The losing Admin's messages are encrypted
with the same $K_{conv}$ and remain readable. No recovery action is needed
beyond a courtesy re-wrap.

**Recovery (1-on-1 Chats)**: The two `KeyWrap` nodes contain different
$K_{conv}$ values for different conversations. The recipient never receives the
losing initiator's key. The **Delivery Confirmation** mechanism (§2.A, Step 3)
prevents the loser from authoring content nodes before the `KEYWRAP_ACK`
arrives. The loser's `KEYWRAP_ACK_TIMEOUT_MS` fires, prompting a retry with a
different OPK. No unreadable messages enter the DAG.

**`KEYWRAP_ACK` Protocol**: Upon successfully decrypting a `WrappedKey` entry,
the recipient sends a `KEYWRAP_ACK` message (transport type `0x0F`) via the
`tox-sequenced` channel to the initiator. The ACK contains the Blake3 hash of
the `KeyWrap` node and the `recipient_pk` of the entry that was processed. This
is an off-DAG transport message. It does not appear in the Merkle DAG.

### Security Rationale

An attacker (Eve) who sees Alice's `KeyWrap` in the DAG could extract the
`opk_id` from Alice's `WrappedKey` entry, author a competing `KeyWrap` with a
ground ephemeral key guaranteed to win any comparison, and deterministically win
the collision. If the collision resolution operated at the `KeyWrap` node level
(invalidating the entire node), this would give Eve a **deterministic
retroactive history erasure** weapon against all content descending from Alice's
`KeyWrap`.

The per-entry `opk_id` design eliminates this blast radius. Even if Eve wins the
"First Seen" race against an online recipient, only the specific recipient entry
is affected. The Admin Seniority rule ensures offline sync batches are resolved
deterministically, and the per-entry scope guarantees the network does not fork
the entire `KeyWrap` node. The losing initiator's ACK timeout prompts an
automatic retry, healing the partitioned recipient without any retroactive
history erasure.
