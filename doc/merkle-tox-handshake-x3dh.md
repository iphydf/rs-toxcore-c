# Merkle-Tox Sub-Design: X3DH Handshake & Announcement Nodes

## Overview

To ensure that the initial connection between two users (and every subsequent
key rotation) provides **Forward Secrecy**, Merkle-Tox implements a
decentralized version of the **Extended Triple Diffie-Hellman (X3DH)**
handshake.

Instead of a centralized "Pre-key Server," Merkle-Tox uses the DAG itself to
publish and distribute ephemeral keys.

## 1. Announcement Nodes

Every user MUST author a new **Announcement Node** in the DAG at a strictly
defined interval (`ANNOUNCEMENT_ROTATION_INTERVAL = 30 days` or
`ANNOUNCEMENT_MAX_HANDSHAKES = 100`). This is an administrative node that is
globally syncable.

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

## 2. The X3DH Exchange

The X3DH exchange establishes the initial conversation key ($K_{conv, 0}$). The
strictness of the handshake depends on the conversation type.

### A. 1-on-1 Conversations (Opportunistic)

To ensure an "instant messaging" experience, 1-on-1 chats prioritize
availability.

1.  **Fetch**: User A fetches User B's latest `Announcement` node.
2.  **Select**:
    -   If valid `pre_keys` exist, User A uses one and performs the 4-part DH.
    -   If only the `last_resort_key` exists, User A **MAY** proceed but
        **MUST** attach a `HandshakePulse` to their first message.
3.  **Forward Secrecy**: The use of the `last_resort_key` provides only limited
    forward secrecy. The `HandshakePulse` forces User B, immediately upon coming
    online, to execute a full `KeyWrap` rotation using fresh ephemeral keys.
    This establishes a completely new $K_{conv}$ for the 1-on-1 chat and compels
    both users to rotate their `SenderKey`s, ensuring that *future* messages
    immediately regain full Forward Secrecy and Post-Compromise Security.
4.  **Debounce (KeyWrap Storm Prevention)**: To prevent a "KeyWrap Storm" if
    User B comes online after receiving multiple offline messages containing a
    `HandshakePulse`, a node **MUST** ignore a `HandshakePulse` if it has
    already authored a `KeyWrap` rotation within the last 5 minutes, or if it
    has already responded to a topologically newer or concurrent pulse from the
    same peer in the current sync batch.

### B. Group Conversations (Strict)

Groups prioritize security and Post-Compromise Security (PCS).

1.  **Onboarding**: New members fetch the Group Genesis and the current Admin
    track.
2.  **Strict Keying**: Content nodes (messages) are ignored and stored only in
    the **Opaque Store** until a `KeyWrap` is received from an authorized Admin.
3.  **Key Delivery**: Admins MUST use valid, unexpired ephemeral keys to wrap
    $K_{conv}$ for new members, ensuring that every onboarding event contributes
    fresh entropy to the conversation.
4.  **No Last Resort Keys**: Admins MUST NOT author a `KeyWrap` for a user if
    that user only has a `last_resort_key` published. Using a Last Resort Key
    for group onboarding would compromise the entire group's $K_{conv}$ and
    `SenderKey`s if that long-term key were ever forensically recovered.
    -   *Operational Resolution*: If an Admin wishes to invite an offline user
        who lacks fresh keys, the Admin's client SHOULD send an off-DAG 1-on-1
        `HandshakePulse` to wake the user up. The Admin client automatically
        buffers the group invite and authors the `KeyWrap` only after the user
        comes online and publishes fresh ephemeral keys.

### C. The DH Exchange (Logic)

Once a fresh `Announcement` is available:

-   User A generates a one-time ephemeral X25519 key pair ($E_a, e_a$).
-   User A computes the shared secret $SK$ using four ECDH operations:
    -   $DH1 = \text{ECDH}(I_a, SPK_b)$
    -   $DH2 = \text{ECDH}(E_a, I_b)$
    -   $DH3 = \text{ECDH}(E_a, SPK_b)$
    -   $DH4 = \text{ECDH}(E_a, OPK_b)$ (Optional)
*   **Derive**:
    -   $SK_{shared} = \text{Blake3-KDF}(\text{context: "merkle-tox v1
        x3dh-shared"}, DH1 || DH2 || DH3 || DH4)$.
    -   $K_{conv, 0} = \text{Blake3-KDF}(\text{context: "merkle-tox v1
        x3dh-kconv"}, SK_{shared})$.
    -   $SK_{pairwise} = \text{Blake3-KDF}(\text{context: "merkle-tox v1
        x3dh-pairwise"}, SK_{shared})$.
*   **Send**: User A authors an `Invite` or `KeyWrap` node containing their
    ephemeral public key $E_a$ and the ID of the pre-key they used.
    -   **Anchor Hint**: The `KeyWrap` node MUST include the `anchor_hash` of
        the latest **Anchor Snapshot** (or Genesis Node) known to the author.
    -   **Authentication**: The `KeyWrap` MUST be authenticated using a
        `Signature` (Ed25519) by the authoring Admin. The internal $K_{conv}$ is
        protected via authenticated encryption using $SK_{pairwise}$.

## 3. Forward Secrecy & Deniability

### A. Forward Secrecy

By enforcing the use of ephemeral pre-keys and providing the `HandshakePulse`
mechanism, Merkle-Tox ensures that the `last_resort_key` is only used for
non-critical one-way signals or as a signal for the interactive handshake. The
actual conversation key $K_{conv, 0}$ is always protected by ephemeral keys that
are deleted after use.

### B. Deniability

Like standard X3DH, the shared secret $SK$ does not involve a digital signature
on the session key. Both parties can compute $SK$, meaning either could have
forged the conversation. This maintains the **DARE** security model.

## 4. Lifecycle Management

-   **Rotation**: Users SHOULD publish a new `Announcement` node every 30 days
    or after 100 successful handshakes.
-   **Cleanup**: Once a new `Announcement` is acknowledged by > 50% of a user's
    peers, the old ephemeral private keys SHOULD be securely erased.
-   **Handshake Retry (Collision Recovery)**: If a user (e.g., Bob) receives an
    interactive handshake request using an OPK that has already been used and
    erased, they MUST respond with a `HANDSHAKE_ERROR`.
    -   **Retry Cap**: The initiator MUST NOT retry more than **3 times** per
        peer per 10-minute window.
    -   **Backoff**: Successive retries MUST use exponential backoff starting at
        a base of 2 seconds, doubling each time, up to a ceiling of 8 seconds
        (`HANDSHAKE_RETRY_BASE_MS = 2000`, `HANDSHAKE_RETRY_MAX_MS = 8000`) to
        prevent overwhelming the peer or the DAG with announcement refetches.
-   **Conflict Resolution**: If two peers try to use the same pre-key
    simultaneously (a collision in the decentralized DAG), the resulting
    $K_{conv}$ will be different. The protocol handles this by treating the
    resulting branches as separate "Speculative" forks until one is successfully
    reconciled.

```
```
