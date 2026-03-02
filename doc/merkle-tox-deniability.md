# Merkle-Tox Sub-Design: Deniable Authentication (DARE)

## Overview

Merkle-Tox provides **Plausible Deniability** alongside **Internal
Authentication** (group members verify message authors during active epochs).

Uses **Ephemeral Signatures with Intentional Key Disclosure**: content nodes are
signed with short-lived Ed25519 keys whose private keys are publicly disclosed
after epoch rotation, making past signatures forgeable.

## 1. DARE Authentication Model

### Shared Conversation Key ($K_{conv}$)

Every conversation establishes a symmetric **Shared Conversation Key**.

-   In **1:1 chats**, distributed via Signed ECIES handshake during initial
    connection.
-   In **Group chats**, distributed via Signed ECIES (`KeyWrap` nodes) to all
    authorized devices.

### Ephemeral Signatures (Content Nodes)

Each content node is authenticated with an **Ephemeral Ed25519 Signature**. The
full cryptographic construction for a Content Node is:

```
# 1. Derive the sender hint from the per-message ratchet key
#    Because K_msg_i is unique per message, the hint changes every message,
#    preventing passive traffic analysis by blind relays (no static value to
#    correlate on). Recipients maintain a lookup table built from their
#    ratchet state (see "Verification Order" in Section 2).
sender_hint = Blake3-KDF("merkle-tox v1 hint", K_msg_i)[0..4]

# 2. Derive per-epoch header key from the sender's current SenderKey
#    (rotates every 7 days / 5,000 messages), ensuring routing metadata
#    has the exact same Post-Compromise Security (PCS) as the payload.
#    New members joining mid-epoch receive this key explicitly via JIT Piggybacking.
K_header_epoch_n = Blake3-KDF("merkle-tox v1 header-key", K_conv || SenderKey_n)

> **Design Rationale (Epoch-Static vs. Per-Message Header Key):**
>
> $K_{header}$ MUST NOT be derived from the per-message $K_{chain_i}$.
>
> Deriving $K_{header}$ per-message introduces an asymmetric CPU Denial of Service (DoS) vector. On a `sender_hint` cache miss, a recipient must identify the sender via trial decryption. A per-message key requires stepping every known sender's ratchet up to `MAX_RATCHET_SKIPS` (2000) to derive candidate keys. For $N$ members, one unauthenticated packet forces $N \times 2000$ sequential Blake3 hashes prior to rejection.
>
> Deriving $K_{header}$ from the epoch-static `SenderKey` sacrifices per-message Forward Secrecy on the `sequence_number` to guarantee:
> 1.  **$O(N)$ AEAD Fast-Fail**: Trial decryption requires at most $N$ `ChaCha20-Poly1305` tag checks against cached epoch keys. Zero ratchet steps occur until the sender and sequence number are authenticated.
> 2.  **Asynchronous Recovery**: A recipient processing out-of-order or offline batches can decrypt routing headers to identify sequence numbers, enabling deterministic ratchet advancement to target indices without interactive off-DAG recovery.
>
> The `content`, `metadata`, and `network_timestamp` maintain per-message Forward Secrecy via $K_{msg_i}$.

# 3. Encrypt routing metadata (random nonce, prepended to ciphertext)
#    MUST use an AEAD cipher like ChaCha20-Poly1305. The 16-byte Poly1305 tag
#    is required to instantly reject garbage during O(N) trial decryption,
#    preventing asymmetric CPU DoS attacks from outsiders.
#    (Note: sender_pk is omitted because the key used implicitly identifies the sender).
#    To prevent replay attacks where a valid routing header is attached
#    to a garbage payload (bypassing the fast DoS check), the hash of the payload
#    MUST be included as Additional Authenticated Data (AAD).
nonce = random_bytes(12)
ciphertext = ChaCha20-Poly1305(
    key:   K_header_epoch_n,
    nonce: nonce,
    aad:   Blake3(payload_data),
    plain: [sequence_number (fixed 8-byte u64)]
)
encrypted_routing = nonce || ciphertext

# 4. Encrypt payload with the per-message ratchet key
#    A random nonce is used because K_msg_i uniqueness depends on ratchet
#    state being persisted before sending. If the ratchet rewinds (database
#    restore, crash before persist, VM clone), the same K_msg_i would be
#    derived again. Reusing a fixed nonce with the same key under ChaCha20
#    is catastrophic (XOR of ciphertexts reveals XOR of plaintexts). A
#    random 96-bit nonce makes collision negligible even under state rewind.
nonce_msg_i = random_bytes(12)
payload_data = nonce_msg_i || ChaCha20-IETF(K_msg_i, nonce_msg_i, [network_timestamp || content || metadata])

# 5. Sign with the sender's current ephemeral signing key (Encrypt-then-Sign)
Node_Contents = ToxProto::serialize([
    parents, sender_hint, encrypted_routing,
    payload_data, topological_rank, flags
])
Authenticator = Ed25519_Sign(ephemeral_signing_sk, "merkle-tox v1 content-sig" || Node_Contents)
```

The signature covers the **ciphertext** of `encrypted_routing` and
`payload_data`, `topological_rank`, and `flags`. Covering `topological_rank`
prevents silent relay inflation of a node's rank; covering `flags` prevents
relay-induced decompression failures. See `merkle-tox-dag.md` for the full
canonical definition and the Admin Node signature variant.

### Internal Authentication

During the active epoch, only the sender holds the ephemeral signing private key
(`ephemeral_signing_sk`). Recipients verify signatures using
`ephemeral_signing_pk` distributed via `SenderKeyDistribution`. Valid signatures
prove authorship to group members, preventing real-time impersonation.

### Plausible Deniability (Key Disclosure)

When a sender rotates their SenderKey (every 7 days or 5,000 messages), the new
`SenderKeyDistribution` node includes the **previous epoch's
`ephemeral_signing_sk`** in the `disclosed_keys` field. Once disclosed:

-   Any authorized member now possesses the old private key and could have
    forged any signature from that epoch.
-   **External Repudiation**: If the DAG is leaked, the sender can plausibly
    claim that any member who received the disclosure could have forged the
    signed content.
-   **Timing**: The disclosure is delivered over the deniable encrypted channel.
    There is no non-repudiable certificate linking the ephemeral key to the
    sender's identity.

> **Note**: During the active epoch (before disclosure), signatures provide
> non-repudiable internal authentication to group members. The deniability
> window is bounded by the SenderKey rotation interval (7 days / 5,000
> messages).

## 2. Key Agreement & Rotation

### Initial Handshake: Signed ECIES

A decentralized **Signed ECIES (Ephemeral-Static Diffie-Hellman)** handshake
establishes the initial conversation key ($K_{conv, 0}$).

1.  **Announcement Nodes**: Users publish signed ephemeral "Pre-keys" to the
    DAG.
2.  **Exchange**: To start a chat or join a group, a user fetches the
    recipient's latest pre-key and performs a 4-part DH exchange.
3.  **Result**: Establishes a shared secret with **Forward Secrecy**.

See **`merkle-tox-handshake-ecies.md`** for the full handshake protocol.

### Bounded Forward Secrecy (Symmetric Ratchet)

Once $K_{conv, 0}$ is established, it seeds a **Symmetric Key Ratchet** (Hash
Chain).

-   Every message is encrypted with a unique, one-way derived key ($K_{msg,i}$).
-   Keys are deleted immediately after use.
-   **The ECIES Trade-off**: Without 1-to-1 Double Ratchets, the root
    `SenderKey` is distributed using ECIES against the recipient's `Signed
    Pre-Key` (SPK). Forward Secrecy of the *entire chain* is bounded by the SPK
    rotation interval (30 days). A compromised SPK allows retroactive decryption
    of `SenderKey` distributions from that epoch.
-   The ratchet handles the non-linear nature of the DAG by keeping each
    sender's chain linear and independent of other senders' branches.

See **`merkle-tox-ratchet.md`** for the ratchet implementation details.

### Per-Epoch Key Rotation (Header & Signing)

The header encryption key is tied to the sender's **SenderKey epoch** and
therefore rotates every 7 days or 5,000 messages, matching the Post-Compromise
Security cadence of payload encryption:

```
K_header_epoch_n = Blake3-KDF("merkle-tox v1 header-key", K_conv || SenderKey_n)
```

The ephemeral signing key pair is generated fresh for each epoch and distributed
alongside the `SenderKey` via `SenderKeyDistribution`.

`SenderKeyDistribution` nodes (Content ID 2) are themselves signed with the
**current** epoch's ephemeral signing key. The new `SenderKeyDistribution`
distributing $SenderKey\_{n+1}$ is signed with the epoch $n$ key (which
recipients already possess). For the initial distribution ($n = 0$), the node
uses `NodeAuth::Signature` (a permanent Ed25519 signature from the device key)
because no ephemeral key has been established yet.

**Forward Secrecy**: When a SenderKey epoch ends, $K_{header\_epoch\_n}$ is
irrecoverable. The old ephemeral signing private key is disclosed, making past
signatures forgeable but past routing metadata unrecoverable.

**Deniability**: After epoch rotation, the old `ephemeral_signing_sk` is
disclosed to all members via the `disclosed_keys` field. Any member can then
produce valid signatures for past content, preserving the DARE deniability
property. Before disclosure, the signature provides non-repudiable internal
authentication.

**Verification Order**: The `sender_hint` is derived from $K_{msg\_i}$ (see
Section 1). Recipients maintain a `{hint → (sender_pk, ratchet_index)}` lookup
table built from their ratchet state (next expected key and cached skipped
keys).

1.  The verifier looks up `sender_hint` in the table for O(1) sender
    identification.
2.  On match, the verifier retrieves the sender's current
    `ephemeral_signing_pk`, verifies the signature, then decrypts
    `encrypted_routing` and `payload_data`.
3.  On collision, the verifier tries each candidate sender's
    `ephemeral_signing_pk` until one succeeds.
4.  **Fallback (table miss)**: On table miss, the verifier falls back to O(N)
    **trial decryption** of `encrypted_routing` using each known sender's
    $K_{header\_epoch\_n}$.
    -   **DoS Protection (AEAD)**: The routing header MUST be encrypted using an
        AEAD cipher (**ChaCha20-Poly1305**). If a message is garbage or uses an
        unknown key, the Poly1305 authentication tag check will fail in a
        fraction of a microsecond, preventing an asymmetric CPU DoS where an
        attacker floods the room with random hints to force O(N) stream
        decryptions and memory comparisons.

Table entries are updated incrementally as the ratchet advances or skipped keys
expire.

### Post-Compromise Security (PCS)

To "heal" a conversation after a device has been compromised, Merkle-Tox
performs periodic **Sender Key Rotations**.

1.  **Triggers**: Rotation occurs per-device every **5,000 messages** or **7
    days**.
2.  **Mechanism**: The device generates a new `SenderKey` (ratchet root) and a
    fresh ephemeral Ed25519 key pair, distributing both via
    `SenderKeyDistribution` to all currently authorized members. The old epoch's
    `ephemeral_signing_sk` is included in `disclosed_keys`.
3.  **Result**: Provides **Post-Compromise Security**, ensuring an attacker is
    rotated out of decryption and forgery capability. The decentralized $O(N)$
    distribution prevents Admin bottlenecks.

## 3. "Lazy Consensus" Fallback

In scenarios where $K_{conv}$ is not yet known (e.g., syncing from a blind
relay):

1.  **Speculative Sync**: The client downloads nodes and validates their `hash`
    but marks them as `Unverified`.
2.  **Attestation (Vouching)**: If a trusted peer includes a node as a parent,
    confidence in that node increases.
3.  **Finalization**: Once the client establishes $K_{conv}$ with an authorized
    peer, the historical DAG is validated.

## 4. Identity vs. Content (Two-Stage Onboarding)

Merkle-Tox uses a **Two-Stage Onboarding** process.

### Stage 1: Non-Repudiable Authorization (Hard Identity)

Nodes that manage the membership and capabilities of the room are **signed** and
transparent.

-   **Admin/Control Nodes**: Authorize/revoke devices, change room title, or
    invite members.
-   **Security**: These nodes use **Ed25519 signatures**, providing
    non-repudiable proof that an Admin performed a specific management action.
-   **Privacy**: These nodes do **not** contain private user content. They only
    establish *who* is allowed to participate.

### Stage 2: Deniable Communication (DARE)

Once authorized, all actual conversation content is protected by the DARE model
using ephemeral signatures.

-   **Content Nodes**: All messages, files, and reactions **MUST** use
    `NodeAuth::EphemeralSignature`.
-   **Internal Authentication**: During the active epoch, the ephemeral signing
    key is held exclusively by the sender. A valid signature proves authorship
    to all group members, preventing real-time impersonation.
-   **Deniability**: After epoch rotation, the sender discloses the old
    `ephemeral_signing_sk`. Any authorized member could then have forged the
    signatures from that epoch. An outsider cannot prove who authored a specific
    `Content::Text` node.
-   **Strict Encryption**: The `content` and `metadata` use Encrypt-then-Sign.
    In Content nodes, the `sequence_number` MUST be encrypted into an
    `encrypted_routing` header using $K_{header\_epoch\_n}$. See Section 1 for
    the full derivation.
    -   **EXCEPTION (KeyWrap)**: `KeyWrap` nodes (Content ID 1) are sent in
        **cleartext** (and signed with an Ed25519 Signature) to allow new
        members to receive the conversation keys. For these nodes, the
        `sender_pk` and `recipient_pk` lists are technically visible to relays.
        However, because room membership is already public via the
        `AuthorizeDevice` Admin nodes, this does not expose any new information,
        and avoiding trial decryption saves massive CPU overhead in large
        groups.

### Transitive Rationale

Separating the **Authority to Speak** (permanently Signed) from the **Act of
Speaking** (ephemerally Signed with disclosed keys) ensures a user's permanent
digital signature on a room-management task never "anchors" the hash of a
private message into a non-repudiable record. Even if presence in a room is
proven, specific messages remain plausibly deniable after epoch rotation.

## 5. Control Chain Isolation

To prevent "Transitive Non-Repudiation," Merkle-Tox enforces a strict separation
between Admin and Content nodes:

-   **Admin nodes** (which are permanently signed) can only reference other
    Admin nodes as parents.
-   **Content nodes** (which use ephemeral signatures) can reference both Admin
    and Content nodes.

## 6. Summary of Security Properties

-   **Integrity**: Guaranteed by the Merkle-DAG (Blake3 hashes) and the
    Encrypt-then-Sign construction covering all wire-visible fields including
    `topological_rank` and `flags`.
-   **Internal Authentication**: During the active epoch, the ephemeral signing
    key is held exclusively by the sender. A valid signature proves authorship
    to all group members. No other member can forge content as another member in
    real time.
-   **Deniability**: After epoch rotation, the old `ephemeral_signing_sk` is
    disclosed to all members. Any authorized member could then forge signatures
    from that epoch. No asymmetric signature permanently binds a message to a
    specific sender.
-   **Forward Secrecy**: Bounded by the 30-day SPK rotation epoch. Provided by
    the symmetric ratchet (per-message deletion) but constrained by the ECIES
    distribution of the root `SenderKey` and ECIES (per-handshake).
-   **Post-Compromise Security (Payload)**: Provided by periodic per-device
    `SenderKey` rotations (every 7 days / 5,000 messages).
-   **Post-Compromise Security (Routing Metadata)**: The `sender_hint` is
    derived from the per-message ratchet key ($K_{msg\_i}$), giving it the same
    bounded Forward Secrecy and PCS inherited from the ratchet chain. The
    `encrypted_routing` header is encrypted with $K_{header\_epoch\_n}$, which
    rotates with the SenderKey (7-day / 5,000-message cadence). Together, no
    cleartext or encrypted routing field is static across messages, and all
    routing metadata gains PCS from the SenderKey rotation schedule.
-   **Post-Compromise Security (Authentication)**: Provided by per-epoch
    ephemeral signing key rotation. An attacker who compromises a device's
    current ephemeral signing key is rotated out of forgery capability within 7
    days. The disclosed old key only enables forging past-epoch content (which
    is already deniable).
