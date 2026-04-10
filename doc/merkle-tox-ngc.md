# Merkle-Tox Sub-Design: NGC Transport Binding

## Overview

This document describes how Merkle-Tox conversations are carried over
c-toxcore's New Group Chat (NGC) protocol, and how the two layers bind
to each other.

NGC provides what Merkle-Tox lacks at the transport layer:

*   **DHT-based peer discovery.** Members find each other via the chat's
    DHT presence (public chats) or via friend-routed invites (private
    chats). No requirement that members be mutual friends, in contrast
    to the direct-friend transport.
*   **Per-chat ephemeral identity.** Each peer's NGC identity is a
    chat-scoped extended ed25519 keypair, unrelated to their long-term
    Tox identity (verified in c-toxcore at `crypto_core.c:57-72` and
    `group_chats.c:7354`). Joining an NGC does not disclose your
    long-term Tox PK to other members.
*   **Built-in routing and moderation primitives.** The NGC layer
    handles peer-to-peer addressing, TCP-relay fallback, and
    founder-cert-based moderation independently of Merkle-Tox.

Merkle-Tox provides what NGC lacks:

*   **End-to-end ratcheted confidentiality.** NGC's shared group key is
    symmetric and known to all current members; a compromised current
    member can decrypt past traffic they were present for. Merkle-Tox's
    per-message ratchet (see [merkle-tox-ratchet.md](merkle-tox-ratchet.md))
    layered on top closes this gap.
*   **Multi-author signed history with DAG sync.** Every Merkle-Tox
    message is signed and links to its parents; late joiners can sync
    full history.
*   **Multi-device identity.** One `LogicalIdentityPk` represents a
    user across N devices via the delegation chain (see
    [merkle-tox-identity.md](merkle-tox-identity.md)).

Each layer is responsible for what it is best at: NGC for routing,
Merkle-Tox for crypto and history. The two compose; they do not
duplicate.

**Principle 9 (Marginal Tox Transport Coupling) applies throughout.**
Merkle-Tox uses NGC custom packets in *lossy mode only*
(`gc_send_custom_*_packet(lossless=false, ...)`). NGC's lossless
mode — with its internal ACK protocol, retransmission, 2048-packet
unacked-window backpressure, and 58-second connection timeout — is
NOT used. Reliability and ordering come from Merkle-Tox's own DAG
sync and application-layer request-IDs. See
[merkle-tox-principles.md §9](merkle-tox-principles.md).

This document does NOT cover the direct-friend transport for
Merkle-Tox (1:1 friend chats, multi-device self-sync). That has its
own conversation-founding conventions and threat model. NGC binding
and direct-friend binding produce different products with different
privacy properties; see Section 7.

--------------------------------------------------------------------------------

## 1. Conversation ID Binding

A Merkle-Tox conversation's `ConversationId` (32 bytes) for an
NGC-transported conversation is **directly equal to the NGC `chat_id`**:

```
ConversationId == chat_id
```

The NGC `chat_id` is the signing half of the founder's NGC extended
keypair (c-toxcore: keypair created by `create_extended_keypair` at
`group_chats.c:7554-7558`, with internal structure at
`crypto_core.c:94-97`; `chat_id` is extracted via `get_chat_id` at
`group_chats.c:2562-2565` and joiners derive only the public half
via `expand_chat_id` at `group_chats.c:760-772`). It is a 32-byte
ed25519 public key, fixed at NGC creation, and globally public to
all members.

### Rationale

*   **No derivation, no per-packet overhead.** Sync packets already
    carry `ConversationId` (see [merkle-tox-wire-format.md](merkle-tox-wire-format.md));
    no separate `chat_id` field is needed.
*   **Trivial lookup.** When a peer receives a custom packet via NGC,
    it knows the `chat_id` (from the NGC API) and immediately knows the
    Merkle-Tox conversation it belongs to. The storage convention
    `conversations/<hex(ConversationId)>/` maps directly to
    `conversations/<hex(chat_id)>/`.
*   **No new disclosure.** The `chat_id` is already known to every NGC
    member by construction. Using it as `ConversationId` reveals
    nothing new to in-chat peers, and the `ConversationId` is not
    exposed to non-NGC observers (custom packets are not visible
    outside the NGC).

### Consequences

*   **Founder of NGC at creation == founder of Merkle-Tox
    conversation.** Genesis (the founding Merkle-Tox node) is signed
    by the *original* `chat_id` holder's `LogicalIdentityPk`. The
    `chat_id` is that user's NGC per-chat-ephemeral signing key,
    which is unrelated to their `LogicalIdentityPk`; the binding
    between the two is asserted in the founder's `PeerIntroduction`
    record (Section 3) and verified against Genesis.
*   **NGC founder-handoff does not change `ConversationId` or the
    Merkle-Tox founder.** NGC's moderation system allows founder-role
    transfer to another peer. `chat_id` is burned at NGC creation and
    never changes, so `ConversationId` is also stable. Genesis
    remains the authority for "who founded this Merkle-Tox
    conversation"; later NGC founders inherit *NGC moderation
    capability* (kick, observer-sanctions) but not Merkle-Tox
    founder identity.
*   **Re-founding hygiene.** If a founder destroys an NGC and
    re-creates one with the "same" name, the new NGC has a fresh
    `chat_id` and is therefore a *different* Merkle-Tox conversation.
    Users will not see the new conversation as a continuation of
    the old one; this is intentional but should be surfaced in UI
    ("This is a new conversation with the same name as one you
    previously left/lost").
*   **No transport migration mid-conversation.** A Merkle-Tox
    conversation founded on NGC cannot keep the same `ConversationId`
    if the membership later migrates to direct-friend transport (or
    vice versa). Cross-transport migration changes the threat model
    and member-set conventions; treat it as "abandon this
    conversation, start a new one" if needed.
*   **Non-NGC conversations derive `ConversationId` differently.** For
    direct-friend Merkle-Tox conversations, `ConversationId` is
    derived per the rules in that transport's binding doc (future
    work; currently the direct-friend binding is implicit in the
    `ToxTransport` implementation and has not been formalised in a
    sub-design doc — cross-references in this doc to "direct-friend
    transport" describe design intent, not a written spec). The
    system handles each transport with its own derivation rule.
*   **Wire-format implication.** For the metadata-disclosure
    properties claimed in this document to hold, `ConversationId`
    SHOULD NOT appear in plaintext in custom-packet payloads visible
    to NGC peers who lack a valid `PeerIntroduction` binding (which
    includes TCP relays). The `tox-sequenced` framing and Merkle-Tox
    sync messages should carry `ConversationId` under the ratchet, or
    at minimum encrypted to the conversation key. See
    [merkle-tox-wire-format.md](merkle-tox-wire-format.md) for the
    canonical answer; this doc assumes that property holds.

--------------------------------------------------------------------------------

## 2. Multi-Device Pseudonymity

Each device of a multi-device user joins the NGC with its **own
independent NGC extended keypair**. There is no shared NGC self-key
across devices.

To other peers in the NGC, a user with N devices appears as N
distinct NGC peers. NGC has no knowledge of their shared identity at
the transport layer.

Inside the Merkle-Tox layer, every message is signed by a
`PhysicalDevicePk`, which is in turn delegated by a
`LogicalIdentityPk`. Merkle-Tox-aware peers therefore see N NGC peers
authoring messages on behalf of one `LogicalIdentityPk`, and group
them as one author in the UI.

### Rationale

This is option (B) from the design discussion. The alternative
(option A, shared NGC self-key across a user's devices) requires the
NGC protocol to handle "one peer, multiple endpoints" cleanly, which
is not what the NGC state machine and announce layer were designed
for. Option (B) reuses NGC unchanged, at the cost of N visible peers
to non-Merkle-Tox-aware NGC clients.

### Consequences

*   **No transport-layer changes to NGC.** Each device runs the
    standard NGC join flow with its own ext keypair, indistinguishable
    to NGC from N unrelated users.
*   **Cross-device state sync uses a separate channel.** A device's
    knowledge of "which NGCs is my user in, which NGC self-keys are
    mine" is held in the user's cross-device Merkle-Tox conversation
    (a device-set conversation founded directly between the user's
    own devices over the direct-friend transport). NGC self-keys are
    NOT distributed via the NGC itself.
*   **Visible-peer-count to legacy clients.** Non-Merkle-Tox-aware NGC
    clients see N peers per multi-device user. Their UI cannot
    deduplicate. This is an accepted cost.
*   **Per-chat unlinkability.** Two NGCs that the same user is in use
    independently generated NGC self-keys per chat (c-toxcore
    `group_chats.c:7354`). Even an attacker correlating peer lists
    across two NGCs cannot link "this peer in chat A is the same
    person as that peer in chat B" from the keys alone.

### Concurrent-Online Sync Coordination

When N devices of the same `LogicalIdentityPk` come online into the
same NGC simultaneously, each independently emits `PeerIntroduction`
and may independently request Merkle-Tox sync from the same other
peers. Naive implementation amplifies sync traffic by ×N per
multi-device user. Two mitigations:

1.  **Responder-side dedupe.** A responder MAY refuse a sync request
    from device D2 of `LogicalIdentityPk` L if it has answered a
    structurally-equivalent request from device D1 of L within a
    short window (e.g. 10 seconds), returning a "ask your sibling
    device" hint or a no-op. Devices on the receiver side cross-share
    received sync data via the cross-device Merkle-Tox conversation.
2.  **Sender-side coordination.** Before issuing sync, a device may
    consult its cross-device conversation for "is another of my
    devices already syncing this NGC?" and defer. This is best-effort
    (the cross-device conversation is eventually consistent) but
    catches the common case of intentional concurrent power-on.

Implementations SHOULD do at least (1); (2) is an optional
optimization. Without either, the system functions correctly but
costs ×N bandwidth during cold-start bursts.

The cross-device conversation itself faces an analogous question:
when N devices come online they will also pairwise-sync the
cross-device conversation. This amplification is bounded by
N(N−1)/2 friend-transport exchanges, contained entirely within the
user's own device fleet (typically 2-5 devices), and does not
cascade because the cross-device conversation never uses NGC. The
analysis is self-terminating.

--------------------------------------------------------------------------------

## 3. PeerIntroduction Record

When a device first contributes to a given Merkle-Tox conversation
over NGC, it MUST emit a `PeerIntroduction` record before any other
authored Merkle-Tox message.

### Purpose

Bind the NGC ephemeral identity (per-chat ext keypair) to the durable
Merkle-Tox identity (`PhysicalDevicePk`, in turn delegated by a
`LogicalIdentityPk`). Establish a cryptographic link from
"NGC peer K" to "this user," so:

*   Sync requests (Section 4) can be gated by Merkle-Tox membership.
*   Multi-device deduplication (Section 2) can be performed reliably
    by Merkle-Tox-aware peers.
*   A malicious NGC peer cannot impersonate a `LogicalIdentityPk` they
    do not control.

### Structure

The record carries:

*   `logical_identity_pk` — the user's `LogicalIdentityPk`.
*   `physical_device_pk` — the device's `PhysicalDevicePk`.
*   `ngc_self_pk` — the device's NGC ext keypair signing pubkey for
    this chat. Redundant with the NGC peer_id the receiver already
    has from the NGC API, but included so the signature is
    self-contained and verifiable against the API-reported key.
*   `intro_epoch` — a monotonically-increasing `u64` chosen by the
    sender, incremented on each fresh emission of `PeerIntroduction`
    for this `(L, P, ConversationId)` triple. Persisted with the
    device's NGC self-key. Initial value is 0.
*   `signature` — a signature **by the device's `PhysicalDevicePk`**
    over the length-prefixed concatenation
    `(domain_separator, logical_identity_pk, physical_device_pk,
    ngc_self_pk, conversation_id, intro_epoch)`. The signature proves
    the holder of `PhysicalDevicePk` knowingly authorized this NGC
    self-key for this conversation at this epoch.
*   `chat_id_attestation` — present **only in the founder's
    `PeerIntroduction`**, optional otherwise. A signature **by the
    `chat_id` secret key** (i.e. by the NGC ext sig secret key whose
    pubkey IS the `chat_id`) over the length-prefixed concatenation
    `(b"merkle-tox v1 ngc-chat-id-attest", logical_identity_pk,
    conversation_id)`. This binds the founder's `LogicalIdentityPk`
    to the NGC creator's identity: only the original NGC creator
    holds the `chat_id` secret key (c-toxcore persists it per
    `group_pack.c:217-218` and never derives or hands it to anyone
    else), so this attestation cannot be forged by any later
    NGC peer — including peers promoted to NGC founder via
    moderation handoff. See "Founder Front-Run Prevention" below.

The domain separator is `b"merkle-tox v1 ngc-peer-intro"`, matching
the existing convention used by `b"merkle-tox v1 content-sig"` and
`b"merkle-tox v1 admin-sig"` in `merkle-tox-core/src/dag.rs:366-368,
588-589`. The currently-known set of Merkle-Tox signature domain
separators (to be moved to a wire-format registry appendix when one
exists):

| Separator | Purpose | Source |
|---|---|---|
| `b"merkle-tox v1 content-sig"` | Content-node ephemeral signature | `dag.rs:366` |
| `b"merkle-tox v1 admin-sig"` | Admin-node permanent signature | `dag.rs:368` |
| `b"merkle-tox v1 ngc-peer-intro"` | `PeerIntroduction` binding (this doc) | this doc |
| `b"merkle-tox v1 ngc-chat-id-attest"` | Founder `chat_id_attestation` (this doc, §3) | this doc |

All separators in this list are mutually non-prefix (verifiable by
inspection); tuple contents are length-prefixed during signing to
prevent prefix-collision attacks if a future separator violates this
property.

### Verification

A receiver verifies a `PeerIntroduction` in two phases. **Phase A**
(steps 1-5) is mandatory for every record. **Phase B** (steps 6 or
7) is a disjunction: exactly one of the two MUST succeed to bind
the record.

**Phase A — universal checks:**

1.  Check `ngc_self_pk` equals the NGC-API-reported signing pubkey
    of the peer the packet arrived on (e.g. via
    `gc_get_peer_public_key`). Reject mismatches — this prevents a
    forwarding attack in which one NGC peer replays another peer's
    intro under its own NGC peer_id.
2.  Check `signature` is valid by `physical_device_pk` over the
    length-prefixed domain-separated tuple including `intro_epoch`.
3.  Check `intro_epoch` is **greater than or equal to** the highest
    previously-accepted `intro_epoch` for this
    `(logical_identity_pk, physical_device_pk, conversation_id)`
    triple, persisted across binding eviction in conversation state.
    Strictly-less is rejected — this prevents replay of an old
    captured `PeerIntroduction` by an attacker who obtained the NGC
    self-secret-key but not the `PhysicalDevicePk` secret. Equality
    is permitted because step 1's `ngc_self_pk` check, combined with
    the device's NGC self-key persistence, makes the record
    effectively byte-identical to the previously-accepted one.
4.  Check `physical_device_pk` is in the delegation chain of
    `logical_identity_pk`, per the rules in
    [merkle-tox-identity.md](merkle-tox-identity.md). The relevant
    `DelegationCertificate` may need to be requested via Merkle-Tox
    sync if not yet locally available; see the bootstrap escape
    valve in Section 4. (This check is skipped only if step 6 of
    Phase B succeeds in the special bootstrap path described below.)
5.  Check `physical_device_pk` is **not currently revoked** for
    this conversation (consult `revoked_devices` for `conversation_id`).

**Phase B — exactly one of:**

6.  **Normal membership.** Check `logical_identity_pk` is a member
    of the Merkle-Tox conversation (in the current `MemberInfo`
    set), or is the founder asserted by Genesis, or is a *pending
    delegation candidate* — a `LogicalIdentityPk` for which a
    `DelegationCertificate` from an existing member is in-flight or
    recently received but not yet fully replayed. Pending candidates
    may bind but receive no Merkle-Tox state until verification
    completes.
7.  **Bootstrap-attestation founder claim.** If no Genesis is yet
    present on the local DAG for this `ConversationId`, the record
    MUST include `chat_id_attestation` and the attestation MUST
    verify against `chat_id` (which equals `ConversationId`). On
    success, the attestation establishes the *founder claim* for
    this `LogicalIdentityPk`; Genesis (when it arrives) MUST be
    authored by this same `LogicalIdentityPk` or it is rejected.
    Step 4 of Phase A is RELAXED for this path: a self-delegation
    is implicit — the founder's `LogicalIdentityPk` may delegate to
    its own `PhysicalDevicePk` without a pre-existing
    `DelegationCertificate`, since the founder authors the first
    `AuthorizeDevice` in Genesis itself.

Records that pass Phase A but fail both options of Phase B are
candidate-non-founder and are held in a pending state — they
cannot install a Genesis claim and receive no Merkle-Tox sync
disclosures. Receivers MAY retain them in case relevant
`MemberInfo` updates arrive later via sync.

**On success (either step 6 or step 7),** cache the binding
`(ngc_peer_id → logical_identity_pk, physical_device_pk,
intro_epoch, chat_id_attestation?)` until one of: the NGC peer's
connection ends (`peer_exit` callback fires); a `RevokeDevice` for
`physical_device_pk` arrives (see Section 5); or a new
`PeerIntroduction` from the same NGC peer_id with a higher
`intro_epoch` replaces it (atomically).

### Founder Front-Run Prevention

Without `chat_id_attestation`, any peer joining an NGC that has not
yet been bootstrapped to Merkle-Tox could write the first Genesis
and have §3.17 invariant 1's "first-Genesis-wins" rule install them
as founder. The attestation closes this race:

*   The NGC `chat_id` is the founder's NGC ext sig pubkey
    (created by `create_extended_keypair` at `group_chats.c:7554-7558`; extracted via `get_chat_id` at `group_chats.c:2562-2565` and `expand_chat_id` at `group_chats.c:760-772`). The secret half is held only by the
    original NGC creator and never transmitted.
*   A founder claiming `LogicalIdentityPk L` includes an attestation
    `Sign_{chat_id_sk}(b"merkle-tox v1 ngc-chat-id-attest", L,
    ConversationId)` in their first `PeerIntroduction`.
*   Receivers verify this signature using `ConversationId` (== `chat_id`)
    as the public key. Any peer who later joins, even one promoted to
    NGC founder via moderation handoff, lacks `chat_id_sk` and cannot
    forge this attestation.
*   Genesis MUST be authored by the `LogicalIdentityPk` whose
    attestation has been verified for this `ConversationId`. A
    Genesis signed by any other `LogicalIdentityPk` is rejected at
    verification time before §3.17 invariant 1's uniqueness check
    runs.

This also means NGC creation and Merkle-Tox bootstrap are coupled
in practice: the NGC creator must invoke their Merkle-Tox client
soon after `gc_new_group` (or accept that the conversation remains
in a pending-Genesis state where Merkle-Tox-aware peers cannot
establish bindings). If the NGC creator never bootstraps Merkle-Tox,
no Genesis is ever valid and the chat exists at the NGC layer only.

### Multi-Device Founder

Only the device that ran `gc_new_group` holds `chat_id_sk`. Joiner
devices via `gc_group_join` call `expand_chat_id` (`group_chats.c:760-772`)
which derives only the public half; the secret is never transmitted
or recovered from joining (verified against c-toxcore). A
multi-device user who founded an NGC on phone, then later joins
from laptop, cannot produce a `chat_id_attestation` from the
laptop.

**Required protocol:** the founder device MUST write Genesis
atomically with NGC creation, before any other device (including
the user's own other devices) joins the NGC. The required
sequence is:

1.  Founder device calls `gc_new_group` (NGC creation; founder
    holds `chat_id_sk`).
2.  Same device emits `PeerIntroduction` (with
    `chat_id_attestation`) and authors Genesis, signing it with
    its `LogicalIdentityPk`. Genesis carries the founder's
    `AuthorizeDevice` for its own `PhysicalDevicePk`.
3.  Same device authors `AuthorizeDevice` nodes for the user's
    other devices it wishes to delegate to (these may be batched
    into a single admin-chain segment).
4.  Only after Genesis + initial `AuthorizeDevice`s are durable in
    local storage may the founder share NGC invite credentials
    with their other devices or with external peers.
5.  Founder's other devices join NGC via `gc_group_join`. They
    emit standard `PeerIntroduction` records (no attestation —
    they pass verification via Phase B step 6 against the
    `AuthorizeDevice`-populated `MemberInfo`).

This makes the founder-device-lifetime constraint explicit: if
the founder device is destroyed *before step 2 completes*, the
NGC cannot be bootstrapped to Merkle-Tox by anyone. The window is
sub-second on the founder device under normal conditions. After
step 4 completes, the founder device's special status is no
longer load-bearing — its delegations are durable on the DAG and
other founder-class devices can take over.

The alternative (transmitting `chat_id_sk` across the user's
devices via the cross-device conversation) is rejected: it would
spread the bootstrap secret across N devices, meaning a compromise
of *any* founder-class device during the bootstrap window could
mint a fraudulent attestation. The atomic-Genesis approach
constrains the secret to one device for the sub-second window in
which it matters.

### Attestation Persistence

The founder includes `chat_id_attestation` on **every**
`PeerIntroduction` they emit, not just the first. Reasons:

*   Late-joining verifiers in pre-Genesis bootstrap state may not
    have seen the founder's initial broadcast.
*   Receivers in clean-reinstall state (see "Clean Reinstall
    Recovery" below) may need to re-verify the founder's claim
    after losing their cached binding.
*   The marginal cost is one 64-byte signature per heartbeat
    re-emit (Section 4a heartbeat constants), negligible.

Receivers cache the attestation alongside the binding. Receivers
also serve the cached attestation as part of any
`AnchorSnapshot` response served via the §4 escape valve when the
requester is in pre-Genesis bootstrap state — though in practice,
once `AnchorSnapshot` exists, Genesis exists too and bootstrap
state is past.

A peer is permitted at most one *currently-cached* binding per NGC
peer_id. A new `PeerIntroduction` from the same NGC peer_id with a
higher `intro_epoch` replaces the cached binding atomically;
in-flight sync responses gated by the old binding are not retracted.

### Term: "Session"

In this document, a *session* spans from a `peer_join` callback firing
for a given NGC peer_id until the corresponding `peer_exit` callback
fires. Replay protection (step 3) extends across sessions: the
`intro_epoch` is persisted with the device's NGC self-key and survives
restarts, so an attacker cannot replay an older record even if they
catch the device offline.

### Clean Reinstall Recovery

A device that has lost its conversation state entirely (clean
reinstall, lost disk, restore-from-stale-backup) has an empty
highest-seen `intro_epoch` table and no `revoked_devices` list. Such
a device MUST NOT serve any sync responses, regardless of binding
validity, until it has bootstrapped current conversation state via
the §4 escape valve (specifically, fetched the latest
`AnchorSnapshot` and any `RevokeDevice` nodes for the conversation).

During the bootstrap window, the device MAY cache `PeerIntroduction`
bindings tentatively, but the cache is subject to retroactive
invalidation by §5 cache-invalidation rules as soon as
`RevokeDevice` nodes arrive. Specifically: when bootstrap completes,
the device scans all tentatively-cached bindings and applies §3
step 5 (revocation check) against the freshly-loaded
`revoked_devices` set. Bindings for revoked devices are invalidated
before any sync response is served.

This makes the bootstrap-window attacker (who replays a captured
`PeerIntroduction` of a now-revoked device) ineffective: they may
establish a tentative binding, but the freshly-reinstalled device
has no state to leak until bootstrap completes, and bootstrap
itself invalidates their binding.

For maximum safety, a device SHOULD recover conversation state
including the highest-seen `intro_epoch` table from an encrypted
backup tied to the same `LogicalIdentityPk` rather than relying on
a clean reinstall + sync. Encrypted backup format is outside this
document's scope.

### Emission Timing

All Merkle-Tox NGC custom packets are sent in *lossy* mode per
[Principle 9](merkle-tox-principles.md) (Marginal Tox Transport
Coupling). NGC's lossless mode is NOT used. A device emits
`PeerIntroduction`:

*   When the NGC `self_join` callback fires (c-toxcore
    `group_chats.c:1804`), the device broadcasts its current
    `PeerIntroduction` via `gc_send_custom_packet(lossless=false, ...)`
    to all currently-confirmed peers.
*   When the NGC `peer_join` callback fires (c-toxcore
    `group_chats.c:2746-2757`) for a peer the device has not yet
    introduced itself to, the device sends `PeerIntroduction` via
    `gc_send_custom_private_packet(lossless=false, ...)` to that peer
    specifically. `peer_join` is the earliest point at which custom
    packets to that peer are guaranteed to succeed (the peer's
    `gconn->confirmed` is true).
*   Because the lossy transport may drop a `PeerIntroduction` in
    flight, devices re-emit on a periodic heartbeat per §4a
    `NGC_PEER_INTRO_REEMIT_INTERVAL` (default 30s ± 5s jitter).
*   On receipt of a Merkle-Tox sync request from a peer for which
    no cached binding exists, the responder MAY re-emit its own
    `PeerIntroduction` to that peer (treating the sync request as
    an implicit "I don't have your binding" signal). To prevent a
    spam-and-extract amplification, the responder MUST rate-limit
    on-demand re-emits to **at most one re-emit per target NGC
    peer_id per `NGC_PEER_INTRO_REEMIT_INTERVAL`**, independent of
    the periodic heartbeat schedule. An attacker spamming sync
    requests from N forged-but-unbound NGC peer_ids therefore
    extracts at most one re-emit per peer_id per heartbeat
    period, capped by NGC's own per-peer state cost.
*   The `intro_epoch` is bumped only on deliberate rotation events
    (e.g. after a `RevokeDevice`-then-re-`AuthorizeDevice` cycle on
    the same `PhysicalDevicePk`, or if the device chooses to
    invalidate prior records for any reason). Routine NGC reconnects
    re-emit the *same* `PeerIntroduction` with the same `intro_epoch`;
    receivers accept it under the `>=` rule in verification step 3.

--------------------------------------------------------------------------------

## 4. Sync-Request Gating

Merkle-Tox sync messages (e.g. `SyncHeads`, `SyncSketch`, `SyncShardChecksums`)
disclose conversation metadata — DAG shape, node hashes, member-list
checksums — to the requester. Payload contents remain ratchet-encrypted,
but metadata is privileged.

A peer MUST gate sync responses by the `PeerIntroduction` binding:

*   If the requesting NGC peer_id has a valid cached binding to a
    `LogicalIdentityPk` that is in the Merkle-Tox `MemberInfo` set
    (or is a pending delegation candidate), serve the request.
*   If the binding is missing or invalid, drop the request silently.

This means an NGC peer who has joined the chat at the NGC layer but
has not yet provided a valid `PeerIntroduction` (or whose
`LogicalIdentityPk` is not a Merkle-Tox member) cannot extract
Merkle-Tox metadata from sync responses.

### Note on Bootstrap

A new joiner's first request is necessarily a sync request — they
have no local state yet. The order is:

1.  Joiner emits `PeerIntroduction` to all known NGC peers (on
    `self_join` and on each `peer_join`).
2.  Joiner sends sync request.
3.  Existing peers verify the introduction (Section 3). Step 4 of
    verification may require fetching the joiner's
    `DelegationCertificate` chain from a third party. See the escape
    valve below.
4.  Sync proceeds once the binding is fully valid.

If the joiner is not authorized at the Merkle-Tox layer (i.e. their
`LogicalIdentityPk` is not in `MemberInfo` and is not a *pending
delegation candidate*), they remain in the chat at the NGC layer
but receive no Merkle-Tox state. Their NGC presence is essentially
silent from the Merkle-Tox perspective.

### Bootstrap Escape Valve for Certificate Lookups

There is an apparent chicken-and-egg: a receiver gating sync by
binding cannot serve a joiner whose binding requires fetching the
joiner's own `DelegationCertificate` via sync. Resolution: receivers
MAY serve a narrow class of *certificate-lookup* requests without a
valid binding, gated tightly as follows:

**Permitted request types:**

*   `DelegationCertificate` lookup by `LogicalIdentityPk` — returns
    the most recent `DelegationCertificate` node from the DAG for
    that key. The returned node is a full `MerkleNode` signed by
    the issuing admin's `LogicalIdentityPk`, validatable
    independently against the requester's existing trust chain.
*   `AnchorSnapshot` lookup — returns the most recent
    `Content::Control(ControlAction::AnchorSnapshot { .. })` node
    for the conversation. The returned node is the full signed
    `MerkleNode`, NOT a decomposed `Vec<MemberInfo>` view. The
    requester verifies the Admin-key signature and the §3.17
    invariant 2 founder-slot rules locally before trusting any
    member information it carries.

Other sync messages (`SyncHeads`, `SyncSketch`, `SyncShardChecksums`,
`BlobReq`, opaque-segment requests, etc.) remain strictly
binding-gated.

**Response semantics:**

*   Responses are always full signed DAG nodes. Implementations MUST
    NOT decompose into "member-info diffs" or any other view that
    drops the enclosing signature.
*   Returning a node still requires the requester to perform the
    same verification a normal sync-derived node would undergo
    (signature, parent topology, admin-distance, §3.17 invariants).
    Transport-layer binding is not load-bearing for authenticity.

**Rate limits and membership-oracle defense:**

*   An unbound NGC peer's escape-valve budget is a **token bucket**
    with burst capacity 8 and refill rate 4 tokens per minute,
    aggregated across all request types and all queried keys — not
    a per-key budget. A higher per-key budget would let an
    attacker fish membership by issuing one request per guessed
    `LogicalIdentityPk`. The burst capacity (8) accommodates
    legitimate joiners who need multiple sequential fetches (e.g.
    a 3-hop delegation chain — founder → admin1 → admin2 → joiner
    — needs 3 `DelegationCertificate` lookups + 1 `AnchorSnapshot`
    = 4 requests under best-case, with headroom for lossy-mode
    packet loss requiring retries).
*   Responses to "not a member" and "rate-limited" queries MUST be
    indistinguishable to the requester. Both return uniform silent
    drop. This denies the requester a presence oracle even within
    their token budget.
*   Token refill is on a fixed wall-clock schedule (not per-request
    sliding window) to make timing-based budget probing harder.
*   Concrete constants: `NGC_ESCAPE_VALVE_BURST = 8`,
    `NGC_ESCAPE_VALVE_REFILL_PER_MIN = 4` (see §4a heartbeat
    constants for the rest).

After receiving the requested `DelegationCertificate`, the
responder re-runs the joiner's `PeerIntroduction` verification
(Section 3 Phase A step 4, then Phase B). On success, the binding
is established and the joiner's subsequent sync requests proceed
normally.

**Note on escape valve vs Phase B step 7:** the escape valve is
invoked from Phase A step 4 (delegation chain lookup) and is
distinct from Phase B step 7 (founder bootstrap-attestation
check). Step 7 verifies the `chat_id_attestation` directly
against `ConversationId` (the public key); it does not invoke the
escape valve or any external fetch.

### Silent Drop and Timing

Sync requests from unbound NGC peers are silently dropped. This is
not a fresh timing oracle: an unauthorized NGC peer can already
infer their lack of authorization by sending an authored Merkle-Tox
message and observing that it does not appear in other peers' UIs.
Silent drop is preferred over explicit error because it does not
let a malicious prober rapidly enumerate "what types of sync are
gated" — they receive uniform silence.

### Request-Response Identification

Merkle-Tox sync exchanges are stateful (e.g. `SyncHeads` → followed
by `SyncShardChecksums` → followed by node fetch). Each sync request
carries a `request_id` (chosen by the requester); responses echo
the `request_id`. Responders MUST NOT rely on NGC transport-layer
ordering or delivery guarantees — per
[Principle 9](merkle-tox-principles.md), Merkle-Tox uses lossy NGC
custom packets exclusively, so any sync packet may be dropped,
reordered, or duplicated. The `request_id` is what binds responses
to their requests; timeouts trigger application-level retries with
either the same or a different peer.

### Term: "Pending Delegation Candidate"

A `LogicalIdentityPk` is a *pending delegation candidate* if there
is a recently-received `DelegationCertificate` from an existing
admin authorizing them, but the certificate has not yet been
verified-and-applied to `MemberInfo` (e.g. the certificate is
awaiting parent-replay in the DAG). Pending candidates may
establish a valid `PeerIntroduction` binding (so they can fetch
their own `MemberInfo` updates), but receive no Merkle-Tox state
disclosures via sync until their `MemberInfo` entry is fully
verified.

--------------------------------------------------------------------------------

## 4a. Other NGC Features

This section addresses NGC features that interact with the
Merkle-Tox binding but do not warrant top-level sections.

### Blob Transfer over NGC

Blob transfer follows the existing `merkle-tox-cas.md` design:
chunk-level swarming, content-addressed fetch via `BlobReq` /
`BlobAvail` packets, MTU-fragmented by `tox-sequenced` over lossy
NGC custom packets (1373-byte payload, per §6). Each request and
response packet carries a `request_id` and is binding-gated by
§4.

The §7 reachability caveat is sharp here. CAS swarming
parallelises chunk delivery among reachable peers, but if a blob
is held *only* by peers unreachable to the requester (no UDP path,
no shared TCP relay), the blob is unfetchable until either (a) a
reachable peer also obtains and advertises the blob, or (b) a
direct reachability path opens. Time-bounded fetch guarantees do
not exist. Application UI must accept that some blobs may be in a
"pending — held by unreachable peer X" state.

### NGC Password Protection

c-toxcore NGC supports a chat-level password (`gc_set_password`,
`gc_get_password_size`). This gates *joining at the NGC layer*:
peers without the correct password are rejected at the NGC
handshake before any custom packet can flow. Merkle-Tox does not
interact with NGC password state. The password is access control
at the transport layer, orthogonal to Merkle-Tox membership.
Implementations need not surface NGC password state into
Merkle-Tox; conversely, changing the NGC password does not affect
existing Merkle-Tox bindings or sync state.

### Capability Negotiation

Merkle-Tox capability bits (per `merkle-tox-capabilities.md`)
are exchanged separately from `PeerIntroduction`. The natural
home for NGC-binding capability advertisement is `CapsAnnounce` /
`CapsAck` (existing `ProtocolMessage` variants). This document
does NOT extend `PeerIntroduction` to carry capabilities — keeping
the binding record minimal and well-versioned is preferred over
piggybacking optional features.

**Normative gating:** `CapsAnnounce` and `CapsAck` are
binding-gated like all other sync-class messages (§4). A device
emits `CapsAnnounce` to a given NGC peer immediately after that
peer's binding is established (Phase B success); receivers drop
`CapsAnnounce` packets arriving from unbound peers. This prevents
a fingerprinting channel in which an unbound NGC peer could
enumerate capability shapes against arbitrary targets.

### Heartbeat Constants

`PeerIntroduction` re-emission cadence (§3) and other periodic
Merkle-Tox-over-NGC operations should align with the c-toxcore
NGC ping interval (`GC_PING_TIMEOUT = 12s`, see
`group_chats.h:30`) and confirmed-peer timeout (`58s`). Concrete
named constants for this binding:

| Constant | Value | Rationale |
|---|---|---|
| `NGC_PEER_INTRO_REEMIT_INTERVAL` | 30s | Half-period of NGC's confirmed-peer timeout; gives two re-emit opportunities before NGC tears down the peer connection. |
| `NGC_PEER_INTRO_REEMIT_JITTER` | ±5s | Prevent re-emit storm correlation across N concurrent peers. |
| `NGC_SYNC_RETRY_INITIAL` | 5s | Application-layer sync request retry under lossy transport. |
| `NGC_SYNC_RETRY_MAX` | 60s | Exponential backoff cap. |

These are to be finalised against measured loss / latency once an
implementation exists; the values above are starting points
consistent with NGC's own timing primitives.

## 5. Membership Reconciliation

NGC and Merkle-Tox each have their own notion of membership. They
may legitimately disagree.

| Layer | Authority | Mechanism |
|---|---|---|
| NGC | "who can route custom packets in this chat" | NGC founder cert, NGC peer-list events, NGC kick (transient) and observer-sanctions (persistent) |
| Merkle-Tox | "who can author signed messages and read decrypted state" | `MemberInfo` set, `DelegationCertificate` chain, `AuthorizeDevice`/`RevokeDevice` events |

### NGC Moderation Primitives

c-toxcore NGC offers two moderation actions, with materially
different semantics:

*   **Kick** (`gc_kick_peer`, `group_chats.c:5131`): transient
    disconnect. The kicked peer is removed from current peer-lists
    via the `GM_KICK_PEER` broadcast, but **NGC has no persistent
    "kicked peers" list** — the peer can immediately rejoin with
    the same NGC self-key (public chat: rediscovered via DHT;
    private chat: needs a fresh invite). Kick is best understood
    as "ask the peer to leave now"; it is not a cryptographic
    revocation.
*   **Observer-sanction** (`gc_set_peer_role(... GR_OBSERVER)`,
    persisted in `Mod_Sanction` list, `group_moderation.h:54`):
    the peer remains in the group but cannot send any messages.
    Sanctions list is replicated and signed, so observer status
    persists across rejoin (within the ~30-entry list cap before
    pruning, `group_moderation.h:52`).

There is no NGC "ban" in the durable-permanent-block sense. For
durable cryptographic exclusion, use Merkle-Tox `RevokeDevice`.

### Possible Divergences

*   **NGC peer present, no Merkle-Tox membership.** An NGC user who
    has not been `AuthorizeDevice`-d (or whose `LogicalIdentityPk` is
    not in `MemberInfo`) sees NGC traffic but no Merkle-Tox state.
    Their `PeerIntroduction` is unbindable (Section 3, step 6 fails)
    until/unless their authorization arrives via Merkle-Tox sync.
    Sync requests from them are denied (Section 4), except the
    bootstrap escape valve for certificate lookups.
*   **Merkle-Tox member, not in NGC.** A user whose device is
    delegated and authorized in Merkle-Tox but who is not currently
    in the NGC is a Merkle-Tox member who cannot receive packets
    until they rejoin the NGC. Their messages from when they were
    offline are not delivered.
*   **NGC kicks a Merkle-Tox member.** The kicked peer cannot route
    NGC packets transiently. Their Merkle-Tox `MemberInfo` membership
    remains valid; they can still author messages locally and
    re-deliver them via the NGC after rejoining (NGC kick is
    transient — they can rejoin immediately with their persisted NGC
    self-key). Their cached binding at other peers remains valid
    across the kick-and-rejoin cycle (same `ngc_self_pk`, same
    `intro_epoch`). The kick acts as a temporary mute, not as
    cryptographic exclusion.
*   **Merkle-Tox `RevokeDevice` against a current NGC peer.** The
    revoked device's future packets are dropped at the Merkle-Tox
    layer. Cached `PeerIntroduction` bindings with
    `physical_device_pk` matching the revoked device MUST be
    invalidated immediately upon receipt-and-verification of the
    `RevokeDevice` node (see Cache Invalidation below). The NGC
    layer is not automatically informed; the application MAY use
    NGC observer-sanction to enforce silence at the transport
    layer as well, or simply rely on Merkle-Tox-layer drops.
*   **NGC founder leaves Merkle-Tox conversation.** A user who
    founded the NGC may leave the Merkle-Tox conversation (e.g.
    voluntary `Leave`, or `RevokeDevice` of all their devices) while
    retaining NGC founder role. Genesis is unchanged — Genesis is a
    historical assertion authored by the founder's
    `LogicalIdentityPk` and remains valid forever. Current-state
    sync gating (Section 4) uses the live `MemberInfo` set, so the
    ex-member-founder cannot extract Merkle-Tox state without a
    valid binding to a currently-present `LogicalIdentityPk`.
    NGC-layer founder powers (kick, observer-sanction) continue to
    work; this is harmless because they do not grant cryptographic
    access.

### Concurrent Action Convergence

If NGC kick and Merkle-Tox `RevokeDevice` against the same target
occur near-simultaneously, peers may receive the events in different
orders. The convergence rule:

*   **Merkle-Tox `MemberInfo` is the authoritative cryptographic
    membership state.** NGC peer-list reflects current
    *transport-layer reachability* and is descriptive, not
    authoritative.
*   If `MemberInfo` lists the target as a member but NGC has them
    kicked, the application UI MAY display them as "offline" or
    "removed at transport layer"; sync responses MUST still treat
    them as a member should they re-establish a binding.
*   If `MemberInfo` excludes the target (via `RevokeDevice`) but NGC
    still routes their packets, all merkle-tox-layer state from them
    is rejected at signature/membership verification; the NGC
    presence is harmless metadata.

### Cache Invalidation on `RevokeDevice`

When a `RevokeDevice(physical_device_pk = P)` Merkle-Tox node is
verified-and-applied, the receiver MUST:

1.  Scan all cached `PeerIntroduction` bindings for entries with
    `physical_device_pk == P` in the conversation matching the
    revocation's scope. Remove them.
2.  Immediately stop scheduling new sync responses tagged for any
    invalidated binding. This is the application-layer queue.
3.  Drain any not-yet-sent responses already queued in the
    `tox-sequenced` pacing buffer that are tagged for the
    invalidated binding.
4.  Persist the revocation in conversation state so that any
    `PeerIntroduction` arriving subsequently with a revoked `P`
    fails verification step 5.

Packets that have *already been handed to the NGC layer*
(`gc_send_custom_*_packet` returned success) may still be delivered
to the revoked peer. Under Principle 9 (lossy-only), there are no
ACKs to recall and no protocol-level cancellation. This is an
accepted small leak window, bounded by the time between
`tox-sequenced` send and NGC-layer transmission (typically
sub-millisecond on the local machine; potentially higher under
load).

Without this rule, an attacker who captured a pre-revocation
`PeerIntroduction` (and obtained the NGC self-secret-key) could
continue to receive sync responses until the cached binding
expired by other means.

### Recommended Policy

*   NGC moderation is a transport-layer tool. Use kick for
    spammers and abusive routing; use observer-sanction for
    persistent silencing at the transport layer.
*   Merkle-Tox `RevokeDevice` is the authoritative cryptographic
    revocation. It is the layer that protects future confidentiality.
*   The application UI should surface NGC moderation state and
    Merkle-Tox membership state as separate facts when they diverge,
    not collapse them into a single membership view.

### Required Coupling: RevokeDevice and NGC Observer-Sanction

An admin issuing `RevokeDevice` against a `PhysicalDevicePk` P
should not stop at Merkle-Tox cryptographic exclusion alone. The
revoked device's NGC self-key remains valid at the NGC transport
layer (NGC moderation and Merkle-Tox membership are independent
authorities), so P can continue to observe transport-layer metadata:
peer-list dynamics, sync-traffic timing patterns, `PeerIntroduction`
broadcasts from current members. This is the residual-leak surface
identified in Section 7's "Revoked ex-member" adversary.

Normative rule: when invoking `RevokeDevice` against P, the admin's
client SHOULD also issue an NGC `gc_set_peer_role(... GR_OBSERVER)`
against P's current NGC self-key (if known and currently present in
the NGC). This couples the two authorities for this specific
adversary case, deliberately overriding the "separate authorities"
default elsewhere in §5. Rationale: full cryptographic exclusion
without metadata exclusion is a fragile state in practice.

Failure modes:

*   **Admin lacks NGC moderation rights.** The admin may have
    Merkle-Tox admin role but not be the NGC founder or NGC moderator.
    In that case the coupling cannot be enforced and the revocation
    is degraded: P loses cryptographic access but retains
    NGC-layer observation. The application MUST surface this state
    to the user ("This user has been removed from the conversation
    but may still observe activity patterns at the network layer.
    Ask the group founder to fully expel them.").
*   **P is offline at revocation time.** The observer-sanction is
    enforced when P next rejoins (sanctions list is replicated
    in NGC state). No special handling needed.
*   **P held NGC founder role.** P cannot be observer-sanctioned
    without first being demoted. In practice: the Merkle-Tox-layer
    admin must coordinate with current NGC moderators to demote P
    first, then sanction. Application UI should warn that this
    specific case requires multi-step admin coordination.

### Self-Revoke (Lost Device)

The most common legitimate use of `RevokeDevice` is *self-revoke*:
a user lost a device (phone stolen, laptop wiped) and revokes that
device's `PhysicalDevicePk` from another of their devices. Naïve
application of Required Coupling fails: the revoking device
(e.g. user's laptop) typically does not hold NGC moderator role
across every NGC the user participates in — only one of the
user's devices is the original NGC peer with NGC moderator status
for any given NGC, and it might not be the device performing the
revoke.

**Required protocol for self-revoke:**

1.  The revoking device authors `RevokeDevice(P)` and broadcasts
    it via Merkle-Tox sync. This propagates cryptographic
    revocation as normal.
2.  The revoking device publishes a *coordination request* to the
    user's cross-device Merkle-Tox conversation: "`RevokeDevice`
    for `P` issued at time T; please observer-sanction `P`'s
    current NGC self-key in any NGC where you hold moderator
    rights." The cross-device conversation carries this between
    the user's devices.
3.  Surviving devices that hold NGC moderator rights in NGCs
    containing `P` issue `gc_set_peer_role(P_ngc_self_key,
    GR_OBSERVER)` on receipt of the coordination request. The
    NGC sanctions list propagates to all members.
4.  If no surviving device holds NGC moderator role in a given
    NGC, the coupling is degraded for that NGC; the application
    surfaces the residual metadata-leak risk to the user as in
    the "Admin lacks NGC moderation rights" failure mode above.

The cross-device coordination message is itself binding-gated
(within the cross-device conversation, which uses friend-transport,
not NGC). Its security is the same as any other cross-device
message. The lost device, if still online, cannot intercept or
forge the coordination because its `PhysicalDevicePk` is already
revoked by step 1.

--------------------------------------------------------------------------------

## 6. c-toxcore NGC Properties (Investigated)

The following properties of c-toxcore's NGC implementation are
load-bearing for this design and have been verified by reading the
c-toxcore source. Citations are to `/src/workspace/c-toxcore/toxcore/`.

1.  **NGC custom-packet size limit.** `MAX_GC_CUSTOM_LOSSLESS_PACKET_SIZE
    = MAX_GC_CUSTOM_LOSSY_PACKET_SIZE = 1373` bytes
    (`group_common.h:44-45`). Validated by
    `custom_gc_packet_length_is_valid` (`group_chats.c:4957-4959`).
    Applies to both broadcast and private packets. Caller must do
    its own application-layer fragmentation for larger payloads;
    `tox-sequenced` already does this.
2.  **Lossy semantics.** Lossy custom packets are pure fire-and-forget
    (`send_lossy_group_packet`, `group_chats.c:1580-1614`). No
    sequence numbers, no retransmission, no rate limiting, no
    backpressure visible to the caller. This is what Merkle-Tox
    uses (per [Principle 9](merkle-tox-principles.md)).
3.  **NGC peer-event callbacks.** `peer_join` fires when
    `gconn->confirmed` transitions to `true` after the full
    handshake + invite + peer-info exchange completes
    (`group_chats.c:2746-2757`); this is the earliest point at
    which custom packets to that peer succeed. `peer_exit` fires
    with a `Group_Exit_Type` enum disambiguating quit, timeout,
    disconnected, self-disconnected, kicked, or sync-error
    (`group_chats.c:6606-6613`). `self_join` fires when the local
    user's `connection_state` first reaches `CS_CONNECTED`
    (`group_chats.c:1804-1807`). A `moderation` callback fires on
    role changes including `MV_KICK` and `MV_OBSERVER` (sanction).
    There is no separate "send buffer drained" event.
4.  **NGC join sequencing.** `gc_group_join` is asynchronous and
    returns almost immediately. Custom-packet sends to a given peer
    are only safe after that peer's `peer_join` callback fires.
    Broadcast sends should wait for `self_join`. Discovery is via
    DHT onion-announce for public chats (`group_chats.c:8344`) and
    friend-routed invite for private chats (`gc_accept_invite`).
5.  **NGC moderation reversibility.** NGC has no persistent ban.
    Kick (`gc_kick_peer`, `group_chats.c:5131`) is transient: the
    kicked peer is removed from current peer-lists via broadcast,
    but there is no kicked-peers list in chat state — the peer can
    immediately rejoin with the same NGC self-key. Observer-sanction
    (`gc_set_peer_role(... GR_OBSERVER)`) is the persistent
    equivalent: the peer remains in the group but cannot send
    messages. Sanctions are replicated in a signed `Mod_Sanction`
    list capped at ~30 entries (`group_moderation.h:52`); old
    sanctions are pruned.
6.  **NGC routing.** **No mesh relay.** `send_gc_*_packet_all_peers`
    iterates over confirmed peers and sends each independently
    (`group_chats.c:2263-2314`); NGC peers do not forward custom
    packets on behalf of other peers. Each hop is direct UDP or
    TCP-relay (`gcc_send_packet`, `group_connection.c:595-622`). If
    two NGC peers cannot directly reach each other (no UDP path,
    no shared TCP relay), they cannot exchange custom packets even
    while both are connected to the rest of the group. This
    contrasts with c-toxcore Conferences, which DO mesh-relay
    through the friend graph (`group.c:2961`).

## 6a. Remaining Open Questions

*   **Pending-binding bootstrap escape-valve abuse.** Section 4's
    escape valve allows unbound NGC peers to issue a rate-limited
    number of `DelegationCertificate` / `MemberInfo` lookup
    requests. The exact rate and the precise set of permitted
    lookups need empirical tuning to balance bootstrap usability
    against metadata-fishing surface.
*   **Cross-device sync-amplification thresholds.** Section 2's
    responder-side dedupe needs concrete timing parameters (window
    width, what counts as "structurally equivalent" requests). To
    be tuned with measurements once the implementation exists.
*   **`tox-sequenced` over NGC lossy.** `tox-sequenced` is designed
    for friend-transport lossy packets. NGC custom packets have
    similar properties (no flow control, no retransmission, ~1373
    MTU) but may have different latency/jitter characteristics due
    to TCP-relay routing and DHT-discovered direct paths. May
    require BBR re-tuning, to be validated empirically.

--------------------------------------------------------------------------------

## 7. Threat Model Deltas vs Direct-Friend Transport

This section summarises what changes when a Merkle-Tox conversation
is transported over NGC versus directly over friend connections. See
[merkle-tox-threat-model.md](merkle-tox-threat-model.md) for the
base model.

| Property | Direct-friend transport | NGC transport |
|---|---|---|
| Transport-layer peer identity | long-term Tox friend PK | per-chat NGC ext keypair |
| Friend-graph linkage in-chat | implicit (each pair is a Tox friend) | none from in-protocol data |
| DHT enumerability | n/a (no DHT presence) | public NGCs: yes by `chat_id`; private NGCs: no |
| Required member-graph topology | path-connected through friend graph (for conferences) or pairwise friendship (current `ToxTransport`) | none — any DHT-reachable peer can join (public) or any invitee can join (private) |
| IP exposure to other members | yes (Tox friend connection) | TCP-relay routing hides IP unless self-announced (public NGC) |

### NGC-Specific Adversaries

*   **Passive DHT observer with `chat_id`.** For public NGCs, can
    enumerate currently-announced peers' NGC self-keys. Cannot link
    these to long-term Tox PKs or to peer-list state in other NGCs.
*   **Malicious NGC peer.** Joins via the NGC layer but has no
    Merkle-Tox authorization. Without a valid `PeerIntroduction`
    they are inert at the Merkle-Tox layer (Section 4). With a
    forged introduction (e.g. claiming a `LogicalIdentityPk` they
    don't control), verification fails (Section 3, steps 1-6). May
    issue a small bounded number of certificate-lookup requests
    (Section 4 escape valve); records returned are self-signed and
    do not reveal conversation state.
*   **NGC founder colluding with a member.** Founder can kick
    Merkle-Tox members at the transport layer, denying them
    routing *transiently* (kick is reversible; durable exclusion
    requires Merkle-Tox `RevokeDevice`). Cannot decrypt past or
    future Merkle-Tox payloads without the ratchet state of an
    actual member. Cannot forge `MemberInfo` changes without a
    Merkle-Tox-layer admin role.
*   **Revoked ex-member with cached NGC self-key.** A user who was
    a Merkle-Tox member, was `RevokeDevice`'d, but still holds
    their NGC self-secret-key (persisted at `group_pack.c:217`).
    They can re-join the NGC, but their `PeerIntroduction` fails
    verification step 5 (revoked-device check) so they receive no
    Merkle-Tox sync state. They can still observe NGC-layer
    metadata: peer-list dynamics, sync-traffic timing,
    `PeerIntroduction` broadcasts. Mitigation: §5 "Required
    Coupling: RevokeDevice and NGC Observer-Sanction" mandates
    that an admin issuing `RevokeDevice` SHOULD also
    observer-sanction the ex-member's NGC self-key. When this
    coupling fails (admin lacks NGC moderation rights, ex-member
    is NGC founder, etc.), the revocation is degraded and the
    metadata-observation surface remains as an accepted residual
    risk, surfaced to the user.
*   **NGC-layer DoS via custom-packet flood.** NGC has no
    transport-layer rate limit on custom packets. A malicious peer
    can spam at line rate. Merkle-Tox layer must impose its own
    per-binding rate limits on accepted records (sync requests,
    `PeerIntroduction` re-emissions). Inert NGC peers (no valid
    binding) are limited to the certificate-lookup escape valve's
    own rate limit.

### Reachability Caveat (No Mesh Relay)

NGC custom packets are routed direct peer-to-peer only
(c-toxcore §6 above). Two Merkle-Tox members in the same NGC who
cannot establish a direct UDP path AND do not share a TCP relay
cannot exchange Merkle-Tox traffic, regardless of being both
"in the group" by the NGC peer-list. This is materially different
from Conferences (which mesh-relay through the friend graph) and
from the direct-friend Merkle-Tox transport (where the pairwise
friendship implies a working Tox connection). Implications:

*   A Merkle-Tox conversation over a public NGC has its
    reachability bounded by per-pair NAT-traversal success +
    TCP-relay availability.
*   **Transitive content convergence, not request relay.** When
    peer A cannot reach peer C directly but both can reach peer B,
    A and C will converge transitively: A syncs with B, B syncs
    with C, eventually B's content store carries A's state to C
    and vice versa. This is a property of the existing
    content-DAG sync (any peer with a node serves it to any other
    peer who asks). It is NOT a request-routing protocol: there
    is no defined "A → B → C" sync-request relay. Latency is
    higher than direct sync (bounded by B's sync intervals with
    each side) and time-critical request/response semantics are
    not guaranteed.
*   **Distinct from CAS swarming.** The chunk-swarming mechanism
    described in `merkle-tox-cas.md` is for blob *content* fetch
    after both sides have advertised inventory via the Merkle-Tox
    sync exchange. Swarming does not bridge unreachable peers at
    the sync-coordination layer; it parallelises chunk delivery
    among reachable peers who hold the same content.
*   **Blob unreachability is sharper.** A blob held only by an
    unreachable peer is unreachable, period — there is no
    request-relay mechanism for sync coordination, and CAS
    swarming requires at least one *reachable* peer to advertise
    the blob's chunks. Application UI MUST handle this case
    (e.g. "this attachment is held by user X who is currently
    unreachable from your device").
*   Application UI should distinguish "member offline" from
    "member reachable only via this peer" from "member holds
    content nobody else has, and is unreachable to me" — the user
    experience differs materially across these states.

The base Merkle-Tox confidentiality property (ratchet-encrypted
payloads, multi-author signed history) is preserved under NGC
transport. NGC adds metadata-disclosure surface to other in-chat
peers but does not weaken cryptographic guarantees.
