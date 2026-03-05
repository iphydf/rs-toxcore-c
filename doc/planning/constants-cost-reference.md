# Merkle-Tox Constants Cost Reference

**Status:** Planning document. Cost analysis to support spec-quality decisions
on every load-bearing constant. Each section characterizes a constant's cost
function so that the chosen value reflects an explicit cost-vs-security
trade-off rather than an artifact.

**Method per constant:**
1. Current value and definition source.
2. Cost function: what gets worse as the constant is tightened or loosened.
3. Typical-case calculation (representative workload).
4. Worst-case calculation (heavy-user workload).
5. Mitigations for worst-case scenarios.
6. Recommended value and rationale.

**Workload definitions** (used across analyses):
- **Light:** 1 user in 3 conversations of 5 peers each, 10 msg/day per
  conversation.
- **Typical:** 1 user in 10 conversations of 20 peers each, 50 msg/day per
  conversation.
- **Heavy:** 1 user in 50 conversations of 200 peers each, 5000 msg/day per
  conversation.

--------------------------------------------------------------------------------

## Index

Status legend: ✅ analyzed | 🟨 partial (needs simulation) | ⬜ not yet started

| Constant | Status | Section |
|---|---|---|
| `ANNOUNCEMENT_ROTATION_INTERVAL_MS` (currently 30 days) | ✅ | [§1](#1-announcement-rotation-interval) |
| `MAX_HANDSHAKES_PER_ANNOUNCEMENT` (currently 100) | ✅ | [§2](#2-handshakes-per-announcement-opk-pool-size) |
| SenderKey rotation: time floor (currently 7 days) | ✅ | [§3](#3-senderkey-rotation-time-floor) |
| SenderKey rotation: message cap (currently 5000) | ⬜ | §4 |
| `MAX_GROUP_DEVICES` (currently 4096) | ⬜ | §5 |
| `MAX_DEVICES_PER_IDENTITY` (currently 32) | ⬜ | §6 |
| Skipped-key cache TTL (currently 24h) | ⬜ | §7 |
| `MAX_PARENTS` (currently 4096) | ⬜ | §8 |
| `MAX_ANCESTRY_HOPS` (currently 500) | ⬜ | §9 |
| `BASELINE_POW_DIFFICULTY` (currently 20 bits) | ⬜ | §10 |
| `MAX_HEADS_SYNC` (currently 64) | ⬜ | §11 |
| `MAX_SYNC_SHARDS` (currently 4096) | ⬜ | §12 |
| `SKETCH_CPU_BUDGET_MS` (currently 500ms / 60s) | ⬜ | §13 |
| `KEYWRAP_ACK_TIMEOUT_MS` (currently 30s) | ⬜ | §14 |
| `HANDSHAKE_PULSE_DEBOUNCE_MS` (currently 5 min) | ⬜ | §15 |
| NGC peer-intro re-emit interval (currently 30s ± 5s) | ⬜ | §16 |
| NGC escape-valve burst / refill (currently 8 / 4/min) | ⬜ | §17 |
| `OPAQUE_STORE_QUOTA` (currently 100 MiB) | ⬜ | §18 |
| `VOUCHER_TIMEOUT_MS` (currently 10s) | ⬜ | §19 |
| `MAX_VERIFIED_NODES_PER_DEVICE` (currently 1000) | ⬜ | §20 |
| `MAX_SPECULATIVE_NODES_PER_CONVERSATION` (currently 1000) | ⬜ | §21 |
| `MAX_AUTH_DEPTH` (currently 16) | ⬜ | §22 |
| `MIN_PADDING_BIN` (currently 128 bytes) | ⬜ | §23 |
| `MAX_EQUIVOCATIONS` (currently 1024) | ⬜ | §24 |
| `COMPACT_THRESHOLD` (currently 500 nodes) | ⬜ | §25 |

--------------------------------------------------------------------------------

## 1. Announcement Rotation Interval

**Defined at:** `tox-proto/src/constants.rs:122` as
`ANNOUNCEMENT_ROTATION_INTERVAL_MS = 30 days`. Cross-referenced
`merkle-tox-handshake-ecies.md` §1.

**Purpose:** Users publish a new Announcement node (containing fresh SPK and
OPKs) every N days, providing forward secrecy for the wrap layer that
delivers SenderKeys.

**Cost function:**
- Shorter (tighter) → more Announcement nodes / month → more
  upload/download per user, larger DAG growth, more frequent SPK private-key
  erasure (better FS, faster forgetting).
- Longer (looser) → fewer rotations → less traffic, longer compromise
  tail if SPK is leaked.

**Co-trigger:** Also rotates after `MAX_HANDSHAKES_PER_ANNOUNCEMENT = 100`
handshakes consumed, whichever comes first. So the time floor only matters
for users with low handshake rate.

### Cost calculation

Announcement node size:
- `identity_pk` (32) + `pre_keys` (N_opks × ~104 bytes) + `last_resort_key`
  (~104) ≈ **payload 16 + N_opks × 104 + 104** bytes
- Plus MerkleNode framing (parents, sender_pk, sig, etc.): ~200 bytes
- For default `MAX_HANDSHAKES_PER_ANNOUNCEMENT = 100`: 100 × 104 + 320 ≈
  **10.7 KB per Announcement**
- For typical-user-emit (~20 OPKs in pool): 20 × 104 + 320 ≈ **2.4 KB**

Per user, per year:

| Cadence | Light user (in 3 conversations) | Typical (10 conversations) | Heavy (50 conversations) |
|---|---|---|---|
| **30 days** (current) | 3 × 12 × 2.4 KB ≈ 86 KB upload + 86 KB × ~5 peers download = ~530 KB | 10 × 12 × 2.4 KB ≈ 290 KB upload + 290 × 20 download = ~6.1 MB | 50 × 12 × 2.4 KB ≈ 1.4 MB upload + 1.4 × 200 download = ~290 MB |
| **7 days** (candidate, aligned with SenderKey) | ~2.2 MB | ~26 MB | ~1.2 GB |
| **1 day** | ~15 MB | ~180 MB | ~8.5 GB |

**Delta 30→7 day:** Typical user +20 MB/year ≈ +1.7 MB/month. Heavy user
+0.9 GB/year ≈ +75 MB/month (notable on metered plans).

**Storage growth (persists in DAG):**
- 30-day at typical: ~3 MB / 5 years
- 7-day at typical: ~22 MB / 5 years
- 1-day at typical: ~155 MB / 5 years

### Worst-case scenarios

- **Heavy user on metered mobile data:** 50 conversations × 200 peers ×
  7-day rotation = ~100 MB/month inbound from peers' Announcements. On a
  500 MB/month plan, that's 20% of cap. Could be significant.
- **Very-long-offline user (>30 days):** With 30-day cadence, returner's
  SPK has expired; incoming handshakes use `last_resort_key`, triggering
  HandshakePulse-induced KeyWrap rotations on return. With 7-day cadence,
  this happens at any offline >7 days — more common.
  - Cost per return KeyWrap cascade: ~50ms CPU × N affected conversations.
    Bounded by Debounce (5 min/peer).
  - For a user offline 30 days returning to 5 affected conversations:
    ~250ms CPU work, processed over ~25 minutes wall-clock (Debounce caps).

### Mitigations

- For metered-data worst case: the user's client can elect to defer
  pulling other peers' announcements until the user is on unmetered
  network. Doesn't change protocol; affects client implementation.
- For long-offline worst case: KeyWrap-on-return cascade is bounded by
  Debounce; nothing changes structurally with rotation cadence.

### Recommended value

**7 days**, aligned with SenderKey rotation cadence. Rationale:
- Two security-relevant cadences (SPK and SenderKey) collapse into one
  number, simplifying the security model documentation.
- Typical-user cost is +1.7 MB/month, negligible.
- Heavy-user cost (+75 MB/month) is notable but the heavy-user profile
  (50 conversations × 200 peers) is uncommon; users at that scale are
  likely on unmetered networks.
- Provides a tighter compromise tail (7 days vs 30 days) for the wrap
  layer that delivers SenderKeys.

Acceptable alternative: **14 days** (between 7 and 30) for a more
conservative bandwidth posture; doesn't gain the cadence-alignment
benefit but halves the compromise tail vs 30. Recommendation stands
on 7 unless heavy-mobile-user metric is load-bearing.

--------------------------------------------------------------------------------

## 2. Handshakes per Announcement (OPK pool size)

**Bound vs runtime default — important distinction:**

- **Bound (cap):** `MAX_HANDSHAKES_PER_ANNOUNCEMENT = 100` at
  `tox-proto/src/constants.rs:118`. This is the type-level
  `BoundedVec` capacity on the `pre_keys` field. It also governs the
  rotation trigger: the device republishes after consuming 100 OPKs.
- **Runtime default (number actually generated):** historically **5**
  pre-keys per Announcement (`engine/authoring.rs` `for _ in 0..5`).
  Of these, by the convention in `engine/mod.rs::consume_recipient_opk`,
  `pre_keys[0]` is the SPK (never consumed) and `pre_keys[1..]` are
  OPKs. So the historical runtime gave 1 SPK + **4 OPKs**.
- **Current runtime default after the fix in this session: 64**
  (1 SPK + 63 OPKs). See commit message for the change.

**Purpose:** Each OPK is consumed by exactly one X3DH handshake (forward
secrecy property of the protocol — used-once keys cannot be replayed).
Pool size bounds the number of fresh-key inbound handshakes a peer can
receive between Announcement rotations before falling through to
`last_resort_key` (weaker FS — single long-lived key).

**Cost function:**
- Larger (more OPKs) → larger Announcement node payload (104 bytes per
  OPK), slightly more Ed25519 signature operations at
  announcement-creation time.
- Smaller (fewer OPKs) → faster fall-through to `last_resort_key` for
  long-offline returners with many pending incoming handshakes,
  compromising FS for those handshakes.

### Cost calculation

Announcement size as a function of pool size N (entries in `pre_keys`):

| Pool size | Total `pre_keys` bytes | + framing | Approx total |
|---|---|---|---|
| 5 (prior) | 5 × 104 = 520 B | ~320 B | **~840 B** |
| 32 | 32 × 104 = 3.3 KB | ~320 B | **~3.6 KB** |
| 64 (new) | 64 × 104 = 6.7 KB | ~320 B | **~7.0 KB** |
| 100 (cap) | 100 × 104 = 10.4 KB | ~320 B | **~10.7 KB** |

Worst-case offline-handshake scenarios (OPKs = pool_size − 1, since first
is SPK):

| Pool size | OPKs available | Typical offline returner (~8 pending) | Heavy returner (~50 pending) |
|---|---|---|---|
| 5 (prior) | 4 | 4/8 fall to last_resort = **50% FS regression** | 46/50 = **92% FS regression** |
| 32 | 31 | 0/8 (typical never exhausts) | 19/50 = 38% FS regression |
| 64 (new) | 63 | 0/8 | 0/50 |
| 100 | 99 | 0/8 | 0/50 |

### Storage / bandwidth impact

Going 5 → 64 adds ~6.2 KB per Announcement.

At the §1-recommended rotation cadence (7 days):
- Per user, per year, outbound (own Announcements): 52 × 6.2 KB ≈ **+320 KB/year**
- Per user, per year, inbound (peers' Announcements at typical = 20 peers
  per conversation × 10 conversations = 200 unique peers): up to **+1.2 MB/year**

For mobile metered-data plans on a 500 MB/month plan: +0.1 MB/month ≈
**0.02% of cap.** Imperceptible.

For DAG storage (Announcements persist): going 5 → 64 means each
Announcement is +6.2 KB on disk. Storage growth over 5 years for a
typical user: +1.6 MB cumulative. Imperceptible.

### Recommended value

**64** (1 SPK + 63 OPKs). Rationale:
- Closes a real FS regression for the typical-user offline-returner case
  (50% fall-through to last_resort_key at the prior pool=5).
- Bandwidth and storage cost is negligible (+0.1 MB/month for typical
  user, +1.6 MB cumulative over 5 years).
- Leaves headroom under the cap of 100 — doesn't max out the
  `BoundedVec` capacity, allowing for future growth without
  immediately re-exceeding.
- The agent recommendation of raising from prior runtime (5) toward the
  cap was correct in direction; 64 is the sweet spot.

### Status

**Implemented in this session.** `engine/authoring.rs:884` updated from
`for _ in 0..5` to `for _ in 0..64`. The cap constant
(`MAX_HANDSHAKES_PER_ANNOUNCEMENT = 100`) remains unchanged — runtime
default is now 64 with headroom for future tuning.

### Notes for future revisits

- The OPK `expires_at` field is hardcoded at "30 days from creation" in
  `authoring.rs:908`. When §1's Announcement rotation cadence is
  finalized (recommended 7 days), this expiry should be revisited —
  setting `expires_at = creation + 2 × rotation_interval` gives a
  reasonable grace window for in-flight handshakes targeting a
  recently-rotated Announcement.
- The SPK-vs-OPK distinction (first pre_keys entry is SPK, rest are
  OPKs) is positional and undocumented in `merkle-tox-handshake-ecies.md`.
  Spec-rewrite work should make this explicit: separate the SPK into its
  own field, or document the positional convention normatively.

--------------------------------------------------------------------------------

## 3. SenderKey Rotation: Time Floor

**Defined at:** `merkle-tox-principles.md` §1 ("epoch rotation ≤7 days /
5,000 messages") and `merkle-tox-deniability.md` §6.

**Purpose:** Sets the active-epoch length. The ephemeral signing key
private half is disclosed at this rotation; content authored in the prior
epoch becomes deniable (signature provides no provenance).

**Cost function:**
- Shorter floor → more frequent SenderKeyDistribution nodes → more
  bandwidth + storage. Crucially, also **shorter non-deniable window for
  authored content**.
- Longer floor → less traffic, but longer window during which content
  signatures provide cryptographic provenance.

**Co-trigger:** Also rotates after 5000 authored messages (whichever
comes first). So the time floor only matters when authoring volume is
low.

### Cost calculation

SenderKeyDistribution node size:
- Per-recipient `WrappedKey` entry: ~80 bytes (32 nonce + 32 ciphertext +
  16 MAC) + ~24 framing = ~104 bytes
- Per-conversation distribution: 200 bytes framing/sig + N_recipients ×
  104 bytes
- For N=20: ~2.3 KB
- For N=200: ~21 KB
- For N=4096: ~430 KB

Rotation frequency:
- Floor=7 days: max(1/week, 1/5000 msgs)
- Floor=1 day: max(1/day, 1/5000 msgs)

| Workload | Floor=7d rotations/month | Floor=1d rotations/month | Delta |
|---|---|---|---|
| Light (10 msg/day) | 4 (time-bound) | 30 (time-bound) | +26 |
| Typical (50 msg/day) | 4 (time-bound) | 30 (time-bound) | +26 |
| Active (200 msg/day) | 4 (time-bound) | 30 (time-bound) | +26 |
| Heavy (5000 msg/day) | ~30 (msg-bound) | ~30 (msg-bound) | 0 |

Per-user-per-month, broadcast cost (all conversations):

| Workload | Floor=7d cost | Floor=1d cost | Delta |
|---|---|---|---|
| Light (3 conversations, N=5) | 4 × 0.7 KB × 3 = 8.4 KB | 30 × 0.7 × 3 = 63 KB | +55 KB |
| Typical (10 conversations, N=20) | 4 × 2.3 × 10 = 92 KB | 30 × 2.3 × 10 = 690 KB | +598 KB |
| Heavy (50 conversations, N=200) | ~30 × 21 × 50 = 31 MB | ~30 × 21 × 50 = 31 MB | 0 (cap-bound) |

**Storage growth over 5 years** (broadcast nodes persist in DAG):

| Workload | Floor=7d | Floor=1d |
|---|---|---|
| Light | 504 KB | 3.8 MB |
| Typical | 5.5 MB | 41 MB |
| Heavy | 1.9 GB | 1.9 GB |

### Security benefit of shorter floor

Active-epoch length is the **non-deniable window** for content authored
in that epoch. After the next rotation discloses the ephemeral signing
key, content from the prior epoch is deniable (anyone with the disclosed
key could have signed it).

| Floor | Non-deniable window for newly-authored content |
|---|---|
| 30 days | Up to 30 days |
| 7 days | Up to 7 days |
| 1 day | Up to 1 day |
| Per-message (Signal Double Ratchet) | Per-message PCS; no equivalent window |

For users whose threat model includes subpoena/coercion, the 1-day
window means a subpoena issued within 1 day of message authoring can
prove authorship cryptographically; older content is deniable.

### Worst-case scenarios

- **Heavy user (cap-bound) sees no resource impact** moving from 7-day
  to 1-day floor. Storage and bandwidth unchanged.
- **Typical user pays +600 KB/month upload broadcast**, ~0.1% of any
  reasonable data plan. Storage +35 MB / 5 years.
- **Light user pays +55 KB/month**, imperceptible.

### Recommended value (revised)

**7 days** for the time floor (status quo). Original recommendation
of 1 day was based on per-user *authoring* cost only and missed the
interaction with group size: at 1-day cadence in a large group
(e.g. N=256), each member sees ~256 rotations/day broadcast, costing
~240 MB/month per conversation (see §5). At 7-day cadence the same
group costs ~34 MB/month — heavy but manageable.

The trade-off:
- **1-day floor:** non-deniable window ≤1 day for content authorship.
  Cost scales linearly with group size; large-group cases become
  bandwidth-heavy.
- **7-day floor:** non-deniable window ≤7 days. Same family as
  Signal/MLS-class systems offer for similar deniability properties.
  Bandwidth scales-with-group-size still applies but stays in usable
  ranges at all v1-target group sizes (≤256).

Keeping 7-day floor gives content deniability with a 7-day delay,
which is the standard published bar for delayed-disclosure
deniability. Tightening to 1-day would only be worthwhile if a
specific user-facing security claim demanded it; absent that, the
bandwidth cost dominates the analysis.

### Storage / per-user totals at 7-day floor

| Workload | Per-user per-month receive | Per-user per-month upload | 5-year DAG growth (own authoring) |
|---|---|---|---|
| Light (3 conversations, N=5) | ~7 KB | ~3 KB | ~50 KB |
| Typical (10 conversations, N=20) | ~190 KB | ~30 KB | ~1.5 MB |
| Heavy (50 conversations, N=200) | ~60 MB (cap-bound) | ~3 MB | ~150 MB |

All comfortable.

--------------------------------------------------------------------------------

## 5. MAX_GROUP_DEVICES

**Defined at:** `tox-proto/src/constants.rs:88` as `MAX_GROUP_DEVICES = 4096`.
Used as the `BoundedVec` cap on `KeyWrap.wrapped_keys`,
`SnapshotData.members`, `SnapshotData.last_seq_numbers`, and several
related fields in `merkle-tox-core/src/dag.rs`.

**Purpose:** Maximum number of authorized device public keys per
conversation. Bounds the size of every `KeyWrap` node (which must
include one `WrappedKey` per authorized device) and every
`AnchorSnapshot` membership table.

**Cost function:**
- Larger cap → bigger maximum `KeyWrap` size; more fragmentation
  at the transport layer; more bandwidth per rotation; more
  fragments susceptible to loss-induced retransmit.
- Smaller cap → smaller maximum group size; rejection of any
  conversation that would exceed the cap.

### Cost calculation

`WrappedKey` size:
- `recipient_pk` (32) + `opk_id` (32) + `ciphertext` (48 with
  ChaCha20-Poly1305 wrapping a 32-byte K_conv or SenderKey) +
  MessagePack framing (~10) = **~122 bytes per WrappedKey**

`KeyWrap` node size as a function of MAX_GROUP_DEVICES N:
- N × 122 (wrapped keys) + 8 (generation) + 32 (anchor_hash) +
  ~20 (MessagePack framing) + ~200 (MerkleNode framing + signature)
  = **~260 + N × 122 bytes**

| N (MAX_GROUP_DEVICES) | KeyWrap size | Fragments @ 1373-byte MTU | Notes |
|---|---|---|---|
| 32 | ~4.2 KB | ~3 | Small-group sweet spot |
| 64 | ~8.1 KB | ~6 | Mid-size groups |
| 128 | ~16 KB | ~12 | |
| 256 | ~31 KB | ~23 | Agent-recommended |
| 512 | ~63 KB | ~46 | Manageable but heavy |
| 1024 | ~125 KB | ~92 | Painful under loss |
| 2048 | ~250 KB | ~183 | Stretches `tox-sequenced` reasonability |
| 4096 (current) | ~500 KB | ~365 | **Operationally infeasible** under any real network conditions |

### KeyWrap rotation frequency

`KeyWrap` is triggered by:
- Membership change (`AuthorizeDevice` / `RevokeDevice`)
- Epoch rotation (currently triggered by §3 SenderKey rotation
  schedule, transitively)
- Explicit refresh on `HandshakePulse` reception

For a group with N members, each member's device generates one
`KeyWrap` per rotation event addressed to all N-1 other members'
devices. Per-conversation bandwidth scales with N² across all
rotations.

### Per-conversation bandwidth analysis

At the **7-day SenderKey rotation cadence** (per §3, revised):

| N | Rotations/week across group | KeyWrap size | Per-user monthly download per conversation |
|---|---|---|---|
| 32 | 32 | 4.2 KB | ~0.56 MB/month |
| 64 | 64 | 8.1 KB | ~2.3 MB/month |
| 128 | 128 | 16 KB | ~8.9 MB/month |
| 256 | 256 | 31 KB | ~34 MB/month |
| 512 | 512 | 63 KB | ~137 MB/month |
| 1024 | 1024 | 125 KB | ~542 MB/month |
| 4096 | 4096 | 500 KB | **~8.7 GB/month** per conversation |

For reference, at 1-day rotation cadence (rejected per §3): multiply
all of the above by ~7. N=256 reaches ~240 MB/month, N=512 reaches
~960 MB/month, N=4096 reaches >60 GB/month — operationally
infeasible.

Per-user download (sees every other member's KeyWrap):
- N=32: ~0.56 MB/month. Imperceptible.
- N=64: ~2.3 MB/month. Easy on all plans.
- N=128: ~8.9 MB/month. Easy.
- N=256: ~34 MB/month. Notable but manageable.
- N=512: ~137 MB/month. Heavy.
- N=4096: ~8.7 GB/month per conversation. Unworkable for any normal user.

### Fragmentation behavior

Tox custom packets are lossy and have a 1373-byte MTU. A KeyWrap node
fragments into ceil(size / 1353) packets in `tox-sequenced` (1353 =
MTU - 20-byte transport header).

Loss recovery for a node with K fragments has expected-completion-time
that grows linearly with K under uniform loss and quadratically under
correlated loss. For N=4096 (365 fragments), even 1% packet loss makes
KeyWrap delivery routinely take seconds. Under realistic wireless
conditions (5% loss), it becomes unreliable.

For N=256 (23 fragments), 1% loss adds ~25% latency; 5% loss is
recoverable. Still painful but workable.

### Worst-case scenarios

- **Maximum legitimate use case at current 4096 cap:** never actually
  achievable. No real Tox group has been or could be 4096 devices.
  The cap is theoretical.
- **Heavy realistic case at N=256:** community chat with 256 members.
  ~34 MB/month per member at 7-day rotation. Manageable on most
  data plans; notable for very-tight metered users.
- **Typical case at N=20:** family group or small team. ~0.2 MB/month
  per member. Imperceptible.

### Mitigations

- **`SenderKey` rotation can be epoch-based** rather than per-msg
  count, reducing total rotation count for active heavy conversations.
- **Late-joiner fallback to `AnchorSnapshot`** rather than DAG replay
  avoids each joiner having to download every historical KeyWrap.
- **CAS-based blob fetch** does not scale with N (each blob is fetched
  once per peer, not N times).

The fundamental issue with N=4096 is not fixable by mitigations —
the KeyWrap size is structural. A future cap higher than ~512
requires a different group-key-distribution scheme (TreeKEM-style,
MLS-style), out of scope for v1.0.

### Recommended value

**256**, per the agent's recommendation. Rationale:
- Closes the operationally-infeasible-4096 case.
- Supports community-chat-sized groups (256 members) with manageable
  bandwidth (~240 MB/month per member, heavy but acceptable on
  unmetered networks).
- Leaves the door open for a future v2.0 cap raise via TreeKEM-style
  group-key derivation (which would make per-`KeyWrap` size
  log(N) rather than N, allowing N=4096+ in a future spec version).
- Mid-spec values (128, 512) are defensible. 128 is more conservative
  (closer to typical group sizes), 512 supports larger communities
  at higher bandwidth cost.

**Decision needed:** confirm 256, or push to 512 or 128.

### Future-direction note

Once v1.0 ships, a v2.0 design conversation should evaluate
TreeKEM-based group key derivation specifically to raise the
practical cap. v1.0 will be limited to ~256-512 by design; this
is honest and aligned with Signal/Matrix patterns.

--------------------------------------------------------------------------------

## 4. SenderKey Rotation Message Cap

**Defined at:** `merkle-tox-principles.md` §1 ("epoch rotation ≤7
days / 5,000 messages"). Co-trigger with §3 time floor.

**Purpose:** Bounds the number of messages signed under one
ephemeral signing key. After this many messages, the key rotates
even if the time floor hasn't elapsed.

**Cost function:**
- Lower cap → more frequent rotations under high-traffic
  conditions → more `KeyWrap` traffic in active groups.
- Higher cap → potentially long-lived ephemeral signing keys in
  very-low-traffic groups (until the time floor fires); each
  individual key signs more content (no security impact —
  signatures are independent — but slightly more material at risk
  if the key leaks).

**Co-trigger:** rotates on max(time floor, message cap). For
groups doing >cap/7 messages per day (cap=5000 → >714 msg/day),
the message cap is the binding constraint. For everything else,
the time floor dominates.

### When does the message cap matter?

The cap bounds the worst-case "very active group keeps rotating
forever" case. For a group authoring 10000 messages/day across
all members (large public chat, busy team), each member who
authors ~1000+ messages/day would hit the cap and rotate
multiple times per day.

A heavy single-author case: someone authoring 5000+ messages/day
themselves rotates daily (or more). Bandwidth: their own SenderKey
distribution costs ~31 KB per rotation × N peers per conversation.
At N=256 and 1 rotation/day from this author: 31 KB × 256 = ~8 MB/day
just for this author's rotations. Per month: ~240 MB just for one
hyperactive author. The cap protects against this growing without
bound.

### Storage impact

Each KeyWrap rotation creates a node persisted in the DAG. More
rotations → more nodes → more storage. At cap=5000 and a heavy
author of 10000/day: 2 rotations/day × ~30 days = 60 KeyWraps/month.
At N=256 each KeyWrap is ~31 KB. Personal storage for own rotations:
60 × 31 KB = ~2 MB/month for own authoring (× group size for total
DAG growth visible to all peers).

### What if the cap were 1000 or 50000?

- **1000:** an active author rotates 10× more often. Bandwidth/storage
  per active conversation scales 10×.
- **5000 (current):** active authors at 1000 msg/day rotate every 5
  days. Time-bound (7 days) almost always wins; cap rarely fires.
- **50000:** active authors at 1000 msg/day rotate every 50 days.
  Time-bound (7 days) wins; cap effectively never fires.

So the cap matters only for very-heavy authors (>500-700 msg/day
sustained). For typical authoring rates (10-100 msg/day per
person), the cap is essentially dead — the time floor always
fires first.

### Security implication

Each ephemeral signing key signs at most `cap` messages. If the
key is compromised, the attacker can forge content signatures
that look indistinguishable from the legitimate ones, for that
many messages within the active epoch. Lower cap = smaller
forgery window per compromise.

But: forward secrecy is per-rotation, not per-message. A key is
compromised → all messages in its epoch are forgeable until the
key rotates. Cap=5000 means 5000 messages per worst-case
compromise; cap=1000 means 1000. For an attacker who maintains
device access continuously across rotations, the per-rotation
cap doesn't help — they get the new key too. So this is
specifically about *catch-and-recover* compromise scenarios, not
sustained ones.

### Recommended value

**5000 (current).** The cap is doing what it's designed to do:
bound the worst-case heavy author. Tightening to 1000 would force
~10× more rotations for the small set of very-heavy authors with
no benefit for typical users. Loosening to 50000 effectively
removes the cap, which is fine 99% of the time but lets a sustained
compromise grow unboundedly during the active epoch.

5000 messages is also a reasonable round number for "much more
than any reasonable person authors in a week." Realistic typical
authoring: 10-50 msg/day. Heavy: 200-500 msg/day. Hyperactive:
1000-2000 msg/day. The cap fires only at the top of the
hyperactive band.

### Open consideration

The interaction with §3 (7-day time floor): for the very-heavy
authors who hit the cap, 7-day floor is essentially irrelevant —
they're rotating every couple of days regardless. For everyone
else, 7-day floor binds. The two are well-matched at current
values.

--------------------------------------------------------------------------------

## 6. MAX_DEVICES_PER_IDENTITY

**Defined at:** `tox-proto/src/constants.rs:84` as
`MAX_DEVICES_PER_IDENTITY = 32`.

**Purpose:** Maximum number of devices a single `LogicalIdentityPk`
may have authorized in a single conversation. Prevents resource
exhaustion via delegation spam from a single (possibly compromised)
identity.

**Cost function:**
- Higher: each user can have more devices (phone, laptop, tablet,
  watch, work laptop, etc.). Looser cap allows real heavy
  multi-device users.
- Lower: tighter bound on per-user device proliferation; less
  attack-leverage per compromised master seed.

### Practical real-world device counts

Realistic device counts per user:
- Single-device user: 1
- Phone + laptop: 2
- Phone + laptop + tablet: 3
- Power user (separate work / personal devices): 4-6
- "Many devices" (developer with multiple test devices, etc.): 7-12

32 is well beyond any realistic legitimate device count.

### Interaction with MAX_GROUP_DEVICES

At MAX_GROUP_DEVICES = 256 and MAX_DEVICES_PER_IDENTITY = 32:
worst case is 256/32 = 8 unique identities in a group. That's a
weird limit; real groups have 50-200 identities each with ≤5
devices.

Lower MAX_DEVICES_PER_IDENTITY = lower attack leverage per
compromised master seed:
- 32: 12.5% of group's device budget per compromised identity
- 16: 6.25%
- 8:  3.1%

### Recommended value

**Keep at 32.** Rationale:
- 32 is well above any realistic legitimate user. Lowering to
  16 or 8 only matters as adversarial-leverage tightening,
  which is a soft consideration: master-seed compromise is the
  bigger problem, and the cap doesn't protect against that.
- Headroom for unusual legitimate cases (developers, IoT
  device fleets, future use cases we haven't anticipated).
- Worst-case interaction with MAX_GROUP_DEVICES = 256 (only
  8 identities if all max out) is an artifact, not a likely
  reality — real groups won't see this distribution.

Defensible alternative: **16** for tighter adversarial-leverage
posture. Halves the worst-case compromise impact at no realistic
cost to legitimate users.

--------------------------------------------------------------------------------

## 7. Skipped-Key Cache TTL

**Defined at:** `merkle-tox-ratchet.md` §4.3.

**Purpose:** Out-of-order message handling. When a message
arrives out-of-sequence relative to the ratchet's expected
counter, the engine derives the missing intermediate keys and
caches them so subsequent late-arriving messages can be decrypted.
TTL bounds how long these keys are retained.

**Cost function:**
- Longer TTL: better tolerance for offline-then-online scenarios;
  late messages within window decrypt reliably.
- Shorter TTL: tighter forward secrecy; compromised device has
  fewer keys to compromise.
- Persistence to disk: keys survive restart (better UX); but
  device seizure within TTL window decrypts cached messages.

### Current behavior

24-hour TTL, persisted in an encrypted local table. Trades FS
for offline-message-recovery UX.

### Per the design-decisions subagent (and pre-1.0 authorized)

**RAM-only**, no disk persistence. Documented as accepting the
loss-of-late-messages property when a client restarts.

Rationale:
- Persistence is a real device-seizure vector. A user's device
  seized within the 24h window decrypts all cached skipped keys —
  i.e., messages they'd recently chosen NOT to read but were
  still pending decryption. Strict FS protection requires that
  these keys exist only in volatile memory.
- The "I restarted my client and lost some late-arriving
  messages" case is recoverable: another peer still has the
  messages and the keys; standard DAG sync will redeliver them.
  Loss is bounded to the specific corner case where the user's
  client restarts during a partial-receive window.
- For the target user (privacy-conscious, threat-aware), this
  trade-off is the right call.

### Recommended value

**RAM-only with no TTL** — keys live in memory until either (a)
the corresponding messages arrive and the keys are consumed, or
(b) the engine evicts them when memory pressure or operational
need dictates. Implementation-defined eviction policy
(LRU + a configurable max-cache-size).

Note: this is **a security-property choice authored by the pre-1.0
batch authorization** (the user explicitly approved RAM-only
skipped keys earlier in the design phase). Documented here for
the cost-reference record.

### Implementation note

`merkle-tox-ratchet.md` §4.3 currently specifies the persistent
24h-TTL behavior. That section will need updating during the
spec-rewrite to match the new RAM-only policy.

--------------------------------------------------------------------------------

## 10. BASELINE_POW_DIFFICULTY

**Defined at:** `merkle-tox-core/src/dag.rs:388` as
`POW_DIFFICULTY: u32 = 20` (bits of leading zeros). Documented in
`merkle-tox.md` constants section.

**Purpose:** Proof-of-work requirement on Genesis nodes. Anti-spam
for conversation creation.

**Cost function:**
- Higher difficulty: slower Genesis creation, deterring bulk
  spam; slower onboarding for legitimate users.
- Lower difficulty: faster onboarding, weaker spam deterrent.

### Time cost

20 bits = ~1 million Blake3 hash operations. On a modern desktop
at ~1M Blake3 hashes/second per core, this is ~1 second of CPU.
On a smartphone, similar (maybe 1-3 seconds depending on hardware).

| Difficulty | Average time on desktop | Average time on phone |
|---|---|---|
| 16 bits | ~0.06 s | ~0.2 s |
| 20 bits (current) | ~1 s | ~3 s |
| 22 bits | ~4 s | ~12 s |
| 24 bits | ~16 s | ~48 s |
| 26 bits | ~64 s | ~3 minutes |

### What does the PoW actually protect against?

Genesis PoW is NOT collision resistance — 20 bits is far too few
for that (256 bits would be needed for full preimage resistance
on a 256-bit hash output).

Genesis PoW IS:
- Anti-creation-spam: bulk-creating fake conversations is slowed.
- Soft sybil-resistance on conversation creation: an attacker
  cannot trivially flood with millions of conversation IDs.

What it does NOT protect against:
- Membership spam within an existing conversation (different
  defense: admin authorization).
- Sybil at the identity level (defense: master-seed
  ownership and delegation chain).
- Targeted Genesis collision attacks (impractical for any sane
  hash).

### Realistic threat assessment

In a P2P system, conversations are private; you have to be
invited. Random peers don't see attackers' Genesis nodes. So
"Genesis spam" mostly targets specific receivers who got
invited to fake conversations — which is itself an
invite-spam problem, not a Genesis-spam problem.

The PoW is therefore mostly a hedge against an attacker who
gains some channel for distributing invites at scale. 20 bits =
1 second per Genesis is ~3600/hour. At that rate, a one-person
spam operation could create ~85K fake Genesis nodes per day on
a single CPU. Notable but not unbounded.

### Recommended value

**Keep at 20 bits.** 1 second on desktop / 3 seconds on phone is
acceptable user-facing latency for conversation creation. Strong
enough to slow bulk operations; weak enough to not annoy real
users.

Defensible alternatives:
- 22 bits (~4 sec desktop / ~12 sec phone) for tighter spam
  deterrence. Real users feel the delay.
- 18 bits (~0.25 sec desktop) for faster onboarding. Bulk
  attacker rate increases 4×.

20 is a reasonable middle.

### Notes

- Smartphone PoW timing is dominated by clock speed and core
  count. Modern phones can be faster than desktops for short
  bursts on a single core. The 3-sec phone estimate is
  conservative.
- If PoW computation becomes problematic on resource-constrained
  devices (older Android, embedded), consider a difficulty
  *announcement* mechanism: the spec specifies a base difficulty,
  but the founder's client may declare a lower difficulty for
  conversation-specific use (subject to network-wide minimum).
  Not needed for v1.

--------------------------------------------------------------------------------

## 13. SKETCH_CPU_BUDGET_MS

**Defined at:** `tox-proto/src/constants.rs:134` as
`SKETCH_CPU_BUDGET_MS: u32 = 500` over a `SKETCH_CPU_WINDOW_MS:
u32 = 60_000` (1 minute) sliding window. Documented in
`merkle-tox-threat-model.md` §3.3b and `merkle-tox-reconcile.md` §3.C.

**Purpose:** Per-peer CPU budget for IBLT sketch peeling.
Anti-DoS: a malicious peer can craft sketches that decode
slowly (close to worst-case peeling time), so per-peer CPU
budget bounds resource exhaustion under attack.

**Cost function:**
- Higher budget: more sketch processing per peer per window;
  better sync reliability under heavy legitimate load.
- Lower budget: tighter DoS protection; legitimate heavy sync
  scenarios may hit the limit and degrade.

### Workload sizing

Legitimate use:
- A peer reconciling a small DAG difference: 1-10 sketches per
  minute, each ~10-50 ms peel time. Total: 50-500 ms per
  minute, well within budget.
- A new joiner syncing a large DAG: 20-50 sketches in a burst,
  ~100 ms each. Total: 2-5 seconds spread across multiple peers
  (each peer's budget is independent). Per-peer: well within.

Adversarial use:
- An attacker can send sketches as fast as the network allows.
- Each sketch costs up to ~100 ms peel-time at the receiver
  if maliciously constructed.
- 500 ms budget caps at ~5 worst-case sketches per minute per
  peer before further sketches are dropped with `SYNC_RATE_LIMITED`.

### Total CPU exposure under sustained attack

If 10 peers are attacking simultaneously:
- 10 × 500 ms = 5 seconds CPU per minute = ~8% sustained CPU
- Combined with the threat model's exponential blacklist tier
  (`merkle-tox-sync.md` §2), attackers who consistently fail
  sketch decoding are blacklisted, reducing sustained pressure
  over time.

8% CPU under sustained attack from 10 peers is acceptable;
the system stays responsive. If 100 peers attack simultaneously,
CPU pressure is 80% — the application stays usable but
sluggish; blacklist tiering should reduce this rapidly.

### Recommended value

**Keep at 500 ms / 60 s.** The chosen value:
- Comfortably handles legitimate sync bursts.
- Provides a hard CPU cap independent of attacker resources.
- Combined with blacklist escalation, attackers cannot
  sustain pressure long.

Defensible alternatives:
- 250 ms / 60 s for tighter protection (legitimate heavy
  syncs may degrade slightly).
- 1000 ms / 60 s for more headroom (CPU exposure doubles
  under attack).

500 ms is a reasonable middle.

### Open question

The interaction with sketch tier choice (`merkle-tox-reconcile.md`
defines Small, Medium, Large sketches with progressively higher
peel cost). The budget applies to all tiers; an attacker would
preferentially use Large tier for worst-case peel cost. Verify
that 500 ms accommodates the largest legitimate Large-tier
sketch (sustained legitimate IBLT decode for a 4096-shard
difference should fit). To be confirmed during sync-protocol
spec drafting.

--------------------------------------------------------------------------------

## 16. NGC PeerIntroduction Re-emit Interval

**Defined at:** `merkle-tox-ngc.md` §3 "Emission Timing" and §4a
"Heartbeat Constants" as `NGC_PEER_INTRO_REEMIT_INTERVAL = 30s`
with `NGC_PEER_INTRO_REEMIT_JITTER = ±5s`.

**Purpose:** Under lossy NGC custom-packet transport (per
Principle 9), `PeerIntroduction` records may be dropped. The
heartbeat re-emits them periodically so any peer that missed
the original eventually receives one.

**Cost function:**
- Faster (shorter interval): faster recovery from lost intros;
  more bandwidth overhead.
- Slower (longer interval): less overhead; longer window where
  a peer who joined mid-session lacks our binding.

### Workload

`PeerIntroduction` size: ~200 bytes (LogicalIdentityPk +
PhysicalDevicePk + NGC self-pk + intro_epoch + signature +
optional chat_id_attestation + MessagePack framing).

At the current 30s heartbeat: 2 emissions per minute.

If broadcast to all peers in the NGC (which the current design
implies):
- N=32 group: 32 × 200 bytes × 120 emit/hour = ~770 KB/hour per
  sender = ~550 MB/month per sender for heartbeat alone
- N=256 group: 256 × 200 × 120/hour = 6 MB/hour = ~4.4 GB/month
  per sender

**This is much heavier than the cost-reference §1 and §3
analyses imply** because heartbeats are unconditional and to
every peer.

### Re-reading the NGC binding doc

Looking at `merkle-tox-ngc.md` §3 Emission Timing carefully:

1. On `self_join`: broadcast to all currently-confirmed peers.
2. On `peer_join` (a new peer becomes confirmed): private send
   to that peer.
3. **Periodic heartbeat:** "every `NGC_PEER_INTRO_REEMIT_INTERVAL`
   while connected to the NGC" — this is the ambiguous one.
   Doc currently suggests unconditional broadcast.
4. On receipt of sync request from unbound peer: private re-emit
   to that peer (capped at one per
   `NGC_PEER_INTRO_REEMIT_INTERVAL` per target).

The c-toxcore peer_join callback is reliable (fires on every
new confirmed peer). So #2 covers the new-joiner case. #4 covers
the "peer lost our intro" case. **#3 (unconditional periodic
broadcast) is redundant with #2 and #4** unless we don't trust
the c-toxcore callbacks.

### Recommended revision

**Drop the unconditional periodic heartbeat.** Use event-driven
emission only:
- `self_join`: one-time broadcast (covers initial join).
- `peer_join` of any new peer: one-time private send to them.
- On receipt of a sync request from an unbound peer: re-emit
  to them, rate-limited at most one per
  `NGC_PEER_INTRO_REEMIT_INTERVAL` per target.

This eliminates ~99% of the heartbeat traffic. The remaining
re-emit cost is bounded:
- Per-peer: at most one re-emit per 30s window in response to
  a sync probe from that peer.
- A malicious peer spamming sync probes extracts at most one
  re-emit per 30s — total bandwidth ~200 bytes × 120 emit/hour =
  ~24 KB/hour per malicious peer. Negligible.

### What the periodic heartbeat would protect against

The case the heartbeat covers: a peer who is already confirmed
in NGC but who has, for some reason, **lost their cached binding
of us** (e.g., they restarted their client and dropped RAM-only
cache; per §7 cached bindings are persisted; if we changed that
to RAM-only, this case becomes relevant).

If bindings are persisted (as the NGC binding doc currently
specifies — "for the lifetime of the NGC peer's connection"),
the heartbeat is redundant. If we move to RAM-only bindings
(matching the §7 skipped-keys policy), heartbeat becomes
useful.

### Decision needed

Two coupled choices:
- **(A) Persist `PeerIntroduction` bindings; drop heartbeat.**
  Cleaner bandwidth profile; some device-seizure exposure
  (cached binding state is plaintext PHI of who's in which NGCs
  with us).
- **(B) RAM-only bindings; keep heartbeat at 30s.** Tighter FS
  for binding state; more bandwidth overhead from heartbeats.

Or a middle ground:
- **(C) Persist bindings BUT add a slow heartbeat** (e.g., 5
  minutes) as defense-in-depth against cache inconsistency.

### Recommended value

**(C) is the sweet spot.** Keep `PeerIntroduction` bindings
persistent (per current NGC binding doc), drop the 30s
heartbeat in favor of event-driven emission, but add a
**5-minute slow heartbeat as belt-and-suspenders** for cache-
inconsistency edge cases.

`NGC_PEER_INTRO_REEMIT_INTERVAL = 300s` (5 minutes),
`NGC_PEER_INTRO_REEMIT_JITTER = ±30s`.

At 5-minute heartbeat, broadcast to N peers:
- N=32: 32 × 200 × 12/hour = ~75 KB/hour = ~55 MB/month per
  sender. Tolerable.
- N=256: 256 × 200 × 12/hour = ~600 KB/hour = ~440 MB/month
  per sender. Still heavy but materially better than 4.4 GB.

Even better: **make the slow heartbeat private (per-peer
re-emission on a longer cadence, not broadcast)** — e.g., each
peer is sent a re-emit at most once per 5 minutes if they
haven't acked. Need an ack mechanism for this, which adds
protocol complexity.

For v1, simplest path: drop heartbeat entirely; rely on
event-driven `peer_join` + sync-request-triggered re-emit. Accept
the rare cache-inconsistency case as recoverable via
sync-request triggering the on-demand re-emit. Update the NGC
binding doc accordingly.

### Implementation note

This requires revising `merkle-tox-ngc.md` §3 Emission Timing
and §4a Heartbeat Constants. To be done during the NGC binding
doc's spec-quality pass.

--------------------------------------------------------------------------------

## M1. Measured cost characterization (empirical baseline)

The §1-§16 analyses above are calculated from protocol-element sizes
and assumed rotation cadences. They are useful but they miss
*interaction* effects — sync coordination overhead, IBLT exchanges,
ACK traffic, MessagePack framing — that only emerge under simulation.

`merkle-tox-workbench/tests/group_cost_test.rs` runs the actual
protocol over `VirtualHub` + `SimulatedTransport` and measures
per-node bytes sent/received via the hub's per-node traffic
counters. The instrumentation is in `merkle-tox-core/src/testing/hub.rs`
(NodeTrafficCounters, TrafficSnapshot).

### M1.1. Content-propagation baseline (pre-shared key)

First measurement: content-propagation cost only, using pre-shared
`KConv` to bypass X3DH and `KeyWrap` rotation. Scope: steady-state
"members authoring messages, propagating to peers via DAG sync."

| Nodes | Msgs/node | Avg sent/node | Avg recv/node | Bytes/incoming msg |
|---|---|---|---|---|
| 2 | 50 | 37 KB | 37 KB | ~743 B |
| 5 | 50 | 170 KB | 170 KB | ~848 B |
| 10 | 30 | 281 KB | 281 KB | ~1040 B |
| 20 | 20 | 536 KB | 536 KB | ~1410 B |

### M1.2. Key finding: content-propagation cost grows with group size

Per-incoming-message receive cost grows from ~743 B at N=2 to
~1410 B at N=20 — almost **2× growth between N=2 and N=20**.
The growth comes from sync coordination overhead (more peers to
ask, more sketches, more ACKs, more sequence-number tracking).

Linear projection to larger N (assuming the trend continues at
roughly the same slope):
- N=50: ~2000 B per incoming message
- N=100: ~2500 B per incoming message
- N=256: ~3500 B per incoming message

### M1.3. Implication: content propagation dominates KeyWrap

At a typical group activity rate (50 msg/day per member), the
content-propagation cost per peer-month is:

| N | Daily incoming msgs | Per-msg cost (projected) | Monthly content traffic |
|---|---|---|---|
| 10 | 9 × 50 = 450 | ~1040 B | ~14 MB/month |
| 50 | 49 × 50 = 2450 | ~2000 B | ~150 MB/month |
| 100 | 99 × 50 = 4950 | ~2500 B | ~370 MB/month |
| 256 | 255 × 50 = 12750 | ~3500 B | ~1.3 GB/month |

Adding KeyWrap rotation traffic from §5 (at 7-day cadence):
- N=10: ~14 + 0.5 = ~15 MB/month total
- N=50: ~150 + ~7 = ~157 MB/month total
- N=100: ~370 + ~15 = ~385 MB/month total
- N=256: ~1.3 GB + 34 = ~1.34 GB/month total

**The §5 analytical estimate of "34 MB/month for N=256" was the
KeyWrap-only figure.** The total cost including content propagation
is dramatically higher (~40× higher).

### M1.4. Revised group-size recommendation

The empirically-measured cost says:
- N=10 (~15 MB/month): comfortable. Family/team focus.
- N=50 (~150 MB/month): notable on metered plans. Acceptable on
  unmetered.
- N=100 (~385 MB/month): heavy. Constrains target users to
  unmetered networks.
- N=256 (~1.3 GB/month): operationally infeasible for most users.

**Revised recommendation: v1 caps MAX_GROUP_DEVICES around 64.**
Numbers are extrapolated; exact figure depends on activity rate.
At light activity (10 msg/day per member, N=100): ~75 MB/month, still
manageable.

The previously-recommended 256 cap from §5 assumed only KeyWrap
cost. Content cost dominates and 256 is too aggressive for v1
under typical activity.

### M1.5. Caveats

- **Concurrent authoring artifact:** the test has all nodes
  round-robin-authoring at the same cadence. Real conversations
  are usually 1-2 active authors at a time. Concurrent authoring
  may inflate the per-message coordination cost; real-world cost
  could be lower.
- **Simulation density:** test runs 60 simulated seconds with
  high message density (50 msgs/60s). Steady-state real
  conversations have idle periods.
- **No KeyWrap measurement yet:** test bypasses X3DH and uses
  pre-shared key. KeyWrap-rotation traffic from §5 analytical
  is layered on top; a follow-up test should measure KeyWrap
  directly.
- **Loopback simulation:** real network has latency, loss,
  retransmission. Real-world cost may be higher (lost packets
  require retransmit traffic).
- **Sync handshake overhead amortized over only 50-100 messages:**
  bytes/msg at small N reflects setup cost amortized over few
  messages; bytes/msg at large N reflects steady-state. Real
  long-running conversations may show lower bytes/msg.

### M1.6. Next measurement steps

1. **Measure with KeyWrap rotation enabled** — drive X3DH
   handshakes between pairs, trigger KeyWrap rotations, measure
   resulting traffic. Compare to §5 analytical estimate.
2. **Measure with realistic activity patterns** — burst of
   authoring from one member, idle periods, occasional join/leave.
3. **Measure with simulated network impairments** — loss,
   latency, jitter via VirtualHub's set_impairments. Quantifies
   retransmission overhead.
4. **Measure storage growth per peer over simulated months** —
   so far only bandwidth is measured; DAG storage is the other
   load-bearing constraint.

These are tractable extensions of the existing harness. Each
takes ~1-2 days of test-writing.

--------------------------------------------------------------------------------

## §8, §9, §11, §12, §14-§15, §17-§25 — To be analyzed

Priority order (highest decision-relevance first):

- §4 SenderKey rotation message cap (5000)
- §6 MAX_DEVICES_PER_IDENTITY (currently 32)
- §7 Skipped-key cache TTL (current 24h, agent recommends RAM-only)
- §10 BASELINE_POW_DIFFICULTY (current 20 bits)
- §13 SKETCH_CPU_BUDGET_MS
- §16 NGC peer-intro re-emit interval

Some constants will require simulation rather than pure analysis
(e.g., COMPACT_THRESHOLD's effect on compaction cascade behavior;
voucher-state interactions under adversarial peer load). Those will
be analyzed in §X-onwards with a "requires simulation" marker and
filled in once the workbench cost-characterization framework
produces the data.

--------------------------------------------------------------------------------

## Analysis methodology notes

- **Cost functions assume the wire format as currently specified.** If
  the pre-1.0 wire-breaking changes (X3DH composition, AEAD on payload,
  version field, sender_hint width) alter node sizes, all per-node-byte
  numbers above will need adjustment.
- **Storage growth assumes no compaction.** Compaction (per
  `merkle-tox-fs/src/lib.rs` `COMPACT_THRESHOLD = 500`) garbage-collects
  old admin-track nodes once their effects are absorbed into snapshots.
  Effective storage growth is bounded by compaction cadence not by raw
  rotation cadence.
- **Network costs reported as "per user broadcast" — actual peer-to-peer
  exchange is amortized.** A node authored once and synced to N peers
  costs each peer ~1 download regardless of N (pull-based sync), so
  per-peer cost scales with the user's *own* authoring rate, not with
  the conversation's total size.
