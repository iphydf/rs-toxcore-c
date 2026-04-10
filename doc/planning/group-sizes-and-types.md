# Product Direction: Group Sizes and Types

**Status:** Product-positioning decision. Not normative spec content.

**Purpose:** Capture the decision (2026-05-12) to position v1 as a
small-group-focused product and design the UX scaffolding so a future
"Community Groups" variant can be added cleanly later without
breaking the v1 UX.

--------------------------------------------------------------------------------

## 1. The Decision

**v1 ships "Private Groups" only, capped at ≤32 members.**

A future v2+ may add "Community Groups" — a different protocol
variant with weaker security guarantees but better scaling. The
two-variant model is captured here so v1's UX is designed to
accommodate it without redesign.

### Why small-group v1

Per `doc/planning/constants-cost-reference.md` §M1 and the measured
bandwidth analysis, the current merkle-tox protocol stack has
~25× the per-user bandwidth of native NGC at the same group size.
At N=100 with 50 msg/day per member, that's ~370 MB/month per
member. Operationally infeasible for mobile-data users; heavy even
for unmetered.

The 25× overhead is the cost of strong cryptographic guarantees
that make merkle-tox what it is: per-message forward secrecy,
multi-author signed history with full convergence, multi-device
sync, post-epoch deniability. None of these are individually
wrong; the combination scales linearly with group size.

For groups of ≤32 members at typical activity, the absolute
bandwidth is comfortable (≤2-5 MB/month per peer). The
cryptographic guarantees provide real value at this scale.

For groups larger than ~64 members, the guarantees become
prohibitively expensive. Users would either:
- Tolerate hundreds of MB/month per chat (rare; alienates mobile
  users)
- Get a fundamentally different protocol with weaker guarantees

v1 ships the strong-guarantee, small-group product. Large-group
support is explicitly out of scope.

--------------------------------------------------------------------------------

## 2. The Two-Variant Product Model

To preserve the option of adding large-group support later, the v1
UX is designed around a two-variant model — even though only one
variant ships in v1.

### Private Groups (ships in v1)

- **Max members:** 32
- **Wire protocol:** current merkle-tox (per-sender ratchet,
  multi-author signed DAG, ECIES handshake, KeyWrap)
- **Cryptographic properties:**
  - Per-message forward secrecy via ratchet
  - Post-epoch content deniability (DARE)
  - Multi-author signed history
  - Convergent late-join (new members get full history)
  - Multi-device identity (LogicalIdentityPk + delegation chain)
- **Use cases:** family, friends, small teams, trusted small
  communities (e.g., book club, neighborhood network)
- **Threat model:** target users include those facing
  subpoena/coercion/device-seizure adversaries
- **Bandwidth per user per month:** ~2-5 MB at typical activity
  for a 5-15 person group

### Community Groups (v2+, not in v1)

- **Max members:** TBD; design target ~256-1000 based on bandwidth
  budget
- **Wire protocol:** TBD; candidates from
  `doc/planning/research-cgka-scaling.md`:
  - Shared-group-key model (Megolm-like): light bandwidth,
    weaker per-message FS
  - Decentralized CGKA (DCGKA / BeeKEM): research-stage,
    O(log N) key distribution
- **Cryptographic properties:** weaker than Private Groups by
  design — exact properties depend on which path v2 takes
- **Use cases:** community channels, larger team chats, public
  discussions, organization-wide rooms
- **Threat model:** lower bar — protects against passive network
  observers and casual snooping, not state-level adversaries with
  device seizure
- **Bandwidth per user per month:** TBD; design target ≤50
  MB/month at N=200 with typical activity

--------------------------------------------------------------------------------

## 3. UX Implications for v1

Even though v1 only ships Private Groups, the UI components should
be designed as if Community Groups also exist. This costs a small
amount of upfront design work and preserves the clean v2+ expansion
path.

### Group creation flow

The "New Group" flow should expose the group type as a first-class
concept, even if only "Private Group" is selectable in v1:

```
┌─ New Group ──────────────────────────┐
│ Name: [____________________]         │
│                                      │
│ Type: [○ Private Group        ]      │
│       (Strong privacy, max 32)       │
│       [○ Community Group      ]      │
│       (Disabled — coming soon)       │
│                                      │
│ [ Cancel ]              [ Create ]   │
└──────────────────────────────────────┘
```

In v1, the Community Group option is disabled with a "coming
soon" tooltip. In v2+, the option becomes selectable and the
flow continues with appropriate parameters.

### Chat list display

Each chat in the chat list should display its type. Visual
indication is light — a small badge, an icon, or a tooltip — not
a banner. Users who don't care never notice; users who care can
see at a glance.

### Security info screen

Every chat has a "Security info" screen accessible from the chat
settings. For Private Groups in v1:

```
┌─ Security info ─────────────────────────┐
│                                         │
│ Private Group                           │
│ ━━━━━━━━━━━━━━━━━━━━━━━━━━━━            │
│                                         │
│ Encryption: End-to-end (per-message     │
│ ratchet)                                │
│                                         │
│ Members: 5 of 32 max                    │
│                                         │
│ History: Full sync to new members       │
│ Forward secrecy: Per-message            │
│ Deniability: Post-epoch (7 days)        │
│ Multi-device: Yes                       │
│ Servers: None                           │
│                                         │
│ Members ↓                               │
│   Alice (you) — 2 devices               │
│   Bob — 1 device                        │
│   ...                                   │
│                                         │
└─────────────────────────────────────────┘
```

In v2+, Community Group chats show a similar but materially
different Security Info screen — making the difference visible
to users who look.

### Member list

Member list display works for both variants. Private Group
member list shows delegation chain (multi-device per identity);
Community Group might show only peer-list entries. UI accommodates
both by having "Members" be a generic concept with an optional
"devices" expansion.

### Migration UX

A Private Group **cannot migrate to a Community Group** mid-life.
The cryptographic and structural properties are too different.
If users outgrow a Private Group, they create a new Community
Group.

In v2+, this migration would show as:

```
┌─ Group full ────────────────────────────┐
│                                         │
│ This Private Group has reached its      │
│ 32-member limit. Larger groups require  │
│ a different security model.             │
│                                         │
│ Options:                                │
│ • Don't add new members (recommended    │
│   if security matters most)             │
│ • Create a new Community Group and      │
│   invite everyone over (history won't   │
│   carry across)                         │
│                                         │
│ [ Cancel ]      [ Create Community ]    │
└─────────────────────────────────────────┘
```

In v1, the migration prompt is replaced with just "Group full —
maximum 32 members" since Community Groups aren't available yet.

--------------------------------------------------------------------------------

## 4. What Could Bleed Into UX (Honest Disclosure)

Some differences between the variants will be user-visible even
with the best UX:

| Property | Private Group | Community Group |
|---|---|---|
| Late joiner history | sees everything | sees from-now only |
| Author identification | per-message cryptographic | group-level (any member could have authored) |
| Forward secrecy | per-message | per-epoch |
| Add 100th member | impossible (capped at 32) | works |
| Network bandwidth | ~2-5 MB/month per user | TBD (~50 MB/month target) |
| Storage growth | bounded by activity, includes full history | possibly bounded by retention policy |
| Mass-content moderation | only via member revocation | possibly admin-driven content blacklist |

Users who don't care about these differences don't see them.
Users who care can read the Security Info screen and understand
the trade-off. UX is honest, not deceptive — Community Groups
shouldn't be marketed as having the security of Private Groups.

--------------------------------------------------------------------------------

## 5. Anchor Examples

This two-variant model maps cleanly onto existing systems:

- **Telegram: Groups vs Channels.** Groups (≤200K) and Channels
  (unlimited subscribers, broadcast-only). Different mechanics,
  same UI surface.
- **Signal: Direct Messages vs Groups.** Different threat models,
  same UI.
- **Matrix: room versions.** Different protocol semantics, mostly
  same UI.

The pattern is well-established: one UI, multiple underlying
protocols matched to use case. Users understand it.

The pattern **we are not** following:

- **WhatsApp: pretends N=5 and N=1024 have the same security
  model.** They don't (group-state churn issues at scale,
  effective Sender Keys downgrades). Pretending they do is
  deceptive. We're choosing to be honest.

--------------------------------------------------------------------------------

## 6. v1 Scaffolding Work

For v1 to preserve the option of adding Community Groups later
without UX redesign, the following pieces need to land in v1:

1. **Group-creation flow shows "Type" as a first-class choice**
   (even with only Private selectable).
2. **Chat list displays group type** (small badge/icon).
3. **Security Info screen exists** and displays the protocol
   guarantees in user-readable terms.
4. **Member list display abstracts over delegation-chain
   visibility** (works for "one identity = N devices" or
   "one peer = one identity").
5. **Storage data model accommodates a `group_type` field**
   (per-conversation) even if only one value is supported in v1.
6. **Conversation creation API accepts a group-type parameter**
   (with v1 rejecting anything other than `Private`).
7. **Wire-format conversation version (per Spec Manifest §3.2)
   encodes the group type** so an implementation receiving an
   invite to a future Community Group knows it can't participate
   yet without upgrading.

These are small additions to the v1 design surface. Adding them
later costs more — both implementation work and migration of
existing chats. Adding them now is cheap.

--------------------------------------------------------------------------------

## 7. Open Questions for v2+ Direction

When the time comes to design Community Groups, these are the
load-bearing decisions:

1. **Cryptographic family.**
   - **Shared group key (Megolm family):** simplest, lightest,
     well-vetted (used by Matrix). Loses per-message FS within
     epoch. ~5× native NGC bandwidth.
   - **DCGKA (Weidner et al., CCS 2021):** decentralized CGKA,
     linear performance, formal proof. ~similar bandwidth to
     Megolm.
   - **BeeKEM (Ink & Switch, research stage):** logarithmic
     performance, decentralized. Research-grade risk.
   - **Plain NGC + thin merkle-tox layer:** lightest path —
     use NGC's own group key, layer minimal merkle-tox state on
     top (multi-device, history sync of recent messages only).

2. **History semantics.**
   - Full convergent history (like Private Groups, but
     bandwidth-expensive at scale)
   - From-now-onwards (matches Megolm/Sender Keys)
   - Bounded retention (last N days)

3. **Moderation primitives.**
   - Admin-driven content blacklist
   - Observer-sanction (NGC-native)
   - Identity-driven revocation (current merkle-tox)
   - Combination

4. **Discovery model.**
   - Invite-only (like Private Groups)
   - Discoverable via DHT (like public NGCs)
   - Both, per-chat

5. **Threat model documentation.**
   - Explicit "Community Group threat model" doc with what is
     and isn't protected against.

These are real design problems, not tweaks. Community Groups
deserve their own design phase — not a "let's just enable larger
N" patch on Private Groups.

--------------------------------------------------------------------------------

## 8. Cross-References

- Cryptographic scaling research (DCGKA, BeeKEM, etc.):
  `doc/planning/research-cgka-scaling.md`
- Per-constant cost analysis:
  `doc/planning/constants-cost-reference.md`
- Spec versioning (how group-type encoded in Conversation Version
  tuple): `doc/planning/spec-manifest.md` §3.2
- Principle 10 (No Privileged Infrastructure):
  `doc/merkle-tox-principles.md` §10
