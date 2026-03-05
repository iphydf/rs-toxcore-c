# Merkle-Tox Specification Manifest

**Status:** Planning document. Defines the architecture of the Merkle-Tox
v1.0 specification. **Not normative content itself** — this is the
blueprint for the spec, not the spec.

**Purpose:** Lock the structural decisions about *how* Merkle-Tox is
specified before any normative drafting begins. Section ordering,
versioning model, registry layout, and conformance approach are decided
once here; downstream spec authors follow the structure. Without this
discipline, every normative section is at risk of structural rewriting
when later decisions invalidate earlier assumptions.

This Manifest is itself reviewable and revisable. Once adopted (status:
"Adopted v1.0"), changes to the Manifest require the same rigor as
changes to the normative spec. Until adopted (status: "Draft"), the
Manifest evolves freely.

**Current status: Draft.**

--------------------------------------------------------------------------------

## 1. Goals of the Specification

The Merkle-Tox v1.0 specification is targeted to satisfy four
properties simultaneously:

1.  **Implementability.** An engineer who has not been part of the
    Merkle-Tox design process can implement a compatible Merkle-Tox
    client by reading the spec, without asking the authors for
    clarification. The spec is the source of truth; the
    rs-toxcore-c Rust implementation is *one* implementation, not
    the definitional one.

2.  **Interoperability.** Multiple independent implementations must
    interoperate correctly: same conversation, different software,
    same observable behavior. Interop is verified by conformance
    tests derived directly from spec text.

3.  **Auditability.** External cryptographic auditors (Trail of
    Bits, NCC Group, Cure53, academic researchers) can review the
    spec in isolation from the implementation and identify
    weaknesses. The spec uses precise notation; cryptographic
    claims are explicit; trade-offs are documented; threat model
    is concrete.

4.  **Stability.** Once a spec version is declared "Final", its
    normative content does not change. Implementations targeting
    that version remain compatible forever. Errata and clarifications
    are published separately; substantive changes require a new
    spec version.

Non-goals:
- Backward compatibility with pre-v1.0 design iterations. The wire
  format breaks repeatedly until v1.0 is declared.
- IETF RFC submission for v1.0. May be considered post-v1.0 once
  multiple independent implementations exist.
- Single canonical implementation. The spec serves multiple
  implementations; rs-toxcore-c is one of them.

--------------------------------------------------------------------------------

## 2. Document Architecture

The specification is **layered** across four documents (one
mandatory, two optional-with-deps, one informative).

The four-document split is **not** chosen to mirror a specific
anchor spec — it is justified on Merkle-Tox-specific grounds:

- **Storage Spec is genuinely optional.** An implementation can
  store conversations in any format and still interoperate. This
  contrasts with TLS or MLS, where there is no on-disk format to
  speak of. Separating Storage into its own doc reflects that
  optionality.
- **Transport Bindings are genuinely pluggable.** Direct Tox
  friend connections and NGC custom packets have different
  semantics; future transports (generic UDP/QUIC) are plausible.
  Splitting per-binding lets each one evolve at its own cadence
  without bloating Core.
- **Informative companions are large.** The current 26 design
  docs include substantial rationale, principles, and audit
  history that are valuable for orientation but not load-bearing
  for interop. Keeping them out of Core preserves Core's role as
  the authoritative interop document.

For reviewer orientation, the anchor specs compared in the
Appendix structure themselves differently:
- TLS 1.3 (RFC 8446) is a single document.
- MLS (RFC 9420) is also a single document; auxiliary
  protocol-related documents like RFC 9750 (MLS Architecture) are
  *informational* and predate the protocol RFC, not companions
  in the way this Manifest uses the term.
- Noise (rev 34) is a single document.
- Signal X3DH is a single short document.
- Matrix is a federated collection of MSCs and a Client-Server
  spec, with room-format embedded inside.

None of these match Merkle-Tox's exact layering needs. The
four-document split is a Merkle-Tox decision based on the three
points above, not a copy of an anchor pattern.

### 2.1. Core Spec (`merkle-tox-v1.md`)

**Status:** Normative. Required for interop.

**Approximate scope:** ~120 pages.

**Contents (sections subject to refinement during drafting):**

1.  Introduction & Conventions
2.  Cryptographic Primitives (algorithm choices, parameter tables)
3.  Identity & Delegation Chain (Master Seed → Admin → Device)
4.  DAG Schema (`MerkleNode`, `WireNode`, canonical signing input)
5.  Wire Format (byte-precise MessagePack tables)
6.  Handshake Protocol (X3DH composition)
7.  Key Wrapping & Distribution (`KeyWrap`, `SenderKeyDistribution`)
8.  Per-Sender Ratchet
9.  Deniability Properties (DARE; calibrated to scope)
10. Sync Protocol (`SyncHeads`, `SyncShardChecksums`, fetch)
11. Set Reconciliation (IBLT-based, tiered sketches)
12. Content-Addressable Storage (CAS / blob protocol)
13. Verifier State Machine (including §3.17 bootstrap-exception invariants — the narrow class of cases where a content type's first signature must be self-validated against a Genesis-embedded or admin-frontier key without recursing through normal delegation verification, e.g. Genesis itself, AuthorizeDevice, AnchorSnapshot, KeyWrap, HistoryExport, SenderKeyDistribution; these are prone to subtle bugs per the existing threat model and require explicit invariants in §14)
14. Threat Model (normative — adversary classes, mitigations, residual risks)
15. IANA-Style Registries (Appendix)
16. Security Considerations

**Independence:** An implementation of the Core Spec alone is a
valid Merkle-Tox implementation. Storage Spec and Transport
Bindings are required only if the implementation interacts with
on-disk format (Storage) or specific transport substrates (Bindings).

### 2.2. Storage Spec (`merkle-tox-storage.md`)

**Status:** Normative-but-optional. Required only for tooling
interop (forensics, migration, multi-implementation single-store).

**Approximate scope:** ~25 pages.

**Contents:**

1.  Introduction (relationship to Core Spec)
2.  Directory Layout
3.  Journal Format (append-only, framing, recovery)
4.  Pack File Format (compacted DAG nodes, index file)
5.  Ratchet Checkpoint File (double-buffered)
6.  State File (`state.bin`, atomic save with fsync discipline)
7.  Blob Store (chunk files, info files)
8.  Cross-Process Locking (POSIX `flock` semantics)
9.  Migration Rules (storage-spec version bumps)
10. Conformance Tests for Storage Format

**Independence:** An implementation may use a completely different
on-disk format (e.g., SQLite, custom KV store) and still be a valid
Merkle-Tox implementation. Storage Spec compliance is needed only
for cross-implementation forensics or shared-store scenarios.

### 2.3. Transport Bindings

Each binding is a separate normative sub-spec, ~30 pages, with the
same structure. Binding A is required for any client targeting
direct Tox friend transport; Binding B is required for any client
targeting NGC transport. A client may support both, one, or (future)
neither.

**Common binding structure:**

1.  Introduction (which substrate, why)
2.  Capabilities Provided by the Substrate
3.  Identity-Layer Binding (PhysicalDevicePk ↔ substrate identity)
4.  Wire Encapsulation
5.  Peer Discovery & Membership Coordination
6.  Threat-Model Deltas vs other bindings
7.  Conformance Tests

**Binding A: Direct Tox Friend Transport (`merkle-tox-binding-direct.md`)**

- Substrate: `tox.friend.send_lossy_packet`
- Identity: PhysicalDevicePk = Tox friend PK
- Membership: pairwise friend graph required
- Use cases: 1:1 friend chats, multi-device self-sync, small
  mutual-friend groups

**Binding B: NGC Custom Packets (`merkle-tox-binding-ngc.md`)**

- Substrate: `gc_send_custom_*_packet(lossless=false, ...)`
- Identity: PhysicalDevicePk independent of NGC self-key (bound via
  `PeerIntroduction` record)
- Membership: NGC-layer discovery + admin-gated Merkle-Tox membership
- Use cases: groups with members not all mutual friends; discoverable
  public groups
- This is the current `doc/merkle-tox-ngc.md` content, reorganized
  to match the common binding structure

**Future Binding C (out of scope for v1.0):** generic UDP/QUIC or
TCP. Specified only once a real implementation exists.

### 2.4. Informative Companions

**Status:** Non-normative. Reference material; not required for
implementation.

**Documents:**

- `merkle-tox-design-rationale.md` — design choices and the reasoning
  behind them. Consolidates current `merkle-tox-design-rationale.md`
  and `merkle-tox-persistence.md`. The principles themselves
  (`merkle-tox-principles.md`) stay normative in Core §1; their
  *rationale paragraphs* move here.

- `merkle-tox-security-analysis.md` — extended cryptographic
  analysis beyond the normative Threat Model section. Includes
  formal-model results (if/when Tamarin/ProVerif modeling is done),
  cited academic analyses, attack-class explorations that didn't
  produce normative changes.

- `merkle-tox-implementation-notes.md` — non-normative guidance
  for implementers: testing strategy, benchmarking methodology,
  recommended fuzz harness shape, observability hooks.

- `merkle-tox-audit-history.md` — historical record of bug classes
  found and fixed. Consolidates `merkle-tox-audit-cleared.md`.

These are useful for orientation, education, and audit-trail
purposes, but are **not load-bearing for interop**.

### 2.5. What Lives Where

| Current doc | Maps to |
|---|---|
| `merkle-tox.md` | Core §1 (Introduction) |
| `merkle-tox-principles.md` | Core §1 (principles stay normative); rationale → Informative |
| `merkle-tox-identity.md` | Core §3 |
| `merkle-tox-dag.md` | Core §4 (DAG schema; wire-format aspects move to §5) |
| `merkle-tox-wire-format.md` | Core §5 |
| `merkle-tox-handshake-ecies.md` | Core §6 (handshake) + Core §7 (KeyWrap) |
| `merkle-tox-ratchet.md` | Core §8 |
| `merkle-tox-deniability.md` | Core §9 (normative properties) + Informative security analysis (extended discussion) |
| `merkle-tox-sync.md` | Core §10 |
| `merkle-tox-reconcile.md` | Core §11 |
| `merkle-tox-cas.md` | Core §12 |
| `merkle-tox-threat-model.md` | Core §14 |
| `merkle-tox-capabilities.md` | Core §15 (capability bit registry) |
| `merkle-tox-storage-format.md` | Storage Spec |
| `merkle-tox-transport.md` | Bindings shared content (extracted to a "Bindings Common Concerns" annex; nothing in Core, since transport semantics are binding-specific) |
| `merkle-tox-ngc.md` | Binding B |
| `merkle-tox-legacy-bridge.md` | Core §10 or §12 (a Content variant; small section, exact placement deferred to drafting) |
| `merkle-tox-clock.md` | Core §10 (network-time consensus, sync-relevant) |
| `merkle-tox-structure.md` | Informative (project layout, not normative) |
| `merkle-tox-client.md` | Informative implementation notes |
| `merkle-tox-testing.md` | Informative |
| `merkle-tox-design-rationale.md` | Informative |
| `merkle-tox-persistence.md` | Storage Spec (operational rationale) + Informative (broader persistence philosophy) |
| `merkle-tox-audit-cleared.md` | Informative audit history |
| `roadmap.md` | Planning (not in spec) |
| `benchmarking-strategy.md` | Informative |
| `doc/planning/*` | Planning (not in spec) |

The mapping is approximate; precise section assignments will be
refined during drafting. Some current docs may be split (e.g.,
`merkle-tox-deniability.md`'s mechanics vs philosophy split into
Core §9 vs Informative).

--------------------------------------------------------------------------------

## 3. Versioning

Three orthogonal version axes (Spec, Conversation Rule, Cipher Suite),
two of them combined into the Conversation Version tuple, plus
Storage and Binding versions which are independent infrastructure
concerns.

### 3.1. Spec Version (semver-style)

**Format:** `merkle-tox/v1.0`, `merkle-tox/v1.1`, `merkle-tox/v2.0`.

**Governs:** additive extensions to the protocol. Adding a new
`Content` variant, a new `ProtocolMessage` variant, a new error code,
a new capability bit, a new transport binding. Implementations
advertise their spec-version support during the capability handshake.

**Compatibility rules:**

- Minor version increments (`v1.0 → v1.1`) are backward-compatible:
  v1.0 implementations interoperate with v1.1 implementations,
  ignoring the v1.1 additions.
- Major version increments (`v1.x → v2.0`) are not backward-compatible:
  a v2.0 implementation MAY support v1.x for legacy peers, but
  v1.x implementations cannot read v2.0 protocol elements.

**Negotiation:** Implementations exchange spec-version support via
`CapsAnnounce` during peer introduction. The agreed spec version is
the highest mutually-supported.

**Status declaration:** Each spec version has a status:
- *Draft* — under active development; wire format may break.
- *Final* — locked; no normative changes permitted; only errata.
- *Deprecated* — superseded by a newer version; implementations
  should migrate.

### 3.2. Conversation Version (frozen-at-Genesis)

**Format:** A tuple `(rule_version, cipher_suite)` stored as a
normative field in the Genesis node. Wire-encoded as a structured
record, not a string identifier.

**Conversation Rule Version (e.g. `merkle-tox-conv-rules-v1`)**
governs **encoding-level** rules that cannot change for a live
conversation without breaking history verification:
- Canonical signing input format
- KDF label structure
- Ratchet construction (the chain shape, not the underlying primitive)
- Padding scheme
- DAG topology rules and §3.17 bootstrap-exception invariants
- Genesis structure and required fields

**Cipher Suite Identifier (e.g. `merkle-tox-cs-ed25519-x25519-chacha20poly1305-blake3`)**
governs **primitive-level** choices:
- Signature algorithm
- DH key-exchange algorithm
- AEAD construction
- Hash algorithm
- KDF underlying hash

**Why two sub-axes:** primitive choices and rule choices have
different evolution frequencies. A post-quantum migration changes
the Cipher Suite but typically not the Conversation Rules. A change
to the canonical-signing-input format changes the Conversation
Rules but not the primitives. Keeping them separate lets the spec
maintain a clean Cipher Suite registry (for PQ migrations and
algorithm-agility) without re-litigating encoding decisions.

**Immutability:** A conversation born under a specific
`(rule_version, cipher_suite)` tuple verifies forever under those
choices. "Upgrading" the tuple means *creating a new conversation*;
the old conversation's DAG remains verifiable independently. The
optional Conversation Version Lifecycle mechanism in §3.6 provides
a normative `superseded_by` migration path.

**Negotiation:** None. The founding device's Genesis specifies the
tuple; all joiners must support it.

### 3.3. Storage Spec Version

**Format:** `merkle-tox-storage/v1.0`, etc. Independent of Spec
Version. Storage Spec migrations are local to one implementation's
on-disk format and do not affect interop.

### 3.4. Binding Versions

**Format:** `merkle-tox-binding-direct/v1.0`,
`merkle-tox-binding-ngc/v1.0`. Each binding versions independently
of Core Spec.

### 3.5. Algorithm Agility

Primitive choices live in the **Cipher Suite Identifier** field of
the Conversation Version tuple (§3.2). They are not negotiated
per-message and not selectable mid-conversation. A new algorithm
(e.g., a PQ signature) requires a new Cipher Suite entry plus a
new conversation that adopts it.

This eliminates per-message cipher-suite-negotiation surface
(downgrade attacks, combinatorial test cases) at the cost of
"can't migrate algorithms within a live conversation." The
mitigation for that cost is §3.6 Conversation Version Lifecycle —
specifically, a forward-migration path with `superseded_by` rather
than requiring abandonment.

### 3.6. Conversation Version Lifecycle

This section addresses a defect in the naïve "frozen at Genesis"
model: when a cryptographic algorithm in a deployed Cipher Suite
develops an exploitable weakness, the conversations using that
Cipher Suite are simultaneously (a) unable to add members safely,
(b) unable to be abandoned without losing history continuity, and
(c) still being attacked. Frozen-forever without an escape hatch
is irresponsible.

The lifecycle adopts Matrix room-versions semantics for the
escape hatch:

**Conversation Version Status:**

- *Active* — the version is current; new conversations SHOULD be
  created under it; existing conversations under it operate normally.
- *Deprecated* — the version is superseded by a newer one; new
  conversations under it SHOULD NOT be created; existing
  conversations continue to operate but SHOULD plan migration.
- *Compromised* — a cryptographic weakness has been identified in
  the version's Cipher Suite. New conversations under this version
  MUST NOT be created; existing conversations MUST stop authoring
  new content; they MAY continue to read historical content.

Status transitions are spec-version events (a `merkle-tox/v1.x`
spec revision may move a Conversation Version from Active to
Deprecated, or to Compromised).

**Migration via `superseded_by`:**

A conversation's Genesis MAY contain a `superseded_by` field
(initially absent). When the founding admin authors a migration
event, they create a new conversation under a newer Conversation
Version and emit a `ControlAction::SupersededBy { new_conv_id }`
admin-track node in the old conversation. The semantics:

- Existing members of the old conversation receive the
  `SupersededBy` event and SHOULD migrate to the new conversation.
- The new conversation has its own Genesis, independent membership
  state, and independent DAG. History does NOT cryptographically
  carry forward; old DAG remains verifiable under old Cipher Suite,
  new DAG begins fresh under new Cipher Suite.
- Implementations MAY display the two conversations as
  user-equivalent ("Same Conversation, New Version") while keeping
  the DAGs cryptographically distinct.

**What about non-migrating members?**

If a member device does not migrate (offline at migration time,
chose not to migrate, lacks support for the new Cipher Suite),
they remain in the old conversation. The old conversation can
continue with reduced membership. Eventually:

- If the last member of the old conversation leaves or migrates,
  the conversation has zero authors. The DAG remains
  verifiable by anyone who held a copy; no new content can be
  authored.
- If the last v1-capable member leaves a v1 conversation before
  successfully migrating, the conversation freezes for any
  remaining members. New content cannot be authored. This is
  expected behavior; alternatives require central authority and
  are forbidden by Principle 10.

**Honest characterization of the trade-off:**

This model trades **algorithmic flexibility within a conversation**
for **downgrade-attack resistance**. A conversation is bound to
its Cipher Suite for its lifetime; algorithm migrations require
explicit founder action and new-conversation creation. There is
no automatic in-place migration; there is no negotiated cipher
suite per-message. This is intentional and aligned with Principle
10 (no privileged infrastructure could automate cross-version
migration without becoming itself a privileged role).

When the inevitable cryptographic-weakness event happens, the
lifecycle is:

1. Spec maintainers move the compromised Cipher Suite to
   *Compromised* status in a spec revision.
2. Existing implementations receive the spec revision and stop
   authoring new content in compromised conversations.
3. Founders use `superseded_by` to create successor conversations
   in non-compromised Cipher Suites; members migrate manually.
4. Historical content remains readable; new content does not.

This is painful but honest. It is similar to (and arguably less
painful than) the alternatives: forced abandonment, central
migration authority, or per-message cipher-suite negotiation
with all of negotiation's complexity.

--------------------------------------------------------------------------------

## 4. Registries

Code-point registries are appendices in Core Spec §15. Each
registry has: integer code point, name, semantic meaning, status
(*Reserved* / *Active* / *Deprecated*), reference (which section of
Core Spec defines the meaning).

### 4.1. Required Registries

**Identity-bearing wire-format and protocol identifiers:**

- **Content ID Registry** — integer codes for `Content` enum
  variants. Currently: Text=0, Reaction=1, Redaction=2, etc.
  through ~11.
- **Control Action Registry** — integer codes for `ControlAction`
  variants. Genesis, AuthorizeDevice, AnchorSnapshot, KeyWrap,
  Announcement, SupersededBy (per §3.6), etc.
- **Packet Type Registry** — `tox-sequenced` packet types
  (DATA, ACK, PING, PONG, FRAGMENT).
- **Protocol Message Registry** — `ProtocolMessage` variants
  (SyncHeads, SyncSketch, BlobReq, etc.).
- **Wire-Format Version Registry** — integer codes governing
  MessagePack schema evolution *within* a Spec Version. Adding
  an optional field bumps wire-format version; removing or
  re-typing a field is a Spec Version increment. Receivers
  reject unknown wire-format codes early.
- **Hash-Prefix / Object-Type Registry** — typed prefixes for
  CAS objects: blob (file content), ratchet checkpoint, anchor
  snapshot, history-export blob, opaque wire node. Each type
  has different fetch semantics, retention rules, and validation
  paths.

**Status and error codes:**

- **Error Code Registry** — every parse/protocol error condition
  with an enumerated code. Decoding failures, signature failures,
  invariant violations from §3.17, storage errors. Excludes
  reason codes (below) which are semantically distinct.
- **Reason / Status Code Registry** — semantic outcome codes,
  distinct from parse errors. Handshake termination reasons
  ("OPK exhausted", "incompatible cipher suite", "peer revoked"),
  conversation deprecation reasons (per §3.6), member-removal
  reasons (kick / revoke / leave / observer-sanction).

**Capability and feature flags:**

- **Capability Bit Registry** — *peer-level* capability flags
  exchanged in `CapsAnnounce` / `CapsAck`. "I support feature X."
  Negotiated; per-session.
- **Feature Flag Registry** — *conversation-level* opt-in flags
  carried in Genesis or admin actions. "This conversation has
  redactions enabled." Frozen-at-conversation-version unless
  the feature explicitly supports mid-conversation toggle.

**Cryptographic identifiers:**

- **Domain Separator Registry** — all signature-input
  domain-separation strings. Currently:
  - `b"merkle-tox v1 content-sig"`
  - `b"merkle-tox v1 admin-sig"`
  - `b"merkle-tox v1 ngc-peer-intro"`
  - `b"merkle-tox v1 ngc-chat-id-attest"`
- **KDF Label Registry** — domain-separation labels for all key
  derivations. Each ratchet step, KeyWrap chain, IBLT keying.
- **Cipher Suite Identifier Registry** — primitive bundles
  referenced by Conversation Version's `cipher_suite` field
  (per §3.2). Each entry is a tuple
  `(signature_algorithm, kex_algorithm, aead, hash, kdf_hash)`
  with a stable name (e.g.,
  `merkle-tox-cs-ed25519-x25519-chacha20poly1305-blake3`).

**Conversation Version index:**

- **Conversation Rule Version Registry** — `merkle-tox-conv-rules-v1`,
  `merkle-tox-conv-rules-v2`, with their status (per §3.6:
  Active / Deprecated / Compromised).
- **Conversation Version Tuple Registry** — known `(rule_version,
  cipher_suite)` combinations and their status. Implementations
  consult this to decide whether to accept a Genesis-declared
  version.

### 4.2. Reserved Ranges

Each registry reserves a "private use" range for experimental
implementations:
- Content IDs ≥ 0xF000_0000
- Control Action codes ≥ 0xF000_0000
- Capability bits ≥ bit 48 (bits 0-47 reserved for spec-assigned; bit 48 is a clean half-of-u64 boundary that avoids 32-bit-word-edge ambiguity in any wire encoding)
- KDF labels prefixed with `b"merkle-tox v1 experimental/"`

Implementations encountering reserved-range values from a peer MUST
ignore them and not treat them as protocol errors.

### 4.3. Registry Maintenance

Registries are appendices in Core Spec, normative. Additions are
spec-version increments. Renaming or repurposing a code point is
**not permitted** within a major version; deprecation creates a
new code point.

--------------------------------------------------------------------------------

## 5. Conformance Testing

Test vectors are the bridge between spec text and implementation
behavior. Spec text is authoritative; vectors operationalize it.

### 5.1. Vector Repository

Vectors live in a **separate repository**:
`github.com/toktok/merkle-tox-test-vectors` (or equivalent location;
exact URL TBD).

Reason for separation (MLS-style):
- Vectors are version-tagged independently of spec.
- Multiple implementations contribute vectors and consume them
  without spec changes.
- Spec text stays focused; vectors can be large.

### 5.2. Vector Categories

Each category is a directory with a stable schema:

- **kdf/** — KDF chain key-derivation KATs. Input chain key,
  input data, output bytes.
- **handshake/** — Full handshake transcripts. Pre-keys, initiator
  ephemeral, expected `KeyWrap` payload.
- **ratchet/** — Ratchet step KATs. Input chain key, input
  message-counter, expected `K_msg_i`.
- **dag-canonical/** — Canonical-signing-input KATs. Input
  `MerkleNode`, expected canonical bytes, expected signature.
- **iblt/** — IBLT encode/decode round-trip vectors. Element set,
  sketch parameters, expected sketch bytes, expected decode
  output.
- **negative/** — Negative tests: malformed inputs that MUST be
  rejected. One test per §3.17 invariant and per error code.

### 5.3. Vector Format

JSON-encoded. Each vector includes:
- Vector ID (stable across versions)
- Spec section reference
- Inputs (hex-encoded byte strings)
- Expected outputs
- "Skip if not supporting feature X" markers (for vectors covering
  optional capabilities)

### 5.4. Generation

Vectors are generated from a **tagged reference-implementation
commit**. This commit is the spec-reference. Re-generating vectors
requires bumping the spec-reference commit, which is a spec-version
event.

### 5.5. Conformance Matrix

Conformance is **not** a linear ladder; it is a set of
independent axes that an implementation declares per-axis.
This avoids the perverse incentive of an implementation
stopping at "Level 1" because the ladder framing makes
higher levels look optional.

**Required for "conformant":**

- **KAT-passing:** implementation produces matching output for
  every test vector in `kdf/`, `handshake/`, `ratchet/`, and
  `dag-canonical/`. This is the minimum bar for being called
  Merkle-Tox-conformant. No implementation lacking this should
  use the name.
- **Negative-test-passing:** implementation correctly rejects
  every vector in `negative/`, including each §3.17 invariant
  violation and each enumerated error code.

**Supplementary axes (implementations declare which they check):**

- **Fuzz-survival:** implementation has survived a sustained
  fuzz-harness run (e.g., OSS-Fuzz integration) for at least
  N CPU-hours without crashes or memory-safety violations.
  Declare N.
- **Interop-corpus:** implementation has been tested against
  at least one other independent Merkle-Tox implementation
  in a live conversation, with verifiable inter-derived
  state. Declare partner implementations.
- **Formal-audit:** implementation has passed external
  cryptographic audit (Trail of Bits, NCC Group, Cure53, or
  equivalent). Declare audit firm, date, and report URL.
- **Property-test:** implementation has property-based tests
  covering the verifier state machine, the ratchet, and the
  IBLT decode. Declare test framework and coverage scope.

**Spec text usage:**

Spec text refers to "conformant implementation" meaning *passes
all required KATs and negative tests*. Spec text does NOT refer
to supplementary axes; those are advertising claims an
implementation makes voluntarily.

This separation prevents two failure modes:
1. A "Level 1" implementation considering itself done at the
   minimum bar.
2. A spec-text author leaning on an implementation's
   advertised conformance level for spec semantics.

--------------------------------------------------------------------------------

## 6. Spec Authoring Discipline

### 6.1. Drafting Order

Two parallel tracks. **Track A (sequential)** covers data model
and primitives. **Track B (concurrent with A, but stabilizes
last)** covers integrating-sections that depend on Track A but
also constrain it.

**Track A — Foundational, sequential:**

1. Cryptographic Primitives (Cipher Suite definition; Core §2 —
   frozen first; everything else cites algorithms)
2. Identity & Delegation (Core §3 — frozen second; DAG depends
   on identity)
3. DAG Schema + Wire Format (Core §4 + §5 — together; one is the
   data model, one is the byte layout)
4. Handshake + KeyWrap (Core §6 + §7 — together; X3DH composition
   binds them)
5. Ratchet (Core §8 — depends on KeyWrap)
6. Deniability Properties (Core §9 — observable property of the
   above)
7. Sync Protocol (Core §10)
8. Set Reconciliation (Core §11 — can start once §4-§5 are stable,
   in parallel with §6-§8)
9. CAS / Blob Protocol (Core §12 — can start once §4-§5 are
   stable, in parallel with §6-§9)
10. Bindings (Binding A and Binding B; depend on §10-§12 being
    stable, start as parallel sub-tracks once those land)

**Track B — Integrating, concurrent with Track A:**

These sections **define what Track A must produce** as much as
they consume Track A's output. They cannot be cleanly drafted
after Track A; they must be co-developed.

- Verifier State Machine (Core §13) — begins as a skeleton at
  Track A step 2 (Identity), receives sections as Track A drafts
  them, finalized after Track A step 9. The §3.17 bootstrap-
  exception invariants (the narrow case where the founding
  device's first AuthorizeDevice signature must be self-validated
  against the Genesis-embedded admin key, prone to subtle bugs
  per the threat model) are co-designed with the verifier *and*
  with §3 + §4. Iteration between Track A and Track B sections is
  expected.

- Registries (Core §15) — populated continuously as Track A
  drafts each section. Code points assigned when sections lock.

**Final track (after both Track A and Track B settle):**

- Threat Model (Core §14) — last sequential step. Cross-validates
  Track A and Track B; every mitigation claim cites a specific
  Track A or Track B section.
- Security Considerations (Core §16) — last.

**Citation discipline:**

- A Track A section may be cited only after it is drafted at
  **5/5 precision** (not 4.5/5 — see m1 fix; 4.5 admits ~10%
  imprecision that compounds across citations).
- A Track B section (Verifier) may be cited at any precision,
  with the understanding that it co-evolves; cross-validation
  in the Threat Model phase will surface drift.
- Citing an unwritten section is forbidden (§6.3).

**Parallelizability summary:**

Sections that can run in parallel once their prerequisites are
met:
- §11, §12 after §4-§5: can start while §6-§8 are being drafted
- Bindings A and B in parallel with each other
- Registries continuously
- Verifier skeleton ramping up from §2 onward

This is meaningful for compressing wall-clock time. A
single-author effort still serializes by author bandwidth, but
the Track A/B model prevents the worst case (drafting §13 last,
discovering it requires reopening §3-§9).

### 6.2. Precision Bar

Every normative claim in the spec must be at one of (RFC 2119
modal verbs):

- **MUST / SHALL** — implementation requirement. Violation is a
  non-conformant implementation.
- **MUST NOT / SHALL NOT** — implementation prohibition.
- **SHOULD** — strong recommendation; deviation must be justified
  and documented.
- **MAY** — implementation option; **peers MUST accept both choices**.
  This is the load-bearing clause: "MAY" without peer-tolerance
  guarantees leaks underspecified peer behavior.

Prose without one of these modal verbs is **explanatory, not
normative**. Explanatory prose should be sparse; the bulk of a
normative section is requirements.

### 6.3. Forbidden Patterns

- "We may want to..." / "It would be nice if..." / "TODO" — none
  of these appear in normative spec text. Either it's a
  requirement or it's not.
- Citing an unwritten section — every cross-reference resolves
  to extant text at draft commit time.
- "See implementation X for details" — the spec stands alone;
  implementations follow the spec, not vice versa.
- Implementation-specific terminology in normative sections —
  "the Rust struct" or "the Bazel target" do not appear; only
  protocol-level abstractions.

Forbidden patterns are enforced by a **lint pass at CI time**
(regex-based). The lint runs as a required check on every
spec-repository commit; merging fails if the lint detects
forbidden phrasing. Exact regex set is maintained at
`tools/spec-lint.toml` (or equivalent). Lint exceptions are not
honoured; if a phrase looks forbidden but is intentional, the
phrase is wrong.

### 6.4. Constants

Every constant has a value, not a placeholder. Constants are:

- Defined in one place (typically Core §15 registry or §2
  Cryptographic Primitives).
- Cited by symbolic name where used.
- Backed by a cost-vs-security trade-off documented in
  `doc/planning/constants-cost-reference.md` (or its successor
  appendix in Informative).

### 6.5. Threat Model Cross-Checking

Every mitigation claim in §14 (Threat Model) must cite the
specific normative section that implements the mitigation. When
a §14 claim references a section, that section must explicitly
mention which threat-model invariant it serves.

Bidirectional cross-references prevent the §3.17-style class of
bugs where a bootstrap exception bypasses an invariant that's
documented in the threat model but not enforced by the actual
code path.

### 6.6. Algorithm Agility Discipline

Cryptographic algorithms are referenced by **algorithm-suite
identifier** in spec text, not by name. The conversation version
binds the suite identifier to specific algorithms. This avoids
the trap where "Ed25519" is hardcoded throughout the spec and
PQ migration requires a global find-and-replace.

Example: spec section says "the device signs `M` using the
conversation's signature algorithm"; the algorithm is bound by
the Conversation Version identifier.

--------------------------------------------------------------------------------

## 7. Process

### 7.1. Manifest Adoption

This document is currently **Draft**. Adoption requires:

1. Review by at least one external cryptographer or
   protocol-engineer (cf. §5 risks in
   `doc/planning/audit-scope.md`).
2. No outstanding objections to the four-document structure,
   versioning model, or registry approach.
3. Explicit "Adopted" status declaration by project lead.

Once Adopted, structural changes to the Manifest follow the
same process as spec changes.

### 7.2. Spec Drafting Milestones

Aligned with `doc/planning/audit-scope.md` §5:

- **M0:** Manifest adopted (this document).
- **M1:** Core Spec §§2-6 drafted at 5/5 precision for sections
  cited downstream by Threat Model or Verifier; 4.5/5 acceptable
  for other sections. Wall-clock estimate: 3 months from M0
  adoption for a single-author effort; longer for multi-reviewer
  passes.
- **M2:** Core Spec §§10-12 drafted (sync, reconcile, CAS).
- **M3:** Core Spec §§13-16 drafted + Storage Spec + Binding A
  drafted.
- **M4:** External review pass 1 (cryptographer + protocol
  engineer). Revisions.
- **M5:** Test vectors generated against tagged spec-reference
  commit.
- **M6:** Independent implementation attempt (different engineer,
  no insider access). Spec gaps fixed.
- **M7:** External review pass 2 + v1.0 *Final* declaration.

Binding B (NGC) drafted in parallel with M3 onwards, depends on
Core §10-§12.

### 7.3. v1.0 Declaration Criteria

Spec version `merkle-tox/v1.0` is declared *Final* only when:

- All Core Spec sections at 5/5 precision.
- All required registries populated (no "TBD" code points).
- Test vectors complete and validated by at least one independent
  implementation.
- External audit (per `doc/planning/audit-scope.md`) completed
  and findings remediated.
- Threat Model cross-checked: every mitigation in §14 cites a
  specific spec section; every spec section that implements a
  mitigation references the §14 invariant it serves.
- No known wire-format-breaking changes in the queue.

Once declared Final, normative content is frozen. Errata are
published separately and do not constitute new spec versions.

### 7.4. Errata and Clarification

Post-Final issues fall into two categories:

- **Errata** — clarifications, typo fixes, ambiguity resolutions
  that don't change implementation behavior.
- **Substantive changes** — anything that changes implementation
  behavior. Requires a new spec version (minor for additive
  changes; major for breaking).

#### 7.4.1. Errata Classification

The line between errata and substantive is judged by: "does a
correctly-implementing-from-the-original-spec implementation
remain conformant?" If yes, errata. If no, new version.

Three errata subtypes:
- **Editorial:** typo, formatting, broken cross-reference. No
  semantic effect.
- **Clarification:** ambiguous spec text replaced with unambiguous
  text producing the same observable behavior. Implementations
  unaffected.
- **Technical:** spec text was internally inconsistent or
  contradicted another normative section. The errata picks one
  reading. Implementations following the "wrong" reading must
  update; this is the borderline-with-substantive case and
  invites scrutiny.

#### 7.4.2. Submission

Erratum submissions are filed as issues against the spec
repository. Each submission includes:
- Section reference (down to subsection / step number)
- Quoted offending text
- Proposed corrected text
- Proposed subtype (Editorial / Clarification / Technical)
- Rationale (why is this an erratum and not a substantive change?)

Anyone may submit. There is no IPR or contribution-license
requirement for filing an erratum issue (this is distinct from
contributing to the spec itself; see §7.6).

#### 7.4.3. Approval

The **Spec Editorial Body** approves errata. This body's
composition is defined in §7.7 (Interpretation Authority).

Approval requires:
- Editorial errata: one Body member's sign-off, 7-day public
  comment window.
- Clarification errata: two Body members' sign-offs, 14-day
  public comment window.
- Technical errata: full Body consensus, 30-day public comment
  window. Borderline cases SHOULD be elevated to a substantive
  change instead.

Comment-window dates are wall-clock from publication of the
proposed erratum.

#### 7.4.4. Publication

Approved errata are published in `spec/errata-merkle-tox-vN.md`
(per spec version), numbered sequentially within their version
(e.g., `v1.0-E001`, `v1.0-E002`). Each entry contains:
- Erratum number
- Section reference
- Subtype
- Original text + corrected text
- Approval date and signing Body members

The spec text itself is **not modified post-Final**. Errata are
delta-published; implementations consult both spec and errata
list.

#### 7.4.5. Implementation Obligation

- **Editorial:** no obligation. Implementations remain conformant.
- **Clarification:** no obligation. Implementations remain
  conformant (clarification specifies the intended reading;
  conformant implementations were already aligned).
- **Technical:** SHOULD-follow. Implementations not following
  a Technical erratum MAY still be called conformant under the
  original spec text, but the original spec text is officially
  superseded by the erratum. Future Spec Version revisions
  fold all Technical errata into the new normative text.

#### 7.4.6. Errata Limit

If a Spec Version accumulates more than ~10 Technical errata,
the Body SHOULD consider a minor-version revision instead of
continuing to publish errata. The threshold is heuristic, not
normative.

### 7.5. Public Review

Each Spec Version *Final* declaration is preceded by a public
review window:

- **Pre-Final draft published** at the end of M3 (per §7.2).
- **Public review window:** 60 days minimum, longer if active
  discussion is ongoing.
- **Comments accepted at:** spec repository issues.
- **Response obligation:** each substantive comment receives a
  written response within 30 days. Comments may be addressed
  (spec text updated), deferred (filed as future-revision
  candidate), or declined (with rationale).
- **Comment closure:** the window closes when (a) the
  minimum 60 days elapsed AND (b) all substantive comments
  have been addressed or declined. No comment unaddressed.

A second public review window of at least 30 days follows any
post-comment substantive changes to the spec text. If the
spec text changes substantively during the review window, the
window restarts.

### 7.6. License and Contribution Policy

#### 7.6.1. Spec License

The Merkle-Tox specification is published under
**Creative Commons Attribution 4.0 International (CC BY 4.0)**.
Anyone may copy, redistribute, adapt, and translate the spec
provided they cite the source.

This license is chosen for compatibility with:
- IETF RFC submission (RFCs require contributor IPR commitments
  compatible with BCP 78/79; CC BY 4.0 contributors retain
  copyright but grant the IETF Trust necessary rights).
- Re-publication in technical documentation, papers, books.
- Translation into other languages.

#### 7.6.2. Contribution License

Contributions to the spec (pull requests, errata submissions,
substantive text) are licensed under the same CC BY 4.0 by
default. Contributors retain copyright but grant the
Merkle-Tox project a non-exclusive license to publish,
modify, and re-distribute their contributions under CC BY 4.0
or any compatible license.

#### 7.6.3. Patent Commitments

The Merkle-Tox project makes the following IPR commitment, modelled
on the IETF's BCP 78/79:

- Contributors to the spec disclose any known patents that
  would be infringed by an implementation of the spec.
- Contributors grant a royalty-free, non-exclusive license to
  any patent they hold that is necessary to implement the spec
  as contributed.
- Implementations need not pay royalties or obtain additional
  patent licenses from contributors.

Patents held by non-contributors are outside the project's
control and may pose risks. Implementers SHOULD perform
their own patent diligence.

### 7.7. Interpretation Authority

When two implementations read a normative MUST differently,
who arbitrates?

#### 7.7.1. Spec Editorial Body

A small, named group with normative authority over spec text.
For v1.0:

- Composition: 3-5 members. Initial composition is the project
  founders + invited external cryptographers and protocol
  engineers (target: at least one external member by M4).
- Term: rolling, no fixed term. Members may step down or be
  removed by majority vote of remaining members.
- Decisions: consensus, with majority fallback. Each Body
  decision is logged with member sign-offs.

The Body's authority is limited to:
- Approving / rejecting errata (per §7.4.3).
- Interpreting ambiguous spec text (per §7.7.2).
- Authorizing spec-version revisions and Final declarations
  (per §7.2 + §7.3).

The Body does NOT:
- Write or modify spec text without going through normal
  drafting and review processes.
- Override Conversation Version Lifecycle (per §3.6) decisions
  unilaterally; those follow the same revision process.

#### 7.7.2. Interpretation Process

When an implementer encounters ambiguous spec text:

1. File an interpretation request at the spec repository.
2. The Body issues a written interpretation within 30 days. The
   interpretation is binding within its scope.
3. If the interpretation reveals that spec text is ambiguous to
   a degree requiring correction, the Body files an erratum
   under §7.4.

Interpretations are catalogued at
`spec/interpretations-merkle-tox-vN.md` and numbered analogously
to errata (e.g., `v1.0-I001`).

#### 7.7.3. Dispute Resolution

If two implementations disagree about spec interpretation and
the Body's interpretation does not resolve the disagreement
(e.g., one party considers the interpretation incorrect):

1. The disagreeing party may file a **reconsideration request**
   with a clear statement of why the original interpretation is
   wrong.
2. The Body reconsiders. The Body may affirm, modify, or reverse
   its earlier interpretation.
3. The Body's final position is normative.

There is no further appeal mechanism. Members who consistently
disagree with Body decisions may step down; implementations
that consistently reject Body decisions effectively fork the
spec.

--------------------------------------------------------------------------------

## 8. Open Questions for Manifest Review

The following decisions are baked into this Draft Manifest but
deserve explicit confirmation before Adoption. Seven primary
questions plus three structural questions surfaced during review
(§8.A-§8.C).

1. **Four-document split (Core / Storage / Bindings / Informative).**
   Alternative: monolithic single-document spec like TLS 1.3. The
   four-document split mirrors MLS + Matrix; the monolithic option
   mirrors TLS. We chose four-document; confirm or push back.

2. **Two-axis versioning (Spec Version + Conversation Version).**
   Alternative: single linear version (like Noise, where every
   parameter is in the protocol name). Two-axis is more flexible
   but more complex; single-axis is simpler but couples
   conversation rules to spec evolution.

3. **Algorithm agility via Conversation Version, not negotiation.**
   Alternative: in-protocol cipher-suite negotiation (like TLS).
   Our approach: bake the suite into the Conversation Version
   identifier; new suites = new version. Trade-off: no
   mid-conversation algorithm change; downgrade-attack surface
   eliminated.

4. **Vectors in separate repository.** Alternative: vectors inline
   in spec text. Separate is MLS-style; inline is more
   self-contained but bloats the spec. Recommend separate.

5. **No IETF RFC submission for v1.0.** Reason: IETF process adds
   2-4 years and benefits multi-implementation specs more than
   single-implementation ones. Re-evaluate post-v1.0 once multiple
   implementations exist.

6. **Spec authoring tool / format.** Markdown (current) or
   reStructuredText (RFC tools) or AsciiDoc? Markdown is what
   we have; consider AsciiDoc for better cross-reference support.
   This is a tooling decision, not a structural one; defer to
   M0+1 if needed.

7. **The relationship between this Manifest and the eventual
   spec.** Once spec drafting begins, the Manifest is reference
   material; does it stay in `doc/planning/` or move into the
   spec hierarchy as a non-normative front-matter document?
   Recommend: move to `doc/spec/00-manifest.md` once Adopted.

Reviewers: please respond to each open question with adopt /
reject / counter-proposal.

### 8.x. Additional Structural Questions

Three questions surfaced during structural review that were
not initially in this Manifest. Proposed answers below; each
is normatively binding only after explicit reviewer confirmation
(adopt as below / counter-propose).

#### 8.A. Spec-vs-Reference-Implementation Drift Policy

**The question.** Test vectors are generated from a tagged
reference-implementation commit (§5.4). If spec text and a
generated vector disagree, who wins?

**Proposed answer: Spec text wins.** Vectors are derived
artifacts and are regenerated to match spec text when they
disagree. The reference implementation has no privileged
normative authority; it is one implementation among potential
many. When spec ↔ vector disagreement is discovered:

1. The party finding the disagreement files an issue.
2. The Spec Editorial Body (§7.7.1) determines whether the
   spec text is correct as-written or whether the vector
   reveals a spec bug.
3. If spec is correct, vectors are regenerated against a new
   tagged reference-implementation commit that implements the
   spec correctly. The previous tagged commit and its derived
   vectors are deprecated.
4. If spec is wrong, the spec is corrected via errata or
   substantive-change process (§7.4). Vectors are regenerated
   afterward.

This rule is critical for "spec-first, multiple implementations
possible" (§1 goal). Vectors-win would privilege the reference
implementation and create a de-facto-definitional-implementation
problem.

#### 8.B. Conversation Liveness at Last v1-Capable Member Exit

**The question.** A v1 conversation has migrated some members
to v2 via §3.6 `superseded_by`. The remaining v1 members
gradually leave or migrate too. What happens to the v1
conversation when the last v1-capable member is gone?

**Proposed answer: The v1 conversation freezes** — its DAG is
verifiable by anyone who holds a copy, but no new content can
be authored because there is no active member with the keys
to do so. This is **expected and normal** behavior; alternatives
require a central authority that could "carry" a conversation
through total-member-loss, which is forbidden by Principle 10.

Implementations SHOULD detect the no-active-member state and
surface it to users ("This conversation has no active members;
it is read-only from this point forward").

Members who later return online find the conversation in the
frozen state and may rejoin (re-acquiring keys via the
delegation chain if their device authorization is still valid),
or may abandon the conversation in favor of the v2 successor.

#### 8.C. Normative DAG Forget Operation

**The question.** Once a node is authored and signed, does it
remain in the DAG forever, or is there a normative "forget"
operation that removes nodes from the cryptographic record?

**Proposed answer: No normative forget.** The DAG is
semantically append-only. A node that has been authored, signed,
and accepted by the verifier is forever a member of its
conversation's DAG, regardless of any later `Redaction` or
storage-layer compaction.

Specifically:
- `Content::Redaction` is a **display-level** signal. Receiving
  it instructs a conformant client to hide the redacted message
  from the UI; it does NOT require removal from the DAG.
- Storage-layer compaction (compacting old admin-track nodes
  into snapshots) is an **implementation choice**, not a
  normative operation. A conformant implementation MAY compact
  to save space; a conformant implementation MAY retain
  uncompressed nodes forever. Either is conformant.
- Cross-implementation forensics (Storage Spec) operates on the
  semantic DAG, not on a particular implementation's compacted
  view. Implementations MUST be able to reproduce signed nodes
  on demand if asked (e.g., by another implementation for
  cross-validation), at least for the period until they have
  been compacted away.

**Why no normative forget:** any forget operation requires
either (a) consensus among current members about what to
forget (which scales poorly and is gameable), (b) a central
authority making forget decisions (forbidden by Principle 10),
or (c) per-implementation policy (acceptable, and what we
have today). Per-implementation forget does not provide the
"right to be forgotten" that some users may expect; this is
acknowledged in the threat model and is a deliberate
limitation of the decentralized design.

--------------------------------------------------------------------------------

## Appendix: Comparison to Anchor Specs

For reviewer orientation, how this Manifest's choices compare:

| Property | TLS 1.3 (RFC 8446) | MLS (RFC 9420) | Noise rev34 | Signal X3DH | Matrix | Merkle-Tox |
|---|---|---|---|---|---|---|
| Document split | Monolithic | Monolithic + companions | Monolithic | Monolithic | Modular | Four-doc layered |
| Versioning | Extension framework + cipher suites | ProtocolVersion + extensions | Protocol names | One curve per deployment | Spec version + room version (frozen) | Spec version + Conversation version (frozen) |
| Algorithm agility | Negotiated cipher suites | Negotiated cipher suites | Bound to protocol name | None | Per-event algorithm choice | Bound to Conversation Version |
| Test vectors | Separate (RFC 8448) | Separate repo (`mlswg/mls-implementations`) | Separate repo | None | Per-implementation | Separate repo (planned) |
| RFC published? | Yes | Yes | No (self-published) | No (self-published) | No (custom standards) | Not for v1.0 |
| Process | IETF WG, ~5 years | IETF WG, ~6 years | Single-author, ~4 years | Single-author/Open Whisper | Foundation MSC process | Single-author |
| Page count | ~160 | ~132 | ~60-70 | ~14 | ~600+ aggregate | comparable to MLS in cryptographic-core depth |

The Merkle-Tox spec is positioned in the same scope-class as
MLS (cryptographic core) plus per-binding sub-specs. It is
smaller than Matrix in aggregate because it does not specify
HTTP/JSON federation. Page-count predictions for early-stage
specs are unreliable; the comparison above is for orientation,
not budget.

--------------------------------------------------------------------------------

## Status Tracking

- 2026-05-11 — Draft v0.1 of this Manifest written.
- 2026-05-11 — Structural review pass by opus subagent; 12+ findings
  surfaced.
- 2026-05-11 — Draft v0.2 produced incorporating all review
  findings: C1 (Conversation Version Lifecycle / §3.6 added),
  C2 (Track A / Track B drafting model in §6.1), C3 (split
  Conversation Rule Version from Cipher Suite in §3.2),
  I1 (drop misleading anchor-spec lineage claims),
  I2 (dedupe §2.5 mapping; reconcile transport mapping),
  I3 (added Wire-Format Version, Feature Flag, Reason/Status,
  Hash-Prefix/Object-Type registries; reorganized §4.1),
  I4 (replaced conformance ladder with matrix in §5.5),
  I5 (specified errata process in §7.4.1-§7.4.6),
  I6 (added §7.5 Public Review, §7.6 License & Contribution,
  §7.7 Interpretation Authority).
  Plus m1-m5 and n1-n4 minor fixes.
  Plus three new structural questions (§8.A-§8.C) with
  proposed answers.
- TBD — Second review pass on Draft v0.2.
- TBD — Adoption.
- TBD — Move to `doc/spec/00-manifest.md` as front-matter.

**Reviewer sign-offs** (each reviewer signs after their pass):

- [ ] Project Lead — adopt as written
- [ ] External Cryptographer #1 — TBD reviewer
- [ ] External Protocol Engineer #1 — TBD reviewer
