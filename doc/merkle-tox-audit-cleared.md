# Merkle-Tox: Audit findings investigated and cleared

This is a project-internal log of security-audit findings that were
**raised, investigated, and determined not to be exploitable** in the
current code architecture. It exists so future auditors don't re-walk
the same ground for findings already analysed.

Entries here are NOT closed bugs (those live in commits + the threat
model). They are non-bugs — places where a careful second reading
shows the surface concern is neutralised by an invariant elsewhere.

When adding to this list, prefer:

- The exact concern as raised, in the language it was raised in.
- Why it isn't exploitable, with file/line citation for the load-bearing
  invariant.
- An "if revisited" pointer in case the threat model later shifts.

When in doubt about whether to add: be generous. The cost of an extra
section is small; the cost of re-discovering and re-disproving the same
finding three audits in a row is real (this has now happened for the
sender_hint collision and the Content discriminant swap).

---

## Crypto / DAG

### Delegation certificate lacks replay nonce / timestamp

**Raised (Round 6, 2026-04-23):**
`DelegationSignData` (`identity.rs:32-39`) contains `version`,
`conversation_id`, `device_pk`, `permissions`, `expires_at`, but no
nonce or signed-at timestamp. The same cert verifies identically every
time, so an attacker who captured a cert could replay it within the
expiry window, re-authorising a device that was since revoked.

**Why it isn't exploitable:**

- A cert by itself does nothing. To re-authorise a device it must be
  wrapped in a fresh `AuthorizeDevice` admin node whose outer signature
  is the *replayer's* device key.
- A non-admin attacker cannot sign that outer node, so the replay path
  never reaches `authorize_device`.
- An admin attacker doesn't need to replay — they can author their own
  cert directly.
- The only remaining case (admin Bob replays Alice's cert after Alice
  revoked the device) is neutralised by `get_permissions_recursive` at
  `identity.rs:676-727`: revocations in `ctx.admin_ancestor_hashes`
  dominate any `AuthRecord` whose `auth_hash` is ancestral to the same
  evaluation, regardless of how the re-auth was produced. The MAD /
  seniority tuple (`rev.revoker_seniority <= my_seniority`) settles
  ordering.

**If revisited:** the cert-replay observation is a cosmetic redundancy
in the signed data, not a forgery vector. If the threat model later
needs cert-level deniability or per-cert audit trails, revisit.

---

### `sender_hint` collision → attribution spoofing

**Raised (Round 6, 2026-04-23):**
`sender_hint: [u8; 4]` in `WireNode` is 4 bytes wide; a birthday
collision between two senders' K_msg-derived hints could let an
attacker swap one sender's hint for another's.

**Why it isn't exploitable:**

- `sender_hint` IS in `WireAuthData` (`dag.rs:287`), so any post-sign
  mutation breaks the signature.
- The hint is a routing optimisation only; sender identification falls
  through to the slow-path AEAD-try-all loop on mismatch (see
  `engine/conversation.rs::try_sender_for_wire`).
- Even with a collision, AEAD under the wrong sender's K_header fails,
  so the slow path takes over and attributes correctly. Worst case:
  one slow-path lookup, no spoofing.

---

### AEAD AAD doesn't include `conversation_id` / `sender_pk` explicitly

**Raised (Round 6, 2026-04-23):**
`encrypt_routing_aead` uses only `payload_hash` as AAD; `conversation_id`
and `sender_pk` are not bound explicitly into the AAD bytes.

**Why it isn't exploitable:**

- `K_header` is derived from `(K_conv, conversation_id, sender ratchet
  state)`, so a cross-room replay attempts decryption under the wrong
  key and fails at the Poly1305 tag check.
- The Poly1305 tag already binds the ciphertext; re-keying an existing
  ciphertext to a different room fails AEAD. No additional AAD fields
  are needed for the current threat model.

---

### `Content` enum discriminant swap

**Raised (Round 6, 2026-04-23):**
Could an attacker swap the `Content` enum variant tag and keep the
signature valid?

**Why it isn't exploitable:**

- `serialize_for_auth` embeds `tox_proto::serialize(&self.content)`
  (`dag.rs:495`), which encodes the discriminant as the first byte(s)
  of the enum's wire form. Changing the variant changes the signed
  bytes and breaks the signature.

---

## Quarantine / verification

### Permission re-check on quarantined nodes

**Raised (Round 10, 2026-04-25):**
A node that quarantines (e.g. parent not yet verified) bypasses the
permission check; if authorisation later arrives the node could be
promoted without ever passing `check_permissions`.

**Why it isn't exploitable:**

- The permission check at `verification.rs:188-194` is correctly gated
  on `is_authorized || has_authorization_record`.
- When a quarantined node is re-verified later (parent arrives,
  authorisation record arrives), `handle_node_internal_ext` runs the
  full pipeline — including the permission check — for the freshly
  unquarantined node. There is no path that promotes a quarantined
  node to verified without re-running this check.

---

### Speculative-quarantine total conversation lockout

**Raised (Round 11, 2026-04-25):**
The per-conversation cap `MAX_SPECULATIVE_NODES_PER_CONVERSATION = 1000`
returns `TooManySpeculativeNodes` for any further node once full. An
authorised peer who fills 1000 quarantine slots could, in principle,
lock out all subsequent legitimate arrivals.

**Why it isn't a real DoS:**

- The cap is only consulted in the `else` branch of
  `verification.rs:859-873` (i.e. for nodes that did not pass the
  generic verified path). Legitimate verified nodes are unaffected.
- An authorised peer's *honest* out-of-order arrival (parent in flight
  but authoring is correct) fails at `check_permissions`
  (`verification.rs:188-194`) BEFORE reaching the spec-cap gate,
  because `admin_ancestor_hashes` is empty when the parent isn't yet
  visible. The error surfaces as `PermissionDenied`, not
  `TooManySpec`.
- The only nodes that legitimately reach the spec gate are
  unauthorised-stranger nodes waiting for vouches, or misbehaving
  authorised authoring (future/past timestamp OOB). Both are useless
  to honest peers; rejecting them is mostly equivalent to silently
  dropping them.

**If revisited:** if the verification flow is rearchitected so
authorised peers' out-of-order nodes reach the spec gate without
permission rejection, this becomes a real DoS surface again. Add a
per-peer quarantine cap then.

---

### `verified_node_seqs` and `peer_ephemeral_signing_keys` unbounded

**Raised (Round 11, 2026-04-25):**
Both are HashMaps keyed by `(peer, ...)` with no global cap. An
authorised peer who keeps authoring at high sequence numbers or who
keeps rotating epochs can grow them indefinitely.

**Why it isn't a real DoS:**

- `verified_node_seqs` is gated by `MAX_VERIFIED_NODES_PER_DEVICE = 1000`
  per epoch (`verification.rs:350`). Each epoch advance requires the
  peer to author an SKD, which itself is rate-limited by their SKD
  authoring rate.
- `peer_ephemeral_signing_keys` has one entry per `(peer, epoch)`. A
  peer must pay for each new SKD; at sustained 100 SKDs/sec a single
  peer takes ~11 days to fill ~50 MB worth of entries. Slow,
  proportional to attacker work, well within "byzantine-authorised
  member abuses their authorisation" rather than a remote DoS.

**If revisited:** if the threat model later treats authorised-member
abuse as a higher-priority concern, add per-peer LRU caps.

---

## CAS / sync

### CAS piece-offset overflow

**Raised (Round 10, 2026-04-25):**
`piece_idx * PIECE_SIZE` could overflow `u64` for an attacker-supplied
piece index.

**Why it isn't exploitable:**

- `piece_idx` is derived internally from chunk geometry (`0..total_pieces_in_chunk`)
  in the receiver's progress code, never read from a peer-supplied
  field. `total_pieces_in_chunk` is at most ~55 (CHUNK_SIZE /
  PIECE_SIZE), so overflow is unreachable.

---

### `BlobAvail` re-advertisement multicast

**Raised (Round 11, 2026-04-25):**
`engine/mod.rs:1161` emits one `BlobAvail` packet per session peer per
active blob_sync per poll cycle. With many peers, this is N packets
per inbound progress message.

**Why it isn't a real DoS:**

- Throttled to once per second per blob_sync via
  `READVERTISE_INTERVAL = 1s`.
- Peer count is bounded by conversation membership; legitimate session
  counts are O(tens), not O(thousands).
- Packets are tiny (~48 bytes payload).
- The amplification factor is bounded and self-limiting; not a DoS
  surface against a healthy mesh.

---

### `K_conv` rotation during sketch

**Raised (Round 10, 2026-04-25):**
A peer mid-sketch when K_conv rotates may compute IBLT cells under a
key the receiver no longer accepts.

**Why it isn't a real DoS:**

- Mitigated by grace-for-joiners (commit `1b166aa`, Round 8b): a peer
  with no successful decode yet is treated as a joiner and gets a
  decode-failure grace window before any blacklist escalation.
- A more robust fix (epoch marker in the sketch envelope) is a protocol
  change, not an audit closure. Defer until the protocol bumps.

---

### Unwrap-on-peer-payload findings

**Raised (Round 10, 2026-04-25, Agent C):**
A pass for `.unwrap()` calls on peer-supplied payload bytes flagged
several sites as panic-on-malformed candidates.

**Why it isn't exploitable:**

- All sites flagged are guarded by upstream length checks. The
  serialisation layer enforces `MAX_MESSAGE_SIZE` (Round 5,
  `tox-proto/src/lib.rs`) and protocol-specific caps before any
  `unwrap()` is reached.

**If revisited:** any new code path that decodes peer payload without
a prior length check should be audited against this invariant. Don't
remove the upstream caps without re-auditing the unwrap sites.

---

## Rate limits / time domain

### Handshake retry cap keyed by `(conv, peer)` rather than per-peer

**Raised (Round 2, 2026-04-22):**
Spec says "3 retries per peer per 10 min"; code shards by
`(conv_id, peer_pk)`, so an attacker sharded across N conversations
multiplies the cap by N.

**Why it isn't a real DoS:**

- `author_x3dh_key_exchange` is locally-triggered only. There is no
  remote-attacker code path that drives more handshakes than the local
  user requests.
- Spec-alignment concern, not a security one.

**If revisited:** if a future code path lets a remote peer trigger our
handshake authoring, re-audit this cap.

---

### Fragment reassembly slot exhaustion

**Raised (Round 2, 2026-04-22):**
`MAX_CONCURRENT_REASSEMBLY = 32` per session — a malicious peer could
exhaust their own slots and silence themselves.

**Why it isn't a real DoS:**

- Per-session scope means the attack is self-defeating. The attacker
  exhausts only their own reassembly slots, not anyone else's.

**If revisited:** if reassembly slots become shared across peers, this
becomes a real surface. Currently they are not.

---

### OPK exhaustion via rapid KeyWrap targeting

**Raised (Round 2, 2026-04-22):**
A peer could rapidly fire KeyWraps to consume all four OPKs from an
Announcement and force fallback to the last-resort pre-key.

**Why it isn't a real DoS:**

- Requires an authorised peer (compromised-authorised threat-model
  bucket).
- Bounded by 4 OPKs per Announcement with rotation at 100 handshakes
  (Gap D, MEMORY).
- The compromised-authorised threat model already accepts forged
  authoring at this scope.

**If revisited:** if OPKs-per-Announcement is raised significantly OR
if Announcement rotation is loosened, the per-peer rate gain matters
again.

---

### Opaque-store cross-restart growth (`opaque_store_usage` resets on startup)

**Raised (Round 12, 2026-04-25):**
At engine startup `MerkleToxEngine::opaque_store_usage` (`engine/mod.rs:80`)
is initialised to `HashMap::new()` (`engine/mod.rs:418`) regardless of
what the persistent store contains. The in-process quota check at
`engine/handlers/mod.rs:650` only evicts entries it knows about
(those in the live `opaque_store_usage` Vec). Stale entries from a
prior session remain in the persistent store but invisible to the
quota — repeated restarts could grow the persisted opaque store
without bound.

**Why it isn't exploitable:**

There are TWO independent 100 MB quotas, not one:

- `OPAQUE_STORE_QUOTA` (in-process, `tox-proto/src/constants.rs:98`) —
  the in-memory tracker the agent flagged.
- `OPAQUE_TOTAL_MAX_SIZE` (on-disk, `merkle-tox-fs/src/opaque.rs:9`) —
  enforced by `check_eviction` (`opaque.rs:96-131`) which fires on
  every `put_node` call (`opaque.rs:50`).

The disk-layer eviction is independent of any in-process state. Even
when `opaque_store_usage` resets to zero on restart, every fresh
`put_wire_node` triggers `check_eviction`, which iterates the actual
on-disk segments and prunes the oldest one whose entries can be
relocated until total size is back under 100 MB. Anchors (admin /
KeyWrap nodes) are preserved across the prune (`opaque.rs:148-186`).

So the persisted opaque-store size is bounded at 100 MB regardless of
restart count. The in-process tracker is an additional defense layer
on the live message path, not the load-bearing cap for persisted
storage.

**If revisited:** the two-quota architecture is load-bearing. If
either quota is removed (e.g. someone "unifies" them by removing the
in-process one), re-audit. If `merkle-tox-fs` ever exposes a path
that bypasses `put_node` (and hence `check_eviction`), re-audit.

---

## How to add to this file

1. Make sure the finding really doesn't fit in the threat model
   (`doc/merkle-tox-threat-model.md`). If it's a real threat with a
   real fix, the threat model is the home. This file is for
   non-threats.
2. Cite the round/date the finding was raised.
3. Cite the load-bearing invariant by file:line. If the invariant is
   far from the surface concern, future auditors won't find it
   without the citation.
4. Add an "If revisited" line. The invariants we rely on today may
   not hold tomorrow; the next auditor needs to know what to re-check.
