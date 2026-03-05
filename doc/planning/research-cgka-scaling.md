# Research Notes: Decentralized CGKA for Group-Size Scaling

**Status:** Parked. Decided 2026-05-11 to focus v1 on linear-scaling
(O(N) per rotation) key distribution, accepting the practical
group-size cap that imposes. Decentralized CGKA is the realistic
v2+ scaling path, captured here for future reference.

**Document type:** Planning / research-notes. Not normative spec
content.

--------------------------------------------------------------------------------

## 1. The Problem This Solves

Merkle-Tox v1 uses **per-sender symmetric ratchet plus `KeyWrap`**
for group key distribution. Each `KeyWrap` node contains one
encrypted entry per recipient device. Per-rotation bandwidth scales
**O(N) per author, O(N²) across the whole group per rotation
cycle.**

This is the same family as Signal Sender Keys, Matrix Megolm, and
Briar. It is the deployed pattern for serverless E2E group chat.
Its practical limit is roughly 100-512 members depending on
rotation cadence and what bandwidth users tolerate. Above that,
the linear scaling becomes operationally infeasible
(`doc/planning/constants-cost-reference.md` §5 has the numbers).

**MLS (RFC 9420) addresses this** with TreeKEM — a binary tree of
keys where each member only updates their path, yielding **O(log N)**
per rotation. This is what makes MLS scale to ~1000+ member groups.
**MLS requires a Delivery Service.** Principle 10 (No Privileged
Infrastructure) forbids deploying MLS as-specified in Merkle-Tox.

The research question: can we get MLS-class scaling without a DS?

--------------------------------------------------------------------------------

## 2. State of the Art (As of 2026-05)

Three published constructions targeting the no-DS case, plus
ongoing research.

### 2.1. DCGKA (Weidner, Kleppmann, Hugenroth, Beresford)

- **Paper:** "Key Agreement for Decentralized Secure Group
  Messaging with Strong Security Guarantees" — ePrint 2020/1281
  ([PDF](https://eprint.iacr.org/2020/1281.pdf)), ACM CCS 2021
  ([DOI](https://dl.acm.org/doi/10.1145/3460120.3484542)).
- **Authors:** Matthew Weidner (then Cambridge, now Carnegie
  Mellon), Martin Kleppmann (Cambridge), Daniel Hugenroth
  (Cambridge), Alastair R. Beresford (Cambridge).
- **Performance:** Linear (O(N)) per rotation. Practical limit
  ~100 members.
- **Threat model:** Adversary may delay, reorder, and observe
  messages. Active corruption of members during the session is
  handled. Causal order via append-only operation log.
- **Maturity:** Published at top-tier venue (CCS); formal security
  proof; 4+ years of cryptographic-community scrutiny; reference
  implementation (TypeScript) by Weidner's group.
- **Why it matters for Merkle-Tox:** Threat model matches almost
  exactly. The "append-only operation log with causal order" is
  Merkle-Tox's DAG. This is the most-vetted CGKA construction
  that fits.
- **Limitations vs MLS TreeKEM:** Performance is linear, not
  logarithmic. So DCGKA doesn't actually unlock larger groups
  than what we already have — it gets us comparable scaling
  with a cleaner formal model.

### 2.2. DeCAF (Alwen et al.)

- **Paper:** "DeCAF: Decentralizable Continuous Group Key Agreement
  with Fast Healing" — ePrint 2022/559
  ([PDF](https://eprint.iacr.org/2022/559.pdf)), SCN 2024
  ([Springer](https://link.springer.com/chapter/10.1007/978-3-031-71073-5_14)).
- **Authors:** Joël Alwen, Benedikt Auerbach, Miguel Cueto Noval,
  Karen Klein, Guillermo Pascual-Perez, Krzysztof Pietrzak (IST
  Austria et al.).
- **Performance:** Linear per rotation; **log(t) recovery** for t
  corrupted users. Faster post-compromise healing than DCGKA.
- **Maturity:** Newer (2024 publication); less battle-tested than
  DCGKA; formal proof exists.
- **Why it matters:** Tighter post-compromise security properties
  than DCGKA. Same operational model (append-only data structure
  / no central authority).

### 2.3. BeeKEM (Ink & Switch / Keyhive)

- **Disclosure:** Research notebook
  ([keyhive/notebook/02](https://www.inkandswitch.com/keyhive/notebook/02/));
  paper forthcoming. Not yet formally published.
- **Authors:** Ink & Switch Keyhive team.
- **Performance:** **Logarithmic** (O(log N)) per rotation —
  comparable to MLS TreeKEM. Target: thousands of members.
- **Maturity:** Research stage. Pre-publication. Less scrutiny
  than DCGKA or DeCAF. Being deployed into Keyhive (Ink &
  Switch's local-first identity infrastructure) but not into a
  messenger.
- **Why it matters:** This is the construction that would
  unlock large-group serverless messaging. If/when it lands at
  a published venue with peer-reviewed proof, it becomes the
  natural target for a v2.

### 2.4. Other Relevant Work

- **CoCoA** (Alwen et al.) — concurrent CGKA construction;
  precursor to DeCAF.
- **Fork-Resilient CGKA** (Alwen et al., 2023) — handles
  conversation forks. Relevant for Merkle-Tox if conversations
  ever split.
- **Continuous Group-Key Agreement: Concurrent Updates Without
  Pruning** — recent (2024+) academic work on concurrent
  update handling.
- **MLS extensions for federated/decentralized operation** —
  active discussion in MLS WG but no published RFC.

--------------------------------------------------------------------------------

## 3. Why Not in v1

The decision (2026-05-11) to keep v1 on linear-scaling key
distribution rests on:

1. **Adopting research-grade crypto at scale is a substantial
   undertaking.** Approximately 2-4 years wall-clock to
   production-grade for a focused team:
   - Implementation: 6-12 engineer-months
   - Integration with surrounding Merkle-Tox: 3-6 engineer-months
   - Formal verification (Tamarin/ProVerif): 6-12 engineer-months
   - External audit ($300K-500K range; firms with CGKA expertise
     are scarce): 3-6 calendar months
   - Empirical validation under adversarial conditions: 3-6 months
   - Cross-implementation interop validation: requires multiple
     implementations to exist

2. **The available construction that's most-vetted (DCGKA) is
   also linear in performance.** Adopting it doesn't change v1's
   scaling envelope — it just changes the cryptographic family.
   The construction that actually changes scaling (BeeKEM) is
   pre-publication and would require trusting research-grade
   crypto at scale.

3. **v1 product positioning is "encrypted decentralized chat for
   friends, family, and small teams"** — the linear-scaling cap
   isn't blocking the target use case.

4. **The trade is scope, not capability.** The current design
   works for v1. CGKA work would expand scope substantially with
   research-grade risk attached.

--------------------------------------------------------------------------------

## 4. When to Revisit

Triggers for re-opening this:

- **BeeKEM gets published at a top venue (CCS, S&P, USENIX,
  Eurocrypt, Crypto) with formal proof.** Removes the
  research-stage risk. Becomes a credible engineering target.
- **The product position shifts toward large-group chat.** If
  v1 is shipping and users want 1000-member groups, the linear
  scaling becomes the binding constraint.
- **An academic collaboration becomes available.** If Weidner,
  Kleppmann, or the Ink & Switch team express interest in
  collaborating on a deployment, the formal-verification and
  audit costs drop substantially because the authors already
  understand the proof.
- **External funding for the research-deployment work.** OTF,
  academic-industry partnership, or similar.

If/when reopening, the immediate next steps would be:

1. Read the DCGKA paper carefully; check whether DCGKA's
   adversary model fully covers Merkle-Tox's bootstrap-exception
   cases (`merkle-tox-threat-model.md` §3.17) and the DAG-causal-
   order assumption matches.
2. Spike: implement DCGKA core algorithm in isolation, in Rust,
   from the paper. 2-4 weeks. Use it to scope the full
   integration timeline.
3. Reach out to the authors. Research-deployment partnerships
   are common; the academic side often welcomes a deployment
   vehicle.
4. Decide between DCGKA (vetted, linear) and BeeKEM
   (research-stage, logarithmic) based on the construction's
   maturity at the time of revisit.

--------------------------------------------------------------------------------

## 5. Validation Approach (For When We Get There)

In increasing rigor, the layered validation a CGKA-deployment
project would need:

1. **Mechanized formal model** in Tamarin or ProVerif. Proves
   the abstract construction has its claimed security
   properties under a precise adversary model. Catches design
   errors.
2. **Property-based testing** against the formal model's
   invariants. proptest-style random message orderings,
   adversarial concurrent operations. Catches
   implementation-doesn't-match-model errors.
3. **Cryptographic fuzzing.** Malformed messages, equivocation,
   replays. Catches input-handling bugs.
4. **Performance benchmarking under adversarial conditions.**
   High packet loss, partitions, byzantine peers. Validates
   performance claims.
5. **Cross-implementation interop.** Second independent
   implementation; same operation log produces same group
   state. Catches spec ambiguities.
6. **External cryptographic audit** with academic consultant.
   Reviews implementation, formal proofs, and composition
   safety.

Each layer catches different bug classes; production-grade
confidence requires most of them.

--------------------------------------------------------------------------------

## 6. References

Direct links collected for future reference:

- **DCGKA (Weidner et al., CCS 2021):**
  - [ePrint 2020/1281 (full version)](https://eprint.iacr.org/2020/1281)
  - [PDF](https://eprint.iacr.org/2020/1281.pdf)
  - [Kleppmann's blog post explaining DCGKA](https://martin.kleppmann.com/2021/11/17/decentralized-key-agreement.html)
  - [ACM DL entry](https://dl.acm.org/doi/10.1145/3460120.3484542)
- **DeCAF (Alwen et al., SCN 2024):**
  - [ePrint 2022/559](https://eprint.iacr.org/2022/559)
  - [PDF](https://eprint.iacr.org/2022/559.pdf)
  - [Springer chapter](https://link.springer.com/chapter/10.1007/978-3-031-71073-5_14)
- **BeeKEM / Keyhive (Ink & Switch):**
  - [Keyhive research notebook entry on BeeKEM](https://www.inkandswitch.com/keyhive/notebook/02/)
- **MLS RFC 9420** (for comparison; what TreeKEM looks like in a
  centralized model):
  - [RFC 9420](https://datatracker.ietf.org/doc/html/rfc9420)
- **Continuous Group-Key Agreement: Concurrent Updates Without
  Pruning:**
  - [Springer chapter](https://link.springer.com/chapter/10.1007/978-3-032-01913-4_5)
- **Fork-Resilient CGKA:**
  - [Springer chapter](https://link.springer.com/chapter/10.1007/978-3-031-38551-3_13)

--------------------------------------------------------------------------------

## 7. Related Park-It Decisions

This document also covers, by extension, related research
directions that we considered for v1 and decided to defer:

- **Ring signatures for admin track** — anonymizes admin
  identities within the admin set. Real benefit (closes the
  "forensic admin-identity extraction" threat surface), but
  the design-decisions subagent argued admin-action
  accountability is a feature, not a leak. Parked unless the
  product position shifts toward higher-anonymity use cases.
  (Was tracked as task #51; reclassified as research-park.)
- **Post-quantum migration** — captured in Spec Manifest §3.6
  (Conversation Version Lifecycle). The mechanism is
  `superseded_by` — when PQ algorithms mature, new
  conversations adopt a new Cipher Suite identifier. No
  research work needed today; the design accommodates the
  future event.
- **Asynchronous CGKA with active adversary** — covered by
  CGKA references above. Same parking rationale.
