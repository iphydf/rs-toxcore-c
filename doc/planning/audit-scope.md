# Merkle-Tox External Audit: Scope and Cost Reference

**Status:** Planning document. Not normative spec content.

**Purpose:** Evidence base for soliciting external security audit quotes from
Trail of Bits, NCC Group, Cure53, or equivalent. Derived from published
audit reports of comparable cryptographic-messaging systems.

--------------------------------------------------------------------------------

## 1. Comparable-Audit Table

| System | Firm / Authors | Year | Scope | Effort | Findings | Funding | Public Report |
|---|---|---|---|---|---|---|---|
| Matrix Olm/Megolm | NCC Group | 2016 | Olm double ratchet + Megolm group ratchet (JS SDK excluded); cryptographic review of libolm v1.3.0 | 2 consultants × ~3 weeks ≈ **6 person-weeks** | 1 H / 1 M / 6 L / 1 Info (3 Olm + 6 Megolm) | Matrix + OTF | [PDF](https://www.nccgroup.com/media/5bspr3ie/_ncc_group_olm_cryptogrpahic_review_2016_11_01-1.pdf) |
| Briar | Cure53 | 2017-03 | Crypto protocols + source code audit + penetration test; full Android app | 6 testers × 13 days ≈ **16 person-weeks** | "Several security-relevant issues," all addressed pre-beta | OTF | [Briar news](https://briarproject.org/news/2017-beta-released-security-audit/) |
| Threema | Cure53 | 2020-10 | iOS + Android mobile apps; cryptographic protocols + code audit | Person-weeks not stated; ~standard mobile-app audit | 8 findings total, **all Informational/Low** | Threema | [PDF](https://cure53.de/pentest-report_threema.pdf) |
| Threema Rust crypto libraries | Cure53 | 2022-02 | Rust crypto libraries (saltyrtc, sodalite, neng) | Not stated | Not stated in summary | Threema | [PDF](https://cure53.de/pentest-report_rust-libs_2022.pdf) |
| Threema Desktop | Cure53 | 2024-01 | Desktop application | Not stated | Not stated in summary | Threema | [PDF](https://cure53.de/pentest-report_threema-desktop.pdf) |
| Signal protocol (formal) | Cohn-Gordon, Cremers, Dowling, Garratt, Stebila | 2016-11 | Formal symbolic security analysis (Tamarin-style); cryptographic protocol only, not implementation | ~6 person-months academic effort | Identified theoretical strengthening suggestions (NAXOS-style, static-static DH) | Academic | [ePrint 2016/1013](https://eprint.iacr.org/2016/1013.pdf) |
| PQXDH (Signal) | Bhargavan et al. | 2024 | Formal verification of post-quantum extension (ProVerif + CryptoVerif) | Multi-month academic effort | "Highlighted parts of specification under-described, could have led to attacks if misinterpreted" | Academic + Signal collaboration | [USENIX Security 2024](https://www.usenix.org/conference/usenixsecurity24/presentation/bhargavan) |
| Matrix Olm/Megolm (academic) | Albrecht, Celi, Dowling, Jones | 2023 | "Practically-exploitable Cryptographic Vulnerabilities in Matrix" — found post-NCC issues academic analysis missed | Academic | Multiple practical attacks against historical Matrix versions | Academic | [paper](https://nebuchadnezzar-megolm.github.io/static/paper.pdf) / [ePrint 2023/1300](https://eprint.iacr.org/2023/1300.pdf) |

### Notes on this table

- **Person-weeks** are extracted where stated; otherwise estimated from
  consultant count × calendar duration. Person-weeks are NOT the same as
  calendar weeks (multiple consultants in parallel compress calendar but not
  effort).
- **Findings** are absolute counts when published. Cure53 historically uses
  Critical / High / Medium / Low / Informational. NCC Group uses similar but
  may bucket differently.
- **Funding** "OTF" = Open Technology Fund. OTF grants for messenger
  cryptographic audits historically run **$50K-$150K** for the work itself;
  larger engagements (multi-firm, formal verification) have run $200K-$500K.
  Costs of academic analyses are research-grant-funded and not directly
  comparable.

--------------------------------------------------------------------------------

## 2. Trail of Bits Pricing Reference

Per published statements:

- **Standard engineer-week rate:** $25,000.
- **Standard audits:** $30,000-$100,000+ for smaller scopes.
- **Enterprise / specialized cryptography audits:** **$80,000-$200,000** for
  typical multi-week engagements.
- **Large multi-domain engagements:** Up to ~$600,000 (24 person-weeks
  cited recently).

NCC Group and Cure53 pricing is comparable; NCC Group tends to take longer
engagements at slightly lower per-week rates, Cure53 is typically more
intensive (6+ consultants × short duration).

--------------------------------------------------------------------------------

## 3. Merkle-Tox Scope Estimate

### Components requiring cryptographic audit

| Component | Comparable analog | Estimated person-weeks |
|---|---|---|
| Handshake (ECIES → X3DH per pre-1.0 plan) | Signal X3DH | 2-3 |
| Ratchet (per-sender linear) | Signal Double Ratchet (Olm half) | 2-3 |
| KeyWrap + epoch rotation | New (no direct analog) | 2-3 |
| Identity / delegation chain | New (more complex than Signal's identity) | 2-3 |
| DAG verifier + §3.17 bootstrap-exception invariants | New | 2-4 |
| Sync state machine (heads + IBLT + reconcile) | New | 2-3 |
| CAS + blob protocol | New | 1-2 |
| NGC transport binding | New | 1-2 |
| Threat-model cross-checks | All NCC/Cure53 audits include this | 1-2 |
| **Subtotal: cryptographic protocol audit** | | **15-25 person-weeks** |

### Components requiring implementation audit (separate or combined)

| Component | Estimated person-weeks |
|---|---|
| `merkle-tox-core` (verifier, ratchet, KeyWrap, identity) | 3-5 |
| `tox-proto` serialization, FFI boundaries | 1-2 |
| `merkle-tox-fs` persistence layer, fsync / locking | 1-2 |
| Memory safety / unsafe blocks / side-channel review | 2-3 |
| **Subtotal: implementation audit** | **7-12 person-weeks** |

### Total scope estimate

- **Crypto-protocol audit alone:** 15-25 person-weeks at $25K/wk = **$375K-$625K**
  (Trail of Bits style)
- **Crypto-protocol audit alone:** Cure53/NCC pricing typically 10-20%
  lower for similar scope = **$300K-$550K**
- **Combined crypto + implementation audit:** 22-37 person-weeks =
  **$550K-$925K** (Trail of Bits) / **$450K-$800K** (Cure53/NCC)
- **Phase 1 only — narrow cryptographic-protocol audit, ratchet + handshake
  + KeyWrap focus:** 8-12 person-weeks = **$200K-$300K**

### Comparison to anchor audits

- **NCC Olm 2016** at 6 person-weeks covered just double ratchet + group
  ratchet. Merkle-Tox crypto core is **2.5-4× this scope** (DAG verifier
  alone is comparable to Olm in surface area; identity / delegation
  doubles it; KeyWrap epoch rotation adds new surface).
- **Briar 2017** at 16 person-weeks (Cure53) covered protocol + implementation
  + pentest on a full Android app. Merkle-Tox aiming at similar coverage
  scope (crypto + implementation + threat-model) would land in the
  **20-30 person-week** range, **comparable to Briar's total scope** but
  with denser cryptographic content.

--------------------------------------------------------------------------------

## 4. Scope Recommendation

**Recommendation: two-phase audit, with optional third phase.**

### Phase 1: Crypto-Protocol Audit (15-25 person-weeks, $300K-$625K)

Scope:
- Handshake protocol (X3DH composition, signed ECIES, KeyWrap)
- Per-sender ratchet construction and key derivation
- Epoch rotation and SenderKey distribution
- Identity hierarchy and DelegationCertificate chain validation
- DAG verifier including §3.17 bootstrap-exception invariants
- Sync protocol (`SyncHeads`, IBLT reconciliation, SyncSketch)
- Threat-model cross-validation: confirm claimed mitigations match
  actual protocol behavior

Goals:
- Identify cryptographic protocol flaws (chosen-ciphertext, replay,
  oracle, malleability, downgrade) before implementation locks them in.
- Validate that the spec is internally consistent and the §3.17
  invariants are sufficient.
- Get a publishable third-party endorsement of the protocol design.

Done **after** the wire-breaking changes from the pre-1.0 checklist
have landed and stabilized (X3DH composition, AEAD on payload, version
field, `conv_id := hash(Genesis)`). Auditing pre-changes wastes
auditor effort on code that's about to change.

### Phase 2: Implementation Audit (7-12 person-weeks, $175K-$300K)

Scope:
- `merkle-tox-core` (verifier hot paths, ratchet ops, identity chain
  evaluation, §3.17 invariant enforcement on real code)
- `tox-proto` deserializer (DoS surface, integer-overflow paths,
  BoundedVec / BoundedBytes enforcement)
- `merkle-tox-fs` persistence layer (fsync discipline, lock enforcement,
  recovery atomicity)
- Memory safety / `unsafe` blocks / zeroization compliance
- Side-channel review of crypto primitives (ChaCha20-Poly1305, Ed25519,
  X25519 — likely RustCrypto / dalek libraries)
- FFI surface (where Rust meets c-toxcore)

Done **after** Phase 1 findings have been fixed in the implementation.
Same or different firm acceptable. Same firm is cheaper (familiarity);
different firm catches more bugs (fresh eyes).

### Phase 3 (Optional): Specification Review (2-4 person-weeks, $50K-$100K)

Scope:
- Read the spec docs as a clean-room implementer would
- Flag ambiguities, missing constants, underspecified state transitions
- Validate conformance-test extractability
- Identify spec-text contradictions and cross-section invariant breaks

Done **before** Phase 1 if budget allows (spec ambiguities found by
auditors during Phase 1 are 3-5× more expensive than spec ambiguities
found by a focused spec review). Skipped if formal verification
(Tamarin/ProVerif) is being commissioned separately — the formal model
work will surface similar issues.

### Total all-three phases: $525K-$1.025M

This is a significant commitment. For comparison:
- Signal commissioned ~$300K of audits over ~5 years across multiple firms
- Matrix Olm audit was ~$75K (OTF-funded)
- Wire's published audits total in the $200K-$400K range over 2-3 audits

Merkle-Tox at the high end is comparable to early-stage MLS audit
investment.

--------------------------------------------------------------------------------

## 5. Timing Recommendation

Audit timeline anchored against the spec-and-impl trajectory:

```
Month  0   2   4   6   8   10  12  14  16  18  20  22  24
       |   |   |   |   |   |   |   |   |   |   |   |   |
[Wire-breaking impl changes]
        (X3DH, AEAD, version, conv_id binding, etc.)
           [Spec Milestone 0+1: Core normative draft v0.9]
                  [Spec M2: Sync/Recon/CAS/Transport]
                          [Spec M3: Threat model + finalization]
                                  [Phase 3: Spec review (optional)]
                                      [Phase 1: Crypto-protocol audit]
                                              [Phase 1 findings fixed]
                                                      [Phase 2: Implementation audit]
                                                              [v1.0 publication]
```

- **Phase 3 (spec review) starts after Spec M3** (~month 10-12).
  Pre-condition: spec at 4.5/5 precision, no in-flight design changes
  in the audited sections.
- **Phase 1 (crypto-protocol audit) starts after Phase 3 findings fixed**
  (~month 14-16). Pre-condition: spec stable, test vectors generated,
  threat model finalized.
- **Phase 2 (implementation audit) starts after Phase 1 findings fixed**
  (~month 18-20). Pre-condition: impl conforms to spec, fuzz harness
  passing, regression tests stable.

Going faster than this is possible but risks auditor effort being
wasted on code that changes between scoping and engagement.

--------------------------------------------------------------------------------

## 6. Pre-Audit Checklist

Comparable audits required these to be in place before engagement:

### For Phase 1 (Crypto-Protocol):

- [ ] **Spec frozen.** No in-flight design changes in the audited
  components for at least 4 weeks pre-engagement.
- [ ] **Threat model published** and reviewed by spec authors.
- [ ] **Reference test vectors** generated and stable (KATs for
  ratchet, handshake transcripts, KDF chains).
- [ ] **Conformance criteria** documented (what does "correct
  implementation" mean for each subprotocol).
- [ ] **Known-attack list** with mitigations cited
  (Merkle-Tox already has this in `merkle-tox-threat-model.md` §3).
- [ ] **Glossary and notation** consistent across spec sections.

### For Phase 2 (Implementation):

- [ ] **Spec → impl traceability document** (which spec section is
  implemented where in code).
- [ ] **Code coverage report** for the components in scope.
- [ ] **Fuzz harness** running continuously, with current findings
  triaged.
- [ ] **CI green** for at least 4 weeks pre-engagement.
- [ ] **Known-issues list** disclosed upfront (don't make auditors
  find bugs you already know about — waste of their time).
- [ ] **Build instructions** that work from a clean checkout
  without insider knowledge.

### For Phase 3 (Spec Review):

- [ ] Same as Phase 1 pre-conditions.
- [ ] **Reference implementation** available for the reviewer to
  cross-check.

--------------------------------------------------------------------------------

## 7. RFP-Ready Scope Brief

The following can be sent to audit firms as a scope brief. Customize the
contact info and timeline before sending.

> Subject: Cryptographic Protocol Audit Request — Merkle-Tox v1.0
>
> Dear [Trail of Bits / NCC Group / Cure53 / etc.],
>
> The TokTok project (toktok.io) is preparing to commission an external
> cryptographic audit of **Merkle-Tox**, a layer on top of the Tox
> peer-to-peer messenger protocol that adds end-to-end encrypted
> multi-device group chat with persistent signed-DAG history.
>
> **Project description.** Merkle-Tox is built around:
> - X3DH-style handshake over published pre-keys
> - Per-sender symmetric ratchet (per-conversation), epoch-rotated
> - Multi-author signed Directed Acyclic Graph for message history
> - Hierarchical identity with master seed → admin → device delegation
> - Set reconciliation via IBLTs for offline-resilient sync
> - Decentralized: no servers; transport over either direct Tox friend
>   connections or NGC custom packets
>
> Design documentation is at <doc-URL>; source code at <repo-URL>;
> implementation in Rust.
>
> **Scope.** [Phase 1: Crypto-Protocol Audit / Phase 2: Implementation
> Audit / Combined]
>
> Estimated effort: [15-25 / 7-12 / 22-37] person-weeks based on
> comparable audits (NCC Group's 2016 Olm review at 6 person-weeks
> covered ~30% of our scope; Cure53's 2017 Briar review at ~16
> person-weeks covered comparable total surface).
>
> **Engagement timing.** We expect Phase 1 to commence approximately
> [date] following completion of our spec-quality documentation pass
> and stabilization of wire-format changes. Calendar duration target:
> 8-12 weeks including report writing and remediation review.
>
> **Deliverables expected.**
> - Written report with findings categorized by severity
>   (Critical / High / Medium / Low / Informational)
> - Recommended remediations with specific code/spec references
> - One retest cycle after remediation
> - Public publication of report (with appropriate redactions for
>   any findings under embargo) — comparable to your published Matrix
>   Olm / Briar / Threema reports
>
> **Reference comparable work.** We are aware of and have studied your
> firm's work on [Matrix Olm 2016 / Briar 2017 / Threema 2020-2024 /
> Signal PQXDH 2024 / etc.] and consider these the closest comparables.
>
> Please share:
> - A scoping call to validate effort estimate
> - A formal SOW with timeline and pricing
> - Names of consultants you would assign and their relevant background
> - Your firm's preferred policy for vulnerability disclosure and
>   embargo handling
>
> Best regards,
> [Project contact]

--------------------------------------------------------------------------------

## 8. Open Decisions for User

These are blocking the audit go-ahead:

1. **Budget approval.** Total all-three-phases is $525K-$1M; Phase 1 alone
   is $300K-$625K. Confirm budget bracket.
2. **Firm preference.** Trail of Bits (higher rate, strong report quality),
   NCC Group (formal-verification-friendly, slower, comparable cost),
   Cure53 (intensive short engagements, mobile-app strong, slightly lower
   per-week). Mix is possible (different firms for different phases).
3. **Public disclosure policy.** Most comparable audits are publicly
   published. Confirm preference; affects firm choice marginally.
4. **OTF or similar grant application?** OTF has funded several
   comparable audits; would defer some cost in exchange for grant
   application overhead (~3-6 months process). Worth considering for
   Phase 1.
