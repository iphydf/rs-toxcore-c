//! Adversarial coverage for `MerkleToxEngine.equivocations`.
//!
//! Equivocation detection at `verification.rs:280-294` pushes a
//! 5-tuple `(conv_id, sender_pk, seq, existing_hash, conflicting_hash)`
//! into `engine.equivocations` every time the same authorised peer
//! re-uses a `(conversation, sender, seq)` triple with a different
//! node hash. The push is unconditional once the predicate is hit;
//! the Vec has no length cap.
//!
//! An authorised peer who keeps re-authoring at the same seq with
//! different content (timestamp, parents, payload) inflates the Vec
//! by ~136 bytes per detection. At 100 messages/sec sustained, the
//! engine accumulates ~1 GB/day of evidence from one attacker —
//! evidence that's only useful for one-shot reporting, not unbounded
//! retention.
//!
//! Pre-fix behaviour: 5000 equivocations from one attacker produces
//! `engine.equivocations.len() == 5000`. Post-fix: capped at
//! `MAX_EQUIVOCATIONS` (1024); excess detections are silently
//! dropped (or older entries evicted).

use merkle_tox_core::clock::ManualTimeProvider;
use merkle_tox_core::dag::Content;
use merkle_tox_core::engine::MerkleToxEngine;
use merkle_tox_core::testing::{
    InMemoryStore, TestRoom, apply_effects, create_signed_content_node,
};
use merkle_tox_core::sync::NodeStore;
use rand::{SeedableRng, rngs::StdRng};
use std::sync::Arc;
use std::time::Instant;

/// §EQ-1 — A single authorised peer who repeatedly equivocates against
/// us must not be able to grow `engine.equivocations` without bound.
/// Each detection is a 136-byte tuple; without a cap an attacker can
/// scale memory consumption linearly with their authoring rate.
#[test]
fn test_equivocation_vec_unbounded_growth() {
    let _ = tracing_subscriber::fmt::try_init();
    let tp = Arc::new(ManualTimeProvider::new(Instant::now(), 0));
    let store = InMemoryStore::new();
    let room = TestRoom::new(2);
    let alice = &room.identities[0]; // attacker
    let observer = &room.identities[1]; // us

    let mut engine = MerkleToxEngine::new(
        observer.device_pk,
        observer.master_pk,
        StdRng::seed_from_u64(0),
        tp.clone(),
    );
    room.setup_engine(&mut engine, &store);

    // Step 1: alice authors one valid msg at seq=2 — observer records
    // (conv, alice, 2) → hash_first in `verified_node_seqs`. Subsequent
    // alice-authored nodes at seq=2 with a different hash will trip the
    // equivocation detector.
    let admin_heads = store.get_admin_heads(&room.conv_id);
    let first = create_signed_content_node(
        &room.conv_id,
        &room.keys,
        alice.master_pk,
        alice.device_pk,
        admin_heads.clone(),
        Content::Text("first".to_string()),
        2,
        2,
        1000,
    );
    let effects = engine
        .handle_node(room.conv_id, first, &store, None)
        .unwrap();
    apply_effects(effects, &store);

    // Step 2: alice equivocates `flood` times. Each malicious node
    // re-uses seq=2 with a different timestamp/text, producing a
    // distinct node hash. The replay check rejects each, but the
    // equivocation push at verification.rs:287 fires before the
    // rejection — so every iteration grows the Vec by one entry.
    const FLOOD: usize = 5_000;
    for i in 0..FLOOD {
        let evil = create_signed_content_node(
            &room.conv_id,
            &room.keys,
            alice.master_pk,
            alice.device_pk,
            admin_heads.clone(),
            Content::Text(format!("evil-{}", i)),
            2,
            2,
            2_000 + i as i64,
        );
        let _ = engine.handle_node(room.conv_id, evil, &store, None);
    }

    let evidence = engine.equivocations.len();
    assert!(
        evidence > 100,
        "the test must actually trigger many equivocation detections \
         to be meaningful — got {} (wiring issue?)",
        evidence,
    );
    const MAX_EQUIVOCATIONS: usize = 1024;
    assert!(
        evidence <= MAX_EQUIVOCATIONS,
        "engine.equivocations grew to {} entries from one attacker — \
         the Vec has no length cap. At ~136 bytes per push that's \
         ~{} KB from one peer; sustained at 100 msg/sec → ~1 GB/day. \
         Should be capped at MAX_EQUIVOCATIONS={}.",
        evidence,
        evidence * 136 / 1024,
        MAX_EQUIVOCATIONS,
    );
}
