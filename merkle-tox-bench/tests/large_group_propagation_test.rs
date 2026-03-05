//! Large-group propagation regression test.
//!
//! Background: in MerkleTox, a content node's parents are the union
//! of the content frontier and the admin frontier (see
//! `authoring.rs::author_node_internal`). With every authorized
//! peer publishing an Announcement, the admin frontier grows to
//! `N`. Each subsequent content node must reference all `N` to
//! preserve admin causality. The original `MAX_PARENTS = 16`
//! capped this at 16, so at `N >= 16` every peer's Text/SKD/JIT-SKD
//! was authored with `N + 1` parents and rejected by every recipient
//! (`ValidationError::MaxParentsExceeded`) — content propagation
//! collapsed to "everyone has only their own messages".
//!
//! The fix raised `MAX_PARENTS` to `MAX_GROUP_DEVICES = 4096`. This
//! test pins that fix: at `N = 32` (well past the previous cliff),
//! one content message from every node must reach every other node,
//! and every peer's ephemeral signing key (from each peer's
//! authoritative SKD) must be ingested everywhere.

use std::time::Duration;

use merkle_tox_bench::harness::SimulationHarness;
use merkle_tox_bench::scenario::{NetworkConfig, PhaseAction, all_scenarios};
use merkle_tox_core::sync::NodeStore;

#[test]
fn n32_authormessages_from_all_propagates_globally() {
    const N: usize = 32;
    let mut h = SimulationHarness::new(N, &NetworkConfig::clean(), 42);

    // Warmup: 5 s of ticks lets every peer publish its Announcement
    // and complete X3DH handshakes.
    for _ in 0..500 {
        h.tick(Duration::from_millis(10));
    }

    h.execute_action(
        &PhaseAction::AuthorMessages { per_node: 1 },
        &all_scenarios()[0],
    );

    // 15 s for content + JIT-SKDs to propagate. Clean network at
    // N=32 converges well under this budget; longer just bloats
    // wall-clock test time.
    for _ in 0..1500 {
        h.tick(Duration::from_millis(10));
    }

    // Expected node tally per peer:
    //   1 Genesis
    // + N AuthorizeDevice (one per peer)
    // + N JIT-SKDs (one per author, propagated to all)
    // + N content nodes (Text "Msg #0" from each peer)
    // = 2N + 1
    //
    // Note: this counts only *directly verified* DAG nodes. The
    // initial KeyWrap from the founding peer is also counted, but
    // it lands in the AuthorizeDevice tally above (Genesis bundles
    // founder authorization). Announcement nodes are admin-track
    // and are also verified, but are NOT counted in
    // `get_node_counts` — only nodes that go through `verify_node`
    // are. Empirically the per-peer total at this scale is
    // `2N + 1` exactly when propagation works.
    let expected_min = 2 * N + 1;
    for (i, bn) in h.nodes.iter().enumerate() {
        let (verified, _spec) = bn.node.store.get_node_counts(&h.conv_id);
        assert!(
            verified >= expected_min,
            "node {} verified={} < expected_min={} (propagation broke?)",
            i,
            verified,
            expected_min,
        );
    }

    // Each peer should have ingested every OTHER peer's ephemeral
    // signing key (one per peer per epoch). With one epoch active,
    // that's exactly `N - 1` peer keys per node.
    for (i, bn) in h.nodes.iter().enumerate() {
        let eph = bn.node.engine.peer_ephemeral_signing_keys.len();
        assert!(
            eph >= N - 1,
            "node {} peer_ephemeral_signing_keys.len()={} < {} (SKDs didn't propagate)",
            i,
            eph,
            N - 1,
        );
    }
}
