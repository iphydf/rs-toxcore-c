use std::sync::atomic::Ordering;
use std::time::Duration;

use merkle_tox_bench::harness::SimulationHarness;
use merkle_tox_bench::scenario::NetworkConfig;

#[test]
fn harness_creates_correct_node_count() {
    let h = SimulationHarness::new(3, &NetworkConfig::clean(), 42);
    assert_eq!(h.nodes.len(), 3);
}

#[test]
fn harness_nodes_have_distinct_pks() {
    let h = SimulationHarness::new(4, &NetworkConfig::clean(), 42);
    let pks: Vec<_> = h.nodes.iter().map(|bn| bn.node.engine.self_pk).collect();
    for i in 0..pks.len() {
        for j in (i + 1)..pks.len() {
            assert_ne!(pks[i], pks[j], "Nodes {} and {} share the same pk", i, j);
        }
    }
}

#[test]
fn harness_initial_bytes_zero() {
    let h = SimulationHarness::new(2, &NetworkConfig::clean(), 42);
    for bn in &h.nodes {
        assert_eq!(bn.bytes_sent.load(Ordering::Relaxed), 0);
        assert_eq!(bn.bytes_received.load(Ordering::Relaxed), 0);
    }
}

#[test]
fn tick_advances_virtual_time() {
    let mut h = SimulationHarness::new(2, &NetworkConfig::clean(), 42);
    assert_eq!(h.virtual_elapsed, Duration::ZERO);

    h.tick(Duration::from_millis(10));
    assert_eq!(h.virtual_elapsed, Duration::from_millis(10));

    h.tick(Duration::from_millis(20));
    assert_eq!(h.virtual_elapsed, Duration::from_millis(30));
}

#[test]
fn tick_generates_network_traffic() {
    // After authoring a message, ticking should cause sync traffic.
    let mut h = SimulationHarness::new(2, &NetworkConfig::clean(), 42);

    // Author a message on node 0.
    h.execute_action(
        &merkle_tox_bench::scenario::PhaseAction::AuthorMessages { per_node: 1 },
        &merkle_tox_bench::scenario::all_scenarios()[0],
    );

    // Run several ticks to let sync happen.
    for _ in 0..20 {
        h.tick(Duration::from_millis(10));
    }

    let total_tx: u64 = h
        .nodes
        .iter()
        .map(|bn| bn.bytes_sent.load(Ordering::Relaxed))
        .sum();
    assert!(
        total_tx > 0,
        "Expected network traffic after authoring + ticks"
    );
}
