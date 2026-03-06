//! Lightweight regression tests for the simulation harness.
//!
//! These use small node counts, tiny blobs, and short durations to run fast
//! while still exercising the full simulation pipeline.

use std::time::Duration;

use merkle_tox_bench::harness::SimulationHarness;
use merkle_tox_bench::scenario::{
    NetworkConfig, PhaseAction, Scenario, ScenarioCategory, ScenarioPhase,
};

const SEED: u64 = 42;

fn quick_scenario(phases: Vec<ScenarioPhase>, node_count: usize) -> Scenario {
    Scenario {
        id: 0,
        name: "test",
        category: ScenarioCategory::DagConvergence,
        node_count,
        network: NetworkConfig::clean(),
        phases,
        timeout: Duration::from_secs(5),
    }
}

#[test]
fn message_burst_converges() {
    let scenario = quick_scenario(
        vec![
            ScenarioPhase {
                name: "burst",
                duration: Duration::from_millis(500),
                action: PhaseAction::AuthorMessages { per_node: 2 },
            },
            ScenarioPhase {
                name: "converge",
                duration: Duration::from_secs(3),
                action: PhaseAction::Run,
            },
        ],
        2,
    );
    let mut h = SimulationHarness::new(2, &scenario.network, SEED);
    let completed = h.run_scenario(&scenario);
    assert!(completed, "Timed out");
    assert!(
        h.metrics.aggregated.convergence_pct >= 50.0,
        "Convergence too low: {}%",
        h.metrics.aggregated.convergence_pct
    );
}

#[test]
fn small_blob_transfer() {
    let scenario = quick_scenario(
        vec![
            ScenarioPhase {
                name: "seed",
                duration: Duration::from_millis(500),
                action: PhaseAction::SeedBlob {
                    seeder_idx: 0,
                    size: 64 * 1024, // 64KB — tiny
                },
            },
            ScenarioPhase {
                name: "transfer",
                duration: Duration::from_secs(8),
                action: PhaseAction::Run,
            },
        ],
        2,
    );
    let mut h = SimulationHarness::new(2, &scenario.network, SEED);
    let completed = h.run_scenario(&scenario);
    assert!(completed, "Timed out");
}

#[test]
fn partition_and_heal() {
    let scenario = quick_scenario(
        vec![
            ScenarioPhase {
                name: "partition",
                duration: Duration::from_millis(100),
                action: PhaseAction::Partition {
                    groups: vec![vec![0], vec![1]],
                },
            },
            ScenarioPhase {
                name: "author",
                duration: Duration::from_secs(1),
                action: PhaseAction::AuthorMessages { per_node: 2 },
            },
            ScenarioPhase {
                name: "heal",
                duration: Duration::from_millis(100),
                action: PhaseAction::HealPartitions,
            },
            ScenarioPhase {
                name: "converge",
                duration: Duration::from_secs(3),
                action: PhaseAction::Run,
            },
        ],
        2,
    );
    let mut h = SimulationHarness::new(2, &scenario.network, SEED);
    let completed = h.run_scenario(&scenario);
    assert!(completed, "Timed out");
}

#[test]
fn concurrent_blobs_no_panic() {
    let scenario = quick_scenario(
        vec![
            ScenarioPhase {
                name: "seed",
                duration: Duration::from_millis(500),
                action: PhaseAction::ConcurrentBlobs {
                    transfers: vec![(0, 32 * 1024), (1, 32 * 1024)],
                },
            },
            ScenarioPhase {
                name: "transfer",
                duration: Duration::from_secs(5),
                action: PhaseAction::Run,
            },
        ],
        3,
    );
    let mut h = SimulationHarness::new(3, &scenario.network, SEED);
    let completed = h.run_scenario(&scenario);
    assert!(completed, "Timed out");
}

#[test]
fn add_node_no_panic() {
    let scenario = quick_scenario(
        vec![
            ScenarioPhase {
                name: "author",
                duration: Duration::from_secs(1),
                action: PhaseAction::AuthorMessages { per_node: 2 },
            },
            ScenarioPhase {
                name: "add",
                duration: Duration::from_millis(100),
                action: PhaseAction::AddNode,
            },
            ScenarioPhase {
                name: "sync",
                duration: Duration::from_secs(3),
                action: PhaseAction::Run,
            },
        ],
        2,
    );
    let mut h = SimulationHarness::new(2, &scenario.network, SEED);
    let completed = h.run_scenario(&scenario);
    assert!(completed, "Timed out");
    assert_eq!(h.nodes.len(), 3);
}

#[test]
fn lossy_network_no_panic() {
    let network = NetworkConfig {
        loss_rate: 0.10,
        loss_model: merkle_tox_bench::scenario::LossModelConfig::Uniform,
        latency: Duration::from_millis(50),
        jitter: 0.1,
    };
    let scenario = Scenario {
        id: 0,
        name: "lossy",
        category: ScenarioCategory::Combined,
        node_count: 2,
        network: network.clone(),
        phases: vec![
            ScenarioPhase {
                name: "author",
                duration: Duration::from_secs(1),
                action: PhaseAction::AuthorMessages { per_node: 2 },
            },
            ScenarioPhase {
                name: "converge",
                duration: Duration::from_secs(3),
                action: PhaseAction::Run,
            },
        ],
        timeout: Duration::from_secs(5),
    };
    let mut h = SimulationHarness::new(2, &network, SEED);
    let completed = h.run_scenario(&scenario);
    assert!(completed, "Timed out");
}

#[test]
fn deterministic_with_same_seed() {
    let scenario = quick_scenario(
        vec![ScenarioPhase {
            name: "burst",
            duration: Duration::from_secs(3),
            action: PhaseAction::AuthorMessages { per_node: 5 },
        }],
        2,
    );

    let mut h1 = SimulationHarness::new(2, &scenario.network, SEED);
    h1.run_scenario(&scenario);
    let score_a = h1.metrics.aggregated.score;

    let mut h2 = SimulationHarness::new(2, &scenario.network, SEED);
    h2.run_scenario(&scenario);
    let score_b = h2.metrics.aggregated.score;

    assert!(
        (score_a - score_b).abs() < 0.01,
        "Scores differ: {score_a} vs {score_b}"
    );
}

#[test]
fn harness_construction_various_sizes() {
    // Validate node setup + mesh peering for different sizes.
    for n in [2, 3, 4] {
        let _h = SimulationHarness::new(n, &NetworkConfig::clean(), SEED);
    }
}
