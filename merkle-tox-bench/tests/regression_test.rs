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
    let scenario = Scenario {
        id: 0,
        name: "test",
        category: ScenarioCategory::DagConvergence,
        node_count: 3,
        network: NetworkConfig::clean(),
        phases: vec![
            ScenarioPhase {
                name: "seed",
                duration: Duration::from_millis(500),
                action: PhaseAction::ConcurrentBlobs {
                    transfers: vec![(0, 32 * 1024), (1, 32 * 1024)],
                },
            },
            ScenarioPhase {
                name: "transfer",
                duration: Duration::from_secs(8),
                action: PhaseAction::Run,
            },
        ],
        timeout: Duration::from_secs(10),
    };
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
        bandwidth_mbps: None,
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
        (score_a - score_b).abs() < 0.1,
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

/// Regression guard for retransmission amplification under loss (task #22).
///
/// The duplicate-piece verification bug (commit 4cd59f0) silently sent
/// 290-924 MB for a 10MB blob under 5% loss — a 5-16x amplification the
/// "converges + doesn't panic" regression tests passed through cleanly.
/// This test asserts an explicit upper bound on bytes_tx: under N% loss
/// with fan-out to M receivers, total_bytes_tx must stay below a
/// modest multiple of goodput.
///
/// The bound is deliberately loose (5x goodput) so normal
/// retransmission behaviour (~1/(1-loss) ≈ 1.05x plus progress/ack
/// overhead) fits comfortably. Anything near an order of magnitude
/// above goodput fails loudly.
///
/// Failing this test means the retransmit/scan pipeline has started
/// amplifying pieces rather than converging — a repeat of the
/// "scenario 5 bimodal 55/83 score" pathology.
#[test]
fn retransmission_amplification_stays_bounded_under_loss() {
    // 3 nodes (1 seeder + 2 receivers), 5% uniform loss, 1MB blob.
    // Small enough to run fast as a unit test (~a few seconds), large
    // enough to exercise the scanner + retransmit-queue + progress
    // cadence interaction that produced the original cascade.
    let network = NetworkConfig {
        loss_rate: 0.05,
        loss_model: merkle_tox_bench::scenario::LossModelConfig::Uniform,
        latency: Duration::from_millis(20),
        jitter: 0.0,
        bandwidth_mbps: None,
    };
    let blob_size: u64 = 1024 * 1024; // 1 MB
    let num_receivers: u64 = 2;

    let scenario = Scenario {
        id: 0,
        name: "amplification_bound",
        category: ScenarioCategory::BlobTransfer,
        node_count: 3,
        network: network.clone(),
        phases: vec![
            ScenarioPhase {
                name: "seed",
                duration: Duration::from_millis(500),
                action: PhaseAction::SeedBlob {
                    seeder_idx: 0,
                    size: blob_size,
                },
            },
            ScenarioPhase {
                name: "transfer",
                duration: Duration::from_secs(10),
                action: PhaseAction::Run,
            },
        ],
        timeout: Duration::from_secs(15),
    };

    let mut h = SimulationHarness::new(3, &network, SEED);
    let completed = h.run_scenario(&scenario);
    assert!(completed, "Timed out before blob transfer completed");
    assert!(
        h.metrics.aggregated.all_blobs_complete,
        "Not all receivers got the blob; convergence={:.1}%",
        h.metrics.aggregated.convergence_pct,
    );

    let goodput = blob_size * num_receivers;
    let bytes_tx = h.metrics.aggregated.total_bytes_tx;
    let amplification = bytes_tx as f64 / goodput as f64;
    // Cap at 5x goodput. Pre-fix runs under 5% loss routinely produced
    // 15-50x amplification; normal healthy behaviour produces ~1-2x.
    // 5x leaves ample headroom for progress/ack overhead on small
    // blobs without tolerating a real retransmit cascade.
    assert!(
        amplification < 5.0,
        "Retransmission amplification too high: total_bytes_tx={} vs \
         goodput={} ({:.2}x). This is the pattern that caused the \
         scenario 5 bimodal 55/83 score regression — something in the \
         retransmit queue, forward scanner, or duplicate-piece handler \
         is re-sending pieces the receiver already has.",
        bytes_tx,
        goodput,
        amplification,
    );
}

/// Regression guard for BlobFetch single-shot loss (task #26).
///
/// `SwarmSync::fetch_sent` used to be a permanent "contacted" marker:
/// the receiver sent one BlobFetch per seeder and then silently gave up
/// if it was dropped in flight. At 1% uniform loss with 4 receivers and
/// multiple seeders, the expected number of lost BlobFetches is ~0.4
/// per scenario run — so roughly one run in ten fails to transfer any
/// blob pieces at all (task #26 seed 1006 reproduced this).
///
/// The fix: resend BlobFetch to seeders from which no pieces have
/// arrived, with a bounded cadence. This test asserts that even when a
/// specific deterministic seed would otherwise drop a BlobFetch, the
/// blob still eventually completes within the scenario timeout.
///
/// Parameters chosen to deterministically reproduce the failure on the
/// current RNG path: 5 nodes, 1% uniform loss, 30ms latency — same as
/// the ab_compare "Realistic group" scenario. Seed 1006 was the
/// reliably-failing seed at the time of the fix.
#[test]
fn blob_fetch_retries_on_loss() {
    use merkle_tox_bench::scenario::ScenarioCategory;

    let network = NetworkConfig {
        loss_rate: 0.01,
        loss_model: merkle_tox_bench::scenario::LossModelConfig::Uniform,
        latency: Duration::from_millis(30),
        jitter: 0.0,
        bandwidth_mbps: None,
    };
    let blob_size: u64 = 5 * 1024 * 1024; // 5 MB, same as scenario 9

    // Match scenario 9's phase shape exactly: a message burst first, then
    // the blob. The burst is what drives the RNG path that makes seed
    // 1006 deterministically drop a BlobFetch in phase 2; without it,
    // the reproducer doesn't reliably trigger the bug.
    let scenario = Scenario {
        id: 0,
        name: "blob_fetch_retry",
        category: ScenarioCategory::BlobTransfer,
        node_count: 5,
        network: network.clone(),
        phases: vec![
            ScenarioPhase {
                name: "messages",
                duration: Duration::from_secs(10),
                action: PhaseAction::AuthorMessages { per_node: 10 },
            },
            ScenarioPhase {
                name: "seed",
                duration: Duration::from_secs(1),
                action: PhaseAction::SeedBlob {
                    seeder_idx: 0,
                    size: blob_size,
                },
            },
            ScenarioPhase {
                name: "transfer",
                duration: Duration::from_secs(60),
                action: PhaseAction::Run,
            },
        ],
        timeout: Duration::from_secs(120),
    };

    // Seed 1006 is the one that dropped a BlobFetch in the original
    // investigation. If the retry mechanism works, this test passes;
    // if it regresses, this test fails loudly.
    let mut h = SimulationHarness::new(5, &network, 1006);
    let completed = h.run_scenario(&scenario);
    assert!(completed, "Timed out before scenario finished");
    assert!(
        h.metrics.aggregated.all_blobs_complete,
        "Blob did not complete — a single dropped BlobFetch likely \
         stalled one receiver forever. The receiver must resend \
         BlobFetch to seeders it has heard nothing from, not leave \
         them in `fetch_sent` permanently."
    );
}
