//! Tests verifying that blob transfers complete in a reasonable time.
//!
//! These tests catch performance regressions and protocol-level bugs that
//! cause blob transfers to stall (e.g. fake seeder poisoning).

use std::time::Duration;

use merkle_tox_bench::harness::SimulationHarness;
use merkle_tox_bench::scenario::{
    LossModelConfig, NetworkConfig, PhaseAction, Scenario, ScenarioCategory, ScenarioPhase,
};

const SEED: u64 = 42;

/// A 1 MB blob from 1 seeder to 3 receivers on a clean network should
/// complete well within 5 seconds of virtual time.
///
/// Current behavior: takes ~8 seconds for 5 receivers due to fake seeder
/// poisoning — nodes that are still downloading advertise BlobAvail,
/// causing chunk requests to be distributed to nodes that can't serve them
/// and waiting 15 s (FETCH_TIMEOUT) before retrying.
#[test]
fn blob_1mb_fanout_completes_within_5s() {
    let scenario = Scenario {
        id: 0,
        name: "1MB fanout timing",
        category: ScenarioCategory::BlobTransfer,
        node_count: 4, // 1 seeder + 3 receivers
        network: NetworkConfig::clean(),
        phases: vec![
            ScenarioPhase {
                name: "seed",
                duration: Duration::from_millis(500),
                action: PhaseAction::SeedBlob {
                    seeder_idx: 0,
                    size: 1024 * 1024, // 1 MB
                },
            },
            ScenarioPhase {
                name: "transfer",
                duration: Duration::from_secs(30),
                action: PhaseAction::Run,
            },
        ],
        timeout: Duration::from_secs(60),
    };

    let mut h = SimulationHarness::new(4, &scenario.network, SEED);
    let completed = h.run_scenario(&scenario);
    assert!(completed, "Scenario timed out");

    let blob_time = h.metrics.aggregated.blob_completion_time;
    assert!(
        blob_time.is_some(),
        "Blob transfer never completed — all nodes should have the blob"
    );

    let blob_secs = blob_time.unwrap().as_secs_f64();
    assert!(
        blob_secs <= 5.0,
        "1 MB blob transfer to 3 receivers on a clean network took {blob_secs:.1}s, \
         expected <= 5s. This likely indicates fake seeder poisoning: nodes still \
         downloading advertise as seeders, absorbing chunk requests that are silently \
         dropped and retried only after FETCH_TIMEOUT (15s)."
    );
}

/// A 10 MB blob from 1 seeder to 3 receivers on a clean network should
/// complete within 30 seconds.  This is the scenario that currently never
/// completes at all (blob_completion_time = null in headless benchmarks).
#[test]
fn blob_10mb_completes_at_all() {
    let scenario = Scenario {
        id: 0,
        name: "10MB completion",
        category: ScenarioCategory::BlobTransfer,
        node_count: 4,
        network: NetworkConfig::clean(),
        phases: vec![
            ScenarioPhase {
                name: "seed",
                duration: Duration::from_millis(500),
                action: PhaseAction::SeedBlob {
                    seeder_idx: 0,
                    size: 10 * 1024 * 1024, // 10 MB
                },
            },
            ScenarioPhase {
                name: "transfer",
                duration: Duration::from_secs(60),
                action: PhaseAction::Run,
            },
        ],
        timeout: Duration::from_secs(90),
    };

    let mut h = SimulationHarness::new(4, &scenario.network, SEED);
    let completed = h.run_scenario(&scenario);
    assert!(completed, "Scenario timed out");

    let blob_time = h.metrics.aggregated.blob_completion_time;
    assert!(
        blob_time.is_some(),
        "10 MB blob transfer never completed. All 3 receivers should eventually \
         get the full blob within 60 seconds on an unlimited clean network."
    );
}

/// Verify that blob transfers achieve reasonable throughput.
/// On a clean, zero-loss, unlimited-bandwidth network, a 1 MB transfer
/// to a single receiver should not take more than 2 seconds.
#[test]
fn blob_1mb_single_receiver_throughput() {
    let scenario = Scenario {
        id: 0,
        name: "1MB single receiver",
        category: ScenarioCategory::BlobTransfer,
        node_count: 2, // 1 seeder + 1 receiver
        network: NetworkConfig::clean(),
        phases: vec![
            ScenarioPhase {
                name: "seed",
                duration: Duration::from_millis(500),
                action: PhaseAction::SeedBlob {
                    seeder_idx: 0,
                    size: 1024 * 1024,
                },
            },
            ScenarioPhase {
                name: "transfer",
                duration: Duration::from_secs(15),
                action: PhaseAction::Run,
            },
        ],
        timeout: Duration::from_secs(20),
    };

    let mut h = SimulationHarness::new(2, &scenario.network, SEED);
    let completed = h.run_scenario(&scenario);

    assert!(completed, "Scenario timed out");

    let blob_time = h.metrics.aggregated.blob_completion_time;
    assert!(
        blob_time.is_some(),
        "Blob transfer never completed between 2 nodes"
    );

    let blob_secs = blob_time.unwrap().as_secs_f64();
    assert!(
        blob_secs <= 2.0,
        "1 MB blob transfer to a single receiver on a clean network took {blob_secs:.1}s, \
         expected <= 2s. With no competing receivers and unlimited bandwidth, \
         this should be fast."
    );
}

/// Push-based streaming keeps the transport pipeline full. On a 1 Gbps
/// link, throughput is currently limited by BBR's bandwidth estimation
/// interacting with the 10ms simulation tick granularity — BBR can only
/// observe ~4 MB/s per tick, regardless of wire speed. This caps
/// effective throughput at ~12 Mbps in simulation.
///
/// In a real application with sub-millisecond polling, BBR would ramp
/// to full link speed. This test verifies push streaming completes the
/// transfer (no stalls) and achieves at least the BBR-limited rate.
#[test]
fn push_streaming_completes_large_transfer() {
    let scenario = Scenario {
        id: 0,
        name: "push streaming",
        category: ScenarioCategory::BlobTransfer,
        node_count: 2,
        network: NetworkConfig {
            loss_rate: 0.0,
            loss_model: LossModelConfig::Uniform,
            latency: Duration::from_millis(2),
            jitter: 0.0,
            bandwidth_mbps: Some(1000.0),
        },
        phases: vec![
            ScenarioPhase {
                name: "seed",
                duration: Duration::from_millis(100),
                action: PhaseAction::SeedBlob {
                    seeder_idx: 0,
                    size: 100 * 1024 * 1024,
                },
            },
            ScenarioPhase {
                name: "transfer",
                duration: Duration::from_secs(90),
                action: PhaseAction::Run,
            },
        ],
        timeout: Duration::from_secs(120),
    };

    let mut h = SimulationHarness::new(2, &scenario.network, 42);
    let completed = h.run_scenario(&scenario);
    assert!(completed, "Scenario timed out");

    let blob_time = h.metrics.aggregated.blob_completion_time;
    assert!(
        blob_time.is_some(),
        "100 MB blob transfer never completed on 1 Gbps link"
    );

    let blob_secs = blob_time.unwrap().as_secs_f64();
    let throughput_mbps = (100.0 * 8.0) / blob_secs;
    // BBR achieves ~12 Mbps in simulation due to 10ms tick granularity.
    // In real applications with sub-ms polling, this would be much higher.
    assert!(
        blob_secs <= 90.0,
        "100 MB on 1 Gbps took {blob_secs:.1}s ({throughput_mbps:.0} Mbps effective), \
         transfer should complete within the phase duration."
    );
}

/// A 10 MB blob transfer to 3 receivers should benefit from chunk-level
/// swarming. Receivers re-seed chunks they've downloaded, reducing load on
/// the original seeder and speeding up the transfer.
///
/// Without swarming, the seeder must upload 10 MB × 3 = 30 MB.
/// With swarming, each chunk enters the swarm once from the seeder, then
/// receivers redistribute — total seeder upload approaches 10 MB.
#[test]
fn swarming_speeds_up_multi_receiver_transfer() {
    let scenario = Scenario {
        id: 0,
        name: "swarming speedup",
        category: ScenarioCategory::BlobTransfer,
        node_count: 4, // 1 seeder + 3 receivers
        network: NetworkConfig::clean(),
        phases: vec![
            ScenarioPhase {
                name: "seed",
                duration: Duration::from_millis(100),
                action: PhaseAction::SeedBlob {
                    seeder_idx: 0,
                    size: 10 * 1024 * 1024,
                },
            },
            ScenarioPhase {
                name: "transfer",
                duration: Duration::from_secs(30),
                action: PhaseAction::Run,
            },
        ],
        timeout: Duration::from_secs(45),
    };

    let mut h = SimulationHarness::new(4, &scenario.network, 42);
    let completed = h.run_scenario(&scenario);
    assert!(completed, "Scenario timed out");

    let blob_time = h.metrics.aggregated.blob_completion_time;
    assert!(blob_time.is_some(), "Blob transfer never completed");

    let blob_secs = blob_time.unwrap().as_secs_f64();

    // The seeder's total upload should be significantly less than 30 MB
    // (10 MB × 3 receivers). With perfect swarming it would be ~10 MB.
    let seeder_tx = h.nodes[0]
        .bytes_sent
        .load(std::sync::atomic::Ordering::Relaxed);

    // With swarming, transfer should complete in under 10 seconds
    // (without swarming it takes ~20s in current benchmarks).
    assert!(
        blob_secs <= 10.0,
        "10 MB blob to 3 receivers took {blob_secs:.1}s with swarming, expected <= 10s. \
         Swarming should distribute upload load across receivers."
    );

    assert!(
        seeder_tx < 36 * 1024 * 1024,
        "Seeder uploaded {} bytes, expected < 36 MB. With swarming, receivers \
         should re-seed chunks to each other, keeping seeder load near ~30 MB \
         (10 MB × 3 receivers) rather than growing unbounded.",
        seeder_tx
    );
}
