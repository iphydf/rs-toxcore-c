//! Validates the AuthorMarkerMessages → observe_marker_propagation
//! pipeline: registering markers, observing them as verified at each
//! recipient, and producing a non-empty LatencyHistogram.
//!
//! These tests pin the small-N path. Larger-N propagation behaviour is
//! exercised by the bench scenarios (`scenario_large.rs`); see the
//! comments there for what the latency histogram is expected to show
//! once the protocol's content-fan-out behaviour at scale is
//! understood. As of writing, content-node propagation from a single
//! sender breaks somewhere between 8 and 16 recipients — surfaced for
//! the first time by this very metric.

use std::time::Duration;

use merkle_tox_bench::harness::SimulationHarness;
use merkle_tox_bench::scenario::{NetworkConfig, PhaseAction, all_scenarios};

#[test]
fn marker_authoring_registers_markers() {
    let mut h = SimulationHarness::new(4, &NetworkConfig::clean(), 42);

    h.execute_action(
        &PhaseAction::AuthorMarkerMessages {
            count: 3,
            author_idx: 0,
        },
        &all_scenarios()[0],
    );

    assert_eq!(
        h.metrics.markers.len(),
        3,
        "expected 3 marker samples registered, got {}",
        h.metrics.markers.len(),
    );
    for m in &h.metrics.markers {
        assert_eq!(m.author_idx, 0);
        assert_eq!(m.verified_at.len(), 4);
        assert!(
            m.verified_at[0].is_some(),
            "author slot must be pre-populated"
        );
        for (i, t) in m.verified_at.iter().enumerate() {
            if i != 0 {
                assert!(
                    t.is_none(),
                    "recipient slot {} should be None at register time",
                    i,
                );
            }
        }
    }
}

#[test]
fn marker_propagation_populates_recipients() {
    // 4 nodes clean: well below the propagation-breakdown threshold.
    // Validates the metric end-to-end (marker auth → tick →
    // observe_marker_propagation → latency_histogram).
    let mut h = SimulationHarness::new(4, &NetworkConfig::clean(), 42);

    h.execute_action(
        &PhaseAction::AuthorMarkerMessages {
            count: 2,
            author_idx: 0,
        },
        &all_scenarios()[0],
    );
    assert_eq!(h.metrics.markers.len(), 2);

    for _ in 0..2000 {
        h.tick(Duration::from_millis(10));
    }

    let hist = h.metrics.latency_histogram();
    // 2 markers × 3 recipients (4 nodes - 1 author) = 6 max samples.
    assert!(hist.samples > 0);
    assert!(hist.p50_ms <= hist.p95_ms);
    assert!(hist.p95_ms <= hist.max_ms);
}
