//! Large-group scenarios (32 / 100 nodes) used to characterise the
//! protocol's scaling behaviour. Opt-in via `--include-large-groups`
//! because their wall-clock cost is orders of magnitude above the
//! small-group set; they don't fit the ab_compare A/B regression flow.

use std::time::Duration;

use crate::scenario::{
    LossModelConfig, NetworkConfig, PhaseAction, Scenario, ScenarioCategory, ScenarioPhase,
};

pub fn large_group_scenarios() -> Vec<Scenario> {
    vec![
        scenario_100_large_group_32(),
        scenario_101_large_group_100(),
    ]
}

/// Scenario 100 — "Large group 32".
///
/// Mid-scale scaling probe. Catches O(N²) issues in the harness or
/// protocol before the 100-node scenario; gives a scaling-slope data
/// point alongside scenario 101.
fn scenario_100_large_group_32() -> Scenario {
    Scenario {
        id: 100,
        name: "Large group 32",
        category: ScenarioCategory::LargeGroup,
        node_count: 32,
        network: NetworkConfig {
            loss_rate: 0.01,
            loss_model: LossModelConfig::Uniform,
            latency: Duration::from_millis(50),
            jitter: 0.05,
            bandwidth_mbps: Some(10.0),
        },
        phases: vec![
            ScenarioPhase {
                name: "Warmup",
                duration: Duration::from_secs(5),
                action: PhaseAction::Run,
            },
            ScenarioPhase {
                name: "Author markers",
                duration: Duration::from_secs(2),
                action: PhaseAction::AuthorMarkerMessages {
                    count: 5,
                    author_idx: 0,
                },
            },
            ScenarioPhase {
                name: "Light chatter",
                duration: Duration::from_secs(15),
                action: PhaseAction::AuthorMessages { per_node: 2 },
            },
            ScenarioPhase {
                name: "Converge",
                duration: Duration::from_secs(180),
                action: PhaseAction::Run,
            },
        ],
        timeout: Duration::from_secs(300),
    }
}

/// Scenario 101 — "Large group 100".
///
/// Top-end group-size probe (100 authorised devices). Very expensive
/// to run — wall-clock cost scales roughly with N² because every
/// authored content node references the full admin frontier. This is
/// why `--include-large-groups` is opt-in; treat scenario 101 as a
/// once-per-release smoke test rather than a tight CI loop.
///
/// If wall-clock pressure ever forces this down, drop `node_count` to
/// 64 — the spec invariant being checked (frontier-wide propagation)
/// fires the same way at any N >= 16 once the previous MAX_PARENTS=16
/// constraint was lifted.
fn scenario_101_large_group_100() -> Scenario {
    Scenario {
        id: 101,
        name: "Large group 100",
        category: ScenarioCategory::LargeGroup,
        node_count: 100,
        network: NetworkConfig {
            loss_rate: 0.01,
            loss_model: LossModelConfig::Uniform,
            latency: Duration::from_millis(50),
            jitter: 0.05,
            bandwidth_mbps: Some(10.0),
        },
        phases: vec![
            ScenarioPhase {
                name: "Warmup",
                duration: Duration::from_secs(10),
                action: PhaseAction::Run,
            },
            ScenarioPhase {
                name: "Author markers",
                duration: Duration::from_secs(2),
                action: PhaseAction::AuthorMarkerMessages {
                    count: 5,
                    author_idx: 0,
                },
            },
            ScenarioPhase {
                name: "Converge",
                duration: Duration::from_secs(300),
                action: PhaseAction::Run,
            },
        ],
        timeout: Duration::from_secs(600),
    }
}
