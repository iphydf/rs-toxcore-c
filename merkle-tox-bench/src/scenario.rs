use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ScenarioCategory {
    BlobTransfer,
    DagConvergence,
    Combined,
    /// Scenarios with high node counts (≥32). Opt-in via
    /// `--include-large-groups` because their wall-clock cost is
    /// orders of magnitude above the small-group set.
    LargeGroup,
}

impl std::fmt::Display for ScenarioCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BlobTransfer => write!(f, "Blob"),
            Self::DagConvergence => write!(f, "DAG"),
            Self::Combined => write!(f, "Combined"),
            Self::LargeGroup => write!(f, "Large"),
        }
    }
}

#[derive(Debug, Clone)]
pub enum LossModelConfig {
    Uniform,
    GilbertElliot { p: f32, r: f32 },
}

#[derive(Debug, Clone)]
pub struct NetworkConfig {
    pub loss_rate: f32,
    pub loss_model: LossModelConfig,
    pub latency: Duration,
    pub jitter: f32,
    /// Per-link bandwidth limit in Mbps. None = unlimited.
    pub bandwidth_mbps: Option<f32>,
}

impl NetworkConfig {
    pub fn clean() -> Self {
        Self {
            loss_rate: 0.0,
            loss_model: LossModelConfig::Uniform,
            latency: Duration::ZERO,
            jitter: 0.0,
            bandwidth_mbps: None,
        }
    }
}

#[derive(Debug, Clone)]
pub enum PhaseAction {
    Run,
    AuthorMessages {
        per_node: usize,
    },
    /// Authors `count` content nodes from one specific node and
    /// registers each with the metrics collector as a latency marker.
    /// Used in large-group scenarios to measure end-to-end propagation
    /// without inflating the per-tick scan cost.
    AuthorMarkerMessages {
        count: usize,
        author_idx: usize,
    },
    SeedBlob {
        seeder_idx: usize,
        size: u64,
    },
    ConcurrentBlobs {
        transfers: Vec<(usize, u64)>,
    },
    Partition {
        groups: Vec<Vec<usize>>,
    },
    HealPartitions,
    AddNode,
    SetImpairments(NetworkConfig),
}

#[derive(Debug, Clone)]
pub struct ScenarioPhase {
    pub name: &'static str,
    pub duration: Duration,
    pub action: PhaseAction,
}

#[derive(Debug, Clone)]
pub struct Scenario {
    pub id: usize,
    pub name: &'static str,
    pub category: ScenarioCategory,
    pub node_count: usize,
    pub network: NetworkConfig,
    pub phases: Vec<ScenarioPhase>,
    pub timeout: Duration,
}

impl Scenario {
    pub fn short_name(&self) -> String {
        format!("[{}] {}", self.id, self.name)
    }
}

pub fn all_scenarios() -> Vec<Scenario> {
    vec![
        scenario_1_fanout(),
        scenario_2_multiseed(),
        scenario_3_large_file(),
        scenario_4_competing(),
        scenario_5_lossy_blob(),
        scenario_6_message_burst(),
        scenario_7_partition_heal(),
        scenario_8_late_joiner(),
        scenario_9_realistic_group(),
        scenario_10_hostile_network(),
        scenario_11_direct_transfer(),
        scenario_12_fast_network(),
    ]
}

pub fn scenarios_by_ids(ids: &[usize]) -> Vec<Scenario> {
    let all = all_scenarios();
    ids.iter()
        .filter_map(|id| all.iter().find(|s| s.id == *id).cloned())
        .collect()
}

// --- Blob Transfer Scenarios ---

fn scenario_1_fanout() -> Scenario {
    Scenario {
        id: 1,
        name: "Fan-out 1MB",
        category: ScenarioCategory::BlobTransfer,
        node_count: 6,
        network: NetworkConfig::clean(),
        phases: vec![
            ScenarioPhase {
                name: "Seed blob",
                duration: Duration::from_secs(1),
                action: PhaseAction::SeedBlob {
                    seeder_idx: 0,
                    size: 1024 * 1024,
                },
            },
            ScenarioPhase {
                name: "Transfer",
                duration: Duration::from_secs(30),
                action: PhaseAction::Run,
            },
        ],
        timeout: Duration::from_secs(60),
    }
}

fn scenario_2_multiseed() -> Scenario {
    Scenario {
        id: 2,
        name: "Multi-seed",
        category: ScenarioCategory::BlobTransfer,
        node_count: 6,
        network: NetworkConfig::clean(),
        phases: vec![
            ScenarioPhase {
                name: "Pre-seed 5 nodes",
                duration: Duration::from_secs(1),
                action: PhaseAction::ConcurrentBlobs {
                    transfers: vec![
                        (0, 1024 * 1024),
                        (1, 1024 * 1024),
                        (2, 1024 * 1024),
                        (3, 1024 * 1024),
                        (4, 1024 * 1024),
                    ],
                },
            },
            ScenarioPhase {
                name: "Transfer to late node",
                duration: Duration::from_secs(30),
                action: PhaseAction::Run,
            },
        ],
        timeout: Duration::from_secs(60),
    }
}

fn scenario_3_large_file() -> Scenario {
    Scenario {
        id: 3,
        name: "Large file 100MB",
        category: ScenarioCategory::BlobTransfer,
        node_count: 4,
        network: NetworkConfig {
            loss_rate: 0.0,
            loss_model: LossModelConfig::Uniform,
            latency: Duration::from_millis(20),
            jitter: 0.1,
            bandwidth_mbps: Some(10.0),
        },
        phases: vec![
            ScenarioPhase {
                name: "Seed blob",
                duration: Duration::from_secs(1),
                action: PhaseAction::SeedBlob {
                    seeder_idx: 0,
                    size: 100 * 1024 * 1024,
                },
            },
            ScenarioPhase {
                name: "Transfer",
                duration: Duration::from_secs(120),
                action: PhaseAction::Run,
            },
        ],
        timeout: Duration::from_secs(300),
    }
}

fn scenario_4_competing() -> Scenario {
    Scenario {
        id: 4,
        name: "Competing 10MB",
        category: ScenarioCategory::BlobTransfer,
        node_count: 5,
        network: NetworkConfig::clean(),
        phases: vec![
            ScenarioPhase {
                name: "Seed 3 blobs",
                duration: Duration::from_secs(1),
                action: PhaseAction::ConcurrentBlobs {
                    transfers: vec![
                        (0, 10 * 1024 * 1024),
                        (1, 10 * 1024 * 1024),
                        (2, 10 * 1024 * 1024),
                    ],
                },
            },
            ScenarioPhase {
                name: "Transfer",
                duration: Duration::from_secs(60),
                action: PhaseAction::Run,
            },
        ],
        timeout: Duration::from_secs(120),
    }
}

fn scenario_5_lossy_blob() -> Scenario {
    Scenario {
        id: 5,
        name: "Lossy blob 10MB",
        category: ScenarioCategory::BlobTransfer,
        node_count: 4,
        network: NetworkConfig {
            loss_rate: 0.05,
            loss_model: LossModelConfig::Uniform,
            latency: Duration::from_millis(20),
            jitter: 0.0,
            bandwidth_mbps: None,
        },
        phases: vec![
            ScenarioPhase {
                name: "Seed blob",
                duration: Duration::from_secs(1),
                action: PhaseAction::SeedBlob {
                    seeder_idx: 0,
                    size: 10 * 1024 * 1024,
                },
            },
            ScenarioPhase {
                name: "Transfer",
                duration: Duration::from_secs(60),
                action: PhaseAction::Run,
            },
        ],
        timeout: Duration::from_secs(120),
    }
}

// --- DAG Convergence Scenarios ---

fn scenario_6_message_burst() -> Scenario {
    Scenario {
        id: 6,
        name: "Message burst",
        category: ScenarioCategory::DagConvergence,
        node_count: 5,
        network: NetworkConfig::clean(),
        phases: vec![
            ScenarioPhase {
                name: "Burst 20 msgs/node",
                duration: Duration::from_secs(5),
                action: PhaseAction::AuthorMessages { per_node: 20 },
            },
            ScenarioPhase {
                name: "Converge",
                duration: Duration::from_secs(30),
                action: PhaseAction::Run,
            },
        ],
        timeout: Duration::from_secs(60),
    }
}

fn scenario_7_partition_heal() -> Scenario {
    Scenario {
        id: 7,
        name: "Partition heal",
        category: ScenarioCategory::DagConvergence,
        node_count: 6,
        network: NetworkConfig::clean(),
        phases: vec![
            ScenarioPhase {
                name: "Partition",
                duration: Duration::from_secs(1),
                action: PhaseAction::Partition {
                    groups: vec![vec![0, 1, 2], vec![3, 4, 5]],
                },
            },
            ScenarioPhase {
                name: "Author partitioned",
                duration: Duration::from_secs(10),
                action: PhaseAction::AuthorMessages { per_node: 10 },
            },
            ScenarioPhase {
                name: "Heal",
                duration: Duration::from_secs(1),
                action: PhaseAction::HealPartitions,
            },
            ScenarioPhase {
                name: "Converge",
                duration: Duration::from_secs(30),
                action: PhaseAction::Run,
            },
        ],
        timeout: Duration::from_secs(60),
    }
}

fn scenario_8_late_joiner() -> Scenario {
    Scenario {
        id: 8,
        name: "Late joiner",
        category: ScenarioCategory::DagConvergence,
        node_count: 4,
        network: NetworkConfig::clean(),
        phases: vec![
            ScenarioPhase {
                name: "Author 50 msgs",
                duration: Duration::from_secs(10),
                action: PhaseAction::AuthorMessages { per_node: 50 },
            },
            ScenarioPhase {
                name: "Add node",
                duration: Duration::from_secs(1),
                action: PhaseAction::AddNode,
            },
            ScenarioPhase {
                name: "Sync",
                duration: Duration::from_secs(30),
                action: PhaseAction::Run,
            },
        ],
        timeout: Duration::from_secs(60),
    }
}

// --- Combined Scenarios ---

fn scenario_9_realistic_group() -> Scenario {
    Scenario {
        id: 9,
        name: "Realistic group",
        category: ScenarioCategory::Combined,
        node_count: 5,
        network: NetworkConfig {
            loss_rate: 0.01,
            loss_model: LossModelConfig::Uniform,
            latency: Duration::from_millis(30),
            jitter: 0.0,
            bandwidth_mbps: None,
        },
        phases: vec![
            ScenarioPhase {
                name: "Messages",
                duration: Duration::from_secs(10),
                action: PhaseAction::AuthorMessages { per_node: 10 },
            },
            ScenarioPhase {
                name: "Seed 5MB blob",
                duration: Duration::from_secs(1),
                action: PhaseAction::SeedBlob {
                    seeder_idx: 0,
                    size: 5 * 1024 * 1024,
                },
            },
            ScenarioPhase {
                name: "Complete",
                duration: Duration::from_secs(60),
                action: PhaseAction::Run,
            },
        ],
        timeout: Duration::from_secs(120),
    }
}

fn scenario_11_direct_transfer() -> Scenario {
    Scenario {
        id: 11,
        name: "1:1 large file",
        category: ScenarioCategory::BlobTransfer,
        node_count: 2,
        network: NetworkConfig {
            loss_rate: 0.0,
            loss_model: LossModelConfig::Uniform,
            latency: Duration::from_millis(2),
            jitter: 0.0,
            bandwidth_mbps: Some(1000.0), // 1 Gbps LAN
        },
        phases: vec![
            ScenarioPhase {
                name: "Seed blob",
                duration: Duration::from_secs(1),
                action: PhaseAction::SeedBlob {
                    seeder_idx: 0,
                    size: 100 * 1024 * 1024,
                },
            },
            ScenarioPhase {
                name: "Transfer",
                duration: Duration::from_secs(90),
                action: PhaseAction::Run,
            },
        ],
        timeout: Duration::from_secs(120),
    }
}

fn scenario_12_fast_network() -> Scenario {
    Scenario {
        id: 12,
        name: "Fast network 100MB",
        category: ScenarioCategory::BlobTransfer,
        node_count: 4,
        network: NetworkConfig {
            loss_rate: 0.0,
            loss_model: LossModelConfig::Uniform,
            latency: Duration::from_millis(5),
            jitter: 0.0,
            bandwidth_mbps: Some(100.0), // 100 Mbps broadband
        },
        phases: vec![
            ScenarioPhase {
                name: "Seed blob",
                duration: Duration::from_secs(1),
                action: PhaseAction::SeedBlob {
                    seeder_idx: 0,
                    size: 100 * 1024 * 1024,
                },
            },
            ScenarioPhase {
                name: "Transfer",
                duration: Duration::from_secs(60),
                action: PhaseAction::Run,
            },
        ],
        timeout: Duration::from_secs(120),
    }
}

fn scenario_10_hostile_network() -> Scenario {
    Scenario {
        id: 10,
        name: "Hostile network",
        category: ScenarioCategory::Combined,
        node_count: 3,
        network: NetworkConfig {
            loss_rate: 0.10,
            loss_model: LossModelConfig::GilbertElliot { p: 0.10, r: 0.50 },
            latency: Duration::from_millis(200),
            jitter: 0.20,
            bandwidth_mbps: None,
        },
        phases: vec![
            ScenarioPhase {
                name: "Messages",
                duration: Duration::from_secs(10),
                action: PhaseAction::AuthorMessages { per_node: 30 },
            },
            ScenarioPhase {
                name: "Seed 2MB blob",
                duration: Duration::from_secs(1),
                action: PhaseAction::SeedBlob {
                    seeder_idx: 0,
                    size: 2 * 1024 * 1024,
                },
            },
            ScenarioPhase {
                name: "Complete",
                duration: Duration::from_secs(120),
                action: PhaseAction::Run,
            },
        ],
        timeout: Duration::from_secs(300),
    }
}
