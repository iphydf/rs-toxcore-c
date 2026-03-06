use std::collections::VecDeque;
use std::time::Duration;

use merkle_tox_core::dag::{ConversationId, NodeHash, PhysicalDevicePk};
use merkle_tox_core::node::MerkleToxNode;
use merkle_tox_core::sync::BlobStore;
use merkle_tox_core::testing::InMemoryStore;

use crate::harness::CountingTransport;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct NodeMetrics {
    pub pk_short: String,
    pub verified_nodes: usize,
    pub speculative_nodes: usize,
    pub bytes_tx: u64,
    pub bytes_rx: u64,
    pub blob_progress_pct: f32,
    pub sessions_active: usize,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AggregatedMetrics {
    pub virtual_elapsed: Duration,
    pub convergence_pct: f32,
    pub all_blobs_complete: bool,
    pub total_bytes_tx: u64,
    pub throughput_mbps: f32,
    pub dag_convergence_time: Option<Duration>,
    pub blob_completion_time: Option<Duration>,
    pub phase_name: String,
    pub phase_idx: usize,
    pub score: f32,
}

impl Default for AggregatedMetrics {
    fn default() -> Self {
        Self {
            virtual_elapsed: Duration::ZERO,
            convergence_pct: 0.0,
            all_blobs_complete: false,
            total_bytes_tx: 0,
            throughput_mbps: 0.0,
            dag_convergence_time: None,
            blob_completion_time: None,
            phase_name: String::new(),
            phase_idx: 0,
            score: 0.0,
        }
    }
}

#[derive(Debug, Clone)]
pub struct MetricSample {
    pub time_secs: f64,
    pub convergence_pct: f32,
    pub throughput_mbps: f32,
}

pub struct MetricsCollector {
    pub history: VecDeque<MetricSample>,
    pub node_metrics: Vec<NodeMetrics>,
    pub aggregated: AggregatedMetrics,
    pub blob_hashes: Vec<NodeHash>,
    pub useful_bytes: u64,
    last_bytes_tx: u64,
    last_sample_time: Duration,
    convergence_reached: bool,
    blobs_completed: bool,
}

impl Default for MetricsCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl MetricsCollector {
    pub fn new() -> Self {
        Self {
            history: VecDeque::with_capacity(300),
            node_metrics: Vec::new(),
            aggregated: AggregatedMetrics::default(),
            blob_hashes: Vec::new(),
            useful_bytes: 0,
            last_bytes_tx: 0,
            last_sample_time: Duration::ZERO,
            convergence_reached: false,
            blobs_completed: false,
        }
    }

    pub fn collect(
        &mut self,
        nodes: &[crate::harness::BenchNode],
        conv_id: &ConversationId,
        virtual_elapsed: Duration,
        phase_name: &str,
        phase_idx: usize,
        timeout: Duration,
    ) {
        self.node_metrics.clear();

        let mut min_verified: usize = usize::MAX;
        let mut max_verified: usize = 0;
        let mut total_bytes_tx: u64 = 0;

        for bn in nodes {
            let status = bn.node.status(conv_id);
            let bytes_tx = bn.bytes_sent.load(std::sync::atomic::Ordering::Relaxed);
            let bytes_rx = bn.bytes_received.load(std::sync::atomic::Ordering::Relaxed);

            let blob_pct = self.compute_blob_progress(&bn.node, conv_id);

            let pk_hex = hex_short(&status.pk);
            self.node_metrics.push(NodeMetrics {
                pk_short: pk_hex,
                verified_nodes: status.verified_count,
                speculative_nodes: status.speculative_count,
                bytes_tx,
                bytes_rx,
                blob_progress_pct: blob_pct,
                sessions_active: status.sessions.len(),
            });

            min_verified = min_verified.min(status.verified_count);
            max_verified = max_verified.max(status.verified_count);
            total_bytes_tx += bytes_tx;
        }

        let convergence_pct = if max_verified > 0 {
            (min_verified as f32 / max_verified as f32) * 100.0
        } else {
            100.0
        };

        let all_blobs_complete = self.check_all_blobs_complete(nodes);

        let dt = virtual_elapsed.saturating_sub(self.last_sample_time);
        let bytes_delta = total_bytes_tx.saturating_sub(self.last_bytes_tx);
        let throughput_mbps = if dt.as_secs_f64() > 0.0 {
            (bytes_delta as f64 * 8.0 / 1_000_000.0) / dt.as_secs_f64()
        } else {
            0.0
        } as f32;

        self.last_bytes_tx = total_bytes_tx;
        self.last_sample_time = virtual_elapsed;

        if convergence_pct >= 99.9 && !self.convergence_reached {
            self.convergence_reached = true;
            self.aggregated.dag_convergence_time = Some(virtual_elapsed);
        }

        if all_blobs_complete && !self.blobs_completed && !self.blob_hashes.is_empty() {
            self.blobs_completed = true;
            self.aggregated.blob_completion_time = Some(virtual_elapsed);
        }

        self.aggregated.virtual_elapsed = virtual_elapsed;
        self.aggregated.convergence_pct = convergence_pct;
        self.aggregated.all_blobs_complete = all_blobs_complete;
        self.aggregated.total_bytes_tx = total_bytes_tx;
        self.aggregated.throughput_mbps = throughput_mbps;
        self.aggregated.phase_name = phase_name.to_string();
        self.aggregated.phase_idx = phase_idx;
        self.aggregated.score = self.compute_score(
            convergence_pct,
            all_blobs_complete,
            virtual_elapsed,
            total_bytes_tx,
            timeout,
        );

        self.history.push_back(MetricSample {
            time_secs: virtual_elapsed.as_secs_f64(),
            convergence_pct,
            throughput_mbps,
        });
        if self.history.len() > 300 {
            self.history.pop_front();
        }
    }

    fn compute_blob_progress(
        &self,
        node: &MerkleToxNode<CountingTransport, InMemoryStore>,
        _conv_id: &ConversationId,
    ) -> f32 {
        if self.blob_hashes.is_empty() {
            return 100.0;
        }
        let mut have = 0;
        for hash in &self.blob_hashes {
            if node.store.has_blob(hash) {
                have += 1;
            }
        }
        (have as f32 / self.blob_hashes.len() as f32) * 100.0
    }

    fn check_all_blobs_complete(&self, nodes: &[crate::harness::BenchNode]) -> bool {
        if self.blob_hashes.is_empty() {
            return true;
        }
        for bn in nodes {
            for hash in &self.blob_hashes {
                if !bn.node.store.has_blob(hash) {
                    return false;
                }
            }
        }
        true
    }

    fn compute_score(
        &self,
        convergence_pct: f32,
        all_blobs_complete: bool,
        elapsed: Duration,
        total_bytes_tx: u64,
        timeout: Duration,
    ) -> f32 {
        // Convergence: 40 points
        let convergence_score = (convergence_pct / 100.0) * 40.0;

        // Speed: 30 points (faster = better)
        let completion_time = elapsed.as_secs_f64();
        let timeout_secs = timeout.as_secs_f64();
        let speed_score = ((1.0 - completion_time / timeout_secs).max(0.0) * 30.0) as f32;

        // Efficiency: 20 points (useful bytes / total bytes)
        let efficiency_score = if total_bytes_tx > 0 && self.useful_bytes > 0 {
            ((self.useful_bytes as f64 / total_bytes_tx as f64).min(1.0) * 20.0) as f32
        } else if total_bytes_tx == 0 {
            20.0
        } else {
            0.0
        };

        // Blob completeness: 10 points
        let blob_score = if all_blobs_complete { 10.0 } else { 0.0 };

        let mut score = convergence_score + speed_score + efficiency_score + blob_score;

        // Timeout penalty
        if elapsed >= timeout {
            score *= 0.5;
        }

        score
    }

    pub fn reset(&mut self) {
        self.history.clear();
        self.node_metrics.clear();
        self.aggregated = AggregatedMetrics::default();
        self.blob_hashes.clear();
        self.useful_bytes = 0;
        self.last_bytes_tx = 0;
        self.last_sample_time = Duration::ZERO;
        self.convergence_reached = false;
        self.blobs_completed = false;
    }
}

fn hex_short(pk: &PhysicalDevicePk) -> String {
    let b = pk.as_bytes();
    format!("{:02x}{:02x}{:02x}{:02x}", b[0], b[1], b[2], b[3])
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ScenarioResult {
    pub scenario_id: usize,
    pub scenario_name: String,
    pub category: crate::scenario::ScenarioCategory,
    pub score: f32,
    pub convergence_pct: f32,
    pub dag_convergence_time_ms: Option<u64>,
    pub blob_completion_time_ms: Option<u64>,
    pub total_bytes_tx: u64,
    pub timed_out: bool,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BenchmarkReport {
    pub results: Vec<ScenarioResult>,
    pub aggregate_score: f32,
}

impl BenchmarkReport {
    pub fn from_results(results: Vec<ScenarioResult>) -> Self {
        let aggregate_score = if results.is_empty() {
            0.0
        } else {
            results.iter().map(|r| r.score).sum::<f32>() / results.len() as f32
        };
        Self {
            results,
            aggregate_score,
        }
    }
}
