use merkle_tox_bench::metrics::{BenchmarkReport, MetricsCollector, ScenarioResult};
use merkle_tox_bench::scenario::ScenarioCategory;

#[test]
fn metrics_collector_starts_empty() {
    let mc = MetricsCollector::new();
    assert!(mc.history.is_empty());
    assert!(mc.node_metrics.is_empty());
    assert!(mc.blob_hashes.is_empty());
    assert_eq!(mc.useful_bytes, 0);
    assert_eq!(mc.aggregated.convergence_pct, 0.0);
    assert!(!mc.aggregated.all_blobs_complete);
}

#[test]
fn metrics_collector_reset_clears_state() {
    let mut mc = MetricsCollector::new();
    mc.useful_bytes = 1000;
    mc.reset();
    assert_eq!(mc.useful_bytes, 0);
    assert!(mc.history.is_empty());
    assert!(mc.blob_hashes.is_empty());
}

#[test]
fn benchmark_report_aggregate_score() {
    let results = vec![
        ScenarioResult {
            scenario_id: 1,
            scenario_name: "A".to_string(),
            category: ScenarioCategory::BlobTransfer,
            score: 80.0,
            convergence_pct: 100.0,
            dag_convergence_time_ms: Some(500),
            blob_completion_time_ms: Some(1000),
            total_bytes_tx: 1024,
            timed_out: false,
            wall_clock_ms: None,
            latency: None,
            peak_admin_frontier: 0,
            peak_content_frontier: 0,
            useful_bytes: 0,
        },
        ScenarioResult {
            scenario_id: 2,
            scenario_name: "B".to_string(),
            category: ScenarioCategory::DagConvergence,
            score: 60.0,
            convergence_pct: 95.0,
            dag_convergence_time_ms: Some(800),
            blob_completion_time_ms: None,
            total_bytes_tx: 512,
            timed_out: false,
            wall_clock_ms: None,
            latency: None,
            peak_admin_frontier: 0,
            peak_content_frontier: 0,
            useful_bytes: 0,
        },
    ];
    let report = BenchmarkReport::from_results(results);
    assert_eq!(report.results.len(), 2);
    assert!((report.aggregate_score - 70.0).abs() < 0.01);
}

#[test]
fn benchmark_report_empty() {
    let report = BenchmarkReport::from_results(vec![]);
    assert_eq!(report.aggregate_score, 0.0);
    assert!(report.results.is_empty());
}
