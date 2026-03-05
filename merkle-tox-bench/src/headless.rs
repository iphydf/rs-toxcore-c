use crate::harness::SimulationHarness;
use crate::metrics::{BenchmarkReport, ScenarioResult};
use crate::scenario::Scenario;

/// Run all scenarios sequentially in headless mode, returning a benchmark report.
pub fn run_headless(scenarios: &[Scenario], seed: u64) -> BenchmarkReport {
    let mut results = Vec::new();

    for scenario in scenarios {
        eprintln!(
            "Running scenario {}: {} ({} nodes)...",
            scenario.id, scenario.name, scenario.node_count
        );

        let mut harness = SimulationHarness::new(scenario.node_count, &scenario.network, seed);
        let wall_clock_start = std::time::Instant::now();
        let completed = harness.run_scenario(scenario);
        let wall_clock_ms = wall_clock_start.elapsed().as_millis() as u64;

        let agg = &harness.metrics.aggregated;
        let latency = if harness.metrics.markers.is_empty() {
            None
        } else {
            Some(harness.metrics.latency_histogram())
        };
        let result = ScenarioResult {
            scenario_id: scenario.id,
            scenario_name: scenario.name.to_string(),
            category: scenario.category,
            score: agg.score,
            convergence_pct: agg.convergence_pct,
            dag_convergence_time_ms: agg.dag_convergence_time.map(|d| d.as_millis() as u64),
            blob_completion_time_ms: agg.blob_completion_time.map(|d| d.as_millis() as u64),
            total_bytes_tx: agg.total_bytes_tx,
            timed_out: !completed,
            wall_clock_ms: Some(wall_clock_ms),
            latency,
            peak_admin_frontier: agg.peak_admin_frontier,
            peak_content_frontier: agg.peak_content_frontier,
            useful_bytes: harness.metrics.useful_bytes,
        };

        eprintln!(
            "  Score: {:.1}/100  Convergence: {:.1}%  Timed out: {}",
            result.score, result.convergence_pct, result.timed_out
        );

        results.push(result);
    }

    BenchmarkReport::from_results(results)
}

/// Save a benchmark report as JSON to the given path.
pub fn save_baseline(report: &BenchmarkReport, path: &str) -> std::io::Result<()> {
    let json = serde_json::to_string_pretty(report).map_err(std::io::Error::other)?;
    std::fs::write(path, json)
}

/// Load a baseline report from JSON.
pub fn load_baseline(path: &str) -> std::io::Result<BenchmarkReport> {
    let json = std::fs::read_to_string(path)?;
    serde_json::from_str(&json).map_err(std::io::Error::other)
}

/// Print a comparison between current results and a baseline.
pub fn print_comparison(current: &BenchmarkReport, baseline: &BenchmarkReport) {
    println!(
        "\n{:<25} {:>10} {:>10} {:>10}",
        "Scenario", "Baseline", "Current", "Delta"
    );
    println!("{}", "-".repeat(60));

    for result in &current.results {
        let baseline_score = baseline
            .results
            .iter()
            .find(|r| r.scenario_id == result.scenario_id)
            .map(|r| r.score);

        if let Some(base) = baseline_score {
            let delta = result.score - base;
            let arrow = if delta > 1.0 {
                "+"
            } else if delta < -1.0 {
                ""
            } else {
                "~"
            };
            println!(
                "{:<25} {:>9.1} {:>9.1} {:>+9.1} {}",
                result.scenario_name, base, result.score, delta, arrow
            );
        } else {
            println!(
                "{:<25} {:>10} {:>9.1} {:>10}",
                result.scenario_name, "N/A", result.score, "new"
            );
        }
    }

    println!("{}", "-".repeat(60));
    if let Some(base_agg) = baseline
        .results
        .iter()
        .map(|r| r.score)
        .reduce(|a, b| a + b)
        .map(|s| s / baseline.results.len() as f32)
    {
        let delta = current.aggregate_score - base_agg;
        println!(
            "{:<25} {:>9.1} {:>9.1} {:>+9.1}",
            "AGGREGATE", base_agg, current.aggregate_score, delta
        );
    } else {
        println!(
            "{:<25} {:>10} {:>9.1}",
            "AGGREGATE", "N/A", current.aggregate_score
        );
    }
}

/// Print the report as JSON to stdout.
pub fn print_json(report: &BenchmarkReport) {
    println!(
        "{}",
        serde_json::to_string_pretty(report).unwrap_or_else(|_| "{}".to_string())
    );
}

/// Print a human-readable summary table.
pub fn print_summary(report: &BenchmarkReport) {
    println!(
        "\n{:<5} {:<25} {:<10} {:>8} {:>8} {:>10} {:>8}",
        "ID", "Scenario", "Category", "Score", "Conv%", "BytesTx", "Timeout"
    );
    println!("{}", "-".repeat(80));

    for r in &report.results {
        println!(
            "{:<5} {:<25} {:<10} {:>7.1} {:>7.1}% {:>10} {:>8}",
            r.scenario_id,
            r.scenario_name,
            format!("{}", r.category),
            r.score,
            r.convergence_pct,
            format_bytes(r.total_bytes_tx),
            if r.timed_out { "YES" } else { "no" }
        );
        if r.wall_clock_ms.is_some()
            || r.latency.is_some()
            || r.dag_convergence_time_ms.is_some()
            || r.peak_admin_frontier > 0
            || r.useful_bytes > 0
        {
            print!("      ");
            if let Some(ms) = r.dag_convergence_time_ms {
                print!("conv-time={}ms  ", ms);
            }
            if let Some(ms) = r.wall_clock_ms {
                print!("wall={}s  ", ms / 1000);
            }
            if r.peak_admin_frontier > 0 || r.peak_content_frontier > 0 {
                print!(
                    "peak-frontier admin/content={}/{}  ",
                    r.peak_admin_frontier, r.peak_content_frontier,
                );
            }
            if r.useful_bytes > 0 && r.total_bytes_tx > 0 {
                let overhead = r.total_bytes_tx as f64 / r.useful_bytes as f64;
                print!(
                    "bw={}useful/{} ({}× overhead)  ",
                    format_bytes(r.useful_bytes),
                    format_bytes(r.total_bytes_tx),
                    if overhead >= 100.0 {
                        format!("{:.0}", overhead)
                    } else {
                        format!("{:.1}", overhead)
                    },
                );
            }
            if let Some(l) = &r.latency {
                print!(
                    "latency p50/p95/max={}/{}/{}ms (n={})",
                    l.p50_ms, l.p95_ms, l.max_ms, l.samples,
                );
            }
            println!();
        }
    }

    println!("{}", "-".repeat(80));
    println!("Aggregate score: {:.1}/100", report.aggregate_score);
}

fn format_bytes(bytes: u64) -> String {
    if bytes >= 1024 * 1024 * 1024 {
        format!("{:.1}GB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
    } else if bytes >= 1024 * 1024 {
        format!("{:.1}MB", bytes as f64 / (1024.0 * 1024.0))
    } else if bytes >= 1024 {
        format!("{:.1}KB", bytes as f64 / 1024.0)
    } else {
        format!("{}B", bytes)
    }
}
