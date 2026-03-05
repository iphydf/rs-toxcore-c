use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Cell, Gauge, Paragraph, Row, Table};

use crate::harness::SimulationHarness;

use crate::scenario::Scenario;

pub struct TuiState {
    pub selected_scenario: usize,
    pub scenarios: Vec<Scenario>,
    pub running: bool,
    pub finished: bool,
    pub scenario_scores: Vec<Option<f32>>,
}

impl TuiState {
    pub fn new(scenarios: Vec<Scenario>) -> Self {
        let len = scenarios.len();
        Self {
            selected_scenario: 0,
            scenarios,
            running: false,
            finished: false,
            scenario_scores: vec![None; len],
        }
    }

    pub fn current_scenario(&self) -> &Scenario {
        &self.scenarios[self.selected_scenario]
    }
}

pub fn render(f: &mut Frame, tui: &TuiState, harness: Option<&SimulationHarness>) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Header
            Constraint::Min(10),   // Main content
            Constraint::Length(5), // Sparklines
            Constraint::Length(3), // Scenario tabs + help
        ])
        .split(f.area());

    render_header(f, chunks[0], tui, harness);
    render_main(f, chunks[1], tui, harness);
    render_sparklines(f, chunks[2], harness);
    render_footer(f, chunks[3], tui);
}

fn render_header(f: &mut Frame, area: Rect, tui: &TuiState, harness: Option<&SimulationHarness>) {
    let scenario = tui.current_scenario();
    let (elapsed_str, progress) = if let Some(h) = harness {
        let elapsed = h.virtual_elapsed;
        let timeout = scenario.timeout;
        let pct = (elapsed.as_secs_f64() / timeout.as_secs_f64()).min(1.0);
        (format!("{:.1}s", elapsed.as_secs_f64()), pct)
    } else {
        ("--".to_string(), 0.0)
    };

    let score_str = if let Some(h) = harness {
        format!("{:.1}", h.metrics.aggregated.score)
    } else if let Some(Some(s)) = tui.scenario_scores.get(tui.selected_scenario) {
        format!("{:.1}", s)
    } else {
        "--".to_string()
    };

    let phase_str = if let Some(h) = harness {
        h.metrics.aggregated.phase_name.clone()
    } else {
        String::new()
    };

    let header_text = format!(
        " Scenario: {} | Phase: {} | Virtual: {} | Score: {}",
        scenario.name, phase_str, elapsed_str, score_str
    );

    let gauge = Gauge::default()
        .block(Block::default().borders(Borders::ALL).title("Progress"))
        .gauge_style(Style::default().fg(Color::Cyan))
        .ratio(progress)
        .label(header_text);

    f.render_widget(gauge, area);
}

fn render_main(f: &mut Frame, area: Rect, tui: &TuiState, harness: Option<&SimulationHarness>) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(35), Constraint::Percentage(65)])
        .split(area);

    render_topology(f, chunks[0], tui, harness);
    render_node_table(f, chunks[1], harness);
}

fn render_topology(f: &mut Frame, area: Rect, tui: &TuiState, harness: Option<&SimulationHarness>) {
    let block = Block::default().borders(Borders::ALL).title("Topology");

    let scenario = tui.current_scenario();
    let mut lines = Vec::new();

    lines.push(Line::from(vec![
        Span::styled("Category: ", Style::default().fg(Color::DarkGray)),
        Span::styled(
            format!("{}", scenario.category),
            Style::default().fg(Color::Yellow),
        ),
    ]));
    lines.push(Line::from(vec![
        Span::styled("Nodes: ", Style::default().fg(Color::DarkGray)),
        Span::styled(
            format!("{}", scenario.node_count),
            Style::default().fg(Color::White),
        ),
    ]));
    lines.push(Line::from(vec![
        Span::styled("Loss: ", Style::default().fg(Color::DarkGray)),
        Span::styled(
            format!("{:.1}%", scenario.network.loss_rate * 100.0),
            Style::default().fg(if scenario.network.loss_rate > 0.0 {
                Color::Red
            } else {
                Color::Green
            }),
        ),
    ]));
    lines.push(Line::from(vec![
        Span::styled("Latency: ", Style::default().fg(Color::DarkGray)),
        Span::styled(
            format!("{}ms", scenario.network.latency.as_millis()),
            Style::default().fg(Color::White),
        ),
    ]));

    if harness.is_none() {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            if tui.running {
                "Setting up nodes..."
            } else {
                "Press Enter to start"
            },
            Style::default().fg(Color::DarkGray),
        )));
    }

    if let Some(h) = harness {
        lines.push(Line::from(""));
        lines.push(Line::from(vec![
            Span::styled("Convergence: ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                format!("{:.1}%", h.metrics.aggregated.convergence_pct),
                Style::default().fg(if h.metrics.aggregated.convergence_pct >= 99.9 {
                    Color::Green
                } else {
                    Color::Yellow
                }),
            ),
        ]));
        lines.push(Line::from(vec![
            Span::styled("Blobs: ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                if h.metrics.aggregated.all_blobs_complete {
                    "Complete"
                } else if h.metrics.blob_hashes.is_empty() {
                    "N/A"
                } else {
                    "In Progress"
                },
                Style::default().fg(if h.metrics.aggregated.all_blobs_complete {
                    Color::Green
                } else {
                    Color::Yellow
                }),
            ),
        ]));
        lines.push(Line::from(vec![
            Span::styled("Throughput: ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                format!("{:.1} Mbps", h.metrics.aggregated.throughput_mbps),
                Style::default().fg(Color::Cyan),
            ),
        ]));

        // Draw ASCII topology
        lines.push(Line::from(""));
        let n = h.nodes.len();
        if n <= 8 {
            // Simple mesh representation
            let labels: Vec<String> = h
                .metrics
                .node_metrics
                .iter()
                .enumerate()
                .map(|(i, _)| format!("[{}]", (b'A' + i as u8) as char))
                .collect();

            let top_row: Vec<Span> = labels
                .iter()
                .take(n.min(4))
                .map(|l| Span::styled(format!("{} ", l), Style::default().fg(Color::Cyan)))
                .collect();
            lines.push(Line::from(top_row));

            if n > 4 {
                let bot_row: Vec<Span> = labels
                    .iter()
                    .skip(4)
                    .map(|l| Span::styled(format!("{} ", l), Style::default().fg(Color::Cyan)))
                    .collect();
                lines.push(Line::from(vec![Span::raw("  ")]));
                lines.push(Line::from(bot_row));
            }
        }
    }

    let paragraph = Paragraph::new(lines).block(block);
    f.render_widget(paragraph, area);
}

fn render_node_table(f: &mut Frame, area: Rect, harness: Option<&SimulationHarness>) {
    let header = Row::new(vec![
        "Node", "Verified", "Spec", "Blob%", "Tx", "Rx", "Sess",
    ])
    .style(
        Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD),
    );

    let rows: Vec<Row> = if let Some(h) = harness {
        h.metrics
            .node_metrics
            .iter()
            .enumerate()
            .map(|(i, m)| {
                let label = format!("{} ({})", (b'A' + i as u8) as char, m.pk_short);
                Row::new(vec![
                    Cell::from(label),
                    Cell::from(format!("{}", m.verified_nodes)),
                    Cell::from(format!("{}", m.speculative_nodes)),
                    Cell::from(format!("{:.0}%", m.blob_progress_pct)),
                    Cell::from(format_bytes_short(m.bytes_tx)),
                    Cell::from(format_bytes_short(m.bytes_rx)),
                    Cell::from(format!("{}", m.sessions_active)),
                ])
            })
            .collect()
    } else {
        vec![]
    };

    let widths = [
        Constraint::Length(16),
        Constraint::Length(8),
        Constraint::Length(6),
        Constraint::Length(6),
        Constraint::Length(8),
        Constraint::Length(8),
        Constraint::Length(5),
    ];

    let table = Table::new(rows, widths).header(header).block(
        Block::default()
            .borders(Borders::ALL)
            .title("Per-Node Stats"),
    );

    f.render_widget(table, area);
}

fn render_sparklines(f: &mut Frame, area: Rect, harness: Option<&SimulationHarness>) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(area);

    // Throughput sparkline (braille-style using block chars)
    let throughput_block = Block::default()
        .borders(Borders::ALL)
        .title("Throughput (Mbps)");
    let throughput_text = if let Some(h) = harness {
        sparkline_text(
            &h.metrics
                .history
                .iter()
                .map(|s| s.throughput_mbps)
                .collect::<Vec<_>>(),
            area.width.saturating_sub(2) as usize,
        )
    } else {
        String::new()
    };
    let tp = Paragraph::new(throughput_text)
        .block(throughput_block)
        .style(Style::default().fg(Color::Cyan));
    f.render_widget(tp, chunks[0]);

    // Convergence sparkline
    let conv_block = Block::default()
        .borders(Borders::ALL)
        .title("Convergence (%)");
    let conv_text = if let Some(h) = harness {
        sparkline_text(
            &h.metrics
                .history
                .iter()
                .map(|s| s.convergence_pct)
                .collect::<Vec<_>>(),
            area.width.saturating_sub(2) as usize,
        )
    } else {
        String::new()
    };
    let cp = Paragraph::new(conv_text)
        .block(conv_block)
        .style(Style::default().fg(Color::Green));
    f.render_widget(cp, chunks[1]);
}

fn render_footer(f: &mut Frame, area: Rect, tui: &TuiState) {
    let s = tui.current_scenario();
    let score_str = if let Some(Some(score)) = tui.scenario_scores.get(tui.selected_scenario) {
        format!("  Score: {:.1}", score)
    } else {
        String::new()
    };

    let status = if tui.running {
        " [Running]"
    } else if tui.finished {
        " [Done]"
    } else {
        ""
    };

    let text = format!(
        " [{}/{}] {}{}{}  |  q:Quit  \u{2190}/\u{2192}:Nav  Enter:Run  n:Next  Esc:Stop",
        s.id,
        tui.scenarios.len(),
        s.name,
        status,
        score_str,
    );

    let footer = Paragraph::new(text)
        .block(Block::default().borders(Borders::ALL).title("Scenario"))
        .style(Style::default().fg(Color::Cyan));

    f.render_widget(footer, area);
}

/// Generate a braille-style sparkline string from float values.
fn sparkline_text(values: &[f32], width: usize) -> String {
    const BARS: &[char] = &[
        ' ', '\u{2581}', '\u{2582}', '\u{2583}', '\u{2584}', '\u{2585}', '\u{2586}', '\u{2587}',
        '\u{2588}',
    ];

    if values.is_empty() {
        return String::new();
    }

    let max = values
        .iter()
        .copied()
        .fold(f32::NEG_INFINITY, f32::max)
        .max(0.001);
    let skip = if values.len() > width {
        values.len() - width
    } else {
        0
    };

    values[skip..]
        .iter()
        .map(|&v| {
            let idx = ((v / max) * 8.0).round() as usize;
            BARS[idx.min(8)]
        })
        .collect()
}

fn format_bytes_short(bytes: u64) -> String {
    if bytes >= 1024 * 1024 {
        format!("{:.1}M", bytes as f64 / (1024.0 * 1024.0))
    } else if bytes >= 1024 {
        format!("{:.0}K", bytes as f64 / 1024.0)
    } else {
        format!("{}", bytes)
    }
}
