use crate::model::{GenericTransport, Model};
use merkle_tox_core::Transport;
use merkle_tox_core::cas::{BlobStatus, CHUNK_SIZE};
use merkle_tox_core::engine::session::PeerSession;
use merkle_tox_core::sync::{BlobStore, NodeStore};
use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    prelude::Line,
    prelude::Span,
    style::{Color, Modifier, Style},
    widgets::{
        Axis, Block, Borders, Cell, Chart, Dataset, GraphType, Paragraph, Row, Table, Tabs, canvas,
    },
};
use std::collections::{HashMap, HashSet};
use std::f64::consts::PI;
use toxcore::types::ToxConnection;

pub fn ui(f: &mut Frame, model: &mut Model) {
    let rects = Layout::default()
        .direction(Direction::Vertical)
        .constraints(
            [
                Constraint::Length(3),  // Header
                Constraint::Length(3),  // Tabs
                Constraint::Min(0),     // Content
                Constraint::Length(12), // Shared Footer
            ]
            .as_ref(),
        )
        .split(f.area());

    // Header Info
    let (synced, heads_count) = model.get_convergence_stats();
    let elapsed = model.virtual_elapsed;
    let gw_status = if let Some(gw) = &model.gateway {
        format!(
            " | GW: Active ({})",
            hex::encode(&gw.real_transport.local_pk().as_bytes()[..4])
        )
    } else {
        "".to_string()
    };
    let header_text = format!(
        " Swarm Status | Nodes: {} | Rate: {:.1} msg/s | Convergence: {}/{} | Heads: {} | Loss: {:.0}% | Latency: {}ms | Jitter: {:.0}% {}{} ",
        model.nodes.len(),
        model.msg_rate,
        synced,
        model.nodes.len(),
        heads_count,
        model.loss_rate * 100.0,
        model.latency_ms,
        model.jitter_rate * 100.0,
        if model.is_paused {
            "| PAUSED"
        } else if model.run_until_interesting {
            "| INTERESTING..."
        } else {
            ""
        },
        gw_status
    );
    let header =
        Paragraph::new(header_text).block(Block::default().borders(Borders::ALL).title(format!(
            " Merkle-Tox Workbench (Virtual: {:.1}s, Steps: {}) ",
            elapsed.as_secs_f32(),
            model.steps
        )));
    f.render_widget(header, rects[0]);

    // Tabs
    let titles = vec![
        " Fleet Overview ",
        " DAG Viewer ",
        " Topology ",
        " Settings ",
    ];
    let tabs = Tabs::new(titles)
        .block(Block::default().borders(Borders::ALL).title(" Tabs "))
        .select(model.current_tab)
        .style(Style::default().fg(Color::Cyan))
        .highlight_style(
            Style::default()
                .add_modifier(Modifier::BOLD)
                .bg(Color::Black),
        );
    f.render_widget(tabs, rects[1]);

    // Shared Footer Split
    let footer_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints(
            [
                Constraint::Length(32), // Impairment Panel
                Constraint::Min(0),     // Diagnostics / Chart
                Constraint::Length(50), // Keyboard Help
            ]
            .as_ref(),
        )
        .split(rects[3]);

    match model.current_tab {
        0 => render_fleet_tab(f, model, rects[2], footer_chunks[1]),
        1 => render_dag_tab(f, model, rects[2], footer_chunks[1]),
        2 => render_topology_tab(f, model, rects[2], footer_chunks[1]),
        3 => render_settings_tab(f, model, rects[2], footer_chunks[1]),
        _ => {}
    }

    render_impairment_panel(f, model, footer_chunks[0]);

    let help_text = [
        " q: Quit | Tab: Switch | Space: Pause",
        " s: Step | i: Step Int | m: Msg Selected",
        " +/-: Rate | [ / ]: Loss | { / }: Latency",
        " j/J: Jitter | b: Blackout | p/P: Partition",
        " L: Joiner | H: Heal | K: Rekey | B: Blob",
        " Up/Down: Select Node | R: Reset",
    ];
    let help = Paragraph::new(help_text.join("\n")).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Keyboard Shortcuts "),
    );
    f.render_widget(help, footer_chunks[2]);
}

fn render_settings_tab(f: &mut Frame, model: &mut Model, area: Rect, info_area: Rect) {
    let settings = [
        ("Virtual Nodes", model.edit_nodes.to_string()),
        ("Real Tox Nodes", model.edit_real_nodes.to_string()),
        ("Random Seed", model.edit_seed.to_string()),
        ("Topology", format!("{:?}", model.edit_topology)),
        ("Authoring Rate", format!("{:.1} msg/s", model.msg_rate)),
        ("Packet Loss", format!("{:.1}%", model.loss_rate * 100.0)),
        ("Base Latency", format!("{}ms", model.latency_ms)),
        ("Jitter", format!("{:.1}%", model.jitter_rate * 100.0)),
        ("[ APPLY STRUCTURAL RESTART ]", "Dangerous!".to_string()),
    ];

    let rows = settings.iter().enumerate().map(|(i, (name, val))| {
        let style = if i == model.settings_cursor {
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Color::White)
        };
        Row::new(vec![
            Cell::from(format!("  {}", name)).style(style),
            Cell::from(val.to_string()).style(style),
        ])
    });

    let table = Table::new(
        rows,
        [Constraint::Percentage(50), Constraint::Percentage(50)],
    )
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Simulation Configuration (Runtime & Structural) "),
    );

    f.render_widget(table, area);

    let info_text = vec![
        Line::from("Settings Navigation:"),
        Line::from(vec![
            Span::styled("  Up/Down", Style::default().fg(Color::Cyan)),
            Span::raw(": Select field"),
        ]),
        Line::from(vec![
            Span::styled("  Left/Right", Style::default().fg(Color::Cyan)),
            Span::raw(": Adjust value (Slow)"),
        ]),
        Line::from(vec![
            Span::styled("  + / -", Style::default().fg(Color::Cyan)),
            Span::raw(": Adjust value (Fast)"),
        ]),
        Line::from(vec![
            Span::styled("  Enter", Style::default().fg(Color::Yellow)),
            Span::raw(": Trigger Restart (if on bottom row)"),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled("NOTE:", Style::default().fg(Color::Red)),
            Span::raw(" Top 4 fields require a Restart to apply."),
        ]),
    ];
    let info = Paragraph::new(info_text).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Settings Help "),
    );
    f.render_widget(info, info_area);
}

fn render_impairment_panel(f: &mut Frame, model: &Model, area: Rect) {
    let loss_pct = (model.loss_rate * 100.0) as u64;
    let jitter_pct = (model.jitter_rate * 100.0) as u64;

    let info = vec![
        Line::from(vec![
            Span::raw(" Loss:    "),
            Span::styled(
                format!("{:>3}%   ", loss_pct),
                Style::default().fg(if loss_pct > 20 {
                    Color::Red
                } else if loss_pct > 0 {
                    Color::Yellow
                } else {
                    Color::Green
                }),
            ),
            Span::raw(format!(
                "[{}]",
                "█".repeat((loss_pct / 10) as usize).pad_right(10, ' ')
            )),
        ]),
        Line::from(vec![
            Span::raw(" Latency: "),
            Span::styled(
                format!("{:>4}ms ", model.latency_ms),
                Style::default().fg(if model.latency_ms > 500 {
                    Color::Red
                } else if model.latency_ms > 0 {
                    Color::Yellow
                } else {
                    Color::Green
                }),
            ),
            Span::raw(format!(
                "[{}]",
                "█"
                    .repeat((model.latency_ms / 200).min(10) as usize)
                    .pad_right(10, ' ')
            )),
        ]),
        Line::from(vec![
            Span::raw(" Jitter:  "),
            Span::styled(
                format!("{:>3}%   ", jitter_pct),
                Style::default().fg(if jitter_pct > 50 {
                    Color::Red
                } else if jitter_pct > 0 {
                    Color::Yellow
                } else {
                    Color::Green
                }),
            ),
            Span::raw(format!(
                "[{}]",
                "█".repeat((jitter_pct / 10) as usize).pad_right(10, ' ')
            )),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::raw(" Scenario: "),
            Span::styled(
                model
                    .active_scenario
                    .map_or("None".to_string(), |s| format!("{:?}", s)),
                Style::default().fg(if model.active_scenario.is_some() {
                    Color::Cyan
                } else {
                    Color::Gray
                }),
            ),
        ]),
    ];

    let panel = Paragraph::new(info).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Network Impairments "),
    );
    f.render_widget(panel, area);
}

trait PadRight {
    fn pad_right(self, len: usize, ch: char) -> String;
}

impl PadRight for String {
    fn pad_right(mut self, len: usize, ch: char) -> String {
        while self.chars().count() < len {
            self.push(ch);
        }
        self
    }
}

fn render_fleet_tab(f: &mut Frame, model: &mut Model, area: Rect, info_area: Rect) {
    let selected_style = Style::default().add_modifier(Modifier::REVERSED);
    let normal_style = Style::default().bg(Color::Blue);
    let header_cells = [
        "Type", "Node PK", "Conn", "Ver", "Spec", "Rank", "Epoch", "Status",
    ]
    .iter()
    .map(|h| Cell::from(*h).style(Style::default().fg(Color::Yellow)));
    let table_header = Row::new(header_cells)
        .style(normal_style)
        .height(1)
        .bottom_margin(1);

    let rows = model.nodes.iter().map(|n| {
        let status = n.node.status(&model.conversation_id);
        let pk_hex = hex::encode(&status.pk.as_bytes()[..6]);

        let mut conn_str = "VHub".to_string();
        let mut conn_style = Style::default().fg(Color::Gray);

        let (node_type, type_style) = match &n.node.transport {
            GenericTransport::Sim(_) => ("Sim".to_string(), Style::default().fg(Color::Gray)),
            GenericTransport::Tox { transport, .. } => {
                let tox = transport.tox.lock();
                let friends = tox.friend_list();
                let connected = friends
                    .iter()
                    .filter(|f| {
                        f.connection_status()
                            .unwrap_or(ToxConnection::TOX_CONNECTION_NONE)
                            != ToxConnection::TOX_CONNECTION_NONE
                    })
                    .count();

                conn_str = format!("{}/{}", connected, friends.len());
                conn_style = if connected > 0 {
                    Style::default().fg(Color::Green)
                } else {
                    Style::default().fg(Color::Red)
                };

                let is_gw = model
                    .gateway
                    .as_ref()
                    .is_some_and(|gw| gw.real_transport.local_pk() == status.pk);
                if is_gw {
                    ("Tox+GW".to_string(), Style::default().fg(Color::Magenta))
                } else {
                    ("Tox".to_string(), Style::default().fg(Color::LightBlue))
                }
            }
        };

        let mut status_str = "Synced".to_string();
        let mut status_style = Style::default().fg(Color::Green);

        if status.speculative_count > 0 {
            status_str = "Speculative".to_string();
            status_style = Style::default().fg(Color::Yellow);
        }

        if let Some(bh) = model.blob_hash
            && let Some(info) = n.node.store.get_blob_info(&bh)
        {
            match info.status {
                BlobStatus::Downloading => {
                    let progress = if let Some(mask) = &info.received_mask {
                        let num_chunks = info.size.div_ceil(CHUNK_SIZE);
                        let mut received = 0;
                        for i in 0..num_chunks {
                            let byte_idx = (i / 8) as usize;
                            let bit_idx = (i % 8) as u8;
                            if byte_idx < mask.len() && (mask[byte_idx] & (1 << bit_idx)) != 0 {
                                received += 1;
                            }
                        }
                        (received as f32 / num_chunks as f32) * 100.0
                    } else {
                        0.0
                    };
                    status_str = format!("DL Blob {:.0}%", progress);
                    status_style = Style::default().fg(Color::Cyan);
                }
                BlobStatus::Available => {
                    // Already handled by Synced usually, but let's be explicit
                    if status_str == "Synced" {
                        status_str = "Synced + Blob".to_string();
                    }
                }
                _ => {}
            }
        }

        Row::new(vec![
            Cell::from(node_type).style(type_style),
            Cell::from(pk_hex),
            Cell::from(conn_str).style(conn_style),
            Cell::from(status.verified_count.to_string()),
            Cell::from(status.speculative_count.to_string()),
            Cell::from(status.max_rank.to_string()),
            Cell::from(status.current_epoch.to_string()),
            Cell::from(status_str).style(status_style),
        ])
    });

    let t = Table::new(
        rows,
        [
            Constraint::Length(7),
            Constraint::Length(10),
            Constraint::Length(6),
            Constraint::Length(4),
            Constraint::Length(4),
            Constraint::Length(4),
            Constraint::Length(5),
            Constraint::Min(15),
        ],
    )
    .header(table_header)
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Virtual Fleet "),
    )
    .row_highlight_style(selected_style)
    .highlight_symbol(">>");

    f.render_stateful_widget(t, area, &mut model.table_state);

    // Node Detail Charting
    if let Some(selected) = model.table_state.selected()
        && let Some(n) = model.nodes.get(selected)
    {
        let status = n.node.status(&model.conversation_id);

        let chart_layout = Layout::default()
            .direction(Direction::Horizontal)
            .constraints(
                [
                    Constraint::Length(30), // Text stats
                    Constraint::Min(0),     // RTT Chart
                    Constraint::Min(0),     // CWND Chart
                    Constraint::Min(0),     // In-flight Chart
                ]
                .as_ref(),
            )
            .split(info_area);

        // Textual stats
        let mut sorted_heads = status.heads.clone();
        sorted_heads.sort();

        let detail_text = format!(
            " Node: {}...\n Auth Devs: {}\n Epoch: {} | DB: {}KB\n Heads: {:?}\n Sessions: {}",
            hex::encode(&status.pk.as_bytes()[..8]),
            status.authorized_devices,
            status.current_epoch,
            status.db_size_bytes / 1024,
            sorted_heads
                .iter()
                .map(|h| hex::encode(&h.as_bytes()[..4]))
                .collect::<Vec<_>>(),
            status.sessions.len()
        );
        let detail = Paragraph::new(detail_text)
            .block(Block::default().borders(Borders::ALL).title(" Stats "));
        f.render_widget(detail, chart_layout[0]);

        // Real-time Metrics Charts
        let now = model.virtual_elapsed.as_secs_f64();
        let x_bounds = [now - 10.0, now];
        let x_axis = Axis::default().bounds(x_bounds).labels(vec!["-10s", "Now"]);

        let rtt_data: Vec<(f64, f64)> =
            n.history.rtt.iter().map(|(t, v)| (*t, *v as f64)).collect();
        let cwnd_data: Vec<(f64, f64)> = n
            .history
            .cwnd
            .iter()
            .map(|(t, v)| (*t, *v as f64))
            .collect();
        let inflight_data: Vec<(f64, f64)> = n
            .history
            .inflight
            .iter()
            .map(|(t, v)| (*t, *v as f64))
            .collect();

        // Dynamic Y-axis labels
        let max_rtt = rtt_data.iter().map(|(_, v)| *v).fold(100.0, f64::max);
        let rtt_max_label = format!("{:.0}", max_rtt);

        let max_cwnd = cwnd_data.iter().map(|(_, v)| *v).fold(10.0, f64::max);
        let cwnd_max_label = format!("{:.0}", max_cwnd);

        let max_inflight = inflight_data.iter().map(|(_, v)| *v).fold(1024.0, f64::max);
        let infl_max_label = format!("{:.0}", max_inflight);

        // RTT Chart
        let rtt_chart = Chart::new(vec![
            Dataset::default()
                .name("RTT")
                .marker(ratatui::symbols::Marker::Braille)
                .graph_type(GraphType::Line)
                .style(Style::default().fg(Color::Cyan))
                .data(&rtt_data),
        ])
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(Line::from(vec![
                    Span::styled(
                        " RTT ",
                        Style::default()
                            .fg(Color::Cyan)
                            .add_modifier(Modifier::BOLD),
                    ),
                    Span::raw("(ms) "),
                ])),
        )
        .x_axis(x_axis.clone())
        .y_axis(
            Axis::default()
                .bounds([0.0, max_rtt])
                .labels(vec!["0", &rtt_max_label]),
        );
        f.render_widget(rtt_chart, chart_layout[1]);

        // CWND Chart
        let cwnd_chart = Chart::new(vec![
            Dataset::default()
                .name("CWND")
                .marker(ratatui::symbols::Marker::Braille)
                .graph_type(GraphType::Line)
                .style(Style::default().fg(Color::Yellow))
                .data(&cwnd_data),
        ])
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(Line::from(vec![
                    Span::styled(
                        " CWND ",
                        Style::default()
                            .fg(Color::Yellow)
                            .add_modifier(Modifier::BOLD),
                    ),
                    Span::raw("(pkts) "),
                ])),
        )
        .x_axis(x_axis.clone())
        .y_axis(
            Axis::default()
                .bounds([0.0, max_cwnd])
                .labels(vec!["0", &cwnd_max_label]),
        );
        f.render_widget(cwnd_chart, chart_layout[2]);

        // In-flight Chart
        let infl_chart = Chart::new(vec![
            Dataset::default()
                .name("In-flight")
                .marker(ratatui::symbols::Marker::Braille)
                .graph_type(GraphType::Line)
                .style(Style::default().fg(Color::Magenta))
                .data(&inflight_data),
        ])
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(Line::from(vec![
                    Span::styled(
                        " In-flight ",
                        Style::default()
                            .fg(Color::Magenta)
                            .add_modifier(Modifier::BOLD),
                    ),
                    Span::raw("(B) "),
                ])),
        )
        .x_axis(x_axis)
        .y_axis(
            Axis::default()
                .bounds([0.0, max_inflight])
                .labels(vec!["0", &infl_max_label]),
        );
        f.render_widget(infl_chart, chart_layout[3]);
    }
}

fn render_dag_tab(f: &mut Frame, model: &mut Model, area: Rect, info_area: Rect) {
    let aspect_ratio = (area.width as f64) / (area.height as f64 * 2.0);
    let x_scale = 100.0 * aspect_ratio;

    if let Some(selected) = model.table_state.selected() {
        if let Some(n) = model.nodes.get(selected) {
            let heads = n.node.store.get_heads(&model.conversation_id);

            let canvas = canvas::Canvas::default()
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .title(" DAG Viewer (Visual) "),
                )
                .x_bounds([0.0, x_scale])
                .y_bounds([0.0, 100.0])
                .paint(|ctx| {
                    let mut visited = HashSet::new();
                    let mut positions = HashMap::new();

                    // Simple BFS placement
                    let mut y = 90.0;
                    let mut current_level = heads.clone();
                    for h in &heads {
                        visited.insert(*h);
                    }

                    while !current_level.is_empty() && y > 0.0 {
                        let mut next_level = Vec::new();
                        let count = current_level.len();
                        for (i, h) in current_level.iter().enumerate() {
                            let x = (i as f64 + 1.0) * x_scale / (count as f64 + 1.0);
                            positions.insert(*h, (x, y));

                            if let Some(node) = n.node.store.get_node(h) {
                                for p in &node.parents {
                                    if !visited.contains(p) {
                                        next_level.push(*p);
                                        visited.insert(*p);
                                    }
                                }
                            }
                        }
                        current_level = next_level;
                        y -= 15.0;
                        if positions.len() > 50 {
                            break;
                        }
                    }

                    // Draw edges
                    for (hash, (x, y)) in &positions {
                        if let Some(node) = n.node.store.get_node(hash) {
                            for p in &node.parents {
                                if let Some((px, py)) = positions.get(p) {
                                    ctx.draw(&canvas::Line {
                                        x1: *x,
                                        y1: *y,
                                        x2: *px,
                                        y2: *py,
                                        color: Color::DarkGray,
                                    });
                                }
                            }
                        }
                    }

                    // Draw nodes
                    for (hash, (x, y)) in &positions {
                        let is_head = heads.contains(hash);
                        let color = if is_head { Color::Green } else { Color::White };
                        ctx.draw(&canvas::Circle {
                            x: *x,
                            y: *y,
                            radius: 2.5,
                            color,
                        });
                        ctx.print(
                            *x + 3.5,
                            *y,
                            Span::styled(hex::encode(&hash.as_bytes()[..2]), color),
                        );
                    }
                });
            f.render_widget(canvas, area);

            // In DAG tab, we can use the info area for node stats
            let status = n.node.status(&model.conversation_id);
            let info_lines = vec![
                Line::from(format!(
                    " Node: {:?}",
                    hex::encode(&status.pk.as_bytes()[..8])
                )),
                Line::from(format!(" Verified Nodes: {}", status.verified_count)),
                Line::from(format!(" Speculative:     {}", status.speculative_count)),
                Line::from(""),
                Line::from(" DAG Legend:"),
                Line::from(vec![
                    Span::raw("  "),
                    Span::styled("Green Circle", Style::default().fg(Color::Green)),
                    Span::raw(": DAG Head (Tip)"),
                ]),
                Line::from(vec![
                    Span::raw("  "),
                    Span::styled("White Circle", Style::default().fg(Color::White)),
                    Span::raw(": Verified Node"),
                ]),
                Line::from(vec![
                    Span::raw("  "),
                    Span::styled("DarkGray Line", Style::default().fg(Color::DarkGray)),
                    Span::raw(":    Parent Link"),
                ]),
                Line::from(""),
                Line::from(" Showing latest 50 nodes."),
            ];
            let info = Paragraph::new(info_lines).block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(" Selected Node Info "),
            );
            f.render_widget(info, info_area);
        }
    } else {
        let p = Paragraph::new("Select a node in Fleet Overview to view its DAG")
            .block(Block::default().borders(Borders::ALL));
        f.render_widget(p, area);
    }
}

fn render_topology_tab(f: &mut Frame, model: &mut Model, area: Rect, info_area: Rect) {
    let aspect_ratio = (area.width as f64) / (area.height as f64 * 2.0);
    let x_scale = 100.0 * aspect_ratio;
    let nodes_count = model.nodes.len();
    let canvas = canvas::Canvas::default()
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Topology (Graph View) "),
        )
        .x_bounds([-x_scale, x_scale])
        .y_bounds([-100.0, 100.0])
        .paint(|ctx| {
            let mut positions = Vec::new();
            for i in 0..nodes_count {
                let angle = (i as f64) * 2.0 * PI / (nodes_count as f64);
                let x = angle.cos() * 80.0 * aspect_ratio;
                let y = angle.sin() * 80.0;
                positions.push((x, y));
            }

            // Draw links
            for (i, n) in model.nodes.iter().enumerate() {
                for ((peer_pk, cid), session) in &n.node.engine.sessions {
                    if cid != &model.conversation_id {
                        continue;
                    }
                    // Find peer index
                    if let Some(j) = model
                        .nodes
                        .iter()
                        .position(|pn| &pn.node.engine.self_pk == peer_pk)
                        && i < j
                    {
                        let color = if matches!(session, PeerSession::Active(_)) {
                            Color::Green
                        } else {
                            Color::DarkGray
                        };
                        ctx.draw(&canvas::Line {
                            x1: positions[i].0,
                            y1: positions[i].1,
                            x2: positions[j].0,
                            y2: positions[j].1,
                            color,
                        });
                    }
                }
            }

            // Draw nodes
            for (i, (x, y)) in positions.iter().enumerate() {
                let pk = model.nodes[i].node.engine.self_pk;
                let is_selected = model.table_state.selected() == Some(i);

                let color = match &model.nodes[i].node.transport {
                    GenericTransport::Sim(_) => Color::Gray,
                    GenericTransport::Tox { .. } => {
                        let is_gw = model
                            .gateway
                            .as_ref()
                            .is_some_and(|gw| gw.real_transport.local_pk() == pk);
                        if is_gw {
                            Color::Magenta
                        } else {
                            Color::LightBlue
                        }
                    }
                };

                ctx.draw(&canvas::Circle {
                    x: *x,
                    y: *y,
                    radius: 8.0,
                    color: if is_selected { Color::Yellow } else { color },
                });

                ctx.print(
                    *x - 5.0,
                    *y - 12.0,
                    Span::styled(hex::encode(&pk.as_bytes()[..2]), Color::White),
                );
            }
        });
    f.render_widget(canvas, area);

    // Expanded Legend
    let legend_lines = vec![
        Line::from(" Nodes: (Color coded by type)"),
        Line::from(vec![
            Span::raw("  "),
            Span::styled("Gray", Style::default().fg(Color::Gray)),
            Span::raw(": Virtual (Sim) Node"),
        ]),
        Line::from(vec![
            Span::raw("  "),
            Span::styled("LightBlue", Style::default().fg(Color::LightBlue)),
            Span::raw(": Real (Tox) Node"),
        ]),
        Line::from(vec![
            Span::raw("  "),
            Span::styled("Magenta", Style::default().fg(Color::Magenta)),
            Span::raw(": Gateway (Bridge)"),
        ]),
        Line::from(vec![
            Span::raw("  "),
            Span::styled("Yellow", Style::default().fg(Color::Yellow)),
            Span::raw(": Selected Node"),
        ]),
        Line::from(""),
        Line::from(" Networking:"),
        Line::from("   Sim <-> Sim: Direct via VirtualHub"),
        Line::from("   Tox <-> Tox: Real DHT / UDP mesh"),
        Line::from("   Sim <-> Tox: Proxied via Gateway"),
        Line::from(""),
        Line::from(vec![
            Span::raw(" "),
            Span::styled("Green Lines", Style::default().fg(Color::Green)),
            Span::raw(": Active Sync Session (Handshake Done)"),
        ]),
        Line::from(vec![
            Span::raw(" "),
            Span::styled("DarkGray Lines", Style::default().fg(Color::DarkGray)),
            Span::raw(": Handshaking / Time Syncing"),
        ]),
    ];
    let info = Paragraph::new(legend_lines)
        .block(Block::default().borders(Borders::ALL).title(" Legend "));
    f.render_widget(info, info_area);
}
