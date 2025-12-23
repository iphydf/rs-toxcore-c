use crate::model::{GenericTransport, MetricHistory, Model, NodeWrapper, Scenario, Topology};
use crate::msg::{Cmd, Msg};
use crossterm::event::{Event as CrosstermEvent, KeyCode};
use merkle_tox_core::cas::{BlobInfo, BlobStatus, CHUNK_SIZE};
use merkle_tox_core::clock::TimeProvider;
use merkle_tox_core::dag::{Content, NodeHash, PhysicalDevicePk};
use merkle_tox_core::node::MerkleToxNode;
use merkle_tox_core::sync::BlobStore;
use merkle_tox_core::testing::gateway::TOX_BRIDGED_PACKET_ID;
use merkle_tox_core::testing::{InMemoryStore, SimulatedTransport};
use merkle_tox_tox::TOX_CUSTOM_PACKET_ID;
use rand::{RngCore, SeedableRng, rngs::StdRng};
use std::collections::HashSet;
use std::time::Duration;
use toxcore::tox::events::Event as ToxEvent;

pub fn update(model: &mut Model, msg: Msg) -> Vec<Cmd> {
    match msg {
        Msg::Input(event) => handle_input(model, event),
        Msg::Tick(dt) => tick(model, dt),
    }
}

fn handle_input(model: &mut Model, event: CrosstermEvent) -> Vec<Cmd> {
    let mut cmds = Vec::new();
    if let CrosstermEvent::Key(key) = event {
        // Global Keys
        match key.code {
            KeyCode::Char('q') => cmds.push(Cmd::Quit),
            KeyCode::Tab => {
                model.current_tab = (model.current_tab + 1) % 4;
            }
            KeyCode::BackTab => {
                model.current_tab = (model.current_tab + 3) % 4;
            }
            KeyCode::Char(' ') => {
                model.is_paused = !model.is_paused;
            }
            _ => {}
        }

        // Tab-specific Keys
        if model.current_tab == 3 {
            match key.code {
                KeyCode::Up => model.settings_cursor = (model.settings_cursor + 8) % 9,
                KeyCode::Down => model.settings_cursor = (model.settings_cursor + 1) % 9,
                KeyCode::Left | KeyCode::Char('-') => match model.settings_cursor {
                    0 => model.edit_nodes = model.edit_nodes.saturating_sub(1),
                    1 => model.edit_real_nodes = model.edit_real_nodes.saturating_sub(1),
                    2 => model.edit_seed = model.edit_seed.saturating_sub(1),
                    3 => {
                        model.edit_topology = match model.edit_topology {
                            Topology::Mesh => Topology::Dynamic,
                            Topology::Star => Topology::Mesh,
                            Topology::Dynamic => Topology::Star,
                        }
                    }
                    4 => model.msg_rate = (model.msg_rate - 0.1).max(0.0),
                    5 => model.loss_rate = (model.loss_rate - 0.005).max(0.0),
                    6 => model.latency_ms = model.latency_ms.saturating_sub(10),
                    7 => model.jitter_rate = (model.jitter_rate - 0.01).max(0.0),
                    _ => {}
                },
                KeyCode::Right | KeyCode::Char('+') => match model.settings_cursor {
                    0 => model.edit_nodes += 1,
                    1 => model.edit_real_nodes += 1,
                    2 => model.edit_seed += 1,
                    3 => {
                        model.edit_topology = match model.edit_topology {
                            Topology::Mesh => Topology::Star,
                            Topology::Star => Topology::Dynamic,
                            Topology::Dynamic => Topology::Mesh,
                        }
                    }
                    4 => model.msg_rate += 0.1,
                    5 => model.loss_rate = (model.loss_rate + 0.005).min(1.0),
                    6 => model.latency_ms += 10,
                    7 => model.jitter_rate = (model.jitter_rate + 0.01).min(1.0),
                    _ => {}
                },
                KeyCode::Enter if model.settings_cursor == 8 => {
                    let is_paused = model.is_paused;
                    let rate = model.msg_rate;
                    *model = Model::new(
                        model.edit_nodes,
                        model.edit_real_nodes,
                        rate,
                        is_paused,
                        model.edit_seed,
                        model.edit_topology,
                    );
                    model.current_tab = 3; // Stay in settings tab after restart
                    model.table_state.select(Some(0));
                }
                _ => {}
            }
        } else {
            match key.code {
                KeyCode::Char('i') => {
                    model.last_interesting_state = model.get_interesting_state();
                    model.run_until_interesting = true;
                }
                KeyCode::Char('m') => {
                    if let Some(selected) = model.table_state.selected()
                        && let Some(n) = model.nodes.get_mut(selected)
                    {
                        let effects = n.node.engine.author_node(
                            model.conversation_id,
                            Content::Text(format!("Manual Msg from {:?}", n.node.engine.self_pk)),
                            vec![],
                            &n.node.store,
                        );
                        if let Ok(effects) = effects {
                            let now = n.node.time_provider.now_instant();
                            let now_ms = n.node.time_provider.now_system_ms() as u64;
                            let mut dummy_wakeup = now;
                            for effect in effects {
                                let _ =
                                    n.node
                                        .process_effect(effect, now, now_ms, &mut dummy_wakeup);
                            }
                        }
                        n.last_authoring = model.time_provider.now_instant();
                    }
                }
                KeyCode::Char('s') if model.is_paused => {
                    model.is_paused = false;
                    tick(model, Duration::from_millis(50));
                    model.is_paused = true;
                }
                KeyCode::Char('+') => model.msg_rate += 0.5,
                KeyCode::Char('-') => model.msg_rate = (model.msg_rate - 0.5).max(0.0),
                KeyCode::Char(']') => model.loss_rate = (model.loss_rate + 0.01).min(1.0),
                KeyCode::Char('[') => model.loss_rate = (model.loss_rate - 0.01).max(0.0),
                KeyCode::Char('}') => model.latency_ms += 50,
                KeyCode::Char('{') => model.latency_ms = model.latency_ms.saturating_sub(50),
                KeyCode::Char('J') => model.jitter_rate = (model.jitter_rate + 0.05).min(1.0),
                KeyCode::Char('j') => model.jitter_rate = (model.jitter_rate - 0.05).max(0.0),
                KeyCode::Char('b') => {
                    if let Some(selected) = model.table_state.selected()
                        && let Some(n) = model.nodes.get(selected)
                    {
                        model.hub.set_blackout(
                            n.node.engine.self_pk,
                            model.time_provider.now_instant() + Duration::from_secs(5),
                        );
                    }
                }
                KeyCode::Char('p') => {
                    // Split swarm into two partitions
                    let mut p1 = HashSet::new();
                    let mut p2 = HashSet::new();
                    for (i, n) in model.nodes.iter().enumerate() {
                        if i < model.nodes.len() / 2 {
                            p1.insert(n.node.engine.self_pk);
                        } else {
                            p2.insert(n.node.engine.self_pk);
                        }
                    }
                    model.hub.clear_partitions();
                    model.hub.add_partition(p1);
                    model.hub.add_partition(p2);
                }
                KeyCode::Char('R') => {
                    let is_paused = model.is_paused;
                    let rate = model.msg_rate;
                    let loss = model.loss_rate;
                    let latency = model.latency_ms;
                    let jitter = model.jitter_rate;
                    let tab = model.current_tab;
                    *model = Model::new(
                        model.edit_nodes,
                        model.edit_real_nodes,
                        rate,
                        is_paused,
                        model.edit_seed,
                        model.edit_topology,
                    );
                    model.loss_rate = loss;
                    model.latency_ms = latency;
                    model.jitter_rate = jitter;
                    model.current_tab = tab;
                    model.table_state.select(Some(0));
                }
                KeyCode::Char('P') => {
                    model.hub.clear_partitions();
                    model.active_scenario = None;
                    model.scenario_timer = None;
                }
                KeyCode::Char('L') => model.active_scenario = Some(Scenario::LateJoiner),
                KeyCode::Char('H') => {
                    model.active_scenario = Some(Scenario::PartitionHeal);
                    model.scenario_timer = None;
                }
                KeyCode::Char('K') => {
                    if model.active_scenario == Some(Scenario::KeyRotationStorm) {
                        model.active_scenario = None;
                        model.scenario_timer = None;
                    } else {
                        model.active_scenario = Some(Scenario::KeyRotationStorm);
                        model.scenario_timer = None;
                    }
                }
                KeyCode::Char('B') => model.active_scenario = Some(Scenario::LargeBlobSwarm),
                KeyCode::Down => {
                    let i = match model.table_state.selected() {
                        Some(i) => (i + 1) % model.nodes.len(),
                        None => 0,
                    };
                    model.table_state.select(Some(i));
                }
                KeyCode::Up => {
                    let i = match model.table_state.selected() {
                        Some(i) => (i + model.nodes.len() - 1) % model.nodes.len(),
                        None => 0,
                    };
                    model.table_state.select(Some(i));
                }
                _ => {}
            }
        }
    }
    cmds
}

fn tick(model: &mut Model, dt: Duration) -> Vec<Cmd> {
    if !model.is_paused || model.run_until_interesting {
        model.time_provider.advance(dt);
        model.virtual_elapsed += dt;
        model.steps += 1;
    } else {
        return vec![];
    }

    let now = model.time_provider.now_instant();

    // Handle Active Scenario
    if let Some(scenario) = model.active_scenario {
        match scenario {
            Scenario::LateJoiner => {
                // Create a new node and add it to the swarm
                let mut pk_bytes = [0u8; 32];
                model.rng.fill_bytes(&mut pk_bytes);
                let pk = PhysicalDevicePk::from(pk_bytes);
                let rx = model.hub.register(pk);
                let transport = SimulatedTransport::new(pk, model.hub.clone());
                let store = InMemoryStore::new();
                let engine = merkle_tox_core::engine::MerkleToxEngine::new(
                    pk,
                    pk.to_logical(),
                    StdRng::seed_from_u64(model.rng.next_u64()),
                    model.time_provider.clone(),
                );
                let mut node = MerkleToxNode::new(
                    engine,
                    GenericTransport::Sim(transport),
                    store,
                    model.time_provider.clone(),
                );

                // Peer with existing nodes
                for existing in &model.nodes {
                    let epk = existing.node.engine.self_pk;
                    let effects =
                        node.engine
                            .start_sync(model.conversation_id, Some(epk), &node.store);
                    let now_inst = node.time_provider.now_instant();
                    let now_ms = node.time_provider.now_system_ms() as u64;
                    let mut dummy_wakeup = now_inst;
                    for effect in effects {
                        let _ = node.process_effect(effect, now_inst, now_ms, &mut dummy_wakeup);
                    }
                }

                model.nodes.push(NodeWrapper {
                    node,
                    rx: Some(rx),
                    last_authoring: now,
                    history: MetricHistory::default(),
                });
                model.active_scenario = None;
            }
            Scenario::PartitionHeal => {
                if model.scenario_timer.is_none() {
                    // Start partition
                    let mut p1 = HashSet::new();
                    let mut p2 = HashSet::new();
                    for (i, n) in model.nodes.iter().enumerate() {
                        if i < model.nodes.len() / 2 {
                            p1.insert(n.node.engine.self_pk);
                        } else {
                            p2.insert(n.node.engine.self_pk);
                        }
                    }
                    model.hub.clear_partitions();
                    model.hub.add_partition(p1);
                    model.hub.add_partition(p2);
                    model.scenario_timer = Some(now + Duration::from_secs(10));
                } else if now >= model.scenario_timer.unwrap() {
                    // Heal partition
                    model.hub.clear_partitions();
                    model.scenario_timer = None;
                    model.active_scenario = None;
                }
            }
            Scenario::KeyRotationStorm => {
                if model.scenario_timer.is_none() {
                    model.scenario_timer = Some(now);
                }

                if now >= model.scenario_timer.unwrap() {
                    // Every 2 seconds, rotate key of a random node
                    let idx = model.rng.next_u32() as usize % model.nodes.len();
                    let n = &mut model.nodes[idx];
                    let effects = n
                        .node
                        .engine
                        .rotate_conversation_key(model.conversation_id, &n.node.store);

                    if let Ok(effects) = effects {
                        let now_inst = n.node.time_provider.now_instant();
                        let now_ms = n.node.time_provider.now_system_ms() as u64;
                        let mut dummy_wakeup = now_inst;
                        for effect in effects {
                            let _ =
                                n.node
                                    .process_effect(effect, now_inst, now_ms, &mut dummy_wakeup);
                        }
                    }

                    model.scenario_timer = Some(now + Duration::from_secs(2));
                }
                // This scenario stays active until manually stopped (or we could limit it)
            }
            Scenario::LargeBlobSwarm => {
                if model.blob_hash.is_none() {
                    // Pick first node to seed a 1MB blob
                    let mut data = vec![0u8; 1024 * 1024];
                    model.rng.fill_bytes(&mut data);
                    let hash = NodeHash::from(*blake3::hash(&data).as_bytes());
                    model.blob_hash = Some(hash);

                    let seeder = &mut model.nodes[0];
                    let info = BlobInfo {
                        hash,
                        size: data.len() as u64,
                        bao_root: None, // No Bao for simple sim
                        status: BlobStatus::Available,
                        received_mask: None,
                    };
                    let _ = seeder.node.store.put_blob_info(info);
                    for i in 0..(data.len() as u64 / CHUNK_SIZE) {
                        let _ = seeder.node.store.put_chunk(
                            &model.conversation_id,
                            &hash,
                            i * CHUNK_SIZE,
                            &data[(i * CHUNK_SIZE) as usize..((i + 1) * CHUNK_SIZE) as usize],
                            None,
                        );
                    }

                    // Author the blob node
                    let effects = seeder.node.engine.author_node(
                        model.conversation_id,
                        Content::Blob {
                            hash,
                            name: "sim_file.bin".to_string(),
                            mime_type: "application/octet-stream".to_string(),
                            size: data.len() as u64,
                            metadata: vec![],
                        },
                        vec![],
                        &seeder.node.store,
                    );

                    if let Ok(effects) = effects {
                        let now_inst = seeder.node.time_provider.now_instant();
                        let now_ms = seeder.node.time_provider.now_system_ms() as u64;
                        let mut dummy_wakeup = now_inst;
                        for effect in effects {
                            let _ = seeder.node.process_effect(
                                effect,
                                now_inst,
                                now_ms,
                                &mut dummy_wakeup,
                            );
                        }
                    }

                    model.active_scenario = None; // Finished starting it
                }
            }
        }
    }

    // Update hub impairments
    model.hub.set_impairments(
        model.loss_rate,
        Duration::from_millis(model.latency_ms),
        model.jitter_rate,
    );

    model.hub.poll();

    if let Some(gw) = &model.gateway {
        gw.poll();

        // Demotion: Real Tox events -> Hub (only for virtual nodes)
        let tox = gw.real_transport.tox.lock();
        if let Ok(events) = tox.events() {
            for event in &events {
                if let ToxEvent::FriendLossyPacket(e) = event {
                    let data = e.data();
                    let from_pk = tox.friend(e.friend_number()).public_key().ok().map(|p| p.0);
                    let local_pk = tox.public_key().0;

                    if let Some(from) = from_pk {
                        if data.first() == Some(&TOX_CUSTOM_PACKET_ID) {
                            gw.demote(
                                PhysicalDevicePk::from(from),
                                PhysicalDevicePk::from(local_pk),
                                data[1..].to_vec(),
                            );
                        } else if data.first() == Some(&TOX_BRIDGED_PACKET_ID) {
                            // Real -> Virtual (Proxied)
                            gw.handle_bridged_packet(PhysicalDevicePk::from(from), &data[1..]);
                        }
                    }
                }
            }
        }
    }

    // 1. Automated Authoring
    if model.msg_rate > 0.0 {
        let interval = Duration::from_secs_f32(1.0 / model.msg_rate);
        for n in &mut model.nodes {
            if now.duration_since(n.last_authoring) >= interval && (model.rng.next_u32() % 100) < 10
            {
                let effects = n.node.engine.author_node(
                    model.conversation_id,
                    Content::Text(format!("Msg from {:?}", n.node.engine.self_pk)),
                    vec![],
                    &n.node.store,
                );

                if let Ok(effects) = effects {
                    let now_inst = n.node.time_provider.now_instant();
                    let now_ms = n.node.time_provider.now_system_ms() as u64;
                    let mut dummy_wakeup = now_inst;
                    for effect in effects {
                        let _ = n
                            .node
                            .process_effect(effect, now_inst, now_ms, &mut dummy_wakeup);
                    }
                }
                n.last_authoring = now;
            }
        }
    }

    // 2. Process incoming packets
    for n in &mut model.nodes {
        let mut virtual_packets = Vec::new();
        let mut tox_packets = Vec::new();

        match &n.node.transport {
            GenericTransport::Sim(_) => {
                if let Some(rx) = &n.rx {
                    while let Ok(pkt) = rx.try_recv() {
                        virtual_packets.push(pkt);
                    }
                }
            }
            GenericTransport::Tox { transport, .. } => {
                let tox = transport.tox.lock();
                if let Ok(events) = tox.events() {
                    for event in &events {
                        if let toxcore::tox::events::Event::FriendLossyPacket(e) = event {
                            let data = e.data();
                            if data.first() == Some(&TOX_CUSTOM_PACKET_ID)
                                && let Ok(from) = tox.friend(e.friend_number()).public_key()
                            {
                                tox_packets
                                    .push((PhysicalDevicePk::from(from.0), data[1..].to_vec()));
                            } else if data.first() == Some(&TOX_BRIDGED_PACKET_ID) {
                                // Virtual -> Real (Proxied via Gateway)
                                if data.len() >= 33 {
                                    let mut target = [0u8; 32];
                                    target.copy_from_slice(&data[1..33]);
                                    if target == tox.public_key().0
                                        && let Ok(from) = tox.friend(e.friend_number()).public_key()
                                    {
                                        tox_packets.push((
                                            PhysicalDevicePk::from(from.0),
                                            data[33..].to_vec(),
                                        ));
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        for (from, data) in virtual_packets {
            n.node.handle_packet(from, &data);
        }
        for (from, data) in tox_packets {
            n.node.handle_packet(from, &data);
        }
    }

    // 3. Poll all nodes for background tasks
    for n in &mut model.nodes {
        n.node.poll();

        // Update history
        let status = n.node.status(&model.conversation_id);
        let mut avg_rtt = 0.0;
        let mut avg_cwnd = 0.0;
        let mut avg_inflight = 0.0;
        if !status.sessions.is_empty() {
            for s in status.sessions.values() {
                avg_rtt += s.rtt.as_millis() as f32;
                avg_cwnd += s.cwnd as f32;
                avg_inflight += s.in_flight_bytes as f32;
            }
            avg_rtt /= status.sessions.len() as f32;
            avg_cwnd /= status.sessions.len() as f32;
            avg_inflight /= status.sessions.len() as f32;
        }
        n.history.push(
            model.virtual_elapsed.as_secs_f64(),
            avg_rtt,
            avg_cwnd,
            avg_inflight,
        );
    }

    if model.run_until_interesting && model.check_interesting() {
        model.run_until_interesting = false;
        model.is_paused = true;
    }

    vec![Cmd::Redraw]
}
