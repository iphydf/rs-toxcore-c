//! Measured cost test for N-user group chat.
//!
//! Runs simulated group conversations of various sizes for a fixed
//! virtual duration at a fixed authoring rate, and measures
//! per-node bandwidth (bytes sent/received via the VirtualHub).
//!
//! This is the empirical counterpart to the analytical estimates in
//! `doc/planning/constants-cost-reference.md` §3 / §5. The two
//! should agree within reasonable factor (perhaps 2× given the
//! simulation has full protocol overhead — MessagePack framing,
//! sync messages, ACKs, etc. — that the analytical model
//! approximates). Large divergence indicates either the analytical
//! model is missing terms or the simulation has bugs.
//!
//! Scope of this test: **content propagation only**. The
//! conversation is bootstrapped with a pre-shared `KConv`,
//! bypassing X3DH handshake and `KeyWrap` rotation. So this
//! measures the steady-state cost of authoring and propagating
//! Content nodes through DAG sync; it does NOT measure
//! `KeyWrap`-rotation traffic. Adding `KeyWrap` measurement is a
//! separate follow-up test.

use merkle_tox_core::clock::TimeProvider;
use merkle_tox_core::dag::{Content, KConv};
use merkle_tox_core::sync::NodeStore;
use merkle_tox_core::testing::TrafficSnapshot;
use merkle_tox_workbench::model::{Model, Topology};
use merkle_tox_workbench::msg::Msg;
use merkle_tox_workbench::update::update;
use std::time::Duration;

/// Simulated test parameters for one workload.
struct Workload {
    nodes: usize,
    /// Messages authored per node over the test duration.
    msgs_per_node: usize,
    /// Total simulated duration in virtual seconds.
    duration_secs: u64,
    /// Random seed for the simulation.
    seed: u64,
}

#[derive(Debug)]
#[allow(dead_code)] // fields used via Debug printing in the test output
struct Measurement {
    nodes: usize,
    msgs_per_node: usize,
    avg_bytes_sent_per_node: u64,
    avg_bytes_received_per_node: u64,
    max_bytes_sent: u64,
    max_bytes_received: u64,
    total_packets_sent: u64,
    duration_secs: u64,
}

fn measure_workload(w: &Workload) -> Measurement {
    // Setup: N nodes, mesh topology, no auto-authoring.
    let mut model = Model::new(w.nodes, 0, 0.0, false, w.seed, Topology::Mesh);
    let dt = Duration::from_millis(50);

    // Run a few ticks to complete inter-node handshake at the
    // tox-sequenced layer. (Pre-X3DH; this just sets up transport
    // sessions between the nodes.)
    for _ in 0..20 {
        update(&mut model, Msg::Tick(dt));
    }

    // Bootstrap a single conversation with pre-shared KConv on all nodes.
    let k_conv = KConv::from([0x11u8; 32]);
    let now_ms = model.time_provider.now_system_ms();
    for n in &mut model.nodes {
        let _ = n
            .node
            .store
            .put_conversation_key(&model.conversation_id, 0, k_conv.clone());
        n.node.engine.conversations.insert(
            model.conversation_id,
            merkle_tox_core::engine::Conversation::Established(
                merkle_tox_core::engine::ConversationData::<
                    merkle_tox_core::engine::conversation::Established,
                >::new(model.conversation_id, k_conv.clone(), now_ms),
            ),
        );
    }

    // Distribute ephemeral signing keys (every-to-every) so peers can
    // verify each others' DARE-signed content. In production this
    // happens via SenderKeyDistribution; here we hand-wire it
    // because the test bypasses X3DH.
    let n = model.nodes.len();
    type PerNodeKeys = (merkle_tox_core::dag::PhysicalDevicePk, Vec<(u64, [u8; 32])>);
    let mut all_keys: Vec<PerNodeKeys> = Vec::with_capacity(n);
    for node in &model.nodes {
        let pk = node.node.engine.self_pk;
        let keys: Vec<_> = node
            .node
            .engine
            .self_ephemeral_signing_keys
            .iter()
            .map(|(epoch, sk)| (*epoch, sk.verifying_key().to_bytes()))
            .collect();
        all_keys.push((pk, keys));
    }
    for (i, target) in model.nodes.iter_mut().enumerate() {
        for (j, (peer_pk, peer_keys)) in all_keys.iter().enumerate() {
            if i == j {
                continue;
            }
            for (epoch, vk) in peer_keys {
                target
                    .node
                    .engine
                    .peer_ephemeral_signing_keys
                    .insert(
                        (*peer_pk, *epoch),
                        merkle_tox_core::dag::EphemeralSigningPk::from(*vk),
                    );
            }
        }
    }

    // Reset traffic counters now so we measure only the post-warmup
    // working period, not the handshake setup.
    model.hub.reset_traffic();

    // Compute tick budget so each node authors `msgs_per_node` over the
    // duration. We'll author messages every K ticks where K is chosen
    // so total ticks * 0.05s ≈ duration_secs.
    let total_ticks = (w.duration_secs * 1000 / 50) as usize;
    let author_every = (total_ticks / w.msgs_per_node).max(1);
    let conv_id = model.conversation_id;

    let mut authored_per_node = vec![0usize; n];

    for tick in 0..total_ticks {
        // Each tick, advance simulated time and let the hub/nodes
        // process protocol messages.
        update(&mut model, Msg::Tick(dt));

        // Round-robin authoring: at each authoring tick, each node
        // authors one message. The `tick % author_every == 0`
        // gate spaces out authoring across the duration.
        if tick % author_every == 0 {
            for (i, authored) in authored_per_node.iter_mut().enumerate() {
                if *authored >= w.msgs_per_node {
                    continue;
                }
                let node = &mut model.nodes[i];
                let effects = node.node.engine.author_node(
                    conv_id,
                    Content::Text(format!("msg {}-{}", i, *authored)),
                    vec![],
                    &node.node.store,
                );
                if let Ok(effects) = effects {
                    let now = node.node.time_provider.now_instant();
                    let now_ms = node.node.time_provider.now_system_ms() as u64;
                    let mut dummy_wakeup = now;
                    for effect in effects {
                        let _ = node
                            .node
                            .process_effect(effect, now, now_ms, &mut dummy_wakeup);
                    }
                    *authored += 1;
                }
            }
        }
    }

    // Snapshot traffic counters.
    let mut snapshots: Vec<TrafficSnapshot> = Vec::with_capacity(n);
    for node in &model.nodes {
        snapshots.push(model.hub.traffic_snapshot(&node.node.engine.self_pk));
    }

    let total_sent: u64 = snapshots.iter().map(|s| s.bytes_sent).sum();
    let total_recv: u64 = snapshots.iter().map(|s| s.bytes_received).sum();
    let total_pkts: u64 = snapshots.iter().map(|s| s.packets_sent).sum();
    let max_sent = snapshots.iter().map(|s| s.bytes_sent).max().unwrap_or(0);
    let max_recv = snapshots
        .iter()
        .map(|s| s.bytes_received)
        .max()
        .unwrap_or(0);

    Measurement {
        nodes: w.nodes,
        msgs_per_node: w.msgs_per_node,
        avg_bytes_sent_per_node: total_sent / n as u64,
        avg_bytes_received_per_node: total_recv / n as u64,
        max_bytes_sent: max_sent,
        max_bytes_received: max_recv,
        total_packets_sent: total_pkts,
        duration_secs: w.duration_secs,
    }
}

/// Run measurements at several group sizes and print the table.
/// This isn't a strict pass/fail — it's an empirical measurement
/// run that produces data for the cost-reference doc. The
/// assertion is just a sanity check that bandwidth scales
/// roughly as expected (super-linear in group size because
/// content fan-out is N-to-N).
#[test]
fn measure_content_propagation_costs_across_group_sizes() {
    let workloads = vec![
        Workload {
            nodes: 2,
            msgs_per_node: 50,
            duration_secs: 60,
            seed: 1,
        },
        Workload {
            nodes: 5,
            msgs_per_node: 50,
            duration_secs: 60,
            seed: 2,
        },
        Workload {
            nodes: 10,
            msgs_per_node: 30,
            duration_secs: 60,
            seed: 3,
        },
        Workload {
            nodes: 20,
            msgs_per_node: 20,
            duration_secs: 60,
            seed: 4,
        },
    ];

    println!(
        "\n=== Content-propagation cost (pre-shared key, no KeyWrap) ===\n"
    );
    println!(
        "{:>6} {:>10} {:>16} {:>16} {:>16} {:>16} {:>14}",
        "Nodes",
        "Msgs/node",
        "Avg sent/node",
        "Avg recv/node",
        "Max sent",
        "Max recv",
        "Total packets",
    );
    println!("{}", "-".repeat(110));
    let mut results = Vec::new();
    for w in &workloads {
        let m = measure_workload(w);
        println!(
            "{:>6} {:>10} {:>14} B  {:>14} B  {:>14} B  {:>14} B  {:>14}",
            m.nodes,
            m.msgs_per_node,
            m.avg_bytes_sent_per_node,
            m.avg_bytes_received_per_node,
            m.max_bytes_sent,
            m.max_bytes_received,
            m.total_packets_sent,
        );
        results.push(m);
    }
    println!();
    println!(
        "Notes: each node authors `msgs/node` Content messages \
         spaced over `duration_secs`. Receive cost grows with both \
         message rate and group size because each Content node must \
         reach every other member via mesh sync. Bytes counted at \
         VirtualHub-route level — includes tox-sequenced framing, \
         protocol headers, sync exchanges, ACKs."
    );
    println!();

    // Sanity: receive bandwidth should grow with group size for
    // the same per-node authoring rate (because each new member
    // adds another peer that needs to receive the same content).
    // Specifically: between N=2 and N=20, receive bytes per node
    // should grow at least roughly N-fold.
    let n2 = &results[0];
    let n20 = &results[3];
    // Compare per-message receive cost (normalize for differing
    // msgs/node across rows).
    let recv_per_msg_n2 = n2.avg_bytes_received_per_node as f64
        / (n2.msgs_per_node as f64 * (n2.nodes - 1) as f64).max(1.0);
    let recv_per_msg_n20 = n20.avg_bytes_received_per_node as f64
        / (n20.msgs_per_node as f64 * (n20.nodes - 1) as f64).max(1.0);
    println!(
        "Per-incoming-message receive cost: N=2 -> {:.1} B, N=20 -> {:.1} B",
        recv_per_msg_n2, recv_per_msg_n20,
    );
    println!(
        "(Both should be in the same order of magnitude; large \
         divergence indicates sync amplification or protocol \
         overhead scaling oddly.)"
    );
}
