use merkle_tox_core::Transport;
use merkle_tox_core::cas::{BlobInfo, BlobStatus, CHUNK_SIZE};
use merkle_tox_core::dag::{Content, ConversationId, KConv, NodeHash};
use merkle_tox_core::sync::{BlobStore, NodeStore};
use merkle_tox_core::vfs::StdFileSystem;
use merkle_tox_fs::FsStore;
use merkle_tox_tox::ToxMerkleBridge;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tempfile::TempDir;
use toxcore::tox::events::Event;
use toxcore::tox::{Options, Tox};
use toxcore::types::{MessageType, ToxConnection};

struct TestNode {
    bridge: ToxMerkleBridge<FsStore>,
    store: FsStore,
    received_messages: Vec<String>,
    _dir: TempDir,
    /// Per-phase timing for the iterate() path. Cumulative ns since
    /// node creation; read at end of run_blob_transfer.
    iter_node_lock_ns: std::sync::Arc<std::sync::atomic::AtomicU64>,
    iter_tox_lock_ns: std::sync::Arc<std::sync::atomic::AtomicU64>,
    iter_events_ffi_ns: std::sync::Arc<std::sync::atomic::AtomicU64>,
    iter_event_dispatch_ns: std::sync::Arc<std::sync::atomic::AtomicU64>,
    iter_poll_ns: std::sync::Arc<std::sync::atomic::AtomicU64>,
}

impl TestNode {
    fn new(name: &str) -> Self {
        let dir = TempDir::new().unwrap();
        let mut opts = Options::new().unwrap();

        opts.set_udp_enabled(true);
        opts.set_tcp_port(0);
        opts.set_local_discovery_enabled(true);

        opts.set_start_port(33445);
        opts.set_end_port(65535);

        let tox = Tox::new(opts).unwrap_or_else(|_| panic!("Failed to create Tox node {}", name));
        tox.set_name(name.as_bytes()).unwrap();

        let store = FsStore::new(dir.path().to_path_buf(), Arc::new(StdFileSystem)).unwrap();
        let bridge = ToxMerkleBridge::new(tox, store.clone());

        Self {
            bridge,
            store,
            received_messages: Vec::new(),
            _dir: dir,
            iter_node_lock_ns: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
            iter_tox_lock_ns: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
            iter_events_ffi_ns: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
            iter_event_dispatch_ns: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
            iter_poll_ns: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
        }
    }

    /// Drive one iteration. Returns the next-wakeup `Instant` requested
    /// by the merkle-tox bridge so the host loop can sleep until then.
    async fn iterate(&mut self) -> Instant {
        use std::sync::atomic::Ordering;

        let node_lock_start = Instant::now();
        let tox_mutex = {
            let node = self.bridge.node.lock().await;
            node.transport.tox.clone()
        };
        self.iter_node_lock_ns
            .fetch_add(node_lock_start.elapsed().as_nanos() as u64, Ordering::Relaxed);

        {
            let tox_lock_start = Instant::now();
            let tox = tox_mutex.lock();
            self.iter_tox_lock_ns
                .fetch_add(tox_lock_start.elapsed().as_nanos() as u64, Ordering::Relaxed);

            let events_start = Instant::now();
            let events = tox.events().unwrap();
            self.iter_events_ffi_ns
                .fetch_add(events_start.elapsed().as_nanos() as u64, Ordering::Relaxed);

            let dispatch_start = Instant::now();
            for event in &events {
                if self.bridge.handle_event(&event).await.is_some() {
                    continue;
                }

                match event {
                    Event::FriendRequest(e) => {
                        let _ = tox.friend_add_norequest(&e.public_key());
                    }
                    Event::FriendMessage(e) => {
                        let msg = String::from_utf8_lossy(e.message()).into_owned();
                        println!("Node {:?} received message: {}", tox.name(), msg);
                        self.received_messages.push(msg);
                    }
                    _ => {}
                }
            }
            self.iter_event_dispatch_ns
                .fetch_add(dispatch_start.elapsed().as_nanos() as u64, Ordering::Relaxed);
        }
        let poll_start = Instant::now();
        let next_wakeup = self.bridge.poll().await;
        self.iter_poll_ns
            .fetch_add(poll_start.elapsed().as_nanos() as u64, Ordering::Relaxed);
        next_wakeup
    }
}

fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_test_writer()
        .try_init();
}

#[tokio::test]
async fn test_multi_node_sync() {
    init_tracing();
    let mut node_a = TestNode::new("NodeA");
    let mut node_b = TestNode::new("VaultBot");
    let mut node_c = TestNode::new("NodeC");

    let addr_b = node_b
        .bridge
        .node
        .lock()
        .await
        .transport
        .tox
        .lock()
        .address();

    let f_ab_num = node_a
        .bridge
        .node
        .lock()
        .await
        .transport
        .tox
        .lock()
        .friend_add(&addr_b, b"Hello Vault")
        .unwrap()
        .get_number();

    let f_cb_num = node_c
        .bridge
        .node
        .lock()
        .await
        .transport
        .tox
        .lock()
        .friend_add(&addr_b, b"Hello Vault")
        .unwrap()
        .get_number();

    // Run iteration until connected
    let start = Instant::now();
    loop {
        node_a.iterate().await;
        node_b.iterate().await;
        node_c.iterate().await;

        let c_ab = node_a
            .bridge
            .node
            .lock()
            .await
            .transport
            .tox
            .lock()
            .friend(f_ab_num)
            .connection_status()
            .unwrap();
        let c_cb = node_c
            .bridge
            .node
            .lock()
            .await
            .transport
            .tox
            .lock()
            .friend(f_cb_num)
            .connection_status()
            .unwrap();

        if c_ab != ToxConnection::TOX_CONNECTION_NONE && c_cb != ToxConnection::TOX_CONNECTION_NONE
        {
            break;
        }

        tokio::time::sleep(Duration::from_millis(100)).await;
        if start.elapsed() > Duration::from_secs(30) {
            panic!(
                "Timed out waiting for connection. A-B: {:?}, C-B: {:?}",
                c_ab, c_cb
            );
        }
    }

    println!("All nodes connected to VaultBot");

    // Baseline: send a regular Tox message from A to B
    println!("Sending baseline message A -> B...");
    node_a
        .bridge
        .node
        .lock()
        .await
        .transport
        .tox
        .lock()
        .friend(f_ab_num)
        .send_message(MessageType::TOX_MESSAGE_TYPE_NORMAL, b"Baseline Check")
        .unwrap();

    let start = Instant::now();
    while node_b.received_messages.is_empty() {
        node_a.iterate().await;
        node_b.iterate().await;
        tokio::time::sleep(Duration::from_millis(50)).await;
        if start.elapsed() > Duration::from_secs(10) {
            panic!("Timed out waiting for baseline message");
        }
    }
    assert_eq!(node_b.received_messages[0], "Baseline Check");
    println!("Baseline message received successfully");

    let conv_id = ConversationId::from([1u8; 32]);
    let k_conv = KConv::from([0xAAu8; 32]);

    // Collect protocol identity PKs (Ed25519, derived from Tox SK).
    // These differ from transport.local_pk() which returns Tox X25519 PKs.
    let pk_a = node_a.bridge.node.lock().await.engine.self_pk;
    let pk_b = node_b.bridge.node.lock().await.engine.self_pk;
    let pk_c = node_c.bridge.node.lock().await.engine.self_pk;
    let all_pks = [pk_a, pk_b, pk_c];

    for n in [&mut node_a, &mut node_b, &mut node_c] {
        n.store
            .put_conversation_key(&conv_id, 0, k_conv.clone())
            .unwrap();
        let mut node_lock = n.bridge.node.lock().await;
        let now_ms = node_lock.engine.clock.network_time_ms();
        node_lock.engine.conversations.insert(
            conv_id,
            merkle_tox_core::engine::Conversation::Established(
                merkle_tox_core::engine::ConversationData::<
                    merkle_tox_core::engine::conversation::Established,
                >::new(conv_id, k_conv.clone(), now_ms),
            ),
        );
        // Register all device keys as members so sender identification
        // works. Bypasses real Genesis+AuthorizeDevice flow; pk_a is
        // the test's stand-in founder (role=0), the rest are regular
        // members (role=1). The founder-slot invariant in
        // `IdentityManager::add_member` rejects role=0 on a different
        // logical_pk once the founder is set, so we cannot tag every
        // peer as role=0 — only the first one.
        for (i, pk) in all_pks.iter().enumerate() {
            let role: u8 = if i == 0 { 0 } else { 1 };
            node_lock
                .engine
                .identity_manager
                .add_member(conv_id, pk.to_logical(), role, now_ms);
        }
    }

    node_b
        .bridge
        .node
        .lock()
        .await
        .engine
        .start_sync(conv_id, None, &node_b.store);

    let content = Content::Text("Hello persistence!".to_string());
    let effects = {
        let mut node_lock = node_a.bridge.node.lock().await;
        node_lock
            .engine
            .author_node(conv_id, content, vec![], &node_a.store)
            .unwrap()
    };

    let node = effects
        .iter()
        .find_map(|e| {
            if let merkle_tox_core::engine::Effect::WriteStore(_, n, _) = e {
                Some(n.clone())
            } else {
                None
            }
        })
        .unwrap();
    let node_hash = node.hash();

    {
        let mut node_lock = node_a.bridge.node.lock().await;
        let now = node_lock.time_provider.now_instant();
        let now_ms = node_lock.time_provider.now_system_ms() as u64;
        let mut dummy_wakeup = now;
        for effect in effects {
            node_lock
                .process_effect(effect, now, now_ms, &mut dummy_wakeup)
                .unwrap();
        }
    }

    let local_pk_b = node_b.bridge.node.lock().await.transport.local_pk();
    node_a.bridge.start_sync(local_pk_b, conv_id).await.unwrap();

    println!("Syncing Node A -> VaultBot...");
    let sync_start = Instant::now();
    while !node_b.store.has_node(&node_hash) {
        node_a.iterate().await;
        node_b.iterate().await;
        node_c.iterate().await;

        tokio::time::sleep(Duration::from_millis(50)).await;
        if sync_start.elapsed() > Duration::from_secs(20) {
            panic!("Timed out waiting for sync A -> B");
        }
    }
    println!("VaultBot received the node");

    let local_pk_b = node_b.bridge.node.lock().await.transport.local_pk();
    node_c.bridge.start_sync(local_pk_b, conv_id).await.unwrap();

    println!("Syncing VaultBot -> Node C...");
    let sync_start_c = Instant::now();
    while !node_c.store.has_node(&node_hash) {
        node_b.iterate().await;
        node_c.iterate().await;
        tokio::time::sleep(Duration::from_millis(50)).await;
        if sync_start_c.elapsed() > Duration::from_secs(20) {
            panic!("Timed out waiting for sync B -> C");
        }
    }

    let received_node = node_c
        .store
        .get_node(&node_hash)
        .expect("Node C should have the node");
    assert_eq!(
        received_node.author_pk,
        node_a.bridge.node.lock().await.engine.self_pk.to_logical()
    );
    println!("Multi-node sync test passed!");
}

/// Sets up two Tox nodes, connects them, establishes a shared conversation
/// with sync sessions, and returns them ready for blob transfer.
async fn setup_blob_transfer_pair() -> (TestNode, TestNode, ConversationId) {
    let mut node_a = TestNode::new("Alice");
    let mut node_b = TestNode::new("Bob");

    // Connect A and B as Tox friends
    let addr_b = node_b.bridge.node.lock().await.transport.tox.lock().address();
    let f_ab_num = node_a
        .bridge
        .node
        .lock()
        .await
        .transport
        .tox
        .lock()
        .friend_add(&addr_b, b"Hello")
        .unwrap()
        .get_number();

    let start = Instant::now();
    loop {
        node_a.iterate().await;
        node_b.iterate().await;

        let connected = node_a
            .bridge
            .node
            .lock()
            .await
            .transport
            .tox
            .lock()
            .friend(f_ab_num)
            .connection_status()
            .unwrap();

        if connected != ToxConnection::TOX_CONNECTION_NONE {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
        if start.elapsed() > Duration::from_secs(30) {
            panic!("Timed out waiting for connection");
        }
    }
    println!("Connected in {:?}", start.elapsed());

    // Set up shared conversation
    let conv_id = ConversationId::from([2u8; 32]);
    let k_conv = KConv::from([0xBBu8; 32]);
    let pk_a = node_a.bridge.node.lock().await.engine.self_pk;
    let pk_b = node_b.bridge.node.lock().await.engine.self_pk;

    for n in [&mut node_a, &mut node_b] {
        n.store
            .put_conversation_key(&conv_id, 0, k_conv.clone())
            .unwrap();
        let mut node_lock = n.bridge.node.lock().await;
        let now_ms = node_lock.engine.clock.network_time_ms();
        node_lock.engine.conversations.insert(
            conv_id,
            merkle_tox_core::engine::Conversation::Established(
                merkle_tox_core::engine::ConversationData::<
                    merkle_tox_core::engine::conversation::Established,
                >::new(conv_id, k_conv.clone(), now_ms),
            ),
        );
        // pk_a is the test's stand-in founder (role=0); pk_b is a
        // regular member (role=1). See note in `test_multi_node_sync`
        // about the founder-slot invariant.
        for (i, pk) in [pk_a, pk_b].iter().enumerate() {
            let role: u8 = if i == 0 { 0 } else { 1 };
            node_lock
                .engine
                .identity_manager
                .add_member(conv_id, pk.to_logical(), role, now_ms);
        }
    }

    // Start sync sessions
    let local_pk_b = node_b.bridge.node.lock().await.transport.local_pk();
    node_a.bridge.start_sync(local_pk_b, conv_id).await.unwrap();
    let local_pk_a = node_a.bridge.node.lock().await.transport.local_pk();
    node_b.bridge.start_sync(local_pk_a, conv_id).await.unwrap();

    // Let sync settle
    for _ in 0..20 {
        node_a.iterate().await;
        node_b.iterate().await;
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    (node_a, node_b, conv_id)
}

/// Runs a blob transfer of `size_mb` MB between two connected nodes.
/// Returns (transfer_time, throughput_mbps).
async fn run_blob_transfer(
    node_a: &mut TestNode,
    node_b: &mut TestNode,
    conv_id: ConversationId,
    size_bytes: u64,
    timeout: Duration,
) -> (Duration, f64) {
    let blob_data: Vec<u8> = (0..size_bytes as usize).map(|i| (i % 251) as u8).collect();
    // The blob's identity is the root of its 64KB-chunk Merkle tree
    // (see doc/merkle-tox-cas.md §3). Must match what the receiver
    // checks proofs against and what goes into Content::Blob.
    let chunk_slices: Vec<&[u8]> = blob_data
        .chunks(CHUNK_SIZE as usize)
        .collect();
    let blob_hash = NodeHash::from(
        merkle_tox_core::cas::ChunkMerkleTree::from_chunks(
            chunk_slices.iter().copied(),
        )
        .root(),
    );

    let info = BlobInfo {
        hash: blob_hash,
        size: size_bytes,
        status: BlobStatus::Available,
        received_mask: None,
        decryption_key: None,
    };
    node_a.store.put_blob_info(info).unwrap();

    let num_chunks = size_bytes.div_ceil(CHUNK_SIZE);
    for i in 0..num_chunks {
        let chunk_start = (i * CHUNK_SIZE) as usize;
        let chunk_end = ((i + 1) * CHUNK_SIZE).min(size_bytes) as usize;
        node_a
            .store
            .put_chunk(
                &conv_id,
                &blob_hash,
                i * CHUNK_SIZE,
                &blob_data[chunk_start..chunk_end],
                None,
            )
            .unwrap();
    }

    // Author the blob content node
    let effects = {
        let mut lock = node_a.bridge.node.lock().await;
        lock.engine
            .author_node(
                conv_id,
                Content::Blob {
                    hash: blob_hash,
                    name: format!("test_{}mb.bin", size_bytes / (1024 * 1024)),
                    mime_type: "application/octet-stream".into(),
                    size: size_bytes,
                    metadata: tox_proto::BoundedBytes::new(),
                },
                vec![],
                &node_a.store,
            )
            .unwrap()
    };

    {
        let mut lock = node_a.bridge.node.lock().await;
        let now = lock.time_provider.now_instant();
        let now_ms = lock.time_provider.now_system_ms() as u64;
        let mut wakeup = now;
        for effect in effects {
            lock.process_effect(effect, now, now_ms, &mut wakeup)
                .unwrap();
        }
    }

    let transfer_start = Instant::now();
    let mut completed = false;
    let mut last_progress_print = Instant::now();
    let mut prev_alice_tx_ok: u64 = 0;
    let mut prev_bob_bd_received: u64 = 0;
    let mut prev_flush_calls: u64 = 0;
    let mut prev_flush_pkts: u64 = 0;
    let mut prev_break_cwnd: u64 = 0;
    let mut prev_break_app: u64 = 0;
    let mut prev_break_rej: u64 = 0;
    // Wall-clock instrumentation: how much time per loop iteration is spent
    // in each phase. Verifies whether the iteration cadence is bounded by
    // tokio sleep, by iterate() work, or by something else entirely.
    let mut total_alice_iter = Duration::ZERO;
    let mut total_bob_iter = Duration::ZERO;
    let mut total_sleep = Duration::ZERO;
    let mut total_loop = Duration::ZERO;
    let mut loop_count: u64 = 0;

    loop {
        let loop_start = Instant::now();
        let alice_iter_start = Instant::now();
        let alice_wakeup = node_a.iterate().await;
        total_alice_iter += alice_iter_start.elapsed();
        let bob_iter_start = Instant::now();
        let bob_wakeup = node_b.iterate().await;
        total_bob_iter += bob_iter_start.elapsed();

        if node_b.store.has_blob(&blob_hash) {
            completed = true;
            break;
        }

        if last_progress_print.elapsed() >= Duration::from_secs(2) {
            let interval_s = last_progress_print.elapsed().as_secs_f64().max(0.001);
            let alice = node_a.bridge.transfer_stats().await;
            let bob = node_b.bridge.transfer_stats().await;
            let alice_tx_rate = (alice.transport.send_ok - prev_alice_tx_ok) as f64 / interval_s;
            let bob_bd_rate =
                (bob.engine.blob_data_received - prev_bob_bd_received) as f64 / interval_s;
            let mbps =
                bob_bd_rate * (merkle_tox_core::cas::MAX_PIECE_DATA as f64) * 8.0 / 1_000_000.0;
            tracing::info!(
                target: "merkle_tox_tox::e2e",
                t = transfer_start.elapsed().as_secs_f64(),
                bob_status = ?node_b.store.get_blob_info(&blob_hash).map(|i| i.status),
                push_streams = alice.push_streams,
                push_credits = alice.push_credits,
                push_offset = alice.push_offset,
                size_bytes,
                alice_tx_ok = alice.transport.send_ok,
                alice_tx_err = alice.transport.send_err,
                alice_tx_rate,
                bob_rx = bob.transport.recv_count,
                bob_tx_ok = bob.transport.send_ok,
                cwnd_bytes = alice.session_cwnd_bytes,
                in_flight_bytes = alice.session_in_flight_bytes,
                outq = alice.session_outgoing_count,
                pacing_mbps = alice.session_pacing_bytes_per_sec * 8.0 / 1_000_000.0,
                bob_msgs = bob.engine.messages_handled,
                bob_bd_received = bob.engine.blob_data_received,
                bob_bd_stored = bob.engine.blob_data_stored,
                bob_bd_rate,
                throughput_mbps = mbps,
                "blob transfer progress",
            );
            // Per-interval flush_diag deltas: how flush() exited and how
            // many packets it actually emitted on average per call.
            let fd = alice.session_flush_diag;
            let dcalls = fd.calls.saturating_sub(prev_flush_calls);
            let dpkts = fd.pkts_sent.saturating_sub(prev_flush_pkts);
            let dcwnd = fd.break_cwnd.saturating_sub(prev_break_cwnd);
            let dapp = fd.break_app_limited.saturating_sub(prev_break_app);
            let drej = fd.break_sender_rejected.saturating_sub(prev_break_rej);
            let pkts_per_call = if dcalls > 0 {
                dpkts as f64 / dcalls as f64
            } else {
                0.0
            };

            // Also keep the print so the e2e diagnostic is visible without
            // needing RUST_LOG=info; tests historically grep for E2E_PROGRESS.
            println!(
                "E2E_PROGRESS t={:.1}s push_credits={} offset={}/{} \
                 alice_tx_ok={} (Δ={:.0}/s) cwnd={}B in_flight={}B outq={} \
                 pacing={:.2}Mbps flush_calls={} pkts/call={:.1} \
                 break(cwnd/app/rej)={}/{}/{} \
                 acks_recv={} losses={} bytes_sent={} bytes_acked={} \
                 unresolved={} ack_age={}ms rto={}ms \
                 bob_msgs={} bob_bd_recv={} (Δ={:.0}/s ≈{:.2}Mbps) bob_bd_stored={}",
                transfer_start.elapsed().as_secs_f64(),
                alice.push_credits,
                alice.push_offset,
                size_bytes,
                alice.transport.send_ok,
                alice_tx_rate,
                alice.session_cwnd_bytes,
                alice.session_in_flight_bytes,
                alice.session_outgoing_count,
                alice.session_pacing_bytes_per_sec * 8.0 / 1_000_000.0,
                dcalls,
                pkts_per_call,
                dcwnd,
                dapp,
                drej,
                alice.session_acks_received,
                alice.session_losses_emitted,
                alice.session_bytes_sent,
                alice.session_bytes_acked,
                alice.session_unresolved_sent,
                alice.session_last_ack_age_ms,
                alice.session_rto_ms,
                bob.engine.messages_handled,
                bob.engine.blob_data_received,
                bob_bd_rate,
                mbps,
                bob.engine.blob_data_stored,
            );
            // Receiver-side state: is bob's session emitting acks?
            // ack_pending=true with last_ack_sent_age climbing means the
            // ack gate is broken (hypothesis 2). send_ok rate dropping to
            // ~0 with flush_calls also flat means bob isn't running flush
            // at all (hypothesis 1). send_ok keeps growing but alice's
            // recv_count doesn't keep up means transport drops (hyp. 3).
            let bfd = bob.session_flush_diag;
            println!(
                "BOB_PROGRESS t={:.1}s conn={:?} tx_ok={} tx_err={} \
                 (sendq={} not_conn={} other={}) rx={} \
                 outq={} in_flight={}B bytes_sent={} \
                 ack_pending={} last_ack_sent_age={}ms recv_bytes={} \
                 acks_recv={} flush_calls={} flush_pkts={} \
                 break(cwnd/app/rej)={}/{}/{}",
                transfer_start.elapsed().as_secs_f64(),
                bob.peer_connection,
                bob.transport.send_ok,
                bob.transport.send_err,
                bob.transport.send_err_sendq,
                bob.transport.send_err_not_connected,
                bob.transport.send_err_other,
                bob.transport.recv_count,
                bob.session_outgoing_count,
                bob.session_in_flight_bytes,
                bob.session_bytes_sent,
                bob.session_ack_pending,
                bob.session_last_ack_sent_age_ms,
                bob.session_recv_bytes,
                bob.session_acks_received,
                bfd.calls,
                bfd.pkts_sent,
                bfd.break_cwnd,
                bfd.break_app_limited,
                bfd.break_sender_rejected,
            );
            prev_alice_tx_ok = alice.transport.send_ok;
            prev_bob_bd_received = bob.engine.blob_data_received;
            prev_flush_calls = fd.calls;
            prev_flush_pkts = fd.pkts_sent;
            prev_break_cwnd = fd.break_cwnd;
            prev_break_app = fd.break_app_limited;
            prev_break_rej = fd.break_sender_rejected;
            last_progress_print = Instant::now();
        }

        // Sleep until the earlier of the two bridges' next-wakeup
        // requests, bounded between 1 ms (don't spin) and 50 ms (stay
        // responsive for completion checks and progress prints). This
        // is the production-shaped pattern: the bridge tells the host
        // when it next has work, and the host honors it.
        let sleep_start = Instant::now();
        let now = Instant::now();
        let target = alice_wakeup
            .min(bob_wakeup)
            .max(now + Duration::from_millis(1))
            .min(now + Duration::from_millis(50));
        tokio::time::sleep_until(tokio::time::Instant::from_std(target)).await;
        total_sleep += sleep_start.elapsed();
        total_loop += loop_start.elapsed();
        loop_count += 1;

        if transfer_start.elapsed() > timeout {
            break;
        }
    }

    // One-shot timing summary so we can see whether iterate() is the
    // bottleneck or whether the iteration cadence is healthy.
    if loop_count > 0 {
        use std::sync::atomic::Ordering;
        let n = loop_count as f64;
        println!(
            "E2E_TIMING loops={} avg_loop={:.2}ms (alice_iter={:.2}ms bob_iter={:.2}ms sleep={:.2}ms) loops/sec={:.1}",
            loop_count,
            total_loop.as_secs_f64() * 1000.0 / n,
            total_alice_iter.as_secs_f64() * 1000.0 / n,
            total_bob_iter.as_secs_f64() * 1000.0 / n,
            total_sleep.as_secs_f64() * 1000.0 / n,
            n / transfer_start.elapsed().as_secs_f64(),
        );

        // Per-layer breakdown: where in the wall-clock loop is time
        // actually being spent. Helps identify whether the gap from sim
        // is in the FFI/syscall path, lock contention, or our own code.
        let alice_xport = node_a.bridge.transfer_stats().await.transport;
        let bob_xport = node_b.bridge.transfer_stats().await.transport;
        let elapsed_total_ms = transfer_start.elapsed().as_secs_f64() * 1000.0;
        let pct = |ns: u64| ns as f64 / 1_000_000.0 / elapsed_total_ms * 100.0;
        let ms = |ns: u64| ns as f64 / 1_000_000.0;

        // poll_engine / push / flush split inside iter_poll, read from
        // MerkleToxNode's atomic counters via the bridge.
        let alice_poll = {
            let n = node_a.bridge.node.lock().await;
            (
                n.poll_engine_ns.load(Ordering::Relaxed),
                n.poll_push_ns.load(Ordering::Relaxed),
                n.poll_flush_ns.load(Ordering::Relaxed),
            )
        };
        let bob_poll = {
            let n = node_b.bridge.node.lock().await;
            (
                n.poll_engine_ns.load(Ordering::Relaxed),
                n.poll_push_ns.load(Ordering::Relaxed),
                n.poll_flush_ns.load(Ordering::Relaxed),
            )
        };
        println!(
            "E2E_LAYER_ALICE send_lock_wait={:.1}ms ({:.1}%) send_lookup={:.1}ms ({:.1}%) \
             send_ffi={:.1}ms ({:.1}%)  iter_node_lock={:.1}ms ({:.1}%) \
             iter_tox_lock={:.1}ms ({:.1}%) iter_events_ffi={:.1}ms ({:.1}%) \
             iter_dispatch={:.1}ms ({:.1}%) iter_poll={:.1}ms ({:.1}%) \
             [poll_engine={:.1}ms ({:.1}%) poll_push={:.1}ms ({:.1}%) poll_flush={:.1}ms ({:.1}%)]",
            ms(alice_xport.send_lock_wait_ns), pct(alice_xport.send_lock_wait_ns),
            ms(alice_xport.send_lookup_ns), pct(alice_xport.send_lookup_ns),
            ms(alice_xport.send_ffi_ns), pct(alice_xport.send_ffi_ns),
            ms(node_a.iter_node_lock_ns.load(Ordering::Relaxed)),
            pct(node_a.iter_node_lock_ns.load(Ordering::Relaxed)),
            ms(node_a.iter_tox_lock_ns.load(Ordering::Relaxed)),
            pct(node_a.iter_tox_lock_ns.load(Ordering::Relaxed)),
            ms(node_a.iter_events_ffi_ns.load(Ordering::Relaxed)),
            pct(node_a.iter_events_ffi_ns.load(Ordering::Relaxed)),
            ms(node_a.iter_event_dispatch_ns.load(Ordering::Relaxed)),
            pct(node_a.iter_event_dispatch_ns.load(Ordering::Relaxed)),
            ms(node_a.iter_poll_ns.load(Ordering::Relaxed)),
            pct(node_a.iter_poll_ns.load(Ordering::Relaxed)),
            ms(alice_poll.0), pct(alice_poll.0),
            ms(alice_poll.1), pct(alice_poll.1),
            ms(alice_poll.2), pct(alice_poll.2),
        );
        println!(
            "E2E_LAYER_BOB   send_lock_wait={:.1}ms ({:.1}%) send_lookup={:.1}ms ({:.1}%) \
             send_ffi={:.1}ms ({:.1}%)  iter_node_lock={:.1}ms ({:.1}%) \
             iter_tox_lock={:.1}ms ({:.1}%) iter_events_ffi={:.1}ms ({:.1}%) \
             iter_dispatch={:.1}ms ({:.1}%) iter_poll={:.1}ms ({:.1}%) \
             [poll_engine={:.1}ms ({:.1}%) poll_push={:.1}ms ({:.1}%) poll_flush={:.1}ms ({:.1}%)]",
            ms(bob_xport.send_lock_wait_ns), pct(bob_xport.send_lock_wait_ns),
            ms(bob_xport.send_lookup_ns), pct(bob_xport.send_lookup_ns),
            ms(bob_xport.send_ffi_ns), pct(bob_xport.send_ffi_ns),
            ms(node_b.iter_node_lock_ns.load(Ordering::Relaxed)),
            pct(node_b.iter_node_lock_ns.load(Ordering::Relaxed)),
            ms(node_b.iter_tox_lock_ns.load(Ordering::Relaxed)),
            pct(node_b.iter_tox_lock_ns.load(Ordering::Relaxed)),
            ms(node_b.iter_events_ffi_ns.load(Ordering::Relaxed)),
            pct(node_b.iter_events_ffi_ns.load(Ordering::Relaxed)),
            ms(node_b.iter_event_dispatch_ns.load(Ordering::Relaxed)),
            pct(node_b.iter_event_dispatch_ns.load(Ordering::Relaxed)),
            ms(node_b.iter_poll_ns.load(Ordering::Relaxed)),
            pct(node_b.iter_poll_ns.load(Ordering::Relaxed)),
            ms(bob_poll.0), pct(bob_poll.0),
            ms(bob_poll.1), pct(bob_poll.1),
            ms(bob_poll.2), pct(bob_poll.2),
        );
    }

    let transfer_time = transfer_start.elapsed();
    let size_mb = size_bytes as f64 / (1024.0 * 1024.0);

    if !completed {
        let bob_info = node_b.store.get_blob_info(&blob_hash);
        println!(
            "E2E_RESULT size_mb={} elapsed_s={:.3} mbps=0 status=TIMEOUT bob_info={:?}",
            size_mb,
            transfer_time.as_secs_f64(),
            bob_info.map(|i| format!("{:?}", i.status)),
        );
        return (transfer_time, 0.0);
    }

    let throughput_mbps = (size_mb * 8.0) / transfer_time.as_secs_f64();
    println!(
        "E2E_RESULT size_mb={} elapsed_s={:.3} mbps={:.3} status=OK",
        size_mb, transfer_time.as_secs_f64(), throughput_mbps,
    );

    // Verify a sample of chunks
    let check_chunks = [0, num_chunks / 2, num_chunks - 1];
    for &i in &check_chunks {
        let chunk = node_b
            .store
            .get_chunk(&blob_hash, i * CHUNK_SIZE, CHUNK_SIZE as u32)
            .unwrap();
        let expected_start = (i * CHUNK_SIZE) as usize;
        let expected_end = ((i + 1) * CHUNK_SIZE).min(size_bytes) as usize;
        assert_eq!(
            chunk,
            blob_data[expected_start..expected_end],
            "Chunk {} data mismatch",
            i
        );
    }

    (transfer_time, throughput_mbps)
}

/// End-to-end 1 MB blob transfer over real Tox transport.
/// Marked `#[ignore]` so it doesn't run in the default test suite —
/// invoke explicitly with `--test_arg=--ignored` to measure throughput.
/// This is a measurement, not a pass/fail check.
#[tokio::test]
#[ignore = "Slow real-Tox measurement; run via ab_compare.py for benchmarking"]
async fn test_blob_transfer_1mb() {
    init_tracing();
    let (mut node_a, mut node_b, conv_id) = setup_blob_transfer_pair().await;
    let blob_size = 1024 * 1024u64;
    let (elapsed, throughput) = run_blob_transfer(
        &mut node_a,
        &mut node_b,
        conv_id,
        blob_size,
        Duration::from_secs(60),
    )
    .await;

    println!("E2E 1 MB: {:.1}s, {:.1} Mbps", elapsed.as_secs_f64(), throughput);
}

/// End-to-end 10 MB blob transfer — measures sustained throughput
/// once DAG sync and blob discovery overhead is amortized.
/// See test_blob_transfer_1mb for invocation notes.
#[tokio::test]
#[ignore = "Slow real-Tox measurement; run via ab_compare.py for benchmarking"]
async fn test_blob_transfer_10mb() {
    init_tracing();
    let (mut node_a, mut node_b, conv_id) = setup_blob_transfer_pair().await;
    let blob_size = 10 * 1024 * 1024u64;

    let (elapsed, throughput) = run_blob_transfer(
        &mut node_a,
        &mut node_b,
        conv_id,
        blob_size,
        Duration::from_secs(120),
    )
    .await;

    println!("E2E 10 MB: {:.1}s, {:.1} Mbps", elapsed.as_secs_f64(), throughput);
}

/// End-to-end 100 MB blob transfer — long enough to clear slow-start
/// and observe steady-state behavior across many progress samples.
/// See test_blob_transfer_1mb for invocation notes.
#[tokio::test]
#[ignore = "Slow real-Tox measurement; run via ab_compare.py for benchmarking"]
async fn test_blob_transfer_100mb() {
    init_tracing();
    let (mut node_a, mut node_b, conv_id) = setup_blob_transfer_pair().await;
    let blob_size = 100 * 1024 * 1024u64;

    let (elapsed, throughput) = run_blob_transfer(
        &mut node_a,
        &mut node_b,
        conv_id,
        blob_size,
        Duration::from_secs(120),
    )
    .await;

    println!("E2E 100 MB: {:.1}s, {:.1} Mbps", elapsed.as_secs_f64(), throughput);
}
