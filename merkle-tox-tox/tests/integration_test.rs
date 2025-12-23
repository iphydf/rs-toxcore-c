use merkle_tox_core::Transport;
use merkle_tox_core::dag::{Content, ConversationId, KConv};
use merkle_tox_core::sync::NodeStore;
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
        }
    }

    fn iterate(&mut self) {
        {
            let tox_mutex = self.bridge.node.transport.tox.clone();
            let tox = tox_mutex.lock();
            let bridge = &mut self.bridge;

            let Ok(events) = tox.events() else { return };

            for event in &events {
                if bridge.handle_event(&event) {
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
        }
        self.bridge.poll();
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

    let addr_b = node_b.bridge.node.transport.tox.lock().address();

    let f_ab_num = node_a
        .bridge
        .node
        .transport
        .tox
        .lock()
        .friend_add(&addr_b, b"Hello Vault")
        .unwrap()
        .get_number();

    let f_cb_num = node_c
        .bridge
        .node
        .transport
        .tox
        .lock()
        .friend_add(&addr_b, b"Hello Vault")
        .unwrap()
        .get_number();

    // Run iteration until connected
    let start = Instant::now();
    loop {
        node_a.iterate();
        node_b.iterate();
        node_c.iterate();

        let c_ab = node_a
            .bridge
            .node
            .transport
            .tox
            .lock()
            .friend(f_ab_num)
            .connection_status()
            .unwrap();
        let c_cb = node_c
            .bridge
            .node
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
        .transport
        .tox
        .lock()
        .friend(f_ab_num)
        .send_message(MessageType::TOX_MESSAGE_TYPE_NORMAL, b"Baseline Check")
        .unwrap();

    let start = Instant::now();
    while node_b.received_messages.is_empty() {
        node_a.iterate();
        node_b.iterate();
        tokio::time::sleep(Duration::from_millis(50)).await;
        if start.elapsed() > Duration::from_secs(10) {
            panic!("Timed out waiting for baseline message");
        }
    }
    assert_eq!(node_b.received_messages[0], "Baseline Check");
    println!("Baseline message received successfully");

    let conv_id = ConversationId::from([1u8; 32]);
    let k_conv = KConv::from([0xAAu8; 32]);

    for n in [&mut node_a, &mut node_b, &mut node_c] {
        n.store
            .put_conversation_key(&conv_id, 0, k_conv.clone())
            .unwrap();
        let now_ms = n.bridge.node.engine.clock.network_time_ms();
        n.bridge.node.engine.conversations.insert(
            conv_id,
            merkle_tox_core::engine::Conversation::Established(
                merkle_tox_core::engine::ConversationData::<
                    merkle_tox_core::engine::conversation::Established,
                >::new(conv_id, k_conv.clone(), now_ms),
            ),
        );
    }

    node_b
        .bridge
        .node
        .engine
        .start_sync(conv_id, None, &node_b.store);

    let content = Content::Text("Hello persistence!".to_string());
    let effects = node_a
        .bridge
        .node
        .engine
        .author_node(conv_id, content, vec![], &node_a.store)
        .unwrap();

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

    let now = node_a.bridge.node.time_provider.now_instant();
    let now_ms = node_a.bridge.node.time_provider.now_system_ms() as u64;
    let mut dummy_wakeup = now;
    for effect in effects {
        node_a
            .bridge
            .node
            .process_effect(effect, now, now_ms, &mut dummy_wakeup)
            .unwrap();
    }

    node_a
        .bridge
        .start_sync(node_b.bridge.node.transport.local_pk(), conv_id)
        .unwrap();

    println!("Syncing Node A -> VaultBot...");
    let sync_start = Instant::now();
    while !node_b.store.has_node(&node_hash) {
        node_a.iterate();
        node_b.iterate();
        node_c.iterate();

        tokio::time::sleep(Duration::from_millis(50)).await;
        if sync_start.elapsed() > Duration::from_secs(20) {
            panic!("Timed out waiting for sync A -> B");
        }
    }
    println!("VaultBot received the node");

    node_c
        .bridge
        .start_sync(node_b.bridge.node.transport.local_pk(), conv_id)
        .unwrap();

    println!("Syncing VaultBot -> Node C...");
    let sync_start_c = Instant::now();
    while !node_c.store.has_node(&node_hash) {
        node_b.iterate();
        node_c.iterate();
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
        node_a.bridge.node.transport.local_pk().to_logical()
    );

    println!("Multi-node sync test passed!");
}
