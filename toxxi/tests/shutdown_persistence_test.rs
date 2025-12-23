use std::time::{Duration, Instant};
use toxcore::tox::FriendNumber;
use toxcore::types::MessageType;
use toxxi::msg::{Msg, ToxEvent};
use toxxi::tester::TestClient;

#[tokio::test]
async fn test_repro_persistence_loss() {
    let start_time = Instant::now();
    let ports = toxxi::tester::find_free_ports(1);
    let mut client = TestClient::new(0, ports[0], start_time);

    // Wait for client to initialize (get ID)
    let timeout = Duration::from_secs(5);
    let start = Instant::now();
    while client.tox_id.to_string()
        == "0000000000000000000000000000000000000000000000000000000000000000000000000000"
    {
        client.step().await;
        if start.elapsed() > timeout {
            panic!("Timeout waiting for client ID");
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    let friend_pk = toxcore::types::PublicKey([1u8; 32]);
    client
        .model
        .session
        .friend_numbers
        .insert(FriendNumber(1), friend_pk);
    client.model.ensure_friend_window(friend_pk);

    // Alice quits, then a message arrives (or they are in the same batch)
    client.cmd("/quit").await;

    client
        .tx_msg
        .send(Msg::Tox(ToxEvent::Message(
            FriendNumber(1),
            MessageType::TOX_MESSAGE_TYPE_NORMAL,
            "Message After Quit".to_string(),
        )))
        .unwrap();

    // Run Alice's step to process the messages
    client.step().await;

    // Wait a bit for the async I/O task to complete
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Check log file instead of state.json
    let logs_dir = client.temp_dir.path().join("logs");
    let log_path = logs_dir.join(format!(
        "friend_{}.jsonl",
        toxxi::utils::encode_hex(&friend_pk.0)
    ));

    assert!(log_path.exists(), "Log file should exist at {:?}", log_path);
    let content = std::fs::read_to_string(log_path).expect("Failed to read log file");
    assert!(content.contains("Message After Quit"));
}
