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
            b"Message After Quit".to_vec(),
        )))
        .unwrap();

    // Run Alice's step to process the messages
    client.step().await;

    // The I/O task keeps it in the event log, on disk, soon.
    let kept = || {
        toxxi::sync::store::read_log(&client.temp_dir.path().join(toxxi::sync::store::EVENTS_FILE))
            .expect("Failed to read the event log")
            .iter()
            .any(|record| matches!(
                toxxi::sync::event::Event::decode(record).map(|event| event.content),
                Ok(toxxi::sync::event::Content::Received { message, .. }) if message == b"Message After Quit"
            ))
    };
    let start = Instant::now();
    while !kept() && start.elapsed() < Duration::from_secs(5) {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(kept());
}
