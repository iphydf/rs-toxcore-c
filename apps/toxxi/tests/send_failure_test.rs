use std::time::{Duration, Instant};
use toxcore::types::PublicKey;
use toxxi::model::{MessageStatus, WindowId};
use toxxi_testing::tester::{TestClient, find_free_ports};

/// A chat that's open after its friend went, as when a device deleted them.
#[tokio::test]
async fn test_message_to_a_friend_who_is_gone_fails() {
    let ports = find_free_ports(1);
    let mut client = TestClient::new(0, ports[0], Instant::now());
    let gone = WindowId::Friend(PublicKey([7u8; 32]));
    client.model.ensure_window(gone);
    client.set_active_window_by_id(gone);

    client.cmd("hello").await;
    let status = |client: &TestClient| {
        client.model.domain.conversations[&gone]
            .messages
            .last()
            .map(|msg| msg.status)
    };
    let start = Instant::now();
    while status(&client) != Some(MessageStatus::Failed) && start.elapsed() < Duration::from_secs(5)
    {
        client.step().await;
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(status(&client), Some(MessageStatus::Failed));
}
