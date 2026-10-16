use std::time::Duration;

use toxxi::model::WindowId;
use toxxi::tester::{TestClient, TestHarness};

#[tokio::test]
async fn test_own_conference_title_shows() {
    let mut h = TestHarness::new(1);
    let conference = |client: &TestClient| {
        client
            .model
            .ui
            .window_ids
            .iter()
            .copied()
            .find(|id| matches!(id, WindowId::Conference(_)))
    };
    h.clients[0].cmd("/conference create").await;
    h.wait_for(|c| conference(&c[0]).is_some(), Duration::from_secs(5))
        .await
        .unwrap();
    let window = conference(&h.clients[0]).unwrap();

    h.clients[0].set_active_window_by_id(window);
    h.clients[0].cmd("/topic Tox (PGC)").await;
    h.wait_for(
        |c| c[0].model.domain.conversations[&window].name == "Tox (PGC)",
        Duration::from_secs(5),
    )
    .await
    .unwrap();
    h.shutdown().await;
}
