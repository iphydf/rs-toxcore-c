use std::time::{Duration, Instant};
use toxxi::worker::{InitialState, get_initial_state};
use toxxi_testing::tester::TestClient;

/// Whether the saved profile passes the check within 5 seconds, without a
/// /quit.
async fn saved(mut client: TestClient, check: impl Fn(&InitialState) -> bool) -> bool {
    let path = Some(client.temp_dir.path().join("savedata.tox"));
    let start = Instant::now();
    let mut saved = false;
    while !saved && start.elapsed() < Duration::from_secs(5) {
        client.step().await;
        tokio::time::sleep(Duration::from_millis(10)).await;
        saved = path.as_ref().unwrap().exists() && check(&get_initial_state(&path).unwrap());
    }
    saved
}

#[tokio::test]
async fn test_new_profile_is_saved_at_once() {
    let ports = toxxi_testing::tester::find_free_ports(1);
    let client = TestClient::new(0, ports[0], Instant::now());

    let address = client.model.domain.tox_id;
    assert!(saved(client, |profile| profile.tox_id == address).await);
}

#[tokio::test]
async fn test_new_name_is_saved_without_quitting() {
    let ports = toxxi_testing::tester::find_free_ports(1);
    let mut client = TestClient::new(0, ports[0], Instant::now());

    client.cmd("/nick Alice").await;
    assert!(saved(client, |profile| profile.name == "Alice").await);
}
