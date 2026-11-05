use std::fs;
use std::time::Duration;
use toxxi_testing::tester::TestHarness;
use toxxi_testing::tlog;

pub async fn run(h: &mut TestHarness) {
    tlog!(h, "Scenario 2: File Transfer...");

    let alice_id = h.clients[0].tox_id;
    let charlie_id = h.clients[2].tox_id;

    let file_content = "End-to-End Test Data";
    let file_path = h.clients[2].temp_dir.path().join("e2e.txt");
    fs::write(&file_path, file_content).unwrap();

    let charlie_to_alice = toxxi::utils::short_key(&alice_id.public_key());
    h.clients[2]
        .cmd(&format!(
            "/file send {} {}",
            charlie_to_alice,
            file_path.to_str().unwrap()
        ))
        .await;

    h.wait_for(
        |clients| !clients[0].model.domain.file_transfers.is_empty(),
        Duration::from_secs(5),
    )
    .await
    .expect("Alice didn't see incoming file");

    // Charlie is Alice's friend 1.
    assert!(
        h.clients[0].has_friend(charlie_id),
        "Alice doesn't know Charlie"
    );

    let (file_id, pk) = {
        let (fid, progress) = h.clients[0]
            .model
            .domain
            .file_transfers
            .iter()
            .next()
            .unwrap();
        (*fid, progress.friend_pk)
    };

    let friend = toxxi::utils::short_key(&pk);

    h.clients[0]
        .cmd(&format!("/file accept {} {}", friend, file_id))
        .await;

    h.wait_for(
        |clients| {
            clients[0].model.domain.file_transfers.is_empty()
                && clients[2].model.domain.file_transfers.is_empty()
        },
        Duration::from_secs(30),
    )
    .await
    .expect("File transfer timed out");

    let received_path = h.clients[0]
        .temp_dir
        .path()
        .join("downloads")
        .join("e2e.txt");
    assert!(received_path.exists());
    let _ = fs::read_to_string(&received_path).unwrap();

    fs::remove_file(received_path).unwrap();
    tlog!(h, "Scenario 2: File Transfer passed.");
}
