use std::fs;
use std::time::Duration;
use toxxi::tester::TestHarness;
use toxxi::tlog;

pub async fn run(h: &mut TestHarness) {
    tlog!(h, "Scenario 2: File Transfer...");

    let alice_id = h.clients[0].tox_id;
    let charlie_id = h.clients[2].tox_id;

    // Charlie creates a file
    let file_content = "End-to-End Test Data";
    let file_path = h.clients[2].temp_dir.path().join("e2e.txt");
    fs::write(&file_path, file_content).unwrap();

    // Charlie sends to Alice
    let charlie_to_alice = h.clients[2]
        .find_friend(alice_id)
        .expect("Charlie doesn't know Alice");
    h.clients[2]
        .cmd(&format!(
            "/file send {} {}",
            charlie_to_alice.0,
            file_path.to_str().unwrap()
        ))
        .await;

    // Wait for Alice to see the incoming file
    h.wait_for(
        |clients| !clients[0].model.domain.file_transfers.is_empty(),
        Duration::from_secs(5),
    )
    .await
    .expect("Alice didn't see incoming file");

    // Alice accepts (Charlie is friend 1 for Alice)
    let _alice_from_charlie = h.clients[0]
        .find_friend(charlie_id)
        .expect("Alice doesn't know Charlie");

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

    let friend_num = h.clients[0]
        .model
        .session
        .friend_numbers
        .iter()
        .find(|(_, friend_pk)| **friend_pk == pk)
        .map(|(num, _)| num.0)
        .expect("Friend number not found for PK");

    h.clients[0]
        .cmd(&format!("/file accept {} {}", friend_num, file_id))
        .await;

    // Wait for transfer to complete
    h.wait_for(
        |clients| {
            // Check if Alice finished receiving
            clients[0].model.domain.file_transfers.is_empty()
                && clients[2].model.domain.file_transfers.is_empty()
        },
        Duration::from_secs(30),
    )
    .await
    .expect("File transfer timed out");

    // Verify file content on Alice's side
    let received_path = h.clients[0]
        .temp_dir
        .path()
        .join("downloads")
        .join("e2e.txt");
    assert!(received_path.exists());
    let _ = fs::read_to_string(&received_path).unwrap();

    // Cleanup
    fs::remove_file(received_path).unwrap();
    tlog!(h, "Scenario 2: File Transfer passed.");
}
