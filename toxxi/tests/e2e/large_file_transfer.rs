use std::fs;
use std::time::Duration;
use toxxi::tester::TestHarness;
use toxxi::tlog;

pub async fn run(h: &mut TestHarness) {
    tlog!(h, "Scenario 3: 10MB File Transfer...");

    let alice_id = h.clients[0].tox_id;
    let _charlie_id = h.clients[2].tox_id;

    // Alice from charlie
    let _alice_from_charlie = h.clients[0]
        .find_friend(h.clients[2].tox_id)
        .expect("Alice should have Charlie as friend");

    // Charlie to alice
    let charlie_to_alice = h.clients[2]
        .find_friend(alice_id)
        .expect("Charlie doesn't know Alice");

    // Charlie creates a 10MB file
    let large_file_path = h.clients[2].temp_dir.path().join("large_e2e.bin");
    let large_file_size = 1024 * 1024;
    let mut large_file_content = vec![0u8; large_file_size];
    for (i, byte) in large_file_content.iter_mut().enumerate() {
        *byte = (i % 256) as u8;
    }
    fs::write(&large_file_path, &large_file_content).unwrap();

    // Charlie sends to Alice
    h.clients[2]
        .cmd(&format!(
            "/file send {} {}",
            charlie_to_alice.0,
            large_file_path.to_str().unwrap()
        ))
        .await;

    // Wait for Alice to see the incoming file
    h.wait_for(
        |clients| !clients[0].model.domain.file_transfers.is_empty(),
        Duration::from_secs(5),
    )
    .await
    .expect("Alice didn't see incoming large file");

    // Alice accepts
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
            clients[0].model.domain.file_transfers.is_empty()
                && clients[2].model.domain.file_transfers.is_empty()
        },
        Duration::from_secs(30),
    )
    .await
    .expect("Large file transfer timed out");

    // Verify file content
    let received_large_path = h.clients[0]
        .temp_dir
        .path()
        .join("downloads")
        .join("large_e2e.bin");
    assert!(received_large_path.exists());
    let received_large_content = fs::read(&received_large_path).unwrap();
    assert_eq!(received_large_content, large_file_content);

    // Cleanup
    fs::remove_file(received_large_path).unwrap();
    tlog!(h, "Scenario 3: 10MB File Transfer passed.");
}
