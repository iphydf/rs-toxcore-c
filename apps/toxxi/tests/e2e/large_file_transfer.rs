use std::fs;
use std::time::Duration;
use toxxi_testing::tester::TestHarness;
use toxxi_testing::tlog;

pub async fn run(h: &mut TestHarness) {
    tlog!(h, "Scenario 3: 10MB File Transfer...");

    let alice_id = h.clients[0].tox_id;
    let _charlie_id = h.clients[2].tox_id;

    assert!(
        h.clients[0].has_friend(h.clients[2].tox_id),
        "Alice should have Charlie as friend"
    );

    let charlie_to_alice = toxxi::utils::short_key(&alice_id.public_key());

    let large_file_path = h.clients[2].temp_dir.path().join("large_e2e.bin");
    let large_file_size = 1024 * 1024;
    let mut large_file_content = vec![0u8; large_file_size];
    for (i, byte) in large_file_content.iter_mut().enumerate() {
        *byte = (i % 256) as u8;
    }
    fs::write(&large_file_path, &large_file_content).unwrap();

    h.clients[2]
        .cmd(&format!(
            "/file send {} {}",
            charlie_to_alice,
            large_file_path.to_str().unwrap()
        ))
        .await;

    h.wait_for(
        |clients| !clients[0].model.domain.file_transfers.is_empty(),
        Duration::from_secs(5),
    )
    .await
    .expect("Alice didn't see incoming large file");

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
    .expect("Large file transfer timed out");

    let received_large_path = h.clients[0]
        .temp_dir
        .path()
        .join("downloads")
        .join("large_e2e.bin");
    assert!(received_large_path.exists());
    let received_large_content = fs::read(&received_large_path).unwrap();
    assert_eq!(received_large_content, large_file_content);

    fs::remove_file(received_large_path).unwrap();
    tlog!(h, "Scenario 3: 10MB File Transfer passed.");
}
