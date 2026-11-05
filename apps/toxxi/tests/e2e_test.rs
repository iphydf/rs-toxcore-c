use toxxi_testing::tester::TestHarness;
use toxxi_testing::tlog;

mod e2e;

#[tokio::test]
#[ignore = "Slow real-Tox 3-node end-to-end test; routinely exceeds the default \
            300s 'medium' Bazel timeout because of real friend-handshake delays \
            and the full message/group-chat exchange. Run explicitly via \
            --test_arg=--ignored with a generous --test_timeout."]
async fn test_toxxi_e2e_full_cycle() {
    let mut h = TestHarness::new(3);

    tlog!(h, "Linking all clients...");
    h.link_all().await;
    tlog!(h, "Network established.");

    // Alice sends Bob a message.
    e2e::messaging::run(&mut h).await;

    // Group chat nicknames.
    e2e::group_chat::run(&mut h).await;

    // Charlie sends Alice a file.
    e2e::file_transfer::run(&mut h).await;

    // Charlie sends Alice a 10 MB file.
    e2e::large_file_transfer::run(&mut h).await;

    h.shutdown().await;
}
