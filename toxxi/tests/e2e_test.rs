use toxxi::tester::TestHarness;
use toxxi::tlog;

mod e2e;

#[tokio::test]
#[ignore = "Slow real-Tox 3-node end-to-end test; routinely exceeds the default \
            300s 'medium' Bazel timeout because of real friend-handshake delays \
            and the full message/group-chat exchange. Run explicitly via \
            --test_arg=--ignored with a generous --test_timeout."]
async fn test_toxxi_e2e_full_cycle() {
    // 1. Initialize Harness with 3 clients (Alice, Bob, Charlie)
    let mut h = TestHarness::new(3);

    // 2. Perform one-time bootstrap and friendship linking
    tlog!(h, "Linking all clients...");
    h.link_all().await;
    tlog!(h, "Network established.");

    // --- Scenario 1: Alice sends message to Bob ---
    e2e::messaging::run(&mut h).await;

    // --- Scenario: Group Chat Nickname ---
    e2e::group_chat::run(&mut h).await;

    // --- Scenario 2: Charlie sends file to Alice ---
    e2e::file_transfer::run(&mut h).await;

    // --- Scenario 3: Charlie sends a 10MB file to Alice ---
    e2e::large_file_transfer::run(&mut h).await;

    h.shutdown().await;
}

// end of tests
