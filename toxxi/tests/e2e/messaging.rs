use std::time::Duration;
use toxxi::model::MessageContent;
use toxxi::tester::TestHarness;
use toxxi::tlog;

pub async fn run(h: &mut TestHarness) {
    tlog!(h, "Scenario 1: Messaging...");

    let bob_id = h.clients[1].tox_id;

    let alice_to_bob = h.clients[0]
        .find_friend(bob_id)
        .expect("Alice doesn't know Bob");
    h.clients[0]
        .cmd(&format!("/msg {} Hello Bob!", alice_to_bob.0))
        .await;

    h.wait_for(
        |clients| {
            clients[1].model.domain.conversations.values().any(|conv| {
                conv.messages
                    .iter()
                    .any(|m| m.content == MessageContent::Text("Hello Bob!".to_owned()))
            })
        },
        Duration::from_secs(5),
    )
    .await
    .expect("Bob failed to receive message");
    tlog!(h, "Scenario 1: Messaging passed.");
}
