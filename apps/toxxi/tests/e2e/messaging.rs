use std::time::Duration;
use toxxi::model::MessageContent;
use toxxi_testing::tester::TestHarness;
use toxxi_testing::tlog;

pub async fn run(h: &mut TestHarness) {
    tlog!(h, "Scenario 1: Messaging...");

    let bob_id = h.clients[1].tox_id;

    let bob = toxxi::utils::short_key(&bob_id.public_key());
    h.clients[0].cmd(&format!("/msg {} Hello Bob!", bob)).await;

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
