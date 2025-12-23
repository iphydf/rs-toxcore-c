use super::setup::TestHarness;
use std::thread;
use std::time::{Duration, Instant};
use toxcore::tox::events::Event;
use toxcore::tox::*;

pub fn subtest_dht_nodes(harness: &mut TestHarness) {
    println!("Running subtest_dht_nodes...");

    if harness.toxes.len() < 2 {
        eprintln!("Skipping dht test, not enough nodes");
        return;
    }

    // Verify basic DHT functions
    let pk0 = harness.toxes[0].tox.dht_id();
    let port0 = harness.toxes[0].tox.udp_port().unwrap();
    println!("DHT ID: {:?}, UDP Port: {}", pk0, port0);

    // Node 1 bootstraps to Node 0 again
    harness.toxes[1]
        .tox
        .bootstrap("127.0.0.1", port0, &pk0)
        .expect("Bootstrap failed");

    let start = Instant::now();
    let mut received = false;

    // We manually drive the event loop for node 1 using the iterator
    while Instant::now().duration_since(start) < Duration::from_secs(5) {
        // Iterate node 0 using legacy handler (noop) just to process networking
        struct NoOpHandler;
        impl ToxHandler for NoOpHandler {}
        harness.toxes[0].tox.iterate(&mut NoOpHandler);

        // Iterate node 1 using events iterator
        let events = harness.toxes[1].tox.events().expect("Failed to get events");
        for event in &events {
            if let Event::DhtNodesResponse(_) = event {
                received = true;
            }
        }

        if received {
            break;
        }
        thread::sleep(Duration::from_millis(50));
    }

    assert!(received, "Did not receive DHT nodes response");
}
