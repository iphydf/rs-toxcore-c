use std::thread;
use std::time::{Duration, Instant};
use toxcore::tox::*;
use toxcore::toxav::*;

struct TestLogger;
impl ToxLogger for TestLogger {
    fn log(&mut self, _level: ToxLogLevel, _file: &str, _line: u32, _func: &str, _message: &str) {}
}

#[test]
fn panic_in_callback_aborts() {
    // This test is expected to crash the test runner or the specific test process.
    // Rust tests capture stdout/stderr, but an abort might bypass that or just show failure.

    let mut opts = Options::new().unwrap();
    opts.set_ipv6_enabled(false);
    opts.set_udp_enabled(true);
    opts.set_local_discovery_enabled(false);
    opts.set_start_port(53445);
    opts.set_end_port(53449);
    opts.set_logger(TestLogger);
    let tox = Tox::new(opts).unwrap();
    // Setup: Simulate a call to trigger a callback
    struct PanicHandler;
    impl ToxAVHandler for PanicHandler {
        fn on_call(&mut self, _: FriendNumber, _: bool, _: bool) {
            println!("Panicking in callback...");
            panic!("Oops, I panicked inside FFI!");
        }
    }

    let mut av = ToxAV::new(&tox, PanicHandler).unwrap();

    // We need to trigger on_call.
    // We can simulate it by connecting another instance?
    // Or we can just call the trampoline manually if it was exposed? It is not.
    // We must drive it via C-api.

    // Setup another peer to call us.
    let mut opts2 = Options::new().unwrap();
    opts2.set_ipv6_enabled(false);
    opts2.set_udp_enabled(true);
    opts2.set_local_discovery_enabled(false);
    opts2.set_start_port(53450);
    opts2.set_end_port(53454);
    let tox2 = Tox::new(opts2).unwrap();

    struct NoOpAvHandler;
    impl ToxAVHandler for NoOpAvHandler {}

    let mut av2 = ToxAV::new(&tox2, NoOpAvHandler).unwrap();

    // Connect
    let pk = tox.public_key();
    let pk2 = tox2.public_key();
    tox.friend_add_norequest(&pk2).unwrap();
    tox2.friend_add_norequest(&pk).unwrap();

    let port = tox.udp_port().unwrap();
    let dht = tox.dht_id();
    tox2.bootstrap("127.0.0.1", port, &dht).unwrap();

    // Wait for connection
    let start = Instant::now();
    let mut connected = false;
    while start.elapsed() < Duration::from_secs(30) {
        struct NullHandler;
        impl ToxHandler for NullHandler {}
        let mut h = NullHandler;
        tox.iterate(&mut h);
        tox2.iterate(&mut h);

        if let Ok(f) = tox2.lookup_friend(&pk)
            && let Ok(status) = f.connection_status()
            && status != ToxConnection::TOX_CONNECTION_NONE
        {
            connected = true;
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }
    assert!(connected, "Failed to connect for panic test");

    // Call
    let f2 = tox2.lookup_friend(&pk).unwrap();
    av2.call(f2.get_number(), 48, 0).unwrap();

    // Loop to receive call and trigger panic
    println!("Waiting for call to trigger panic...");
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(5) {
        struct NullHandler;
        impl ToxHandler for NullHandler {}
        let mut h = NullHandler;
        tox.iterate(&mut h);
        tox2.iterate(&mut h);
        av.iterate();
        av2.iterate();
        thread::sleep(Duration::from_millis(10));
    }
}
