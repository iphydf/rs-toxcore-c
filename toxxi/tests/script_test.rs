use std::fs::File;
use std::io::Write;
use std::sync::mpsc;
use tempfile::tempdir;
use toxxi::msg::{Msg, SystemEvent};
use toxxi::script::{ScriptRequest, ScriptResponse, spawn_script};

#[test]
fn test_script_execution_flow() {
    let dir = tempdir().unwrap();
    let script_path = dir.path().join("test.rhai");
    let mut file = File::create(&script_path).unwrap();

    // Write a simple script
    writeln!(
        file,
        r#"
        cmd("/nick ScriptBot");
        sleep(50);
        cmd("/status Ready");
    "#
    )
    .unwrap();

    let (tx_msg, rx_msg) = mpsc::channel();

    // Spawn script thread
    let (handle, tx_res) = spawn_script(script_path, tx_msg);

    // 1. Expect /nick ScriptBot
    let msg = rx_msg
        .recv_timeout(std::time::Duration::from_secs(5))
        .expect("Timeout waiting for 1st cmd");
    if let Msg::System(SystemEvent::ScriptRequest(ScriptRequest::Command(cmd))) = msg {
        assert_eq!(cmd, "/nick ScriptBot");
        // Resume script
        tx_res.send(ScriptResponse::Ok).unwrap();
    } else {
        panic!("Expected Command(/nick ...), got {:?}", msg);
    }

    // 2. Expect sleep(50)
    let msg = rx_msg
        .recv_timeout(std::time::Duration::from_secs(5))
        .expect("Timeout waiting for sleep");
    if let Msg::System(SystemEvent::ScriptRequest(ScriptRequest::Sleep(ms))) = msg {
        assert_eq!(ms, 50);
        tx_res.send(ScriptResponse::Ok).unwrap();
    } else {
        panic!("Expected Sleep(50), got {:?}", msg);
    }

    // 3. Expect /status Ready
    let msg = rx_msg
        .recv_timeout(std::time::Duration::from_secs(5))
        .expect("Timeout waiting for 2nd cmd");
    if let Msg::System(SystemEvent::ScriptRequest(ScriptRequest::Command(cmd))) = msg {
        assert_eq!(cmd, "/status Ready");
        tx_res.send(ScriptResponse::Ok).unwrap();
    } else {
        panic!("Expected Command(/status ...), got {:?}", msg);
    }

    // Script should finish
    handle.join().unwrap().expect("Script execution failed");
}
