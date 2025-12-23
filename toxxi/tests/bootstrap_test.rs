use std::fs::File;
use std::io::Write;
use tempfile::tempdir;
use toxxi::bootstrap::{Node, get_cached_nodes, select_random_nodes};

#[test]
fn test_select_random_nodes() {
    let nodes = vec![
        Node {
            ipv4: "1.1.1.1".to_string(),
            ipv6: "::1".to_string(),
            port: 33445,
            tcp_ports: None,
            public_key: "A".repeat(64),
            status_udp: true,
            status_tcp: true,
            maintainer: "m1".to_string(),
            location: "l1".to_string(),
        },
        Node {
            ipv4: "2.2.2.2".to_string(),
            ipv6: "::2".to_string(),
            port: 33445,
            tcp_ports: None,
            public_key: "B".repeat(64),
            status_udp: false, // UDP down
            status_tcp: true,
            maintainer: "m2".to_string(),
            location: "l2".to_string(),
        },
        Node {
            ipv4: "3.3.3.3".to_string(),
            ipv6: "::3".to_string(),
            port: 33445,
            tcp_ports: None,
            public_key: "C".repeat(64),
            status_udp: true,
            status_tcp: true,
            maintainer: "m3".to_string(),
            location: "l3".to_string(),
        },
    ];

    // Case 1: Request 1 node. Viable are [1, 3] (UDP & TCP). Should return 1 or 3.
    // Since we can't easily mock the RNG, we check that the selected node is valid.
    for _ in 0..10 {
        let selected = select_random_nodes(&nodes, 1);
        assert_eq!(selected.len(), 1);
        assert!(selected[0].status_udp && selected[0].status_tcp);
        assert!(selected[0].ipv4 == "1.1.1.1" || selected[0].ipv4 == "3.3.3.3");
    }

    // Case 2: Request 3 nodes. Only 2 are viable. Logic falls back to all nodes.
    // It should return all 3 (shuffled).
    let selected = select_random_nodes(&nodes, 3);
    assert_eq!(selected.len(), 3);
    let ips: Vec<_> = selected.iter().map(|n| &n.ipv4).collect();
    assert!(ips.contains(&&"1.1.1.1".to_string()));
    assert!(ips.contains(&&"2.2.2.2".to_string()));
    assert!(ips.contains(&&"3.3.3.3".to_string()));
}

#[test]
fn test_get_cached_nodes() {
    let dir = tempdir().unwrap();
    let config_dir = dir.path().to_path_buf();

    // 1. No file -> None
    assert!(get_cached_nodes(&config_dir).is_none());

    // 2. Invalid file -> None
    let nodes_path = config_dir.join("nodes.json");
    let mut f = File::create(&nodes_path).unwrap();
    write!(f, "invalid json").unwrap();
    assert!(get_cached_nodes(&config_dir).is_none());

    // 3. Valid file -> Some(nodes)
    let json = r#"[
        {
            "ipv4": "1.2.3.4",
            "ipv6": "::1",
            "port": 1234,
            "public_key": "DEADBEEF",
            "status_udp": true,
            "status_tcp": true,
            "maintainer": "Test",
            "location": "Test"
        }
    ]"#;
    let mut f = File::create(&nodes_path).unwrap();
    write!(f, "{}", json).unwrap();

    let nodes = get_cached_nodes(&config_dir).unwrap();
    assert_eq!(nodes.len(), 1);
    assert_eq!(nodes[0].ipv4, "1.2.3.4");
    assert_eq!(nodes[0].public_key, "DEADBEEF");
}
