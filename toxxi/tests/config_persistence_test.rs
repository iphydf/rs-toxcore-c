use tempfile::tempdir;
use toxxi::config::{load_config, save_config};

#[test]
fn test_config_save_load_roundtrip() {
    let dir = tempdir().unwrap();
    let config_dir = dir.path().to_path_buf();

    // 1. Load non-existent -> Default
    let default_config = load_config(&config_dir);
    assert!(default_config.ipv6_enabled);

    // 2. Modify and Save
    let mut new_config = default_config.clone();
    new_config.ipv6_enabled = false;
    new_config.blocked_strings.push("badword".to_string());

    save_config(&config_dir, &new_config).unwrap();
    assert!(config_dir.join("config.json").exists());

    // 3. Load again -> Modified values should persist
    let loaded = load_config(&config_dir);
    assert!(!loaded.ipv6_enabled);
    assert_eq!(loaded.blocked_strings, vec!["badword".to_string()]);
}
