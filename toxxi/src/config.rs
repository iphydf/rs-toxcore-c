use serde::{Deserialize, Serialize};
use std::io::Write;
use std::{fs, io};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub enum SystemMessageType {
    Join,
    Leave,
    NickChange,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Config {
    // Network Settings
    pub ipv6_enabled: bool,
    pub udp_enabled: bool,
    pub local_discovery_enabled: bool,
    pub start_port: u16,
    pub end_port: u16,
    pub blocked_strings: Vec<String>,
    pub highlight_strings: Vec<String>,
    pub enabled_system_messages: Vec<SystemMessageType>,
    pub downloads_directory: Option<String>,
    pub timezone: Option<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            ipv6_enabled: true,
            udp_enabled: true,
            local_discovery_enabled: false,
            start_port: 33445,
            end_port: 33455,
            blocked_strings: Vec::new(),
            highlight_strings: Vec::new(),
            enabled_system_messages: vec![
                SystemMessageType::Join,
                SystemMessageType::Leave,
                SystemMessageType::NickChange,
            ],
            downloads_directory: None,
            timezone: None,
        }
    }
}

impl Config {
    pub fn requires_restart(&self, other: &Config) -> bool {
        self.ipv6_enabled != other.ipv6_enabled
            || self.udp_enabled != other.udp_enabled
            || self.local_discovery_enabled != other.local_discovery_enabled
            || self.start_port != other.start_port
            || self.end_port != other.end_port
    }
}

pub fn load_config(config_dir: &std::path::Path) -> Config {
    let config_path = config_dir.join("config.json");
    fs::read_to_string(config_path)
        .ok()
        .and_then(|data| serde_json::from_str::<Config>(&data).ok())
        .unwrap_or_default()
}

pub fn save_config(config_dir: &std::path::Path, config: &Config) -> io::Result<()> {
    let config_path = config_dir.join("config.json");
    let data = serde_json::to_string_pretty(config)?;
    let mut file = fs::File::create(config_path)?;
    file.write_all(data.as_bytes())?;
    Ok(())
}
