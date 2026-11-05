use serde::{Deserialize, Serialize};
use std::{fs, io};
use toxcore::types::PublicKey;

use crate::sync::event::Content;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub enum SystemMessageType {
    Join,
    Leave,
    NickChange,
}

impl SystemMessageType {
    /// The kind `content` is, if it's one the config can hide.
    pub fn of(content: &Content) -> Option<Self> {
        match content {
            Content::PeerJoined { .. } => Some(Self::Join),
            Content::PeerLeft { .. } => Some(Self::Leave),
            Content::PeerRenamed { .. } => Some(Self::NickChange),
            Content::Received { .. }
            | Content::Send { .. }
            | Content::Sent { .. }
            | Content::Delivered { .. }
            | Content::Notice { .. }
            | Content::File { .. }
            | Content::FileEnded { .. }
            | Content::FileAnswered { .. }
            | Content::Call { .. }
            | Content::CallEnded { .. }
            | Content::ReceivedPrivately { .. }
            | Content::SendPrivately { .. }
            | Content::TopicSet { .. }
            | Content::TitleSet { .. }
            | Content::Moderated { .. }
            | Content::WantFriend { .. }
            | Content::UnwantFriend { .. }
            | Content::ReadUpTo { .. }
            | Content::FriendRequest { .. }
            | Content::MergeChat { .. }
            | Content::RelayBot { .. }
            | Content::Fact { .. }
            | Content::Want { .. }
            | Content::ChatInvite { .. }
            | Content::AnswerInvite { .. }
            | Content::InviteJoined { .. }
            | Content::Setting { .. }
            | Content::ClearSetting { .. }
            | Content::Device { .. }
            | Content::DeviceGone { .. }
            | Content::NewChat { .. }
            | Content::JoinChat { .. }
            | Content::InviteToChat { .. }
            | Content::ChatJoined { .. }
            | Content::Unknown { .. } => None,
        }
    }
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
    #[cfg_attr(tokstyle, tokstyle::bounded("one per paired device"))]
    pub sync_devices: Vec<PublicKey>,
    /// The home device of the account this profile is a device of, after
    /// `/link`. None if this profile is its own account's home.
    #[serde(default)]
    pub home: Option<PublicKey>,
    /// Emojis left out of the picker and completion, as this terminal draws
    /// them badly.
    #[serde(default)]
    pub hidden_emojis: Vec<String>,
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
            sync_devices: Vec::new(),
            home: None,
            hidden_emojis: Vec::new(),
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
    crate::utils::write_atomically(&config_path, data.as_bytes())
}
