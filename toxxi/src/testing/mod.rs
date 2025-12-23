pub mod lib;

use crate::config::Config;
use crate::model::DomainState;
use crate::model::Model;
use crate::model::SessionState;
use crate::model::UiState;
use crate::time::RealTimeProvider;
pub use lib::{buffer_to_string, configure_insta};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tempfile::TempDir;
use toxcore::tox::Address;
use toxcore::tox::ToxConnection;
use toxcore::tox::ToxUserStatus;
use toxcore::types::PublicKey;

pub struct TestContext {
    pub temp_dir: TempDir,
    pub config_dir: PathBuf,
}

impl Default for TestContext {
    fn default() -> Self {
        Self::new()
    }
}

impl TestContext {
    pub fn new() -> Self {
        let temp_dir = TempDir::new().unwrap();
        let config_dir = temp_dir.path().to_path_buf();
        Self {
            temp_dir,
            config_dir,
        }
    }

    pub fn create_model(&self) -> Model {
        let config = Config::default();
        let domain = DomainState {
            tox_id: Address([1u8; 38]),            // Dummy address
            self_public_key: PublicKey([1u8; 32]), // Dummy PK
            self_name: "Tester".to_string(),
            self_status_message: "".to_string(),
            self_status_type: ToxUserStatus::TOX_USER_STATUS_NONE,
            self_connection_status: ToxConnection::TOX_CONNECTION_NONE,
            friends: HashMap::new(),
            conversations: HashMap::new(),
            console_messages: Vec::new(),
            tox_logs: HashMap::new(),
            pending_items: Vec::new(),
            next_internal_id: crate::model::InternalMessageId(1),
            file_transfers: HashMap::new(),
        };

        Model {
            domain,
            ui: UiState::new(),
            session: SessionState::default(),
            saved_config: config.clone(),
            config,
            tick_count: 0,
            time_provider: Arc::new(RealTimeProvider::new(None)),
        }
    }
}

pub trait TestModelUtils {
    // Add methods here if needed, or remove the trait if unused
}

impl TestModelUtils for Model {}
