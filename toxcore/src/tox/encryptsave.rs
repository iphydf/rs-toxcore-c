// apigen generates the `PassKey` wrapper and the `encrypt`, `decrypt`,
// `get_salt` and `is_data_encrypted` functions: this module re-exports them.
#[path = "../core/generated/safe_pass_key.rs"]
mod safe_pass_key;

pub use safe_pass_key::*;
