//! Tauri command surface, grouped by product domain.
//! Keep this file as the public registry only; behavior lives in the domain modules.

mod backups;
mod cards;
mod custom_records;
mod documents;
mod history;
mod identities;
mod imports;
mod items;
mod lifecycle;
mod logins;
mod quick_access;
mod record_commands;
mod release;
mod secure_notes;
mod software_licenses;
mod ssh_keys;
mod support;
mod tools;
mod trash;
mod wifi;
// Compiled only under sync-preview and deliberately not registered: the webview cannot reach these.
#[cfg(feature = "sync-preview")]
pub mod sync;
#[cfg(feature = "sync-preview")]
pub mod sync_adopt;
#[cfg(feature = "sync-preview")]
pub mod sync_transfer;
mod updater;

pub(crate) use crate::adapters::network::account_api::*;
pub(crate) use crate::adapters::platform::autotype::*;
pub use backups::*;
pub use cards::*;
pub use custom_records::*;
pub use documents::*;
pub use history::*;
pub use identities::*;
pub use imports::*;
pub use items::*;
pub use lifecycle::*;
pub use logins::*;
pub use quick_access::*;
pub use release::*;
pub use secure_notes::*;
pub use software_licenses::*;
pub use ssh_keys::*;
pub use support::*;
pub use tools::*;
pub use trash::*;
pub use updater::*;
pub use wifi::*;
