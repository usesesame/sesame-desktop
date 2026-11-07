use std::cell::RefCell;
use std::path::PathBuf;

use zeroize::Zeroizing;

use crate::commands::test_support::TestVault;
use crate::release::{ReleasePresence, PRESENCE_REQUIRED};
use crate::vault::storage::write_vault_file;
use crate::vault::{
    random_id, Card, TaggedItem, UnlockedVault, VaultResult, VaultSnapshot, VaultState, WifiNetwork,
};

use super::lifecycle::{lock_and_notify, unlock_vault_in_state};
use super::records::{
    login_card_in_state, login_summary_in_state, record_view_in_state, redacted_view,
    vault_snapshot_in_state,
};
use super::reveal::{copy_item_field_in_state, item_field_in_state};
use super::search::search_items_in_state;
use super::DesktopEffects;

const MASTER_PASSWORD: &str = "fictional master password";
const WRONG_PASSWORD: &str = "fictional wrong password";
const EMIT_ERROR: &str = "Sesame could not notify the interface that the vault locked.";
const CANARY: &str = "fictional-secret-canary";
const COPY_EPOCH: u64 = 41;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum Effect {
    ReportKeyPageFallback,
    ObserveUnlock,
    ObserveLock {
        session_present: bool,
    },
    ClearArmedClipboard,
    CopySecret {
        value: String,
        clear_after_ms: Option<u64>,
    },
    RevokePresence,
    CancelBreachScan,
    EstablishPinThrottle,
    EmitVaultLocked,
    CancelPendingApprovals,
    ReportBackupIoError,
}

pub(super) struct FakeEffects<'a> {
    path: PathBuf,
    presence: Option<&'a ReleasePresence>,
    fail_emit: bool,
    copy_epoch: u64,
    calls: RefCell<Vec<Effect>>,
}

impl<'a> FakeEffects<'a> {
    pub(super) fn new(path: PathBuf) -> Self {
        Self {
            path,
            presence: None,
            fail_emit: false,
            copy_epoch: COPY_EPOCH,
            calls: RefCell::new(Vec::new()),
        }
    }

    fn with_presence(path: PathBuf, presence: &'a ReleasePresence) -> Self {
        Self {
            presence: Some(presence),
            ..Self::new(path)
        }
    }

    fn failing_emit(path: PathBuf) -> Self {
        Self {
            fail_emit: true,
            ..Self::new(path)
        }
    }

    pub(super) fn calls(&self) -> Vec<Effect> {
        self.calls.borrow().clone()
    }

    fn record(&self, effect: Effect) {
        self.calls.borrow_mut().push(effect);
    }
}

impl DesktopEffects for FakeEffects<'_> {
    fn vault_path(&self) -> VaultResult<PathBuf> {
        Ok(self.path.clone())
    }

    fn report_key_page_fallback(&self, _unlocked: &UnlockedVault) {
        self.record(Effect::ReportKeyPageFallback);
    }

    fn observe_unlock(&self, _snapshot: &VaultSnapshot) {
        self.record(Effect::ObserveUnlock);
    }

    fn observe_lock(&self, state: &VaultState) {
        let session_present = state.session.lock().expect("session lock").is_some();
        self.record(Effect::ObserveLock { session_present });
    }

    fn clear_armed_clipboard(&self) -> VaultResult<()> {
        self.record(Effect::ClearArmedClipboard);
        Ok(())
    }

    fn copy_secret(
        &self,
        value: Zeroizing<String>,
        clear_after_ms: Option<u64>,
    ) -> VaultResult<u64> {
        self.record(Effect::CopySecret {
            value: value.to_string(),
            clear_after_ms,
        });
        Ok(self.copy_epoch)
    }

    fn revoke_presence(&self) {
        self.record(Effect::RevokePresence);
        if let Some(presence) = self.presence {
            presence.revoke();
        }
    }

    fn cancel_breach_scan(&self) {
        self.record(Effect::CancelBreachScan);
    }

    fn emit_vault_locked(&self) -> Result<(), ()> {
        self.record(Effect::EmitVaultLocked);
        if self.fail_emit {
            Err(())
        } else {
            Ok(())
        }
    }

    fn establish_pin_throttle_state(&self, _state: &VaultState) -> VaultResult<()> {
        self.record(Effect::EstablishPinThrottle);
        Ok(())
    }

    fn cancel_pending_approvals(&self) {
        self.record(Effect::CancelPendingApprovals);
    }

    fn report_backup_io_error(&self) {
        self.record(Effect::ReportBackupIoError);
    }
}

struct TempVault {
    directory: PathBuf,
    path: PathBuf,
}

impl TempVault {
    fn new() -> Self {
        let (opened, _) = sesame_core::api::create_vault(MASTER_PASSWORD, "Fictional vault")
            .expect("created vault");
        let directory = std::env::temp_dir().join(format!("sesame-application-{}", random_id()));
        std::fs::create_dir_all(&directory).expect("temp directory");
        let path = directory.join("vault.sesame");
        write_vault_file(&path, &opened.file).expect("written vault");
        Self { directory, path }
    }
}

impl Drop for TempVault {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

fn grant(vault: &TestVault, presence: &ReleasePresence) {
    let session = vault.state.session.lock().expect("session lock");
    presence
        .grant_with_password(
            session.as_ref().expect("session"),
            vault.state.session_epoch(),
            MASTER_PASSWORD,
        )
        .expect("granted presence");
}

#[test]
fn unlocking_installs_the_session_and_records_the_effects_in_order() {
    let vault = TempVault::new();
    let state = VaultState::default();
    let presence = ReleasePresence::default();
    let effects = FakeEffects::new(vault.path.clone());
    let before = state.session_epoch();

    let snapshot = unlock_vault_in_state(
        &state,
        &presence,
        &effects,
        Zeroizing::new(MASTER_PASSWORD.to_string()),
    )
    .expect("unlocked");

    assert!(snapshot.vault_id.is_some());
    assert!(state.session.lock().expect("session lock").is_some());
    assert_eq!(state.session_epoch(), before + 1);
    assert_eq!(state.cached_pin_unlock(), Some(false));
    assert_eq!(state.cached_hello_unlock(), Some(false));
    assert!(presence.require(state.session_epoch()).is_ok());
    assert_eq!(
        effects.calls(),
        vec![
            Effect::ReportKeyPageFallback,
            Effect::ObserveUnlock,
            Effect::EstablishPinThrottle,
        ]
    );
}

#[test]
fn a_wrong_password_installs_nothing() {
    let vault = TempVault::new();
    let state = VaultState::default();
    let presence = ReleasePresence::default();
    let effects = FakeEffects::new(vault.path.clone());
    let before = state.session_epoch();

    assert!(unlock_vault_in_state(
        &state,
        &presence,
        &effects,
        Zeroizing::new(WRONG_PASSWORD.to_string()),
    )
    .is_err());

    assert!(state.session.lock().expect("session lock").is_none());
    assert_eq!(state.session_epoch(), before);
    assert_eq!(state.cached_pin_unlock(), None);
    assert_eq!(presence.require(before), Err(PRESENCE_REQUIRED.to_string()));
    assert!(effects.calls().is_empty());
}

#[test]
fn locking_observes_before_clearing_and_records_every_effect_in_order() {
    let vault = TestVault::with_login("fictional-login", "https://northwind.example");
    let presence = ReleasePresence::default();
    grant(&vault, &presence);
    let effects = FakeEffects::with_presence(PathBuf::new(), &presence);
    let before = vault.state.session_epoch();

    lock_and_notify(&vault.state, &effects).expect("locked");

    assert!(vault.state.session.lock().expect("session lock").is_none());
    assert_eq!(vault.state.session_epoch(), before + 1);
    assert_eq!(presence.require(before), Err(PRESENCE_REQUIRED.to_string()));
    assert_eq!(
        effects.calls(),
        vec![
            Effect::ObserveLock {
                session_present: true
            },
            Effect::ClearArmedClipboard,
            Effect::RevokePresence,
            Effect::CancelBreachScan,
            Effect::EmitVaultLocked,
        ]
    );
}

#[test]
fn locking_an_already_locked_vault_keeps_the_existing_behavior() {
    let state = VaultState::default();
    let presence = ReleasePresence::default();
    let effects = FakeEffects::with_presence(PathBuf::new(), &presence);
    let before = state.session_epoch();

    lock_and_notify(&state, &effects).expect("locked");

    assert!(state.session.lock().expect("session lock").is_none());
    assert_eq!(state.session_epoch(), before + 1);
    assert_eq!(
        effects.calls(),
        vec![
            Effect::ObserveLock {
                session_present: false
            },
            Effect::ClearArmedClipboard,
            Effect::RevokePresence,
            Effect::CancelBreachScan,
            Effect::EmitVaultLocked,
        ]
    );
}

#[test]
fn after_locking_reveal_needs_presence_and_search_needs_an_unlocked_vault() {
    let vault = TestVault::with_login("fictional-login", "https://northwind.example");
    let presence = ReleasePresence::default();
    grant(&vault, &presence);
    let effects = FakeEffects::with_presence(PathBuf::new(), &presence);

    assert_eq!(
        search_items_in_state(&vault.state, "northwind").expect("search"),
        vec!["fictional-login".to_string()]
    );
    assert_eq!(
        item_field_in_state(
            &vault.state,
            &presence,
            "fictional-login",
            "login",
            "password"
        )
        .expect("released")
        .as_str(),
        "fictional-stored-secret"
    );

    lock_and_notify(&vault.state, &effects).expect("locked");

    assert_eq!(
        item_field_in_state(
            &vault.state,
            &presence,
            "fictional-login",
            "login",
            "password"
        )
        .map(|value| value.to_string()),
        Err(PRESENCE_REQUIRED.to_string())
    );
    assert_eq!(
        search_items_in_state(&vault.state, "northwind"),
        Err("Unlock your vault first.".to_string())
    );
}

#[test]
fn a_grant_from_before_a_lock_is_rejected_after_the_next_unlock() {
    let vault = TempVault::new();
    let state = VaultState::default();
    let presence = ReleasePresence::default();
    let effects = FakeEffects::with_presence(vault.path.clone(), &presence);

    unlock_vault_in_state(
        &state,
        &presence,
        &effects,
        Zeroizing::new(MASTER_PASSWORD.to_string()),
    )
    .expect("unlocked");
    let first_epoch = state.session_epoch();
    assert!(presence.require(first_epoch).is_ok());

    lock_and_notify(&state, &effects).expect("locked");
    assert_eq!(
        presence.require(first_epoch),
        Err(PRESENCE_REQUIRED.to_string())
    );

    unlock_vault_in_state(
        &state,
        &presence,
        &effects,
        Zeroizing::new(MASTER_PASSWORD.to_string()),
    )
    .expect("unlocked again");

    assert_eq!(state.session_epoch(), first_epoch + 2);
    assert_eq!(
        presence.require(first_epoch),
        Err(PRESENCE_REQUIRED.to_string())
    );
    assert!(presence.require(state.session_epoch()).is_ok());
}

fn record_view_vault() -> TestVault {
    let vault = TestVault::with_login("fictional-login", "https://northwind.example");
    vault.seed(|payload| {
        let mut card = Card::default();
        card.id = "fictional-card".to_string();
        card.title = "Fictional card".to_string();
        card.number = format!("{CANARY}-number");
        card.security_code = format!("{CANARY}-code");
        payload.cards.push(card);
        let mut network = WifiNetwork::default();
        network.id = "fictional-wifi".to_string();
        network.title = "Fictional network".to_string();
        network.password = format!("{CANARY}-wifi");
        payload.wifi_networks.push(network);
    });
    vault
}

fn card_of(item: &TaggedItem) -> Option<&Card> {
    match item {
        TaggedItem::Card(card) => Some(card),
        _ => None,
    }
}

fn wifi_of(item: &TaggedItem) -> Option<&WifiNetwork> {
    match item {
        TaggedItem::WifiNetwork(network) => Some(network),
        _ => None,
    }
}

#[test]
fn a_redacted_view_names_the_secrets_and_carries_none() {
    let mut card = Card::default();
    card.number = format!("{CANARY}-number");
    card.security_code = format!("{CANARY}-code");
    card.title = "Fictional card".to_string();
    let view = redacted_view(card);
    let json = serde_json::to_string(&view).expect("serialized view");

    assert!(!json.contains(CANARY));
    assert!(json.contains("\"secretFields\":[\"number\",\"securityCode\"]"));
    assert!(json.contains("Fictional card"));
}

#[test]
fn the_snapshot_and_login_views_need_an_unlocked_vault() {
    let state = VaultState::default();

    assert_eq!(
        vault_snapshot_in_state(&state).err(),
        Some("Unlock your vault first.".to_string())
    );
    assert_eq!(
        login_card_in_state(&state, "fictional-login").err(),
        Some("Unlock your vault first.".to_string())
    );
    assert_eq!(
        login_summary_in_state(&state, "fictional-login").err(),
        Some("Unlock your vault first.".to_string())
    );
}

#[test]
fn the_snapshot_and_login_views_read_the_unlocked_vault() {
    let vault = TestVault::with_login("fictional-login", "https://northwind.example");

    let snapshot = vault_snapshot_in_state(&vault.state).expect("snapshot");
    let card = login_card_in_state(&vault.state, "fictional-login").expect("card");
    let summary = login_summary_in_state(&vault.state, "fictional-login").expect("summary");

    assert_eq!(snapshot.entries.len(), 1);
    assert_eq!(snapshot.entries[0].id, "fictional-login");
    assert_eq!(card.id, "fictional-login");
    assert!(card.has_password);
    assert_eq!(summary.id, "fictional-login");
    assert_eq!(summary.username, "fictional-user");
}

#[test]
fn record_views_need_an_unlocked_vault() {
    let state = VaultState::default();

    assert_eq!(
        record_view_in_state(&state, "fictional-card", "card", card_of).err(),
        Some("Unlock your vault first.".to_string())
    );
}

#[test]
fn a_record_view_redacts_each_kinds_secret_slots() {
    let vault = record_view_vault();

    let card =
        record_view_in_state(&vault.state, "fictional-card", "card", card_of).expect("card view");
    let card_json = serde_json::to_string(&card).expect("serialized card view");
    assert!(!card_json.contains(CANARY));
    assert!(card_json.contains("\"secretFields\":[\"number\",\"securityCode\"]"));
    assert!(card_json.contains("Fictional card"));

    let network = record_view_in_state(&vault.state, "fictional-wifi", "network", wifi_of)
        .expect("network view");
    let network_json = serde_json::to_string(&network).expect("serialized network view");
    assert!(!network_json.contains(CANARY));
    assert!(network_json.contains("\"secretFields\":[\"password\"]"));
    assert!(network_json.contains("Fictional network"));
}

#[test]
fn a_record_view_for_another_kind_reports_that_it_no_longer_exists() {
    let vault = record_view_vault();

    assert_eq!(
        record_view_in_state(&vault.state, "fictional-card", "network", wifi_of).err(),
        Some("That saved network no longer exists.".to_string())
    );
}

#[test]
fn copying_a_field_without_presence_never_reaches_the_clipboard() {
    let vault = TestVault::with_login("fictional-login", "https://northwind.example");
    let presence = ReleasePresence::default();
    let effects = FakeEffects::new(PathBuf::new());

    assert_eq!(
        copy_item_field_in_state(
            &vault.state,
            &presence,
            &effects,
            "fictional-login",
            "login",
            "password",
            Some(30_000),
        ),
        Err(PRESENCE_REQUIRED.to_string())
    );
    assert!(effects.calls().is_empty());
}

#[test]
fn copying_a_field_passes_the_exact_secret_and_returns_the_effect_epoch() {
    let vault = TestVault::with_login("fictional-login", "https://northwind.example");
    let presence = ReleasePresence::default();
    grant(&vault, &presence);
    let effects = FakeEffects::with_presence(PathBuf::new(), &presence);

    let epoch = copy_item_field_in_state(
        &vault.state,
        &presence,
        &effects,
        "fictional-login",
        "login",
        "password",
        Some(30_000),
    )
    .expect("copied");

    assert_eq!(epoch, COPY_EPOCH);
    assert_eq!(
        effects.calls(),
        vec![Effect::CopySecret {
            value: "fictional-stored-secret".to_string(),
            clear_after_ms: Some(30_000),
        }]
    );
}

#[test]
fn copying_after_a_lock_fails_and_never_reaches_the_clipboard() {
    let vault = TestVault::with_login("fictional-login", "https://northwind.example");
    let presence = ReleasePresence::default();
    grant(&vault, &presence);
    let effects = FakeEffects::with_presence(PathBuf::new(), &presence);
    lock_and_notify(&vault.state, &effects).expect("locked");
    let calls_after_lock = effects.calls().len();

    assert_eq!(
        copy_item_field_in_state(
            &vault.state,
            &presence,
            &effects,
            "fictional-login",
            "login",
            "password",
            None,
        ),
        Err(PRESENCE_REQUIRED.to_string())
    );
    assert_eq!(effects.calls().len(), calls_after_lock);
}

#[test]
fn an_emit_failure_returns_the_existing_error_and_still_clears_the_session() {
    let vault = TestVault::with_login("fictional-login", "https://northwind.example");
    let presence = ReleasePresence::default();
    let effects = FakeEffects::failing_emit(PathBuf::new());

    assert_eq!(
        lock_and_notify(&vault.state, &effects),
        Err(EMIT_ERROR.to_string())
    );
    assert!(vault.state.session.lock().expect("session lock").is_none());
    assert!(presence.require(vault.state.session_epoch()).is_err());
    assert_eq!(
        effects.calls(),
        vec![
            Effect::ObserveLock {
                session_present: true
            },
            Effect::ClearArmedClipboard,
            Effect::RevokePresence,
            Effect::CancelBreachScan,
            Effect::EmitVaultLocked,
        ]
    );
}
