impl TwoDevices {
    fn device(&self, on_laptop: bool) -> (&TestVault, &SyncStore, &Scratch) {
        if on_laptop {
            (&self.laptop, &self.laptop_store, &self._scratch[0])
        } else {
            (&self.desktop, &self.desktop_store, &self._scratch[1])
        }
    }

    fn leave_on_format_10(&self, on_laptop: bool, edit: impl FnOnce(&mut crate::vault::VaultPayload)) {
        let (vault, store, _) = self.device(on_laptop);
        let (key, agreed) = {
            let session = vault.state.session.lock().expect("session lock");
            let unlocked = session.as_ref().expect("unlocked");
            (
                unlocked.expose_vault_key(|key| Ok(*key)).expect("key"),
                unlocked.open_payload().expect("payload").clone(),
            )
        };
        let mut written = agreed.clone();
        edit(&mut written);
        let mut file: crate::vault::VaultFile =
            serde_json::from_slice(&std::fs::read(vault.path()).expect("vault bytes"))
                .expect("vault file");
        file.format_version = 10;
        file.payload = crate::vault::crypto::encrypt_bytes(
            &key,
            &crate::vault::crypto::serialize_payload(&written).expect("serialized payload"),
            sesame_core::FORMAT_10_PAYLOAD_AAD,
        )
        .expect("sealed format 10 payload");
        std::fs::write(vault.path(), serde_json::to_vec(&file).expect("encoded vault"))
            .expect("wrote format 10 vault");
        let mut local = store.load_state().expect("state").expect("saved state");
        local.payload_digest =
            payload_digest(&serde_json::to_vec(&agreed).expect("serialized payload"));
        store.save_state(&local).expect("state as 0.5.3 left it");
        vault.state.lock_for_lifecycle().expect("locked");
    }

    fn upgrade(&self, on_laptop: bool) {
        self.upgrade_with(on_laptop, &crate::sync::coordinator::Coordinator::new());
    }

    fn upgrade_with(&self, on_laptop: bool, coordinator: &crate::sync::coordinator::Coordinator) {
        let (vault, _, scratch) = self.device(on_laptop);
        crate::application::lifecycle::unlock_vault_in_state(
            &vault.state,
            &crate::release::ReleasePresence::default(),
            &FakeEffects::with_sync(
                vault.path().to_path_buf(),
                scratch.path.clone(),
                coordinator.clone(),
            ),
            zeroize::Zeroizing::new(PASSWORD.to_string()),
        )
        .expect("unlocked on the new version");
        let format: Value =
            serde_json::from_slice(&std::fs::read(vault.path()).expect("vault bytes"))
                .expect("vault file");
        assert_eq!(format["formatVersion"], 11, "the unlock saved the upgrade");
    }

    fn unsynced(&self, on_laptop: bool) -> bool {
        let (vault, store, _) = self.device(on_laptop);
        let local = store.load_state().expect("state").expect("saved state");
        let session = vault.state.session.lock().expect("session lock");
        crate::application::sync::vault_has_local_changes(
            &local,
            session.as_ref().expect("unlocked"),
        )
        .expect("compared")
    }

    fn content(&self, on_laptop: bool) -> String {
        let (vault, _, _) = self.device(on_laptop);
        let session = vault.state.session.lock().expect("session lock");
        let payload = session
            .as_ref()
            .expect("unlocked")
            .open_payload()
            .expect("payload");
        crate::sync::state::change_digest(&payload).expect("change digest")
    }
}

fn imported_fields() -> Vec<crate::vault::types::LegacyField> {
    vec![
        crate::vault::types::LegacyField {
            label: "Member number".into(),
            value: "fictional-member-0042".into(),
            secret: false,
        },
        crate::vault::types::LegacyField {
            label: "Door code".into(),
            value: "fictional-door-code".into(),
            secret: true,
        },
    ]
}

fn two_devices_synced_by_0_5_3(change: impl FnOnce(&mut crate::vault::VaultPayload)) -> TwoDevices {
    use crate::sync::coordinator::Outcome;

    let devices = two_synced_devices();
    devices.laptop.seed(|payload| {
        payload.entries[0].created_at = 40;
        change(payload);
    });
    assert_eq!(devices.run(true), Ok(Outcome::Uploaded { revision: 2 }));
    assert_eq!(devices.run(false), Ok(Outcome::Downloaded { revision: 2 }));
    assert_eq!(devices.content(true), devices.content(false));
    devices
}

fn unchanged(_: &mut crate::vault::VaultPayload) {}

#[test]
fn an_in_sync_device_that_upgrades_its_vault_format_has_nothing_to_sync() {
    use crate::sync::coordinator::Outcome;

    let devices = two_synced_devices();
    devices.leave_on_format_10(true, unchanged);

    devices.upgrade(true);

    assert!(!devices.unsynced(true), "the upgrade alone is not an edit");
    assert_eq!(devices.run(true), Ok(Outcome::AlreadyCurrent));
    assert_eq!(devices.uploads(), 1);
}

#[test]
fn two_in_sync_devices_upgrade_in_turn_without_a_conflict() {
    use crate::sync::coordinator::Outcome;

    let devices = two_devices_synced_by_0_5_3(unchanged);
    devices.leave_on_format_10(true, unchanged);
    devices.leave_on_format_10(false, unchanged);

    devices.upgrade(true);
    assert_eq!(devices.run(true), Ok(Outcome::AlreadyCurrent));
    devices.upgrade(false);
    assert_eq!(devices.run(false), Ok(Outcome::AlreadyCurrent));

    assert_eq!(devices.uploads(), 2);
    assert_eq!(devices.content(true), devices.content(false));
}

#[test]
fn devices_that_stamp_a_missing_creation_time_at_different_moments_still_do_not_conflict() {
    use crate::sync::coordinator::Outcome;

    let devices = two_synced_devices();
    assert_eq!(login_of(&devices.laptop).created_at, 0);
    devices.leave_on_format_10(true, unchanged);
    devices.leave_on_format_10(false, unchanged);

    devices.upgrade(true);
    std::thread::sleep(std::time::Duration::from_millis(1_100));
    devices.upgrade(false);

    assert_ne!(
        login_of(&devices.laptop).created_at,
        login_of(&devices.desktop).created_at
    );
    assert_eq!(devices.run(true), Ok(Outcome::AlreadyCurrent));
    assert_eq!(devices.run(false), Ok(Outcome::AlreadyCurrent));
    assert_eq!(devices.uploads(), 1);
}

#[test]
fn a_device_behind_the_server_upgrades_and_takes_the_newer_copy() {
    use crate::sync::coordinator::Outcome;

    let devices = two_devices_synced_by_0_5_3(unchanged);
    devices.leave_on_format_10(true, unchanged);
    devices.leave_on_format_10(false, unchanged);
    devices.upgrade(true);
    devices.laptop.seed(|payload| {
        payload.entries[0].match_rule = crate::vault::types::MatchRule::Site;
        payload
            .never_save_sites
            .push("https://never.adatum.example".into());
    });
    assert_eq!(devices.run(true), Ok(Outcome::Uploaded { revision: 3 }));

    devices.upgrade(false);

    assert!(!devices.unsynced(false));
    assert_eq!(devices.run(false), Ok(Outcome::Downloaded { revision: 3 }));
    assert_eq!(
        login_of(&devices.desktop).match_rule,
        crate::vault::types::MatchRule::Site
    );
    assert_eq!(devices.content(true), devices.content(false));
    assert_eq!(devices.run(false), Ok(Outcome::AlreadyCurrent));
}

#[test]
fn an_edit_made_before_the_upgrade_still_uploads() {
    use crate::sync::coordinator::Outcome;

    let devices = two_synced_devices();
    devices.leave_on_format_10(false, |payload| {
        payload.entries[0].username = "fictional-user-edited-on-0.5.3".into();
        payload.revision += 1;
    });

    devices.upgrade(false);

    assert!(devices.unsynced(false));
    assert_eq!(devices.run(false), Ok(Outcome::Uploaded { revision: 2 }));
    assert_eq!(devices.run(true), Ok(Outcome::Downloaded { revision: 2 }));
    assert_eq!(
        login_of(&devices.laptop).username,
        "fictional-user-edited-on-0.5.3"
    );
}

#[test]
fn an_edit_made_before_the_upgrade_still_conflicts_with_a_newer_server_copy() {
    use crate::sync::coordinator::Outcome;

    let devices = two_synced_devices();
    devices.leave_on_format_10(true, unchanged);
    devices.leave_on_format_10(false, |payload| {
        payload.entries[0].username = "fictional-user-edited-on-0.5.3".into();
        payload.revision += 1;
    });
    devices.upgrade(true);
    devices.laptop.seed(|payload| {
        payload.vault_name = "Fictional vault renamed on the laptop".into();
    });
    assert_eq!(devices.run(true), Ok(Outcome::Uploaded { revision: 2 }));

    devices.upgrade(false);

    assert_eq!(devices.run(false), Err("sync_conflict:2".to_string()));
    assert_eq!(devices.uploads(), 2, "the conflicting side uploads nothing");
    assert_eq!(
        login_of(&devices.desktop).username,
        "fictional-user-edited-on-0.5.3",
        "a conflict leaves the local edit in place"
    );
}

#[test]
fn devices_with_imported_fields_upgrade_and_converge_with_the_fields_intact() {
    use crate::sync::coordinator::Outcome;

    let devices = two_devices_synced_by_0_5_3(|payload| {
        payload.entries[0].legacy_fields = imported_fields();
    });
    assert_eq!(login_of(&devices.desktop).legacy_fields.len(), 2);
    devices.leave_on_format_10(true, unchanged);
    devices.leave_on_format_10(false, unchanged);

    devices.upgrade(true);
    assert_eq!(devices.run(true), Ok(Outcome::AlreadyCurrent));
    devices.upgrade(false);
    assert_eq!(devices.run(false), Ok(Outcome::AlreadyCurrent));
    assert_eq!(devices.uploads(), 2);
    assert_eq!(devices.content(true), devices.content(false));

    devices.laptop.seed(|payload| {
        payload.entries[0].title = "Northwind edited after the upgrade".into();
    });
    assert_eq!(devices.run(true), Ok(Outcome::Uploaded { revision: 3 }));
    assert_eq!(devices.run(false), Ok(Outcome::Downloaded { revision: 3 }));

    let login = login_of(&devices.desktop);
    assert_eq!(login.title, "Northwind edited after the upgrade");
    assert!(login.legacy_fields.is_empty());
    assert_eq!(
        login
            .custom_fields
            .iter()
            .map(|field| (field.label.as_str(), field.value.as_str(), field.kind.as_str()))
            .collect::<Vec<_>>(),
        [
            ("Member number", "fictional-member-0042", "text"),
            ("Door code", "fictional-door-code", "secret"),
        ]
    );
    assert_eq!(devices.content(true), devices.content(false));
}

#[test]
fn an_upgrade_made_while_a_run_held_the_store_survives_a_lock_before_the_run_lets_go() {
    use crate::sync::coordinator::{Coordinator, Outcome};

    let devices = two_devices_synced_by_0_5_3(unchanged);
    devices.leave_on_format_10(true, unchanged);
    let stored = || {
        devices
            .laptop_store
            .load_state()
            .expect("state")
            .expect("saved state")
            .payload_digest
    };
    let before = stored();
    let busy = Coordinator::new();
    assert!(busy.begin());

    devices.upgrade_with(true, &busy);
    assert_eq!(stored(), before, "the unlock found a run in progress");
    assert!(devices.laptop_store.load_upgrade().is_some());
    devices.laptop.state.lock_for_lifecycle().expect("locked");
    busy.finish(Outcome::AlreadyCurrent);

    let reopened = Coordinator::new();
    crate::application::lifecycle::unlock_vault_in_state(
        &devices.laptop.state,
        &crate::release::ReleasePresence::default(),
        &FakeEffects::with_sync(
            devices.laptop.path().to_path_buf(),
            devices._scratch[0].path.clone(),
            reopened,
        ),
        zeroize::Zeroizing::new(PASSWORD.to_string()),
    )
    .expect("unlocked again");

    assert_ne!(stored(), before);
    assert!(devices.laptop_store.load_upgrade().is_none());
    assert!(!devices.unsynced(true));
    assert_eq!(devices.run(true), Ok(Outcome::AlreadyCurrent));
    assert_eq!(devices.uploads(), 2);
}

#[test]
fn turning_sync_off_forgets_a_recorded_upgrade() {
    let devices = two_devices_synced_by_0_5_3(unchanged);
    devices.leave_on_format_10(true, unchanged);
    let busy = crate::sync::coordinator::Coordinator::new();
    assert!(busy.begin());
    devices.upgrade_with(true, &busy);
    assert!(devices.laptop_store.load_upgrade().is_some());

    devices
        .laptop_store
        .forget_everything()
        .expect("Sync turned off");

    assert!(devices.laptop_store.load_upgrade().is_none());
    assert!(!devices.laptop_store.upgrade_path().exists());
}

impl TwoDevices {
    fn stored_digest(&self, on_laptop: bool) -> String {
        let (_, store, _) = self.device(on_laptop);
        store
            .load_state()
            .expect("state")
            .expect("saved state")
            .payload_digest
    }

    fn unlock_again(&self, on_laptop: bool) {
        let (vault, _, _) = self.device(on_laptop);
        vault.state.lock_for_lifecycle().expect("locked");
        self.upgrade(on_laptop);
    }

    fn upgrade_copies(&self, on_laptop: bool) -> Vec<Vec<u8>> {
        let (vault, _, _) = self.device(on_laptop);
        let Ok(entries) = std::fs::read_dir(vault.path().with_file_name("backups")) else {
            return Vec::new();
        };
        entries
            .flatten()
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with("sesame-before-upgrade-")
            })
            .map(|entry| std::fs::read(entry.path()).expect("backup bytes"))
            .collect()
    }
}

fn block(path: &std::path::Path) {
    std::fs::create_dir_all(path.join("occupied")).expect("blocked path");
}

fn unblock(path: &std::path::Path) {
    std::fs::remove_dir_all(path).expect("unblocked path");
}

fn upgrade_staging(store: &SyncStore) -> PathBuf {
    store.upgrade_path().with_extension("json.next")
}

#[test]
fn an_unlock_that_cannot_record_or_adopt_the_upgrade_still_saves_it_with_its_format_10_copy() {
    let devices = two_devices_synced_by_0_5_3(unchanged);
    devices.leave_on_format_10(true, unchanged);
    let original = std::fs::read(devices.laptop.path()).expect("format 10 bytes");
    block(&upgrade_staging(&devices.laptop_store));
    let busy = crate::sync::coordinator::Coordinator::new();
    assert!(busy.begin());

    devices.upgrade_with(true, &busy);

    assert_eq!(devices.upgrade_copies(true), std::slice::from_ref(&original));
    {
        let mut session = devices.laptop.state.session.lock().expect("session lock");
        crate::vault::storage::remove_pin_for_session(session.as_mut().expect("unlocked"))
            .expect("a credential change after the upgrade");
    }
    assert_eq!(devices.upgrade_copies(true), [original]);
}

#[test]
fn an_upgrade_kept_only_in_the_session_is_adopted_by_the_first_run() {
    use crate::sync::coordinator::{Coordinator, Outcome};

    let devices = two_devices_synced_by_0_5_3(unchanged);
    devices.leave_on_format_10(true, unchanged);
    let before = devices.stored_digest(true);
    block(&upgrade_staging(&devices.laptop_store));
    let busy = Coordinator::new();
    assert!(busy.begin());
    devices.upgrade_with(true, &busy);
    assert!(devices.laptop_store.load_upgrade().is_none());
    busy.finish(Outcome::AlreadyCurrent);

    assert!(!devices.unsynced(true));
    assert_eq!(devices.run(true), Ok(Outcome::AlreadyCurrent));
    assert_ne!(devices.stored_digest(true), before);
    assert_eq!(devices.uploads(), 2);
}

#[test]
fn a_lock_before_any_run_with_an_unrecorded_upgrade_counts_it_as_an_edit_and_loses_nothing() {
    use crate::sync::coordinator::{Coordinator, Outcome};

    let devices = two_devices_synced_by_0_5_3(unchanged);
    devices.leave_on_format_10(true, unchanged);
    block(&upgrade_staging(&devices.laptop_store));
    let busy = Coordinator::new();
    assert!(busy.begin());
    devices.upgrade_with(true, &busy);
    busy.finish(Outcome::AlreadyCurrent);

    devices.unlock_again(true);

    assert!(devices.unsynced(true));
    assert_eq!(devices.run(true), Ok(Outcome::Uploaded { revision: 3 }));
    assert_eq!(devices.run(false), Ok(Outcome::Downloaded { revision: 3 }));
    assert_eq!(devices.content(true), devices.content(false));
}

#[test]
fn an_upgrade_made_while_the_sync_state_cannot_be_read_is_adopted_once_it_can() {
    use crate::sync::coordinator::Outcome;

    let devices = two_devices_synced_by_0_5_3(unchanged);
    devices.leave_on_format_10(true, unchanged);
    let before = devices.stored_digest(true);
    let tag = devices.laptop_store.state_path().with_extension("json.tag");
    let readable = std::fs::read(&tag).expect("state tag");
    std::fs::write(&tag, b"fictional tag the protector cannot open").expect("broken tag");

    devices.upgrade(true);
    assert!(devices.laptop_store.load_state().expect("state").is_none());
    assert!(devices.laptop_store.load_upgrade().is_some());

    std::fs::write(&tag, readable).expect("restored tag");
    devices.unlock_again(true);

    assert_ne!(devices.stored_digest(true), before);
    assert!(!devices.laptop_store.upgrade_path().exists());
    assert!(!devices.unsynced(true));
    assert_eq!(devices.run(true), Ok(Outcome::AlreadyCurrent));
    assert_eq!(devices.uploads(), 2);
}

#[test]
fn a_vault_save_that_fails_after_the_mapping_leaves_the_sync_state_alone() {
    use crate::sync::coordinator::{Coordinator, Outcome};

    let devices = two_synced_devices();
    assert_eq!(login_of(&devices.laptop).created_at, 0);
    devices.leave_on_format_10(true, unchanged);
    let before = devices.stored_digest(true);
    let original = std::fs::read(devices.laptop.path()).expect("format 10 bytes");
    let previous = devices.laptop.path().with_extension("sesame.prev");
    block(&previous);

    let failed = crate::application::lifecycle::unlock_vault_in_state(
        &devices.laptop.state,
        &crate::release::ReleasePresence::default(),
        &FakeEffects::with_sync(
            devices.laptop.path().to_path_buf(),
            devices._scratch[0].path.clone(),
            Coordinator::new(),
        ),
        zeroize::Zeroizing::new(PASSWORD.to_string()),
    );

    assert!(failed.is_err());
    assert_eq!(devices.stored_digest(true), before);
    assert_eq!(
        std::fs::read(devices.laptop.path()).expect("vault bytes"),
        original
    );
    assert!(devices.laptop_store.load_upgrade().is_some());
    unblock(&previous);
    std::thread::sleep(std::time::Duration::from_millis(1_100));
    devices.upgrade(true);
    assert!(!devices.unsynced(true));
    assert_eq!(devices.run(true), Ok(Outcome::AlreadyCurrent));
    assert_eq!(devices.uploads(), 1);
}

#[test]
fn a_stop_after_the_vault_save_finishes_the_adoption_at_the_next_unlock() {
    use crate::sync::coordinator::Outcome;

    let devices = two_devices_synced_by_0_5_3(unchanged);
    devices.leave_on_format_10(true, unchanged);
    let before = devices.stored_digest(true);
    let staging = devices.laptop_store.state_path().with_extension("json.next");
    block(&staging);

    devices.upgrade(true);
    assert_eq!(devices.stored_digest(true), before);
    assert!(devices.laptop_store.load_upgrade().is_some());
    devices.laptop.state.lock_for_lifecycle().expect("locked");
    unblock(&staging);

    devices.upgrade(true);
    assert_ne!(devices.stored_digest(true), before);
    assert!(!devices.laptop_store.upgrade_path().exists());
    assert!(!devices.unsynced(true));
    assert_eq!(devices.run(true), Ok(Outcome::AlreadyCurrent));
    assert_eq!(devices.uploads(), 2);
}

#[test]
fn a_stop_before_the_mapping_is_removed_changes_nothing_at_the_next_unlock() {
    use crate::sync::coordinator::{Coordinator, Outcome};

    let devices = two_devices_synced_by_0_5_3(unchanged);
    devices.leave_on_format_10(true, unchanged);
    let busy = Coordinator::new();
    assert!(busy.begin());
    devices.upgrade_with(true, &busy);
    busy.finish(Outcome::AlreadyCurrent);
    let mapping = devices.laptop_store.upgrade_path();
    let tag = mapping.with_extension("json.tag");
    let kept = (
        std::fs::read(&mapping).expect("mapping"),
        std::fs::read(&tag).expect("mapping tag"),
    );
    devices.unlock_again(true);
    let adopted = devices.stored_digest(true);
    assert!(!mapping.exists());
    std::fs::write(&mapping, kept.0).expect("mapping left behind");
    std::fs::write(&tag, kept.1).expect("mapping tag left behind");

    devices.unlock_again(true);

    assert_eq!(devices.stored_digest(true), adopted);
    assert!(!mapping.exists());
    assert!(!devices.unsynced(true));
    assert_eq!(devices.run(true), Ok(Outcome::AlreadyCurrent));
    assert_eq!(devices.uploads(), 2);
}

fn rename_after_the_upgrade(payload: &mut crate::vault::VaultPayload) {
    payload.entries[0].title = "Northwind renamed on 0.6.0".into();
}

#[test]
fn an_edit_made_after_the_upgrade_and_before_the_first_run_uploads() {
    use crate::sync::coordinator::{Coordinator, Outcome};

    let devices = two_devices_synced_by_0_5_3(unchanged);
    devices.leave_on_format_10(true, unchanged);
    let busy = Coordinator::new();
    assert!(busy.begin());
    devices.upgrade_with(true, &busy);
    busy.finish(Outcome::AlreadyCurrent);

    devices.laptop.seed(rename_after_the_upgrade);

    assert!(devices.unsynced(true));
    assert_eq!(devices.run(true), Ok(Outcome::Uploaded { revision: 3 }));
    assert_eq!(devices.run(false), Ok(Outcome::Downloaded { revision: 3 }));
    assert_eq!(
        login_of(&devices.desktop).title,
        "Northwind renamed on 0.6.0"
    );
}

#[test]
fn an_edit_made_after_the_upgrade_still_uploads_after_a_lock() {
    use crate::sync::coordinator::{Coordinator, Outcome};

    let devices = two_devices_synced_by_0_5_3(unchanged);
    devices.leave_on_format_10(true, unchanged);
    let busy = Coordinator::new();
    assert!(busy.begin());
    devices.upgrade_with(true, &busy);
    devices.laptop.seed(rename_after_the_upgrade);
    devices.laptop.state.lock_for_lifecycle().expect("locked");
    busy.finish(Outcome::AlreadyCurrent);

    devices.upgrade(true);

    assert!(!devices.laptop_store.upgrade_path().exists());
    assert!(devices.unsynced(true));
    assert_eq!(devices.run(true), Ok(Outcome::Uploaded { revision: 3 }));
    assert_eq!(devices.run(false), Ok(Outcome::Downloaded { revision: 3 }));
    assert_eq!(
        login_of(&devices.desktop).title,
        "Northwind renamed on 0.6.0"
    );
}

#[test]
fn a_corrupt_mapping_is_ignored_and_removed_without_losing_anything() {
    use crate::sync::coordinator::{Coordinator, Outcome};

    let devices = two_devices_synced_by_0_5_3(unchanged);
    devices.leave_on_format_10(true, unchanged);
    let busy = Coordinator::new();
    assert!(busy.begin());
    devices.upgrade_with(true, &busy);
    busy.finish(Outcome::AlreadyCurrent);
    std::fs::write(devices.laptop_store.upgrade_path(), b"{\"before\":").expect("corrupt");

    devices.unlock_again(true);

    assert!(!devices.laptop_store.upgrade_path().exists());
    assert!(devices.unsynced(true));
    assert_eq!(devices.run(true), Ok(Outcome::Uploaded { revision: 3 }));
    assert_eq!(devices.run(false), Ok(Outcome::Downloaded { revision: 3 }));
}

#[test]
fn a_mapping_from_another_vault_is_ignored_and_removed() {
    use crate::sync::coordinator::Outcome;

    let devices = two_synced_devices();
    let foreign = sesame_core::UpgradeDigests {
        before: vec![payload_digest(b"fictional other vault")],
        after: payload_digest(b"fictional other vault upgraded"),
    };
    devices
        .laptop_store
        .save_upgrade(&foreign)
        .expect("foreign mapping");

    devices.unlock_again(true);

    assert_ne!(devices.stored_digest(true), foreign.after);
    assert!(!devices.laptop_store.upgrade_path().exists());
    assert!(!devices.unsynced(true));
    assert_eq!(devices.run(true), Ok(Outcome::AlreadyCurrent));
    assert_eq!(devices.uploads(), 1);
}

#[test]
fn an_upgrade_during_an_unfinished_join_is_kept_until_the_join_completes() {
    use crate::sync::coordinator::Outcome;

    let devices = two_devices_synced_by_0_5_3(unchanged);
    devices.leave_on_format_10(true, unchanged);
    let before = devices.stored_digest(true);
    let mut joining = devices.laptop_store.load_state().expect("state").expect("saved state");
    joining.pending_join = Some(sesame_sync::pairing::ApproverIdentity {
        device_id: "fictional-approver".into(),
        signing_key: "fictional-signing-key".into(),
        vault_id: joining.vault_id.clone(),
        head_digest: "fictional-head".into(),
    });
    devices.laptop_store.save_state(&joining).expect("joining state");

    devices.upgrade(true);

    assert!(devices.laptop_store.load_upgrade().is_some());
    joining.pending_join = None;
    devices.laptop_store.save_state(&joining).expect("join finished");
    assert_eq!(devices.stored_digest(true), before);
    assert_eq!(devices.run(true), Ok(Outcome::AlreadyCurrent));
    assert!(!devices.laptop_store.upgrade_path().exists());
    assert_eq!(devices.uploads(), 2);
}
