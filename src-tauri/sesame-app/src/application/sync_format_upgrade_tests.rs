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
        let (vault, _, scratch) = self.device(on_laptop);
        crate::application::lifecycle::unlock_vault_in_state(
            &vault.state,
            &crate::release::ReleasePresence::default(),
            &FakeEffects::with_sync(
                vault.path().to_path_buf(),
                scratch.path.clone(),
                crate::sync::coordinator::Coordinator::new(),
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
