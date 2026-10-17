use serde::Serialize;
use sesame_core::secret_fields::{redact, secret_value, SecretSlots};
use tauri::{AppHandle, State};
use zeroize::Zeroizing;

use crate::adapters::network::breach;
use crate::adapters::platform::clipboard::{copy_secret_value, ClipboardGuard};
use crate::commands::require_release_presence;
use crate::release::ReleasePresence;
use crate::vault::{TaggedItem, VaultResult, VaultState};

const BACKUP_CODES: &str = "backupCodes";

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecordView<T> {
    #[serde(flatten)]
    pub record: T,
    pub secret_fields: Vec<String>,
}

pub fn redacted_view<T: SecretSlots>(mut record: T) -> RecordView<T> {
    let secret_fields = redact(&mut record);
    RecordView {
        record,
        secret_fields,
    }
}

fn record_item(state: &VaultState, id: &str, kind: &str) -> VaultResult<TaggedItem> {
    let session = state
        .session
        .lock()
        .map_err(|_| "Sesame could not read the vault session.".to_string())?;
    let session = session.as_ref().ok_or("Unlock your vault first.")?;
    let item = session.open_item(id.trim())?;
    if item.kind() != kind {
        return Err("That saved item no longer exists.".into());
    }
    Ok((*item).clone())
}

pub(crate) fn item_field_in_state(
    state: &VaultState,
    presence: &ReleasePresence,
    id: &str,
    kind: &str,
    field: &str,
) -> VaultResult<Zeroizing<String>> {
    require_release_presence(state, presence)?;
    let item = record_item(state, id, kind)?;
    let field = field.trim();
    let value = match &item {
        TaggedItem::Login(entry) if field == BACKUP_CODES => {
            Some(Zeroizing::new(entry.backup_codes.join("\n")))
        }
        _ => secret_value(&item, field),
    };
    value
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| "Nothing is saved in that field for this item.".to_string())
}

#[tauri::command]
pub fn release_item_field(
    id: String,
    kind: String,
    field: String,
    state: State<'_, VaultState>,
    presence: State<'_, ReleasePresence>,
) -> VaultResult<String> {
    item_field_in_state(&state, &presence, &id, &kind, &field).map(|value| value.to_string())
}

#[tauri::command]
pub fn copy_item_field(
    app: AppHandle,
    id: String,
    kind: String,
    field: String,
    clear_after_ms: Option<u64>,
    state: State<'_, VaultState>,
    presence: State<'_, ReleasePresence>,
    clipboard: State<'_, ClipboardGuard>,
) -> VaultResult<u64> {
    let value = item_field_in_state(&state, &presence, &id, &kind, &field)?;
    copy_secret_value(app, &clipboard, value.to_string(), clear_after_ms)
}

#[tauri::command]
pub async fn check_login_breach(
    id: String,
    state: State<'_, VaultState>,
    presence: State<'_, ReleasePresence>,
) -> VaultResult<breach::BreachCheckResult> {
    let password = item_field_in_state(&state, &presence, &id, "login", "password")?;
    breach::check_password_breach(password.to_string()).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::cards::save_card_in_state;
    use crate::commands::custom_records::save_custom_record_in_state;
    use crate::commands::ssh_keys::save_ssh_key_in_state;
    use crate::commands::test_support::TestVault;
    use crate::release::PRESENCE_REQUIRED;
    use crate::vault::{
        Card, CardInput, CustomFieldEntry, CustomRecord, CustomRecordInput, LegacyField,
        SoftwareLicense, SshKey, SshKeyInput, WifiNetwork,
    };
    use std::time::{Duration, Instant};

    const CANARY: &str = "fictional-secret-canary";

    fn seeded_vault() -> TestVault {
        let vault = TestVault::with_login("fictional-login", "https://northwind.example");
        vault.seed(|payload| {
            payload.entries[0].backup_codes = vec![
                "fictional-code-1".to_string(),
                "fictional-code-2".to_string(),
            ];
            payload.entries[0].legacy_fields = vec![LegacyField {
                label: "Old PIN".to_string(),
                value: format!("{CANARY}-legacy"),
                secret: true,
            }];
            let mut card = Card::default();
            card.id = "fictional-card".to_string();
            card.title = "Fictional card".to_string();
            card.number = format!("{CANARY}-number");
            card.security_code = format!("{CANARY}-code");
            payload.cards.push(card);
            let mut empty_card = Card::default();
            empty_card.id = "fictional-empty-card".to_string();
            empty_card.title = "Fictional empty card".to_string();
            payload.cards.push(empty_card);
            let mut network = WifiNetwork::default();
            network.id = "fictional-wifi".to_string();
            network.password = format!("{CANARY}-wifi");
            payload.wifi_networks.push(network);
            let mut key = SshKey::default();
            key.id = "fictional-ssh".to_string();
            key.title = "Fictional key".to_string();
            key.private_key = format!("{CANARY}-private");
            key.passphrase = format!("{CANARY}-passphrase");
            payload.ssh_keys.push(key);
            let mut license = SoftwareLicense::default();
            license.id = "fictional-license".to_string();
            license.license_key = format!("{CANARY}-license");
            payload.software_licenses.push(license);
            let mut custom = CustomRecord::default();
            custom.id = "fictional-custom".to_string();
            custom.title = "Fictional record".to_string();
            custom.fields = vec![
                CustomFieldEntry {
                    label: "Visible".to_string(),
                    value: "fictional visible".to_string(),
                    kind: "text".to_string(),
                },
                CustomFieldEntry {
                    label: "Hidden".to_string(),
                    value: format!("{CANARY}-custom"),
                    kind: "secret".to_string(),
                },
            ];
            payload.custom_records.push(custom);
        });
        vault
    }

    fn grant(vault: &TestVault, presence: &ReleasePresence) {
        let session = vault.state.session.lock().expect("session lock");
        presence
            .grant_with_password(
                session.as_ref().expect("session"),
                vault.state.session_epoch(),
                "fictional master password",
            )
            .expect("granted presence");
    }

    fn stored(vault: &TestVault, id: &str) -> TaggedItem {
        let session = vault.state.session.lock().expect("session lock");
        (*session
            .as_ref()
            .expect("session")
            .open_item(id)
            .expect("stored item"))
        .clone()
    }

    const SECRET_ITEMS: [(&str, &str, &str); 8] = [
        ("fictional-card", "card", "number"),
        ("fictional-wifi", "wifi_network", "password"),
        ("fictional-ssh", "ssh_key", "privateKey"),
        ("fictional-license", "software_license", "licenseKey"),
        ("fictional-custom", "custom_record", "field:1"),
        ("fictional-login", "login", "password"),
        ("fictional-login", "login", "backupCodes"),
        ("fictional-login", "login", "legacy:0"),
    ];

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
    fn revealing_and_copying_a_field_need_a_grant_every_time() {
        let vault = seeded_vault();
        let presence = ReleasePresence::default();

        for (id, kind, field) in SECRET_ITEMS {
            let error = item_field_in_state(&vault.state, &presence, id, kind, field)
                .expect_err("no grant");
            assert_eq!(error, PRESENCE_REQUIRED, "{id} {field}");
        }

        grant(&vault, &presence);
        for (id, kind, field) in SECRET_ITEMS {
            let value = item_field_in_state(&vault.state, &presence, id, kind, field)
                .unwrap_or_else(|error| panic!("{id} {field}: {error}"));
            assert!(!value.is_empty(), "{id} {field}");
        }
    }

    #[test]
    fn the_login_backup_codes_come_back_as_one_line_each() {
        let vault = seeded_vault();
        let presence = ReleasePresence::default();
        grant(&vault, &presence);

        let value = item_field_in_state(
            &vault.state,
            &presence,
            "fictional-login",
            "login",
            "backupCodes",
        )
        .expect("released");

        assert_eq!(value.as_str(), "fictional-code-1\nfictional-code-2");
    }

    #[test]
    fn an_expired_stale_or_revoked_grant_releases_no_field() {
        let vault = seeded_vault();
        let presence = ReleasePresence::default();

        presence.grant_until(
            vault.state.session_epoch(),
            Instant::now() - Duration::from_secs(1),
        );
        assert_eq!(
            item_field_in_state(&vault.state, &presence, "fictional-card", "card", "number")
                .map(|value| value.to_string()),
            Err(PRESENCE_REQUIRED.to_string())
        );

        grant(&vault, &presence);
        vault.state.advance_session_epoch();
        assert_eq!(
            item_field_in_state(&vault.state, &presence, "fictional-card", "card", "number")
                .map(|value| value.to_string()),
            Err(PRESENCE_REQUIRED.to_string())
        );

        grant(&vault, &presence);
        presence.revoke();
        assert_eq!(
            item_field_in_state(&vault.state, &presence, "fictional-card", "card", "number")
                .map(|value| value.to_string()),
            Err(PRESENCE_REQUIRED.to_string())
        );
    }

    #[test]
    fn a_wrong_kind_a_plain_field_an_empty_secret_or_a_missing_item_is_refused_even_with_a_grant() {
        let vault = seeded_vault();
        let presence = ReleasePresence::default();
        grant(&vault, &presence);
        let refused = |id: &str, kind: &str, field: &str| {
            item_field_in_state(&vault.state, &presence, id, kind, field).is_err()
        };

        assert!(refused("fictional-card", "wifi_network", "number"));
        assert!(refused("fictional-card", "card", "title"));
        assert!(refused("fictional-empty-card", "card", "number"));
        assert!(refused("missing", "card", "number"));
        assert!(refused("fictional-login", "card", "password"));
        assert!(!refused("fictional-card", "card", "securityCode"));
    }

    #[test]
    fn a_locked_vault_releases_nothing() {
        let vault = seeded_vault();
        let presence = ReleasePresence::default();
        grant(&vault, &presence);
        *vault.state.session.lock().expect("session lock") = None;

        assert!(
            item_field_in_state(&vault.state, &presence, "fictional-card", "card", "number")
                .is_err()
        );
    }

    fn card_input(number: &str, kept: &[&str]) -> CardInput {
        serde_json::from_value(serde_json::json!({
            "id": "fictional-card",
            "title": "Fictional card",
            "number": number,
            "keptSecrets": kept,
        }))
        .expect("card input")
    }

    #[test]
    fn saving_a_card_with_its_secrets_kept_leaves_them_as_stored() {
        let vault = seeded_vault();

        save_card_in_state(card_input("", &["number", "securityCode"]), &vault.state)
            .expect("saved card");

        let stored_item = stored(&vault, "fictional-card");
        let TaggedItem::Card(card) = &stored_item else {
            panic!("not a card");
        };
        assert_eq!(card.number, format!("{CANARY}-number"));
        assert_eq!(card.security_code, format!("{CANARY}-code"));
        assert_eq!(card.revision, 1);
    }

    #[test]
    fn saving_a_card_without_keeping_a_blank_secret_removes_it() {
        let vault = seeded_vault();

        save_card_in_state(card_input("", &["securityCode"]), &vault.state).expect("saved card");

        let stored_item = stored(&vault, "fictional-card");
        let TaggedItem::Card(card) = &stored_item else {
            panic!("not a card");
        };
        assert!(card.number.is_empty());
        assert_eq!(card.security_code, format!("{CANARY}-code"));
    }

    #[test]
    fn a_typed_card_number_replaces_the_stored_one_even_when_listed_as_kept() {
        let vault = seeded_vault();

        save_card_in_state(
            card_input("fictional-new-number", &["number", "securityCode"]),
            &vault.state,
        )
        .expect("saved card");

        let stored_item = stored(&vault, "fictional-card");
        let TaggedItem::Card(card) = &stored_item else {
            panic!("not a card");
        };
        assert_eq!(card.number, "fictional-new-number");
        assert_eq!(card.security_code, format!("{CANARY}-code"));
    }

    #[test]
    fn keeping_a_secret_never_reaches_across_items() {
        let vault = seeded_vault();
        let input: CardInput = serde_json::from_value(serde_json::json!({
            "title": "Fictional new card",
            "keptSecrets": ["number", "securityCode"],
        }))
        .expect("card input");

        let result = save_card_in_state(input, &vault.state).expect("saved card");

        let stored_item = stored(&vault, &result.id);
        let TaggedItem::Card(card) = &stored_item else {
            panic!("not a card");
        };
        assert!(card.number.is_empty());
        assert!(card.security_code.is_empty());
    }

    #[test]
    fn the_old_secret_stays_in_history_after_a_kept_save_replaces_another_secret() {
        let vault = seeded_vault();

        save_ssh_key_in_state(
            serde_json::from_value::<SshKeyInput>(serde_json::json!({
                "id": "fictional-ssh",
                "title": "Fictional key",
                "privateKey": "fictional-new-private",
                "keptSecrets": ["passphrase"],
            }))
            .expect("ssh input"),
            &vault.state,
        )
        .expect("saved key");

        let stored_item = stored(&vault, "fictional-ssh");
        let TaggedItem::SshKey(key) = &stored_item else {
            panic!("not a key");
        };
        assert_eq!(key.private_key, "fictional-new-private");
        assert_eq!(key.passphrase, format!("{CANARY}-passphrase"));
        let session = vault.state.session.lock().expect("session lock");
        let payload = session
            .as_ref()
            .expect("session")
            .open_payload()
            .expect("payload");
        assert_eq!(payload.history.len(), 1);
    }

    #[test]
    fn a_custom_secret_follows_its_row_through_a_save() {
        let vault = seeded_vault();
        let input: CustomRecordInput = serde_json::from_value(serde_json::json!({
            "id": "fictional-custom",
            "title": "Fictional record",
            "fields": [
                { "label": "Hidden", "value": "", "kind": "secret" },
                { "label": "Visible", "value": "fictional visible", "kind": "text" },
            ],
            "keptSecrets": ["field:0<-1"],
        }))
        .expect("custom input");

        save_custom_record_in_state(input, &vault.state).expect("saved record");

        let stored_item = stored(&vault, "fictional-custom");
        let TaggedItem::CustomRecord(record) = &stored_item else {
            panic!("not a record");
        };
        assert_eq!(record.fields[0].value, format!("{CANARY}-custom"));
        assert_eq!(record.fields[1].value, "fictional visible");
    }
}
