use zeroize::Zeroizing;

use crate::types::{
    Card, CardInput, CustomRecord, CustomRecordInput, DocumentMetadata, DocumentMetadataInput,
    Identity, IdentityInput, LegacyField, SecureNote, SecureNoteInput, SoftwareLicense,
    SoftwareLicenseInput, SshKey, SshKeyInput, TaggedItem, VaultEntry, WifiNetwork,
    WifiNetworkInput,
};

pub trait SecretSlots {
    fn visit_secrets(&mut self, visit: &mut dyn FnMut(&str, &mut String));

    fn keep_secrets(&mut self, existing: &Self, kept: &[String])
    where
        Self: Sized + Clone,
    {
        let carried: Vec<(String, Zeroizing<String>)> = kept
            .iter()
            .filter_map(|key| secret_value(existing, key).map(|value| (key.clone(), value)))
            .collect();
        self.visit_secrets(&mut |slot, value| {
            if !value.is_empty() {
                return;
            }
            if let Some((_, previous)) = carried.iter().find(|(key, _)| key == slot) {
                *value = previous.to_string();
            }
        });
    }
}

pub trait KeptSecrets {
    fn kept_secrets(&self) -> Vec<String> {
        Vec::new()
    }
}

pub fn redacted_legacy(fields: &[LegacyField]) -> Vec<LegacyField> {
    fields
        .iter()
        .map(|field| LegacyField {
            label: field.label.clone(),
            value: if field.secret {
                String::new()
            } else {
                field.value.clone()
            },
            secret: field.secret,
        })
        .collect()
}

fn visit_legacy(fields: &mut [LegacyField], visit: &mut dyn FnMut(&str, &mut String)) {
    for (index, field) in fields.iter_mut().enumerate() {
        if field.secret {
            visit(&format!("legacy:{index}"), &mut field.value);
        }
    }
}

macro_rules! kept_secrets_from_field {
    ($($input:ty),* $(,)?) => {
        $(impl KeptSecrets for $input {
            fn kept_secrets(&self) -> Vec<String> {
                self.kept_secrets.clone()
            }
        })*
    };
}

kept_secrets_from_field!(
    CardInput,
    WifiNetworkInput,
    SshKeyInput,
    SoftwareLicenseInput,
    DocumentMetadataInput,
    CustomRecordInput,
);

impl KeptSecrets for IdentityInput {}
impl KeptSecrets for SecureNoteInput {}

impl SecretSlots for VaultEntry {
    fn visit_secrets(&mut self, visit: &mut dyn FnMut(&str, &mut String)) {
        visit("password", &mut self.password);
        visit_legacy(&mut self.legacy_fields, visit);
    }
}

impl SecretSlots for Identity {
    fn visit_secrets(&mut self, visit: &mut dyn FnMut(&str, &mut String)) {
        visit_legacy(&mut self.legacy_fields, visit);
    }
}

impl SecretSlots for SecureNote {
    fn visit_secrets(&mut self, visit: &mut dyn FnMut(&str, &mut String)) {
        visit_legacy(&mut self.legacy_fields, visit);
    }
}

impl SecretSlots for Card {
    fn visit_secrets(&mut self, visit: &mut dyn FnMut(&str, &mut String)) {
        visit("number", &mut self.number);
        visit("securityCode", &mut self.security_code);
        visit_legacy(&mut self.legacy_fields, visit);
    }
}

impl SecretSlots for WifiNetwork {
    fn visit_secrets(&mut self, visit: &mut dyn FnMut(&str, &mut String)) {
        visit("password", &mut self.password);
    }
}

impl SecretSlots for SshKey {
    fn visit_secrets(&mut self, visit: &mut dyn FnMut(&str, &mut String)) {
        visit("privateKey", &mut self.private_key);
        visit("passphrase", &mut self.passphrase);
    }
}

impl SecretSlots for SoftwareLicense {
    fn visit_secrets(&mut self, visit: &mut dyn FnMut(&str, &mut String)) {
        visit("licenseKey", &mut self.license_key);
    }
}

impl SecretSlots for DocumentMetadata {
    fn visit_secrets(&mut self, visit: &mut dyn FnMut(&str, &mut String)) {
        visit("documentNumber", &mut self.document_number);
    }
}

impl SecretSlots for CustomRecord {
    fn visit_secrets(&mut self, visit: &mut dyn FnMut(&str, &mut String)) {
        for (index, field) in self.fields.iter_mut().enumerate() {
            if field.kind == "secret" {
                visit(&format!("field:{index}"), &mut field.value);
            }
        }
    }

    fn keep_secrets(&mut self, existing: &Self, kept: &[String]) {
        for entry in kept {
            let Some(rest) = entry.strip_prefix("field:") else {
                continue;
            };
            let (new_index, old_index) = rest.split_once("<-").unwrap_or((rest, rest));
            let (Ok(new_index), Ok(old_index)) =
                (new_index.parse::<usize>(), old_index.parse::<usize>())
            else {
                continue;
            };
            let Some(previous) = existing
                .fields
                .get(old_index)
                .filter(|field| field.kind == "secret")
            else {
                continue;
            };
            if let Some(field) = self
                .fields
                .get_mut(new_index)
                .filter(|field| field.kind == "secret" && field.value.is_empty())
            {
                field.value = previous.value.clone();
            }
        }
    }
}

impl SecretSlots for TaggedItem {
    fn visit_secrets(&mut self, visit: &mut dyn FnMut(&str, &mut String)) {
        match self {
            TaggedItem::Login(item) => item.visit_secrets(visit),
            TaggedItem::Identity(item) => item.visit_secrets(visit),
            TaggedItem::SecureNote(item) => item.visit_secrets(visit),
            TaggedItem::Card(item) => item.visit_secrets(visit),
            TaggedItem::WifiNetwork(item) => item.visit_secrets(visit),
            TaggedItem::SshKey(item) => item.visit_secrets(visit),
            TaggedItem::SoftwareLicense(item) => item.visit_secrets(visit),
            TaggedItem::Document(item) => item.visit_secrets(visit),
            TaggedItem::CustomRecord(item) => item.visit_secrets(visit),
        }
    }
}

pub fn secret_keys<T: SecretSlots + Clone>(item: &T) -> Vec<String> {
    let mut copy = item.clone();
    let mut keys = Vec::new();
    copy.visit_secrets(&mut |key, _| keys.push(key.to_string()));
    keys
}

pub fn secret_value<T: SecretSlots + Clone>(item: &T, key: &str) -> Option<Zeroizing<String>> {
    let mut copy = item.clone();
    let mut found = None;
    copy.visit_secrets(&mut |slot, value| {
        if slot == key {
            found = Some(Zeroizing::new(std::mem::take(value)));
        }
    });
    found
}

pub fn has_secret<T: SecretSlots + Clone>(item: &T) -> bool {
    let mut copy = item.clone();
    let mut any = false;
    copy.visit_secrets(&mut |_, value| any |= !value.trim().is_empty());
    any
}

pub fn redact<T: SecretSlots>(item: &mut T) -> Vec<String> {
    let mut present = Vec::new();
    item.visit_secrets(&mut |key, value| {
        if !value.trim().is_empty() {
            present.push(key.to_string());
        }
        zeroize::Zeroize::zeroize(value);
    });
    present
}

#[cfg(test)]
mod tests {
    use super::*;

    const CANARY: &str = "fictional-secret-canary";

    fn card() -> Card {
        let mut card = Card::default();
        card.id = "card-a".to_string();
        card.title = "Fictional card".to_string();
        card.number = format!("{CANARY}-number");
        card.security_code = format!("{CANARY}-code");
        card.brand = "Fictional brand".to_string();
        card.legacy_fields = vec![
            LegacyField {
                label: "Old PIN".to_string(),
                value: format!("{CANARY}-legacy"),
                secret: true,
            },
            LegacyField {
                label: "Old note".to_string(),
                value: "fictional visible value".to_string(),
                secret: false,
            },
        ];
        card
    }

    #[test]
    fn a_card_names_every_secret_slot_including_secret_legacy_fields() {
        assert_eq!(
            secret_keys(&card()),
            vec!["number", "securityCode", "legacy:0"]
        );
    }

    #[test]
    fn redacting_blanks_each_secret_and_keeps_everything_else() {
        let mut item = card();

        let present = redact(&mut item);

        assert_eq!(present, vec!["number", "securityCode", "legacy:0"]);
        assert!(item.number.is_empty());
        assert!(item.security_code.is_empty());
        assert!(item.legacy_fields[0].value.is_empty());
        assert_eq!(item.legacy_fields[1].value, "fictional visible value");
        assert_eq!(item.brand, "Fictional brand");
        assert!(!serde_json::to_string(&item)
            .expect("serialized card")
            .contains(CANARY));
    }

    #[test]
    fn an_empty_secret_is_not_reported_as_present() {
        let mut item = card();
        item.security_code.clear();

        assert_eq!(redact(&mut item), vec!["number", "legacy:0"]);
    }

    #[test]
    fn a_secret_value_is_read_by_key_without_touching_the_item() {
        let item = card();

        assert_eq!(
            secret_value(&item, "securityCode")
                .as_deref()
                .map(String::as_str),
            Some(format!("{CANARY}-code").as_str())
        );
        assert!(secret_value(&item, "brand").is_none());
        assert_eq!(item.security_code, format!("{CANARY}-code"));
    }

    #[test]
    fn only_secret_kind_custom_fields_are_slots() {
        use crate::types::CustomFieldEntry;
        let mut record = CustomRecord::default();
        record.fields = vec![
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

        assert_eq!(secret_keys(&record), vec!["field:1"]);
        assert_eq!(redact(&mut record), vec!["field:1"]);
        assert_eq!(record.fields[0].value, "fictional visible");
        assert!(record.fields[1].value.is_empty());
    }

    #[test]
    fn every_item_kind_redacts_to_a_form_without_the_canary() {
        let mut login = VaultEntry::default();
        login.password = format!("{CANARY}-login");
        let mut wifi = WifiNetwork::default();
        wifi.password = format!("{CANARY}-wifi");
        let mut ssh = SshKey::default();
        ssh.private_key = format!("{CANARY}-private");
        ssh.passphrase = format!("{CANARY}-passphrase");
        let mut license = SoftwareLicense::default();
        license.license_key = format!("{CANARY}-license");
        let mut document = DocumentMetadata::default();
        document.document_number = format!("{CANARY}-document");
        let mut custom = CustomRecord::default();
        custom.fields = vec![crate::types::CustomFieldEntry {
            label: "Hidden".to_string(),
            value: format!("{CANARY}-custom"),
            kind: "secret".to_string(),
        }];
        let mut identity = Identity::default();
        identity.legacy_fields = vec![LegacyField {
            label: "Old".to_string(),
            value: format!("{CANARY}-identity"),
            secret: true,
        }];
        let mut note = SecureNote::default();
        note.legacy_fields = vec![LegacyField {
            label: "Old".to_string(),
            value: format!("{CANARY}-note"),
            secret: true,
        }];

        let mut items = vec![
            TaggedItem::Login(login),
            TaggedItem::Identity(identity),
            TaggedItem::SecureNote(note),
            TaggedItem::Card(card()),
            TaggedItem::WifiNetwork(wifi),
            TaggedItem::SshKey(ssh),
            TaggedItem::SoftwareLicense(license),
            TaggedItem::Document(document),
            TaggedItem::CustomRecord(custom),
        ];
        for item in &mut items {
            assert!(has_secret(item));
            assert!(!redact(item).is_empty());
            assert!(!has_secret(item));
            assert!(!serde_json::to_string(item)
                .expect("serialized item")
                .contains(CANARY));
        }
    }

    #[test]
    fn a_blank_secret_keeps_the_stored_value_only_when_it_is_listed_as_kept() {
        let existing = card();
        let mut next = Card::default();
        next.id = "card-a".to_string();

        next.keep_secrets(&existing, &["number".to_string()]);

        assert_eq!(next.number, format!("{CANARY}-number"));
        assert!(next.security_code.is_empty());
    }

    #[test]
    fn a_typed_secret_wins_over_a_kept_one() {
        let existing = card();
        let mut next = Card::default();
        next.number = "fictional-new-number".to_string();

        next.keep_secrets(&existing, &["number".to_string()]);

        assert_eq!(next.number, "fictional-new-number");
    }

    #[test]
    fn an_unknown_or_plain_key_keeps_nothing() {
        let existing = card();
        let mut next = Card::default();

        next.keep_secrets(&existing, &["brand".to_string(), "missing".to_string()]);

        assert!(next.brand.is_empty());
        assert!(next.number.is_empty());
    }

    #[test]
    fn a_custom_secret_follows_its_row_to_a_new_position() {
        use crate::types::CustomFieldEntry;
        let entry = |label: &str, value: &str, kind: &str| CustomFieldEntry {
            label: label.to_string(),
            value: value.to_string(),
            kind: kind.to_string(),
        };
        let mut existing = CustomRecord::default();
        existing.fields = vec![
            entry("Hidden", &format!("{CANARY}-custom"), "secret"),
            entry("Plain", "fictional plain", "text"),
        ];
        let mut next = CustomRecord::default();
        next.fields = vec![
            entry("Plain", "fictional plain", "text"),
            entry("Hidden", "", "secret"),
        ];

        next.keep_secrets(&existing, &["field:1<-0".to_string()]);

        assert_eq!(next.fields[1].value, format!("{CANARY}-custom"));
        assert_eq!(next.fields[0].value, "fictional plain");
    }

    #[test]
    fn a_custom_key_that_points_at_a_plain_row_or_a_typed_value_keeps_nothing() {
        use crate::types::CustomFieldEntry;
        let entry = |value: &str, kind: &str| CustomFieldEntry {
            label: "Row".to_string(),
            value: value.to_string(),
            kind: kind.to_string(),
        };
        let mut existing = CustomRecord::default();
        existing.fields = vec![
            entry("fictional plain", "text"),
            entry(&format!("{CANARY}-custom"), "secret"),
        ];
        let mut next = CustomRecord::default();
        next.fields = vec![entry("", "secret"), entry("fictional typed", "secret")];

        next.keep_secrets(
            &existing,
            &[
                "field:0<-0".to_string(),
                "field:1<-1".to_string(),
                "field:x".to_string(),
            ],
        );

        assert!(next.fields[0].value.is_empty());
        assert_eq!(next.fields[1].value, "fictional typed");
    }
}
