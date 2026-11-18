use std::fs;
use std::path::{Path, PathBuf};

use sesame_core::api::{create_vault, open_vault_with_password};
use sesame_core::backup::{inspect_backup_file, preserve_vault_before_upgrade};
use sesame_core::crypto::{encrypt_bytes, serialize_payload};
use sesame_core::loader::{LoadFailure, VaultLoader};
use sesame_core::storage::{
    complete_recovery_setup_for_session, persist_session, resume_recovery_setup_for_session,
};
use sesame_core::{
    random_id, BackupCompatibility, EmailAliasService, EmailAliasSettings, HistoryEntry,
    HistoryOperation, LegacyField, MatchRule, TaggedItem, TrashedItem, UnlockedVault, VaultEntry,
    VaultFile, VaultPayload, FORMAT_10_PAYLOAD_AAD, FORMAT_10_PENDING_SETUP_PAYLOAD_AAD,
    PAYLOAD_AAD, PENDING_SETUP_PAYLOAD_AAD, VAULT_FORMAT_VERSION,
};

const PASSWORD: &str = "fictional master password";
const VISIBLE_VALUE: &str = "fictional member number";
const SECRET_VALUE: &str = "fictional-secret-canary";

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("sesame-format-11-{}", random_id()));
        fs::create_dir_all(&path).expect("test directory");
        Self(path)
    }

    fn vault(&self) -> PathBuf {
        self.0.join("vault.sesame")
    }

    fn upgrade_backups(&self) -> Vec<PathBuf> {
        let Ok(entries) = fs::read_dir(self.0.join("backups")) else {
            return Vec::new();
        };
        let mut paths = entries
            .flatten()
            .map(|entry| entry.path())
            .filter(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.starts_with("sesame-before-upgrade-"))
            })
            .collect::<Vec<_>>();
        paths.sort();
        paths
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn legacy_fields() -> Vec<LegacyField> {
    vec![
        LegacyField {
            label: "Member number".to_string(),
            value: VISIBLE_VALUE.to_string(),
            secret: false,
        },
        LegacyField {
            label: "Security answer".to_string(),
            value: SECRET_VALUE.to_string(),
            secret: true,
        },
    ]
}

fn login_with_legacy_fields(id: &str) -> VaultEntry {
    let mut entry = VaultEntry::default();
    entry.id = id.to_string();
    entry.title = "Northwind".to_string();
    entry.url = "https://northwind.test".to_string();
    entry.username = "casey".to_string();
    entry.password = "fictional password".to_string();
    entry.created_at = 1_700_000_000;
    entry.updated_at = 1_700_000_100;
    entry.password_updated_at = 1_700_000_090;
    entry.revision = 1;
    entry.legacy_fields = legacy_fields();
    entry
}

fn format_10_vault(setup_complete: bool) -> (VaultFile, String) {
    let (mut opened, kit) = create_vault(PASSWORD, "Fictional vault").expect("created vault");
    if setup_complete {
        opened
            .payload
            .entries
            .push(login_with_legacy_fields("login-alpha"));
        opened.payload.trash.push(TrashedItem {
            item: TaggedItem::Login(login_with_legacy_fields("login-trashed")),
            deleted_at: 1_700_000_200,
        });
        opened.payload.history.push(HistoryEntry {
            id: "history-alpha".to_string(),
            item: TaggedItem::Login(login_with_legacy_fields("login-alpha")),
            captured_at: 1_700_000_150,
            operation: HistoryOperation::Edit,
        });
    }
    let aad = if setup_complete {
        FORMAT_10_PAYLOAD_AAD
    } else {
        FORMAT_10_PENDING_SETUP_PAYLOAD_AAD
    };
    let mut file = opened.file.clone();
    file.format_version = 10;
    file.setup_complete = setup_complete;
    file.payload = encrypt_bytes(
        &opened.key,
        &serialize_payload(&opened.payload).expect("serialized payload"),
        aad,
    )
    .expect("sealed format 10 payload");
    (file, kit)
}

fn write_file(path: &Path, file: &VaultFile) -> Vec<u8> {
    let bytes = serde_json::to_vec(file).expect("encoded vault");
    fs::write(path, &bytes).expect("wrote vault");
    bytes
}

fn unlock(path: &Path) -> (UnlockedVault, bool) {
    let file = VaultLoader::read(path).expect("read vault");
    let opened = open_vault_with_password(&file, PASSWORD).expect("opened vault");
    let session = UnlockedVault::from_opened(path.to_path_buf(), &opened).expect("session");
    (session, opened.migrated)
}

fn assert_legacy_fields_moved(entry: &VaultEntry) {
    assert!(entry.legacy_fields.is_empty());
    assert_eq!(entry.custom_fields.len(), 2);
    assert_eq!(entry.custom_fields[0].label, "Member number");
    assert_eq!(entry.custom_fields[0].value, VISIBLE_VALUE);
    assert_eq!(entry.custom_fields[0].kind, "text");
    assert_eq!(entry.custom_fields[1].label, "Security answer");
    assert_eq!(entry.custom_fields[1].value, SECRET_VALUE);
    assert_eq!(entry.custom_fields[1].kind, "secret");
    assert_eq!(entry.match_rule, MatchRule::Exact);
}

fn assert_payload_migrated(payload: &VaultPayload) {
    assert_legacy_fields_moved(&payload.entries[0]);
    let TaggedItem::Login(trashed) = &payload.trash[0].item else {
        panic!("trashed login");
    };
    assert_legacy_fields_moved(trashed);
    let TaggedItem::Login(previous) = &payload.history[0].item else {
        panic!("history login");
    };
    assert_legacy_fields_moved(previous);
    assert!(payload.never_save_sites.is_empty());
    assert!(payload.email_aliases.is_none());
}

fn written_payload(file: &VaultFile) -> serde_json::Value {
    let authenticated = VaultLoader::authenticate(
        file,
        sesame_core::loader::Credential::MasterPassword(PASSWORD),
    )
    .expect("authenticated payload");
    serde_json::from_slice(authenticated.bytes()).expect("payload json")
}

#[test]
fn a_format_10_vault_opens_as_format_11_with_its_login_fields_intact() {
    let (file, _) = format_10_vault(true);
    let opened = open_vault_with_password(&file, PASSWORD).expect("format 10 opens");

    assert!(opened.migrated);
    assert_eq!(opened.migration.source_format, 10);
    assert_eq!(opened.file.format_version, VAULT_FORMAT_VERSION);
    assert!(opened.file.setup_complete);
    assert_payload_migrated(&opened.payload);
    assert_eq!(opened.payload.entries[0].created_at, 1_700_000_000);
    assert_eq!(opened.payload.entries[0].updated_at, 1_700_000_100);
}

#[test]
fn saving_an_upgraded_vault_keeps_one_untouched_format_10_copy() {
    let directory = TestDirectory::new();
    let path = directory.vault();
    let (file, kit) = format_10_vault(true);
    let original = write_file(&path, &file);

    let (mut session, migrated) = unlock(&path);
    assert!(migrated);
    assert!(session.format_upgrade_pending());
    persist_session(&mut session).expect("saved the upgrade");
    assert!(!session.format_upgrade_pending());

    let backups = directory.upgrade_backups();
    assert_eq!(backups.len(), 1);
    assert_eq!(fs::read(&backups[0]).expect("backup bytes"), original);
    let inspection = inspect_backup_file(&backups[0]).expect("backup inspection");
    assert_eq!(inspection.format_version, 10);
    assert_eq!(inspection.compatibility, BackupCompatibility::Upgrade);

    let upgraded = VaultLoader::read(&path).expect("upgraded vault");
    assert_eq!(upgraded.format_version, VAULT_FORMAT_VERSION);
    assert!(upgraded.setup_complete);
    let reopened = open_vault_with_password(&upgraded, PASSWORD).expect("upgraded opens");
    assert!(!reopened.migrated);
    assert_payload_migrated(&reopened.payload);
    let with_kit = VaultLoader::open(
        &upgraded,
        sesame_core::loader::Credential::RecoveryKit(&kit),
    )
    .expect("recovery kit opens the upgraded vault");
    assert_eq!(with_kit.payload.vault_id, reopened.payload.vault_id);

    persist_session(&mut session).expect("a later save");
    assert_eq!(directory.upgrade_backups().len(), 1);
}

#[test]
fn a_crash_after_the_backup_leaves_a_format_10_vault_that_opens() {
    let directory = TestDirectory::new();
    let path = directory.vault();
    let (file, _) = format_10_vault(true);
    let original = write_file(&path, &file);

    let name = preserve_vault_before_upgrade(&path)
        .expect("backup written")
        .expect("backup named");
    assert_eq!(fs::read(&path).expect("vault bytes"), original);
    assert_eq!(
        fs::read(directory.0.join("backups").join(&name)).expect("backup bytes"),
        original
    );

    let (mut session, migrated) = unlock(&path);
    assert!(migrated);
    assert_payload_migrated(&session.open_payload().expect("payload"));
    persist_session(&mut session).expect("the upgrade saves after the crash");

    let backups = directory.upgrade_backups();
    assert_eq!(backups.len(), 1);
    assert_eq!(fs::read(&backups[0]).expect("backup bytes"), original);
    assert_eq!(
        VaultLoader::read(&path).expect("vault").format_version,
        VAULT_FORMAT_VERSION
    );
}

#[test]
fn a_failed_vault_write_after_the_backup_leaves_the_format_10_vault_in_place() {
    let directory = TestDirectory::new();
    let path = directory.vault();
    let (file, _) = format_10_vault(true);
    let original = write_file(&path, &file);
    let blocker = path.with_extension("sesame.prev");
    fs::create_dir_all(blocker.join("occupied")).expect("blocked previous copy");

    let (mut session, _) = unlock(&path);
    assert!(persist_session(&mut session).is_err());
    assert!(session.format_upgrade_pending());
    assert_eq!(fs::read(&path).expect("vault bytes"), original);
    assert_eq!(directory.upgrade_backups().len(), 1);
    let (reopened, migrated) = unlock(&path);
    assert!(migrated);
    assert_payload_migrated(&reopened.open_payload().expect("payload"));

    fs::remove_dir_all(&blocker).expect("removed blocker");
    persist_session(&mut session).expect("the retry saves");
    assert_eq!(directory.upgrade_backups().len(), 1);
    assert_eq!(
        fs::read(&directory.upgrade_backups()[0]).expect("backup bytes"),
        original
    );
    assert_eq!(
        VaultLoader::read(&path).expect("vault").format_version,
        VAULT_FORMAT_VERSION
    );
}

#[test]
fn a_pending_format_10_vault_stays_pending_until_its_kit_is_verified() {
    let directory = TestDirectory::new();
    let path = directory.vault();
    let (file, kit) = format_10_vault(false);
    let original = write_file(&path, &file);

    let opened = open_vault_with_password(&file, PASSWORD).expect("pending format 10 opens");
    assert!(opened.migrated);
    assert_eq!(opened.file.format_version, VAULT_FORMAT_VERSION);
    assert!(!opened.file.setup_complete);

    let (mut session, _) = unlock(&path);
    assert!(!session.setup_complete);
    assert!(persist_session(&mut session).is_err());
    assert_eq!(fs::read(&path).expect("vault bytes"), original);

    complete_recovery_setup_for_session(&mut session, &kit).expect("setup completes");
    let completed = VaultLoader::read(&path).expect("completed vault");
    assert_eq!(completed.format_version, VAULT_FORMAT_VERSION);
    assert!(completed.setup_complete);
    assert!(open_vault_with_password(&completed, PASSWORD).is_ok());
    let backups = directory.upgrade_backups();
    assert_eq!(backups.len(), 1);
    assert_eq!(fs::read(&backups[0]).expect("backup bytes"), original);
}

#[test]
fn resuming_setup_on_a_pending_format_10_vault_keeps_no_copy_of_the_abandoned_kit() {
    let directory = TestDirectory::new();
    let path = directory.vault();
    let (file, abandoned_kit) = format_10_vault(false);
    write_file(&path, &file);

    let (mut session, _) = unlock(&path);
    let kit = resume_recovery_setup_for_session(&mut session).expect("setup resumes");
    assert_ne!(kit, abandoned_kit);
    let resumed = VaultLoader::read(&path).expect("resumed vault");
    assert_eq!(resumed.format_version, VAULT_FORMAT_VERSION);
    assert!(!resumed.setup_complete);
    assert!(open_vault_with_password(&resumed, PASSWORD).is_ok());
    assert!(directory.upgrade_backups().is_empty());
    assert!(!path.with_extension("sesame.prev").exists());
}

#[test]
fn an_older_header_cannot_downgrade_a_format_11_payload() {
    let (opened, _) = create_vault(PASSWORD, "Fictional vault").expect("created vault");
    for (setup_complete, aad) in [(true, PAYLOAD_AAD), (false, PENDING_SETUP_PAYLOAD_AAD)] {
        let mut file = opened.file.clone();
        file.setup_complete = setup_complete;
        file.payload = encrypt_bytes(
            &opened.key,
            &serialize_payload(&opened.payload).expect("serialized payload"),
            aad,
        )
        .expect("sealed format 11 payload");
        assert!(open_vault_with_password(&file, PASSWORD).is_ok());

        let mut downgraded = file.clone();
        downgraded.format_version = 10;
        assert_eq!(
            VaultLoader::open(
                &downgraded,
                sesame_core::loader::Credential::MasterPassword(PASSWORD)
            )
            .err(),
            Some(LoadFailure::Authentication),
            "a format 11 payload authenticated under a format 10 header"
        );
    }

    let (format_10, _) = format_10_vault(true);
    let mut relabelled = format_10.clone();
    relabelled.format_version = VAULT_FORMAT_VERSION;
    assert_eq!(
        VaultLoader::open(
            &relabelled,
            sesame_core::loader::Credential::MasterPassword(PASSWORD)
        )
        .err(),
        Some(LoadFailure::Authentication)
    );
}

#[test]
fn a_format_12_vault_still_needs_a_newer_sesame() {
    let directory = TestDirectory::new();
    let (opened, _) = create_vault(PASSWORD, "Fictional vault").expect("created vault");
    let mut file = opened.file.clone();
    file.format_version = VAULT_FORMAT_VERSION + 1;
    let path = directory.0.join("newer.sesame");
    let bytes = write_file(&path, &file);

    let failure = LoadFailure::NewerFormat { format: 12 };
    assert_eq!(VaultLoader::parse(&bytes).err(), Some(failure));
    assert_eq!(
        failure.to_string(),
        "This vault requires a newer version of Sesame."
    );
    assert_eq!(VaultLoader::compatibility(12), BackupCompatibility::Newer);
    assert_eq!(
        inspect_backup_file(&path)
            .expect("newer backup inspection")
            .compatibility,
        BackupCompatibility::Newer
    );
    assert_eq!(preserve_vault_before_upgrade(&path).expect("no copy"), None);
}

const ALIAS_TOKEN: &str = "fictional-alias-token";

fn format_11_vault_with_payload(edit: impl FnOnce(&mut serde_json::Value)) -> (VaultFile, String) {
    let (opened, kit) = create_vault(PASSWORD, "Fictional vault").expect("created vault");
    let mut payload: serde_json::Value =
        serde_json::from_slice(&serialize_payload(&opened.payload).expect("serialized payload"))
            .expect("payload json");
    edit(&mut payload);
    let mut file = opened.file.clone();
    file.setup_complete = true;
    file.payload = encrypt_bytes(
        &opened.key,
        &serde_json::to_vec(&payload).expect("payload bytes"),
        PAYLOAD_AAD,
    )
    .expect("sealed format 11 payload");
    (file, kit)
}

fn with_email_aliases(value: serde_json::Value) -> impl FnOnce(&mut serde_json::Value) {
    move |payload| {
        payload["emailAliases"] = value;
    }
}

#[test]
fn a_format_11_vault_with_email_aliases_opens_and_keeps_them_through_a_save() {
    let directory = TestDirectory::new();
    let path = directory.vault();
    let (file, kit) = format_11_vault_with_payload(with_email_aliases(serde_json::json!({
        "service": "addy",
        "token": ALIAS_TOKEN,
        "domain": "anonaddy.me",
        "nameSite": true,
    })));
    let original = write_file(&path, &file);
    assert!(!String::from_utf8_lossy(&original).contains(ALIAS_TOKEN));

    let (mut session, migrated) = unlock(&path);
    assert!(!migrated);
    let expected =
        EmailAliasSettings::validated(EmailAliasService::Addy, ALIAS_TOKEN, "anonaddy.me", true)
            .expect("valid settings");
    {
        let payload = session.open_payload().expect("payload");
        let settings = payload.email_aliases.as_ref().expect("alias settings");
        assert!(settings == &expected);
        assert!(settings.is_valid());
    }
    persist_session(&mut session).expect("saved");

    let saved = VaultLoader::read(&path).expect("saved vault");
    assert_eq!(saved.format_version, VAULT_FORMAT_VERSION);
    assert_eq!(
        written_payload(&saved)["emailAliases"],
        serde_json::json!({
            "service": "addy",
            "token": ALIAS_TOKEN,
            "domain": "anonaddy.me",
            "nameSite": true,
        })
    );
    for credential in [
        sesame_core::loader::Credential::MasterPassword(PASSWORD),
        sesame_core::loader::Credential::RecoveryKit(&kit),
    ] {
        let reopened = VaultLoader::open(&saved, credential).expect("reopened");
        assert!(!reopened.migrated);
        assert!(reopened.payload.email_aliases.as_ref() == Some(&expected));
    }
}

#[test]
fn a_simplelogin_setting_writes_only_the_fields_it_has() {
    let (file, _) = format_11_vault_with_payload(with_email_aliases(serde_json::json!({
        "service": "simpleLogin",
        "token": ALIAS_TOKEN,
    })));
    let opened = open_vault_with_password(&file, PASSWORD).expect("opened");
    let written: serde_json::Value =
        serde_json::from_slice(&serialize_payload(&opened.payload).expect("serialized payload"))
            .expect("payload json");
    assert_eq!(
        written["emailAliases"],
        serde_json::json!({ "service": "simpleLogin", "token": ALIAS_TOKEN })
    );
}

fn payload_without_email_aliases() -> VaultPayload {
    let mut payload = VaultPayload::default();
    payload.vault_name = "Fictional vault".to_string();
    payload.vault_id = Some("fictional-vault-id".to_string());
    payload.revision = 7;
    payload.never_save_sites = vec!["https://fictional.example".to_string()];
    let mut entry = VaultEntry::default();
    entry.id = "login-alpha".to_string();
    entry.title = "Northwind".to_string();
    entry.url = "https://northwind.test".to_string();
    entry.username = "casey".to_string();
    entry.password = "fictional password".to_string();
    entry.created_at = 1_700_000_000;
    entry.updated_at = 1_700_000_100;
    entry.password_updated_at = 1_700_000_090;
    entry.revision = 1;
    payload.entries.push(entry);
    payload
}

const PAYLOAD_WRITTEN_BEFORE_EMAIL_ALIASES: &str = r#"{"vaultName":"Fictional vault","folders":[],"items":[{"kind":"login","id":"login-alpha","title":"Northwind","url":"https://northwind.test","username":"casey","email":"","password":"fictional password","favourite":false,"totp":null,"backupCodes":[],"recoveryEmail":null,"recoveryPhone":null,"recoveryNotApplicable":false,"notes":null,"createdAt":1700000000,"updatedAt":1700000100,"passwordUpdatedAt":1700000090,"revision":1}],"trash":[],"history":[],"vaultId":"fictional-vault-id","revision":7,"neverSaveSites":["https://fictional.example"]}"#;

#[test]
fn a_payload_without_email_aliases_is_written_byte_for_byte_as_before() {
    let payload = payload_without_email_aliases();
    assert_eq!(
        serde_json::to_string(&payload).expect("payload json"),
        PAYLOAD_WRITTEN_BEFORE_EMAIL_ALIASES
    );
    let padded = serialize_payload(&payload).expect("serialized payload");
    assert!(padded.starts_with(PAYLOAD_WRITTEN_BEFORE_EMAIL_ALIASES.as_bytes()));
    assert!(padded[PAYLOAD_WRITTEN_BEFORE_EMAIL_ALIASES.len()..]
        .iter()
        .all(|byte| *byte == b' '));
}

#[test]
fn a_format_11_vault_without_email_aliases_saves_without_the_key() {
    let directory = TestDirectory::new();
    let path = directory.vault();
    let (file, _) = format_11_vault_with_payload(|_| {});
    write_file(&path, &file);
    assert!(written_payload(&file).get("emailAliases").is_none());

    let (mut session, _) = unlock(&path);
    assert!(session
        .open_payload()
        .expect("payload")
        .email_aliases
        .is_none());
    persist_session(&mut session).expect("saved");
    let saved = VaultLoader::read(&path).expect("saved vault");
    assert!(written_payload(&saved).get("emailAliases").is_none());
}

#[test]
fn a_format_10_vault_upgrades_with_no_email_alias_setting() {
    let directory = TestDirectory::new();
    let path = directory.vault();
    let (file, _) = format_10_vault(true);
    write_file(&path, &file);

    let (mut session, migrated) = unlock(&path);
    assert!(migrated);
    assert!(session
        .open_payload()
        .expect("payload")
        .email_aliases
        .is_none());
    persist_session(&mut session).expect("saved the upgrade");
    let upgraded = VaultLoader::read(&path).expect("upgraded vault");
    assert_eq!(upgraded.format_version, VAULT_FORMAT_VERSION);
    assert!(written_payload(&upgraded).get("emailAliases").is_none());
}

#[test]
fn a_malformed_email_alias_setting_is_refused_without_guessing() {
    for value in [
        serde_json::json!({
            "service": "addy",
            "token": ALIAS_TOKEN,
            "domain": "anonaddy.me",
            "forwardTo": "someone@fictional.example",
        }),
        serde_json::json!({ "service": "fictionalService", "token": ALIAS_TOKEN }),
        serde_json::json!({ "service": "simpleLogin" }),
        serde_json::json!({ "service": "simpleLogin", "token": 42 }),
        serde_json::json!(ALIAS_TOKEN),
        serde_json::json!([ALIAS_TOKEN]),
    ] {
        let (file, _) = format_11_vault_with_payload(with_email_aliases(value.clone()));
        assert_eq!(
            VaultLoader::open(
                &file,
                sesame_core::loader::Credential::MasterPassword(PASSWORD)
            )
            .err(),
            Some(LoadFailure::RecoveryRequired {
                format: VAULT_FORMAT_VERSION
            }),
            "{value}"
        );
    }
}

#[test]
fn an_unusable_stored_email_alias_setting_opens_as_not_set_up() {
    for value in [
        serde_json::json!({ "service": "addy", "token": "has space", "domain": "anonaddy.me" }),
        serde_json::json!({ "service": "addy", "token": "line\nbreak", "domain": "anonaddy.me" }),
        serde_json::json!({ "service": "addy", "token": "", "domain": "anonaddy.me" }),
        serde_json::json!({ "service": "addy", "token": "x".repeat(513), "domain": "anonaddy.me" }),
        serde_json::json!({ "service": "addy", "token": ALIAS_TOKEN }),
        serde_json::json!({ "service": "addy", "token": ALIAS_TOKEN, "domain": "Anonaddy.ME" }),
        serde_json::json!({ "service": "addy", "token": ALIAS_TOKEN, "domain": "1.2.3.4" }),
        serde_json::json!({ "service": "simpleLogin", "token": ALIAS_TOKEN, "domain": "anonaddy.me" }),
        serde_json::Value::Null,
    ] {
        let (file, _) = format_11_vault_with_payload(with_email_aliases(value.clone()));
        let opened = open_vault_with_password(&file, PASSWORD)
            .unwrap_or_else(|error| panic!("{value} kept the vault shut: {error:?}"));
        assert!(!opened.migrated, "{value}");
        assert!(
            opened
                .payload
                .email_aliases
                .as_ref()
                .is_none_or(|settings| !settings.is_valid()),
            "{value}"
        );
        assert_eq!(opened.payload.vault_name, "Fictional vault");
    }
}
