use tauri::State;

use crate::commands::record_commands::impl_record_commands;
use crate::commands::require_release_presence;
use crate::release::ReleasePresence;
use crate::vault::types::{
    DeleteSecureNoteResult, SaveSecureNoteResult, SecureNote, SecureNoteInput, TaggedItem,
};
use crate::vault::util::{random_id, unix_timestamp};
use crate::vault::{VaultResult, VaultState};

fn secure_note_from_input(input: SecureNoteInput) -> VaultResult<SecureNote> {
    let title = input.title.trim();
    if title.is_empty() {
        return Err("Give this note a title so you can find it again.".into());
    }
    if title.chars().count() > 160 {
        return Err("That note title is too long.".into());
    }
    if input.content.chars().count() > 20_000 {
        return Err("That note is too long.".into());
    }
    for tag in &input.tags {
        if tag.chars().count() > 64 {
            return Err("A tag is too long.".into());
        }
    }
    let now = unix_timestamp();
    Ok(SecureNote {
        id: input
            .id
            .and_then(crate::vault::util::non_empty)
            .unwrap_or_else(random_id),
        title: title.to_string(),
        content: input.content.trim().to_string(),
        locked: input.locked,
        tags: input
            .tags
            .into_iter()
            .map(|tag| tag.trim().to_string())
            .filter(|tag| !tag.is_empty())
            .collect(),
        legacy_fields: Vec::new(),
        folder_id: None,
        favourite: false,
        last_used_at: None,
        created_at: now,
        updated_at: now,
        revision: 1,
    })
}

impl_record_commands! {
    item: SecureNote,
    input: SecureNoteInput,
    variant: SecureNote,
    save_result: SaveSecureNoteResult,
    delete_result: DeleteSecureNoteResult,
    from_input: secure_note_from_input,
    get_fn: get_secure_note,
    save_fn: save_secure_note,
    save_in_state_fn: save_secure_note_in_state,
    delete_fn: delete_secure_note,
    missing_noun: "note",
    save_unlock_msg: "Unlock your vault before saving a note.",
    delete_unlock_msg: "Unlock your vault before deleting a note.",
    delete_empty_msg: "Choose a saved note to delete.",
    extra_carry: |item, existing| {
        item.legacy_fields = existing.legacy_fields.clone();
        item.locked |= existing.locked;
    },
}

#[tauri::command]
pub fn set_secure_note_lock(
    id: String,
    locked: bool,
    state: State<'_, VaultState>,
    presence: State<'_, ReleasePresence>,
) -> VaultResult<SaveSecureNoteResult> {
    set_secure_note_lock_in_state(&id, locked, &state, &presence)
}

pub(crate) fn set_secure_note_lock_in_state(
    id: &str,
    locked: bool,
    state: &VaultState,
    presence: &ReleasePresence,
) -> VaultResult<SaveSecureNoteResult> {
    if !locked {
        require_release_presence(state, presence)?;
    }
    let id = id.trim();
    let mut session = state
        .session
        .lock()
        .map_err(|_| "Sesame could not read the vault session.".to_string())?;
    let session = session
        .as_mut()
        .ok_or("Unlock your vault before changing a note lock.")?;
    let payload = session.open_payload()?;
    let mut next_payload = payload.clone();
    let mut tagged = next_payload
        .take_active_item(id)
        .ok_or("That saved note no longer exists.")?;
    let TaggedItem::SecureNote(note) = &mut tagged else {
        return Err("That item id belongs to a different kind of saved item.".into());
    };
    if note.locked == locked {
        return Ok(SaveSecureNoteResult {
            id: id.to_string(),
            snapshot: session.snapshot(),
        });
    }
    note.locked = locked;
    note.updated_at = unix_timestamp();
    note.revision = note.revision.saturating_add(1);
    next_payload.insert_active_item(&mut tagged)?;
    crate::vault::storage::commit_payload_change(session, next_payload)?;
    state.advance_session_epoch();
    Ok(SaveSecureNoteResult {
        id: id.to_string(),
        snapshot: session.snapshot(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::secret_release::item_field_in_state;
    use crate::commands::test_support::TestVault;
    use crate::release::{ReleasePresence, PRESENCE_REQUIRED};
    use crate::vault::types::TaggedItem;

    const BODY: &str = "fictional-note-body-canary";

    fn input(id: Option<&str>, content: &str, locked: bool, kept: &[&str]) -> SecureNoteInput {
        SecureNoteInput {
            id: id.map(str::to_string),
            title: "Fictional note".to_string(),
            content: content.to_string(),
            locked,
            tags: Vec::new(),
            kept_secrets: kept.iter().map(|key| key.to_string()).collect(),
        }
    }

    fn vault() -> TestVault {
        TestVault::with_login("fictional-login", "https://northwind.example")
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

    fn stored(vault: &TestVault, id: &str) -> SecureNote {
        let session = vault.state.session.lock().expect("session lock");
        match &*session
            .as_ref()
            .expect("session")
            .open_item(id)
            .expect("stored note")
        {
            TaggedItem::SecureNote(note) => note.clone(),
            _ => panic!("not a note"),
        }
    }

    fn read(vault: &TestVault, presence: &ReleasePresence, id: &str) -> VaultResult<String> {
        item_field_in_state(&vault.state, presence, id, "secure_note", "content")
            .map(|value| value.to_string())
    }

    #[test]
    fn a_locked_note_is_stored_whole_but_releases_its_body_only_with_presence() {
        let vault = vault();
        let presence = ReleasePresence::default();
        let id = save_secure_note_in_state(input(None, BODY, true, &[]), &vault.state)
            .expect("saved")
            .id;

        assert_eq!(stored(&vault, &id).content, BODY);
        assert_eq!(
            read(&vault, &presence, &id),
            Err(PRESENCE_REQUIRED.to_string())
        );

        grant(&vault, &presence);
        assert_eq!(read(&vault, &presence, &id).as_deref(), Ok(BODY));
    }

    #[test]
    fn an_open_note_has_nothing_to_release() {
        let vault = vault();
        let presence = ReleasePresence::default();
        let id = save_secure_note_in_state(input(None, BODY, false, &[]), &vault.state)
            .expect("saved")
            .id;
        grant(&vault, &presence);

        assert!(read(&vault, &presence, &id).is_err());
    }

    #[test]
    fn an_edit_that_keeps_the_body_leaves_the_stored_text_unchanged() {
        let vault = vault();
        let id = save_secure_note_in_state(input(None, BODY, true, &[]), &vault.state)
            .expect("saved")
            .id;

        save_secure_note_in_state(input(Some(&id), "", true, &["content"]), &vault.state)
            .expect("kept");

        let note = stored(&vault, &id);
        assert_eq!(note.content, BODY);
        assert!(note.locked);
        assert_eq!(note.revision, 2);
    }

    #[test]
    fn an_edit_that_types_a_new_body_replaces_it_and_stays_locked() {
        let vault = vault();
        let id = save_secure_note_in_state(input(None, BODY, true, &[]), &vault.state)
            .expect("saved")
            .id;

        save_secure_note_in_state(
            input(Some(&id), "fictional-new-body", true, &["content"]),
            &vault.state,
        )
        .expect("replaced");

        let note = stored(&vault, &id);
        assert_eq!(note.content, "fictional-new-body");
        assert!(note.locked);
    }

    #[test]
    fn a_save_cannot_turn_the_lock_off() {
        let vault = vault();
        let id = save_secure_note_in_state(input(None, BODY, true, &[]), &vault.state)
            .expect("saved")
            .id;

        save_secure_note_in_state(input(Some(&id), "", false, &["content"]), &vault.state)
            .expect("saved");

        let note = stored(&vault, &id);
        assert!(note.locked);
        assert_eq!(note.content, BODY);
    }

    #[test]
    fn a_save_can_turn_the_lock_on_and_the_body_is_then_gated() {
        let vault = vault();
        let presence = ReleasePresence::default();
        let id = save_secure_note_in_state(input(None, BODY, false, &[]), &vault.state)
            .expect("saved")
            .id;

        save_secure_note_in_state(input(Some(&id), BODY, true, &[]), &vault.state).expect("locked");

        assert!(stored(&vault, &id).locked);
        assert_eq!(
            read(&vault, &presence, &id),
            Err(PRESENCE_REQUIRED.to_string())
        );
    }

    #[test]
    fn locking_a_note_needs_no_presence_and_unlocking_it_does() {
        let vault = vault();
        let presence = ReleasePresence::default();
        let id = save_secure_note_in_state(input(None, BODY, false, &[]), &vault.state)
            .expect("saved")
            .id;

        set_secure_note_lock_in_state(&id, true, &vault.state, &presence).expect("locked");
        assert!(stored(&vault, &id).locked);

        assert_eq!(
            set_secure_note_lock_in_state(&id, false, &vault.state, &presence).map(|_| ()),
            Err(PRESENCE_REQUIRED.to_string())
        );
        assert!(stored(&vault, &id).locked);

        grant(&vault, &presence);
        set_secure_note_lock_in_state(&id, false, &vault.state, &presence).expect("unlocked");
        let note = stored(&vault, &id);
        assert!(!note.locked);
        assert_eq!(note.content, BODY);
    }

    #[test]
    fn a_lock_change_that_changes_nothing_writes_nothing() {
        let vault = vault();
        let presence = ReleasePresence::default();
        let id = save_secure_note_in_state(input(None, BODY, true, &[]), &vault.state)
            .expect("saved")
            .id;
        let before = stored(&vault, &id).revision;

        set_secure_note_lock_in_state(&id, true, &vault.state, &presence).expect("already locked");

        assert_eq!(stored(&vault, &id).revision, before);
    }

    #[test]
    fn the_lock_command_refuses_a_missing_note_and_another_kind_of_item() {
        let vault = vault();
        let presence = ReleasePresence::default();
        grant(&vault, &presence);

        assert!(set_secure_note_lock_in_state("missing", true, &vault.state, &presence).is_err());
        assert!(
            set_secure_note_lock_in_state("fictional-login", true, &vault.state, &presence)
                .is_err()
        );
    }

    #[test]
    fn a_stale_grant_does_not_unlock_a_note() {
        let vault = vault();
        let presence = ReleasePresence::default();
        let id = save_secure_note_in_state(input(None, BODY, true, &[]), &vault.state)
            .expect("saved")
            .id;
        grant(&vault, &presence);
        vault.state.advance_session_epoch();

        assert_eq!(
            set_secure_note_lock_in_state(&id, false, &vault.state, &presence).map(|_| ()),
            Err(PRESENCE_REQUIRED.to_string())
        );
    }
}
