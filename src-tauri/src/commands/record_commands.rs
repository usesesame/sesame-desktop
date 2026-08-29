//! Shared get/save/delete command bodies for the item kinds that store one
//! `Vec<T>` in `VaultPayload` and carry the same folder/favourite/last-used/
//! revision metadata across a save. Field validation stays hand-written per
//! kind (`*_from_input` in each kind's own file) because those rules are
//! genuinely different from one kind to the next.
//!
//! Kinds with extra commands beyond get/save/delete (documents' attachments)
//! or storage outside `VaultPayload`'s tagged-item collections (logins) don't
//! use this macro.

/// `extra_carry` is a `|item: &mut T, existing: &T| { .. }` closure run right
/// after the shared metadata carry-forward in `save`. Use it for a field the
/// shared list does not cover, such as a legacy-import artifact or an
/// attachment list that only changes through its own dedicated command.
/// (A plain statement block can't be used here: macro hygiene keeps caller
/// tokens from resolving names the macro binds internally, so the bridge has
/// to be a real function call with explicit parameters, not a spliced-in
/// name lookup.)
///
/// `save_result` and `delete_result` take a bare, already-imported type name
/// rather than a full path: a `path`- or `ty`-fragment substituted directly
/// into `Name { field: value }` does not reparse as a struct literal, so the
/// caller imports the short name and passes that.
macro_rules! impl_record_commands {
    (
        item: $Item:ty,
        input: $Input:ty,
        variant: $Variant:ident,
        save_result: $SaveResult:ident,
        delete_result: $DeleteResult:ident,
        from_input: $from_input:path,
        get_fn: $get_fn:ident,
        save_fn: $save_fn:ident,
        delete_fn: $delete_fn:ident,
        missing_noun: $missing_noun:expr,
        save_unlock_msg: $save_unlock_msg:expr,
        delete_unlock_msg: $delete_unlock_msg:expr,
        delete_empty_msg: $delete_empty_msg:expr,
        $(extra_carry: $extra_carry:expr,)?
    ) => {
        #[tauri::command]
        pub fn $get_fn(
            id: String,
            state: tauri::State<'_, crate::vault::VaultState>,
        ) -> crate::vault::VaultResult<$Item> {
            let session = state
                .session
                .lock()
                .map_err(|_| "Sesame could not read the vault session.".to_string())?;
            let session = session.as_ref().ok_or("Unlock your vault first.")?;
            let item = session.open_item(&id)?;
            match &*item {
                crate::vault::types::TaggedItem::$Variant(item) => Ok(item.clone()),
                _ => Err(format!("That saved {} no longer exists.", $missing_noun)),
            }
        }

        #[tauri::command]
        pub fn $save_fn(
            input: $Input,
            state: tauri::State<'_, crate::vault::VaultState>,
        ) -> crate::vault::VaultResult<$SaveResult> {
            let mut item = $from_input(input)?;
            let item_id = item.id.clone();
            let mut session = state
                .session
                .lock()
                .map_err(|_| "Sesame could not read the vault session.".to_string())?;
            let session = session.as_mut().ok_or($save_unlock_msg)?;
            let payload = session.open_payload()?;
            let mut next_payload = payload.clone();
            if let Some(previous) = next_payload.take_active_item(&item_id) {
                let crate::vault::types::TaggedItem::$Variant(existing) = previous else {
                    return Err("That item id belongs to a different kind of saved item.".into());
                };
                item.created_at = existing.created_at;
                item.revision = existing.revision.saturating_add(1);
                item.folder_id = existing.folder_id.clone();
                item.favourite = existing.favourite;
                item.last_used_at = existing.last_used_at;
                $(
                    let extra_carry: fn(&mut $Item, &$Item) = $extra_carry;
                    extra_carry(&mut item, &existing);
                )?
                crate::vault::history::capture_history(
                    &mut next_payload,
                    crate::vault::types::TaggedItem::$Variant(existing),
                );
            }
            next_payload.insert_active_item(crate::vault::types::TaggedItem::$Variant(item))?;
            crate::vault::storage::commit_payload_change(session, next_payload)?;
            state.advance_session_epoch();
            Ok($SaveResult {
                id: item_id,
                snapshot: session.snapshot(),
            })
        }

        #[tauri::command]
        pub fn $delete_fn(
            id: String,
            state: tauri::State<'_, crate::vault::VaultState>,
        ) -> crate::vault::VaultResult<$DeleteResult> {
            let id = id.trim();
            if id.is_empty() {
                return Err($delete_empty_msg.into());
            }
            let mut session = state
                .session
                .lock()
                .map_err(|_| "Sesame could not read the vault session.".to_string())?;
            let session = session.as_mut().ok_or($delete_unlock_msg)?;
            let payload = session.open_payload()?;
            let mut next_payload = payload.clone();
            let item = match next_payload.take_active_item(id) {
                Some(crate::vault::types::TaggedItem::$Variant(item)) => item,
                Some(_) => {
                    return Err("That item id belongs to a different kind of saved item.".into())
                }
                None => return Err(format!("That saved {} no longer exists.", $missing_noun)),
            };
            crate::vault::trash::trash_item(&mut next_payload, crate::vault::types::TaggedItem::$Variant(item));
            crate::vault::storage::commit_payload_change(session, next_payload)?;
            state.advance_session_epoch();
            Ok($DeleteResult {
                deleted_id: id.to_string(),
                snapshot: session.snapshot(),
            })
        }
    };
}

pub(crate) use impl_record_commands;
