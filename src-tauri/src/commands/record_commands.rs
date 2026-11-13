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
        save_in_state_fn: $save_in_state_fn:ident,
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
        ) -> crate::vault::VaultResult<crate::application::records::RecordView<$Item>> {
            crate::application::records::record_view_in_state(
                &state,
                &id,
                $missing_noun,
                |item| match item {
                    crate::vault::types::TaggedItem::$Variant(record) => Some(record),
                    _ => None,
                },
            )
        }

        #[tauri::command]
        pub fn $save_fn(
            input: $Input,
            state: tauri::State<'_, crate::vault::VaultState>,
        ) -> crate::vault::VaultResult<$SaveResult> {
            $save_in_state_fn(input, &state)
        }

        pub(crate) fn $save_in_state_fn(
            input: $Input,
            state: &crate::vault::VaultState,
        ) -> crate::vault::VaultResult<$SaveResult> {
            let extra_carry: Option<fn(&mut $Item, &$Item)> = None $(.or(Some($extra_carry)))?;
            let saved = crate::application::record_writes::save_record_in_state(
                input,
                state,
                $save_unlock_msg,
                $from_input,
                extra_carry,
            )?;
            Ok($SaveResult {
                id: saved.id,
                snapshot: saved.snapshot,
            })
        }

        #[tauri::command]
        pub fn $delete_fn(
            id: String,
            state: tauri::State<'_, crate::vault::VaultState>,
        ) -> crate::vault::VaultResult<$DeleteResult> {
            let deleted = crate::application::record_writes::delete_record_in_state::<$Item>(
                &state,
                &id,
                $missing_noun,
                $delete_unlock_msg,
                $delete_empty_msg,
            )?;
            Ok($DeleteResult {
                deleted_id: deleted.id,
                snapshot: deleted.snapshot,
            })
        }
    };
}

pub(crate) use impl_record_commands;
