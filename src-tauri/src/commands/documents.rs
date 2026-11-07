use tauri::{AppHandle, State, WebviewWindow};
use tauri_plugin_dialog::DialogExt;

use crate::application::document_attachments::attachment_for_save;
use crate::commands::file_selection::path_from_file;
use crate::commands::record_commands::impl_record_commands;
use crate::vault::types::{
    DeleteDocumentMetadataResult, DocumentMetadata, DocumentMetadataInput,
    SaveDocumentMetadataResult,
};
use crate::vault::util::{random_id, unix_timestamp};
use crate::vault::{VaultResult, VaultState};

fn document_from_input(input: DocumentMetadataInput) -> VaultResult<DocumentMetadata> {
    let title = input.title.trim();
    if title.is_empty() {
        return Err("Give this document a name so you can find it again.".into());
    }
    if title.chars().count() > 160 {
        return Err("That document name is too long.".into());
    }
    for (value, limit, message) in [
        (&input.document_type, 64, "That document type is too long."),
        (
            &input.document_number,
            128,
            "That document number is too long.",
        ),
        (
            &input.issuing_authority,
            256,
            "That issuing authority is too long.",
        ),
        (&input.issue_date, 32, "That issue date is too long."),
        (&input.expiry_date, 32, "That expiry date is too long."),
        (&input.notes, 4_000, "That note is too long."),
    ] {
        if value.chars().count() > limit {
            return Err(message.into());
        }
    }
    for tag in &input.tags {
        if tag.chars().count() > 64 {
            return Err("A tag is too long.".into());
        }
    }
    let now = unix_timestamp();
    Ok(DocumentMetadata {
        id: input
            .id
            .and_then(crate::vault::util::non_empty)
            .unwrap_or_else(random_id),
        title: title.to_string(),
        document_type: input.document_type.trim().to_string(),
        document_number: input.document_number.trim().to_string(),
        issuing_authority: input.issuing_authority.trim().to_string(),
        issue_date: input.issue_date.trim().to_string(),
        expiry_date: input.expiry_date.trim().to_string(),
        notes: input.notes.trim().to_string(),
        tags: input
            .tags
            .into_iter()
            .map(|tag| tag.trim().to_string())
            .filter(|tag| !tag.is_empty())
            .collect(),
        folder_id: None,
        favourite: false,
        last_used_at: None,
        created_at: now,
        updated_at: now,
        revision: 1,
        attachments: Vec::new(),
    })
}

impl_record_commands! {
    item: DocumentMetadata,
    input: DocumentMetadataInput,
    variant: Document,
    save_result: SaveDocumentMetadataResult,
    delete_result: DeleteDocumentMetadataResult,
    from_input: document_from_input,
    get_fn: get_document,
    save_fn: save_document,
    save_in_state_fn: save_document_in_state,
    delete_fn: delete_document,
    missing_noun: "document",
    save_unlock_msg: "Unlock your vault before saving a document.",
    delete_unlock_msg: "Unlock your vault before deleting a document.",
    delete_empty_msg: "Choose a saved document to delete.",
    // Attachments change only through the dedicated add/remove commands below.
    extra_carry: |item, existing| item.attachments = existing.attachments.clone(),
}

/// No history capture: 20 full versions of binary attachments would multiply storage by 20x.
#[tauri::command]
pub fn add_document_attachment(
    document_id: String,
    filename: String,
    content_type: String,
    data: String,
    state: State<'_, VaultState>,
) -> VaultResult<SaveDocumentMetadataResult> {
    let saved = crate::application::record_writes::add_document_attachment_in_state(
        &state,
        &document_id,
        &filename,
        &content_type,
        &data,
    )?;
    Ok(SaveDocumentMetadataResult {
        id: saved.id,
        snapshot: saved.snapshot,
    })
}

#[tauri::command]
pub async fn save_document_attachment(
    app: AppHandle,
    window: WebviewWindow,
    document_id: String,
    attachment_id: String,
    state: State<'_, VaultState>,
) -> VaultResult<Option<String>> {
    if window.label() != "main" {
        return Err("This window cannot save attachments.".into());
    }
    let saved = {
        let session = state
            .session
            .lock()
            .map_err(|_| "Sesame could not read the vault session.".to_string())?;
        let payload = session
            .as_ref()
            .map(|session| session.open_payload())
            .transpose()?;
        attachment_for_save(payload.as_deref(), &document_id, &attachment_id)?
    };
    let Some(destination) = app
        .dialog()
        .file()
        .set_title("Save the attachment")
        .set_file_name(&saved.filename)
        .blocking_save_file()
        .and_then(path_from_file)
    else {
        return Ok(None);
    };
    let file_name = destination
        .file_name()
        .and_then(|name| name.to_str())
        .map(str::to_string)
        .ok_or("Sesame could not name the saved attachment.")?;
    crate::vault::storage::write_export_file(&destination, &saved.bytes)?;
    Ok(Some(file_name))
}

#[tauri::command]
pub fn remove_document_attachment(
    document_id: String,
    attachment_id: String,
    state: State<'_, VaultState>,
) -> VaultResult<SaveDocumentMetadataResult> {
    let saved = crate::application::record_writes::remove_document_attachment_in_state(
        &state,
        &document_id,
        &attachment_id,
    )?;
    Ok(SaveDocumentMetadataResult {
        id: saved.id,
        snapshot: saved.snapshot,
    })
}
