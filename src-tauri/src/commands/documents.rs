use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use tauri::State;

use crate::commands::record_commands::impl_record_commands;
use crate::vault::types::{
    Attachment, DeleteDocumentMetadataResult, DocumentMetadata, DocumentMetadataInput,
    SaveDocumentMetadataResult,
};
use crate::vault::util::{random_id, unix_timestamp};
use crate::vault::{VaultResult, VaultState};

/// Local-only storage inside the encrypted payload blob, so worst-case growth stays bounded.
pub const MAX_ATTACHMENT_BYTES: usize = 5 * 1024 * 1024;
/// Bounds per-document storage to 25 MB total.
pub const MAX_ATTACHMENTS_PER_DOCUMENT: usize = 5;

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
    delete_fn: delete_document,
    missing_noun: "document",
    save_unlock_msg: "Unlock your vault before saving a document.",
    delete_unlock_msg: "Unlock your vault before deleting a document.",
    delete_empty_msg: "Choose a saved document to delete.",
    // Attachments change only through the dedicated add/remove commands below.
    extra_carry: |item, existing| item.attachments = existing.attachments.clone(),
}

fn attachment_from_input(
    filename: &str,
    content_type: &str,
    data: &str,
) -> VaultResult<Attachment> {
    let filename = filename.trim();
    if filename.is_empty() {
        return Err("Name this attachment before adding it.".into());
    }
    if filename.chars().count() > 200 {
        return Err("That attachment's name is too long.".into());
    }
    let content_type = content_type.trim();
    if content_type.chars().count() > 128 {
        return Err("That attachment's type is too long.".into());
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(data.as_bytes())
        .map_err(|_| "That file could not be read.".to_string())?;
    if bytes.is_empty() {
        return Err("Choose a file to attach.".into());
    }
    if bytes.len() > MAX_ATTACHMENT_BYTES {
        return Err(format!(
            "Attachments are limited to {} MB.",
            MAX_ATTACHMENT_BYTES / (1024 * 1024)
        ));
    }
    Ok(Attachment {
        id: random_id(),
        filename: filename.to_string(),
        content_type: content_type.to_string(),
        size: bytes.len() as u64,
        data: bytes,
    })
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
    let attachment = attachment_from_input(&filename, &content_type, &data)?;

    let mut session = state
        .session
        .lock()
        .map_err(|_| "Sesame could not read the vault session.".to_string())?;
    let session = session
        .as_mut()
        .ok_or("Unlock your vault before adding an attachment.")?;
    let payload = session.open_payload()?;
    let mut next_payload = payload.clone();
    let index = next_payload
        .documents
        .iter()
        .position(|document| document.id == document_id)
        .ok_or("That saved document no longer exists.")?;
    if next_payload.documents[index].attachments.len() >= MAX_ATTACHMENTS_PER_DOCUMENT {
        return Err(format!(
            "A document can hold up to {MAX_ATTACHMENTS_PER_DOCUMENT} attachments."
        ));
    }
    let document = &mut next_payload.documents[index];
    document.attachments.push(attachment);
    document.updated_at = unix_timestamp();
    document.revision = document.revision.saturating_add(1);

    crate::vault::storage::commit_payload_change(session, next_payload)?;
    state.advance_session_epoch();
    Ok(SaveDocumentMetadataResult {
        id: document_id,
        snapshot: session.snapshot(),
    })
}

#[tauri::command]
pub fn remove_document_attachment(
    document_id: String,
    attachment_id: String,
    state: State<'_, VaultState>,
) -> VaultResult<SaveDocumentMetadataResult> {
    let mut session = state
        .session
        .lock()
        .map_err(|_| "Sesame could not read the vault session.".to_string())?;
    let session = session
        .as_mut()
        .ok_or("Unlock your vault before removing an attachment.")?;
    let payload = session.open_payload()?;
    let mut next_payload = payload.clone();
    let index = next_payload
        .documents
        .iter()
        .position(|document| document.id == document_id)
        .ok_or("That saved document no longer exists.")?;
    let document = &mut next_payload.documents[index];
    let before = document.attachments.len();
    document.attachments.retain(|item| item.id != attachment_id);
    if document.attachments.len() == before {
        return Err("That attachment no longer exists.".into());
    }
    document.updated_at = unix_timestamp();
    document.revision = document.revision.saturating_add(1);

    crate::vault::storage::commit_payload_change(session, next_payload)?;
    state.advance_session_epoch();
    Ok(SaveDocumentMetadataResult {
        id: document_id,
        snapshot: session.snapshot(),
    })
}
