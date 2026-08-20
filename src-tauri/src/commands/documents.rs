use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use tauri::State;

use crate::vault::snapshot::snapshot_for;
use crate::vault::trash::trash_item;
use crate::vault::types::{
    Attachment, DeleteDocumentMetadataResult, DocumentMetadata, DocumentMetadataInput,
    SaveDocumentMetadataResult, TaggedItem,
};
use crate::vault::util::{random_id, unix_timestamp};
use crate::vault::{VaultPayload, VaultResult, VaultState};

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

fn payload_without_document(payload: &VaultPayload, id: &str) -> VaultResult<VaultPayload> {
    if !payload.documents.iter().any(|document| document.id == id) {
        return Err("That saved document no longer exists.".into());
    }
    let mut next = payload.clone();
    next.documents.retain(|document| document.id != id);
    Ok(next)
}

#[tauri::command]
pub fn get_document(id: String, state: State<'_, VaultState>) -> VaultResult<DocumentMetadata> {
    let session = state
        .session
        .lock()
        .map_err(|_| "Sesame could not read the vault session.".to_string())?;
    let session = session.as_ref().ok_or("Unlock your vault first.")?;
    session
        .payload
        .documents
        .iter()
        .find(|document| document.id == id)
        .cloned()
        .ok_or_else(|| "That saved document no longer exists.".to_string())
}

#[tauri::command]
pub fn save_document(
    input: DocumentMetadataInput,
    state: State<'_, VaultState>,
) -> VaultResult<SaveDocumentMetadataResult> {
    let mut document = document_from_input(input)?;
    let document_id = document.id.clone();
    let mut session = state
        .session
        .lock()
        .map_err(|_| "Sesame could not read the vault session.".to_string())?;
    let session = session
        .as_mut()
        .ok_or("Unlock your vault before saving a document.")?;
    let mut next_payload = session.payload.clone();
    if let Some(existing) = next_payload
        .documents
        .iter_mut()
        .find(|saved| saved.id == document_id)
    {
        let previous = existing.clone();
        document.created_at = existing.created_at;
        document.revision = existing.revision.saturating_add(1);
        document.folder_id = existing.folder_id.clone();
        document.favourite = existing.favourite;
        document.last_used_at = existing.last_used_at;
        // Attachments change only through the dedicated add/remove commands.
        document.attachments = existing.attachments.clone();
        *existing = document;
        crate::vault::history::capture_history(&mut next_payload, TaggedItem::Document(previous));
    } else {
        next_payload.documents.push(document);
    }
    crate::vault::storage::commit_payload_change(session, next_payload)?;
    state.advance_session_epoch();
    Ok(SaveDocumentMetadataResult {
        id: document_id,
        snapshot: snapshot_for(&session.payload),
    })
}

#[tauri::command]
pub fn delete_document(
    id: String,
    state: State<'_, VaultState>,
) -> VaultResult<DeleteDocumentMetadataResult> {
    let id = id.trim();
    if id.is_empty() {
        return Err("Choose a saved document to delete.".into());
    }
    let mut session = state
        .session
        .lock()
        .map_err(|_| "Sesame could not read the vault session.".to_string())?;
    let session = session
        .as_mut()
        .ok_or("Unlock your vault before deleting a document.")?;
    let document = session
        .payload
        .documents
        .iter()
        .find(|document| document.id == id)
        .cloned()
        .ok_or("That saved document no longer exists.")?;
    let mut next_payload = payload_without_document(&session.payload, id)?;
    trash_item(&mut next_payload, TaggedItem::Document(document));
    crate::vault::storage::commit_payload_change(session, next_payload)?;
    state.advance_session_epoch();
    Ok(DeleteDocumentMetadataResult {
        deleted_id: id.to_string(),
        snapshot: snapshot_for(&session.payload),
    })
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
    let mut next_payload = session.payload.clone();
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
        snapshot: snapshot_for(&session.payload),
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
    let mut next_payload = session.payload.clone();
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
        snapshot: snapshot_for(&session.payload),
    })
}
