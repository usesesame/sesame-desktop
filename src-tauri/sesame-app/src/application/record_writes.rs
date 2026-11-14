use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use sesame_core::secret_fields::{KeptSecrets, SecretSlots};

use crate::application::release::require_release_presence;
use crate::release::ReleasePresence;
use crate::vault::history::capture_history;
use crate::vault::storage::commit_payload_change;
use crate::vault::trash::trash_item;
use crate::vault::util::{random_id, unix_timestamp};
use crate::vault::{
    Attachment, Card, CustomRecord, DocumentMetadata, Identity, SecureNote, SoftwareLicense,
    SshKey, TaggedItem, VaultResult, VaultSnapshot, VaultState, WifiNetwork,
};

pub const MAX_ATTACHMENT_BYTES: usize = 5 * 1024 * 1024;
pub const MAX_ATTACHMENTS_PER_DOCUMENT: usize = 5;

pub struct SavedRecord {
    pub id: String,
    pub snapshot: VaultSnapshot,
}

pub struct DeletedRecord {
    pub id: String,
    pub snapshot: VaultSnapshot,
}

pub trait RecordWriteItem: Clone + Default + SecretSlots {
    fn id(&self) -> &str;
    fn created_at(&self) -> u64;
    fn set_created_at(&mut self, created_at: u64);
    fn revision(&self) -> u32;
    fn set_revision(&mut self, revision: u32);
    fn folder_id(&self) -> Option<&str>;
    fn set_folder_id(&mut self, folder_id: Option<String>);
    fn favourite(&self) -> bool;
    fn set_favourite(&mut self, favourite: bool);
    fn last_used_at(&self) -> Option<u64>;
    fn set_last_used_at(&mut self, last_used_at: Option<u64>);
    fn into_tagged(self) -> TaggedItem;
    fn from_tagged(item: &mut TaggedItem) -> Option<&mut Self>;
    fn is_tagged(item: &TaggedItem) -> bool;
}

macro_rules! impl_record_write_item {
    ($($Item:ty => $Variant:ident),+ $(,)?) => {
        $(
            impl RecordWriteItem for $Item {
                fn id(&self) -> &str {
                    &self.id
                }

                fn created_at(&self) -> u64 {
                    self.created_at
                }

                fn set_created_at(&mut self, created_at: u64) {
                    self.created_at = created_at;
                }

                fn revision(&self) -> u32 {
                    self.revision
                }

                fn set_revision(&mut self, revision: u32) {
                    self.revision = revision;
                }

                fn folder_id(&self) -> Option<&str> {
                    self.folder_id.as_deref()
                }

                fn set_folder_id(&mut self, folder_id: Option<String>) {
                    self.folder_id = folder_id;
                }

                fn favourite(&self) -> bool {
                    self.favourite
                }

                fn set_favourite(&mut self, favourite: bool) {
                    self.favourite = favourite;
                }

                fn last_used_at(&self) -> Option<u64> {
                    self.last_used_at
                }

                fn set_last_used_at(&mut self, last_used_at: Option<u64>) {
                    self.last_used_at = last_used_at;
                }

                fn into_tagged(self) -> TaggedItem {
                    TaggedItem::$Variant(self)
                }

                fn from_tagged(item: &mut TaggedItem) -> Option<&mut Self> {
                    match item {
                        TaggedItem::$Variant(record) => Some(record),
                        _ => None,
                    }
                }

                fn is_tagged(item: &TaggedItem) -> bool {
                    matches!(item, TaggedItem::$Variant(_))
                }
            }
        )+
    };
}

impl_record_write_item! {
    Card => Card,
    Identity => Identity,
    SecureNote => SecureNote,
    WifiNetwork => WifiNetwork,
    SshKey => SshKey,
    SoftwareLicense => SoftwareLicense,
    DocumentMetadata => Document,
    CustomRecord => CustomRecord,
}

pub fn save_record_in_state<I, T>(
    input: I,
    state: &VaultState,
    save_unlock_msg: &str,
    from_input: fn(I) -> VaultResult<T>,
    extra_carry: Option<fn(&mut T, &T)>,
) -> VaultResult<SavedRecord>
where
    I: KeptSecrets,
    T: RecordWriteItem,
{
    let kept = input.kept_secrets();
    let mut item = from_input(input)?;
    let item_id = item.id().to_string();
    let mut session = state
        .session
        .lock()
        .map_err(|_| "Sesame could not read the vault session.".to_string())?;
    let session = session.as_mut().ok_or(save_unlock_msg)?;
    let payload = session.open_payload()?;
    let mut next_payload = payload.clone();
    if let Some(mut previous) = next_payload.take_active_item(&item_id) {
        let existing = T::from_tagged(&mut previous)
            .ok_or("That item id belongs to a different kind of saved item.")?;
        item.set_created_at(existing.created_at());
        item.set_revision(existing.revision().saturating_add(1));
        item.set_folder_id(existing.folder_id().map(str::to_string));
        item.set_favourite(existing.favourite());
        item.set_last_used_at(existing.last_used_at());
        if let Some(extra_carry) = extra_carry {
            extra_carry(&mut item, existing);
        }
        SecretSlots::keep_secrets(&mut item, &*existing, &kept);
        capture_history(&mut next_payload, std::mem::take(existing).into_tagged());
    }
    next_payload.insert_active_item(&mut item.into_tagged())?;
    commit_payload_change(session, next_payload)?;
    state.advance_session_epoch();
    Ok(SavedRecord {
        id: item_id,
        snapshot: session.snapshot(),
    })
}

pub fn delete_record_in_state<T>(
    state: &VaultState,
    id: &str,
    missing_noun: &str,
    delete_unlock_msg: &str,
    delete_empty_msg: &str,
) -> VaultResult<DeletedRecord>
where
    T: RecordWriteItem,
{
    let id = id.trim();
    if id.is_empty() {
        return Err(delete_empty_msg.into());
    }
    let mut session = state
        .session
        .lock()
        .map_err(|_| "Sesame could not read the vault session.".to_string())?;
    let session = session.as_mut().ok_or(delete_unlock_msg)?;
    let payload = session.open_payload()?;
    let mut next_payload = payload.clone();
    let tagged = next_payload
        .take_active_item(id)
        .ok_or_else(|| format!("That saved {missing_noun} no longer exists."))?;
    if !T::is_tagged(&tagged) {
        return Err("That item id belongs to a different kind of saved item.".into());
    }
    trash_item(&mut next_payload, tagged);
    commit_payload_change(session, next_payload)?;
    state.advance_session_epoch();
    Ok(DeletedRecord {
        id: id.to_string(),
        snapshot: session.snapshot(),
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

pub fn add_document_attachment_in_state(
    state: &VaultState,
    document_id: &str,
    filename: &str,
    content_type: &str,
    data: &str,
) -> VaultResult<SavedRecord> {
    let attachment = attachment_from_input(filename, content_type, data)?;

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

    commit_payload_change(session, next_payload)?;
    state.advance_session_epoch();
    Ok(SavedRecord {
        id: document_id.to_string(),
        snapshot: session.snapshot(),
    })
}

pub fn remove_document_attachment_in_state(
    state: &VaultState,
    document_id: &str,
    attachment_id: &str,
) -> VaultResult<SavedRecord> {
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

    commit_payload_change(session, next_payload)?;
    state.advance_session_epoch();
    Ok(SavedRecord {
        id: document_id.to_string(),
        snapshot: session.snapshot(),
    })
}

pub fn set_secure_note_lock_in_state(
    id: &str,
    locked: bool,
    state: &VaultState,
    presence: &ReleasePresence,
) -> VaultResult<SavedRecord> {
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
        return Ok(SavedRecord {
            id: id.to_string(),
            snapshot: session.snapshot(),
        });
    }
    note.locked = locked;
    note.updated_at = unix_timestamp();
    note.revision = note.revision.saturating_add(1);
    next_payload.insert_active_item(&mut tagged)?;
    commit_payload_change(session, next_payload)?;
    state.advance_session_epoch();
    Ok(SavedRecord {
        id: id.to_string(),
        snapshot: session.snapshot(),
    })
}
