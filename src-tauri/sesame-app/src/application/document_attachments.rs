use sesame_core::types::VaultPayload;
use sesame_core::VaultResult;
use zeroize::Zeroizing;

pub struct AttachmentForSave {
    pub filename: String,
    pub bytes: Zeroizing<Vec<u8>>,
}

pub fn attachment_for_save(
    payload: Option<&VaultPayload>,
    document_id: &str,
    attachment_id: &str,
) -> VaultResult<AttachmentForSave> {
    let payload = payload.ok_or("Unlock your vault before saving an attachment.")?;
    let document_id = document_id.trim();
    let attachment_id = attachment_id.trim();
    if document_id.is_empty() || attachment_id.is_empty() {
        return Err("Choose an attachment to save.".into());
    }
    let document = payload
        .documents
        .iter()
        .find(|document| document.id == document_id)
        .ok_or("That saved document no longer exists.")?;
    let attachment = document
        .attachments
        .iter()
        .find(|attachment| attachment.id == attachment_id)
        .ok_or("That attachment no longer exists.")?;
    let filename = safe_file_name(&attachment.filename)
        .ok_or("Sesame could not name the saved attachment.")?;
    Ok(AttachmentForSave {
        filename,
        bytes: Zeroizing::new(attachment.data.clone()),
    })
}

fn safe_file_name(name: &str) -> Option<String> {
    let name = name.rsplit(['/', '\\']).next()?.trim();
    if name.is_empty() || name == "." || name == ".." || name.chars().any(char::is_control) {
        return None;
    }
    Some(name.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sesame_core::types::{Attachment, DocumentMetadata};

    fn attachment(id: &str, filename: &str, data: &[u8]) -> Attachment {
        Attachment {
            id: id.to_string(),
            filename: filename.to_string(),
            content_type: "application/pdf".to_string(),
            size: data.len() as u64,
            data: data.to_vec(),
        }
    }

    fn document(id: &str, attachment: Attachment) -> DocumentMetadata {
        DocumentMetadata {
            id: id.to_string(),
            title: "Fictional passport".to_string(),
            document_type: String::new(),
            document_number: String::new(),
            issuing_authority: String::new(),
            issue_date: String::new(),
            expiry_date: String::new(),
            notes: String::new(),
            tags: Vec::new(),
            folder_id: None,
            favourite: false,
            last_used_at: None,
            created_at: 0,
            updated_at: 0,
            revision: 1,
            attachments: vec![attachment],
        }
    }

    fn payload() -> VaultPayload {
        let mut payload = VaultPayload::default();
        payload.documents = vec![document(
            "fictional-document-01",
            attachment("fictional-attachment-01", "scan.pdf", b"fictional scan"),
        )];
        payload
    }

    #[test]
    fn a_locked_vault_cannot_save_an_attachment() {
        assert_eq!(
            attachment_for_save(None, "fictional-document-01", "fictional-attachment-01")
                .err()
                .as_deref(),
            Some("Unlock your vault before saving an attachment.")
        );
    }

    #[test]
    fn a_missing_document_or_attachment_is_refused() {
        let payload = payload();
        assert_eq!(
            attachment_for_save(
                Some(&payload),
                "fictional-document-02",
                "fictional-attachment-01"
            )
            .err()
            .as_deref(),
            Some("That saved document no longer exists.")
        );
        assert_eq!(
            attachment_for_save(
                Some(&payload),
                "fictional-document-01",
                "fictional-attachment-02"
            )
            .err()
            .as_deref(),
            Some("That attachment no longer exists.")
        );
    }

    #[test]
    fn an_empty_identity_is_refused_before_the_vault_is_read() {
        let payload = payload();
        for (document_id, attachment_id) in [
            ("", "fictional-attachment-01"),
            ("fictional-document-01", "   "),
        ] {
            assert_eq!(
                attachment_for_save(Some(&payload), document_id, attachment_id)
                    .err()
                    .as_deref(),
                Some("Choose an attachment to save.")
            );
        }
    }

    #[test]
    fn the_saved_attachment_carries_the_vault_bytes_and_its_own_name() {
        let saved = attachment_for_save(
            Some(&payload()),
            " fictional-document-01 ",
            " fictional-attachment-01 ",
        )
        .expect("saved attachment");
        assert_eq!(saved.filename, "scan.pdf");
        assert_eq!(&*saved.bytes, b"fictional scan");
    }

    #[test]
    fn a_path_shaped_attachment_name_is_reduced_to_one_component() {
        let mut payload = payload();
        payload.documents[0].attachments[0].filename = "..\\fictional folder\\scan.pdf".to_string();
        let saved = attachment_for_save(
            Some(&payload),
            "fictional-document-01",
            "fictional-attachment-01",
        )
        .expect("saved attachment");
        assert_eq!(saved.filename, "scan.pdf");
    }

    #[test]
    fn a_name_with_no_usable_component_is_refused() {
        for filename in ["", "   ", "..", "/", "fictional\nscan.pdf"] {
            assert_eq!(safe_file_name(filename), None, "{filename:?}");
        }
    }
}
