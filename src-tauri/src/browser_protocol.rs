use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

pub const PROTOCOL_VERSION: u8 = 1;
pub const CARD_PROTOCOL_VERSION: u8 = 2;
pub const MAX_NATIVE_MESSAGE_BYTES: usize = 16 * 1024;
pub const MAX_CREDENTIAL_FIELD_BYTES: usize = 4096;

/// Closed set: anything outside it fails validation before it reaches the vault.
pub const IDENTITY_FIELD_KEYS: [&str; 9] = [
    "fullName",
    "email",
    "phone",
    "addressLine1",
    "addressLine2",
    "city",
    "region",
    "postalCode",
    "country",
];

pub const CARD_FIELD_KEYS: [&str; 5] = [
    "cardholderName",
    "number",
    "expiryMonth",
    "expiryYear",
    "securityCode",
];

pub(crate) fn parse_identity_fields(value: &str) -> Option<Vec<String>> {
    let mut fields = Vec::new();
    for part in value.split(',') {
        if !IDENTITY_FIELD_KEYS.contains(&part) || fields.iter().any(|seen| seen == part) {
            return None;
        }
        fields.push(part.to_string());
    }
    // An empty `fields` yields one empty part, which is never a valid key.
    Some(fields)
}

pub(crate) fn parse_card_fields(value: &str) -> Option<Vec<String>> {
    let mut fields = Vec::new();
    for part in value.split(',') {
        if !CARD_FIELD_KEYS.contains(&part) || fields.iter().any(|seen| seen == part) {
            return None;
        }
        fields.push(part.to_string());
    }
    Some(fields)
}

pub fn supported_protocol_version(version: u8) -> bool {
    matches!(version, PROTOCOL_VERSION | CARD_PROTOCOL_VERSION)
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BrowserRequest {
    pub version: u8,
    #[serde(rename = "type")]
    pub message_type: String,
    pub request_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fields: Option<String>,
    // Save-only inbound credentials, zeroized on drop, rejected for every other operation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// Decided by the extension from the page's form structure.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
}

impl Drop for BrowserRequest {
    fn drop(&mut self) {
        self.username.zeroize();
        self.password.zeroize();
        self.title.zeroize();
    }
}

impl BrowserRequest {
    pub fn validate(&self) -> bool {
        if !supported_protocol_version(self.version) || !valid_identifier(&self.request_id) {
            return false;
        }
        if (self.version == PROTOCOL_VERSION && self.message_type == "card")
            || (self.version == CARD_PROTOCOL_VERSION && self.message_type != "card")
        {
            return false;
        }
        let no_save_payload = self.username.is_none()
            && self.password.is_none()
            && self.title.is_none()
            && self.kind.is_none();
        match self.message_type.as_str() {
            "capabilities" | "activate" => {
                self.origin.is_none() && self.fields.is_none() && no_save_payload
            }
            "fill" => {
                self.origin.as_deref().is_some_and(|origin| {
                    !origin.is_empty()
                        && origin.len() <= 2048
                        && !origin.chars().any(char::is_control)
                }) && matches!(
                    self.fields.as_deref().unwrap_or("both"),
                    "username" | "password" | "both"
                ) && no_save_payload
            }
            "identity" => {
                self.origin.as_deref().is_some_and(|origin| {
                    !origin.is_empty()
                        && origin.len() <= 2048
                        && !origin.chars().any(char::is_control)
                }) && self
                    .fields
                    .as_deref()
                    .is_some_and(|fields| parse_identity_fields(fields).is_some())
                    && no_save_payload
            }
            "card" => {
                self.version == CARD_PROTOCOL_VERSION
                    && self.origin.as_deref().is_some_and(|origin| {
                        origin.starts_with("https://")
                            && origin.len() <= 2048
                            && !origin.chars().any(char::is_control)
                    })
                    && self
                        .fields
                        .as_deref()
                        .is_some_and(|fields| parse_card_fields(fields).is_some())
                    && no_save_payload
            }
            "save" => {
                let origin_ok = self.origin.as_deref().is_some_and(|origin| {
                    !origin.is_empty()
                        && origin.len() <= 2048
                        && !origin.chars().any(char::is_control)
                });
                let password_ok = self.password.as_deref().is_some_and(|password| {
                    !password.is_empty() && password.len() <= MAX_CREDENTIAL_FIELD_BYTES
                });
                let username_ok = self.username.as_deref().map_or(true, |username| {
                    username.len() <= MAX_CREDENTIAL_FIELD_BYTES
                });
                let title_ok = self
                    .title
                    .as_deref()
                    .map_or(true, |title| !title.is_empty() && title.len() <= 512);
                let kind_ok = matches!(self.kind.as_deref(), Some("new") | Some("update"));
                origin_ok
                    && password_ok
                    && username_ok
                    && title_ok
                    && kind_ok
                    && self.fields.is_none()
            }
            _ => false,
        }
    }
}

/// Only the subset the page asked for and the approval granted.
#[derive(Debug, Serialize, Deserialize, Default, Zeroize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IdentityFillFields {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub full_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub phone: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address_line1: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address_line2: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub city: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub postal_code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Default, Zeroize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CardFillFields {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cardholder_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub number: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expiry_month: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expiry_year: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub security_code: Option<String>,
}

impl CardFillFields {
    fn matches_requested(&self, requested: &[String]) -> bool {
        let present: std::collections::HashSet<&str> =
            requested.iter().map(String::as_str).collect();
        let values_are_bounded = [
            self.cardholder_name.as_deref(),
            self.number.as_deref(),
            self.expiry_month.as_deref(),
            self.expiry_year.as_deref(),
            self.security_code.as_deref(),
        ]
        .into_iter()
        .flatten()
        .all(|value| value.len() <= MAX_CREDENTIAL_FIELD_BYTES);
        values_are_bounded
            && (self.cardholder_name.is_some() == present.contains("cardholderName"))
            && (self.number.is_some() == present.contains("number"))
            && (self.expiry_month.is_some() == present.contains("expiryMonth"))
            && (self.expiry_year.is_some() == present.contains("expiryYear"))
            && (self.security_code.is_some() == present.contains("securityCode"))
    }
}

impl IdentityFillFields {
    /// Present keys must equal requested keys exactly.
    fn matches_requested(&self, requested: &[String]) -> bool {
        let present: std::collections::HashSet<&str> =
            requested.iter().map(String::as_str).collect();
        let values_are_bounded = [
            self.full_name.as_deref(),
            self.email.as_deref(),
            self.phone.as_deref(),
            self.address_line1.as_deref(),
            self.address_line2.as_deref(),
            self.city.as_deref(),
            self.region.as_deref(),
            self.postal_code.as_deref(),
            self.country.as_deref(),
        ]
        .into_iter()
        .flatten()
        .all(|value| value.len() <= MAX_CREDENTIAL_FIELD_BYTES);
        values_are_bounded
            && (self.full_name.is_some() == present.contains("fullName"))
            && (self.email.is_some() == present.contains("email"))
            && (self.phone.is_some() == present.contains("phone"))
            && (self.address_line1.is_some() == present.contains("addressLine1"))
            && (self.address_line2.is_some() == present.contains("addressLine2"))
            && (self.city.is_some() == present.contains("city"))
            && (self.region.is_some() == present.contains("region"))
            && (self.postal_code.is_some() == present.contains("postalCode"))
            && (self.country.is_some() == present.contains("country"))
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BrowserResponse {
    pub version: u8,
    #[serde(rename = "type")]
    pub message_type: String,
    pub request_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub installed: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub desktop_available: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub locked: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fill_available: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub opened: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub saved: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity: Option<IdentityFillFields>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub card: Option<CardFillFields>,
}

impl BrowserResponse {
    pub fn capabilities(request_id: &str, desktop_available: bool, locked: bool) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            message_type: "capabilities".into(),
            request_id: request_id.into(),
            installed: Some(true),
            desktop_available: Some(desktop_available),
            locked: Some(locked),
            fill_available: Some(!locked),
            opened: None,
            username: None,
            password: None,
            reason: None,
            message: None,
            saved: None,
            identity: None,
            card: None,
        }
    }

    pub fn activated(request_id: &str, opened: bool) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            message_type: "activated".into(),
            request_id: request_id.into(),
            installed: None,
            desktop_available: None,
            locked: None,
            fill_available: None,
            opened: Some(opened),
            username: None,
            password: None,
            reason: None,
            message: None,
            saved: None,
            identity: None,
            card: None,
        }
    }

    pub fn fill_for(request: &BrowserRequest, username: String, password: String) -> Self {
        let fields = request.fields.as_deref().unwrap_or("both");
        Self {
            version: PROTOCOL_VERSION,
            message_type: "fill".into(),
            request_id: request.request_id.clone(),
            installed: None,
            desktop_available: None,
            locked: None,
            fill_available: None,
            opened: None,
            username: matches!(fields, "username" | "both").then_some(username),
            password: matches!(fields, "password" | "both").then_some(password),
            reason: None,
            message: None,
            saved: None,
            identity: None,
            card: None,
        }
    }

    pub fn unavailable(request_id: &str, reason: &'static str) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            message_type: "fill-unavailable".into(),
            request_id: request_id.into(),
            installed: None,
            desktop_available: None,
            locked: None,
            fill_available: None,
            opened: None,
            username: None,
            password: None,
            reason: Some(reason.into()),
            message: None,
            saved: None,
            identity: None,
            card: None,
        }
    }

    pub fn error(request_id: &str, message: &'static str) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            message_type: "error".into(),
            request_id: request_id.into(),
            installed: None,
            desktop_available: None,
            locked: None,
            fill_available: None,
            opened: None,
            username: None,
            password: None,
            reason: None,
            message: Some(message.into()),
            saved: None,
            identity: None,
            card: None,
        }
    }

    pub fn saved(request_id: &str) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            message_type: "saved".into(),
            request_id: request_id.into(),
            installed: None,
            desktop_available: None,
            locked: None,
            fill_available: None,
            opened: None,
            username: None,
            password: None,
            reason: None,
            message: None,
            saved: Some(true),
            identity: None,
            card: None,
        }
    }

    pub fn save_unavailable(request_id: &str, reason: &'static str) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            message_type: "save-unavailable".into(),
            request_id: request_id.into(),
            installed: None,
            desktop_available: None,
            locked: None,
            fill_available: None,
            opened: None,
            username: None,
            password: None,
            reason: Some(reason.into()),
            message: None,
            saved: None,
            identity: None,
            card: None,
        }
    }

    /// A field not requested is never populated, even if the identity has a value for it.
    pub fn identity_for(request: &BrowserRequest, fields: IdentityFillFields) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            message_type: "identity".into(),
            request_id: request.request_id.clone(),
            installed: None,
            desktop_available: None,
            locked: None,
            fill_available: None,
            opened: None,
            username: None,
            password: None,
            reason: None,
            message: None,
            saved: None,
            identity: Some(fields),
            card: None,
        }
    }

    pub fn identity_unavailable(request_id: &str, reason: &'static str) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            message_type: "identity-unavailable".into(),
            request_id: request_id.into(),
            installed: None,
            desktop_available: None,
            locked: None,
            fill_available: None,
            opened: None,
            username: None,
            password: None,
            reason: Some(reason.into()),
            message: None,
            saved: None,
            identity: None,
            card: None,
        }
    }

    pub fn card_for(request: &BrowserRequest, fields: CardFillFields) -> Self {
        Self {
            version: CARD_PROTOCOL_VERSION,
            message_type: "card".into(),
            request_id: request.request_id.clone(),
            installed: None,
            desktop_available: None,
            locked: None,
            fill_available: None,
            opened: None,
            username: None,
            password: None,
            reason: None,
            message: None,
            saved: None,
            identity: None,
            card: Some(fields),
        }
    }

    pub fn card_unavailable(request_id: &str, reason: &'static str) -> Self {
        Self {
            version: CARD_PROTOCOL_VERSION,
            message_type: "card-unavailable".into(),
            request_id: request_id.into(),
            installed: None,
            desktop_available: None,
            locked: None,
            fill_available: None,
            opened: None,
            username: None,
            password: None,
            reason: Some(reason.into()),
            message: None,
            saved: None,
            identity: None,
            card: None,
        }
    }

    pub fn validate_for(&self, request: &BrowserRequest) -> bool {
        if self.version != request.version
            || self.request_id != request.request_id
            || !valid_identifier(&self.request_id)
        {
            return false;
        }
        let no_capability = self.installed.is_none()
            && self.desktop_available.is_none()
            && self.locked.is_none()
            && self.fill_available.is_none();
        let no_activation = self.opened.is_none();
        let no_credential = self.username.is_none() && self.password.is_none();
        let no_saved = self.saved.is_none();
        let no_identity = self.identity.is_none();
        let no_card = self.card.is_none();
        if request.message_type != "card" && !no_card {
            return false;
        }
        match (request.message_type.as_str(), self.message_type.as_str()) {
            ("capabilities", "capabilities") => {
                self.installed == Some(true)
                    && self.desktop_available.is_some()
                    && self.locked.is_some()
                    && self.fill_available.is_some()
                    && no_credential
                    && self.reason.is_none()
                    && self.message.is_none()
                    && self.fill_available == self.locked.map(|locked| !locked)
                    && (self.desktop_available == Some(true) || self.locked == Some(true))
                    && no_activation
                    && no_saved
                    && no_identity
            }
            ("activate", "activated") => {
                no_capability
                    && self.opened.is_some()
                    && no_credential
                    && self.reason.is_none()
                    && self.message.is_none()
                    && no_saved
                    && no_identity
            }
            ("save", "saved") => {
                no_capability
                    && no_activation
                    && no_credential
                    && self.saved == Some(true)
                    && self.reason.is_none()
                    && self.message.is_none()
                    && no_identity
            }
            ("save", "save-unavailable") => {
                no_capability
                    && no_activation
                    && no_credential
                    && no_saved
                    && self.message.is_none()
                    && self.reason.as_deref().is_some_and(valid_reason)
                    && no_identity
            }
            ("identity", "identity") => {
                let requested = request.fields.as_deref().and_then(parse_identity_fields);
                no_capability
                    && no_activation
                    && no_credential
                    && no_saved
                    && self.reason.is_none()
                    && self.message.is_none()
                    && self.identity.as_ref().is_some_and(|fields| {
                        requested
                            .as_deref()
                            .is_some_and(|requested| fields.matches_requested(requested))
                    })
            }
            ("identity", "identity-unavailable") => {
                no_capability
                    && no_activation
                    && no_credential
                    && no_saved
                    && no_identity
                    && self.message.is_none()
                    && self.reason.as_deref().is_some_and(valid_reason)
            }
            ("fill", "fill") => {
                let fields = request.fields.as_deref().unwrap_or("both");
                let username_valid = self.username.as_deref().is_some_and(|username| {
                    !username.is_empty() && username.len() <= MAX_CREDENTIAL_FIELD_BYTES
                });
                let password_valid = self.password.as_deref().is_some_and(|password| {
                    !password.is_empty() && password.len() <= MAX_CREDENTIAL_FIELD_BYTES
                });
                let credential_valid = match fields {
                    "username" => username_valid && self.password.is_none(),
                    "password" => self.username.is_none() && password_valid,
                    "both" => {
                        self.username
                            .as_deref()
                            .is_some_and(|username| username.len() <= MAX_CREDENTIAL_FIELD_BYTES)
                            && password_valid
                    }
                    _ => false,
                };
                no_capability
                    && no_activation
                    && credential_valid
                    && self.reason.is_none()
                    && self.message.is_none()
                    && no_saved
                    && no_identity
            }
            ("fill", "fill-unavailable") => {
                no_capability
                    && no_activation
                    && no_credential
                    && no_saved
                    && no_identity
                    && self.message.is_none()
                    && self.reason.as_deref().is_some_and(valid_reason)
            }
            ("card", "card") => {
                let requested = request.fields.as_deref().and_then(parse_card_fields);
                no_capability
                    && no_activation
                    && no_credential
                    && no_saved
                    && no_identity
                    && self.reason.is_none()
                    && self.message.is_none()
                    && self.card.as_ref().is_some_and(|fields| {
                        requested
                            .as_deref()
                            .is_some_and(|requested| fields.matches_requested(requested))
                    })
            }
            ("card", "card-unavailable") => {
                no_capability
                    && no_activation
                    && no_credential
                    && no_saved
                    && no_identity
                    && no_card
                    && self.message.is_none()
                    && self.reason.as_deref().is_some_and(valid_reason)
            }
            (_, "error") => {
                no_capability
                    && no_activation
                    && no_credential
                    && no_saved
                    && no_identity
                    && self.reason.is_none()
                    && self.message.as_deref().is_some_and(valid_error_message)
            }
            _ => false,
        }
    }

    pub fn to_zeroizing_bytes(&self) -> Result<Zeroizing<Vec<u8>>, serde_json::Error> {
        serde_json::to_vec(self).map(Zeroizing::new)
    }
}

impl Drop for BrowserResponse {
    fn drop(&mut self) {
        self.request_id.zeroize();
        self.username.zeroize();
        self.password.zeroize();
        self.reason.zeroize();
        self.message.zeroize();
        self.identity.zeroize();
        self.card.zeroize();
    }
}

fn valid_identifier(value: &str) -> bool {
    (1..=64).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn valid_reason(value: &str) -> bool {
    matches!(
        value,
        "desktopUnavailable"
            | "locked"
            | "noMatch"
            | "approvalUnavailable"
            | "approvalDeclined"
            | "approvalTimeout"
            | "staleRequest"
            | "invalidSelection"
            | "multipleMatches"
    )
}

fn valid_error_message(value: &str) -> bool {
    matches!(
        value,
        "Unsupported protocol version."
            | "Invalid browser request."
            | "Unsupported browser request."
            | "Browser response unavailable."
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(version: u8, message_type: &str) -> BrowserRequest {
        BrowserRequest {
            version,
            message_type: message_type.to_string(),
            request_id: "request-1".to_string(),
            origin: Some("https://checkout.example.test".to_string()),
            fields: Some("number,securityCode".to_string()),
            username: None,
            password: None,
            title: None,
            kind: None,
        }
    }

    #[test]
    fn card_requests_require_protocol_v2_and_https() {
        assert!(request(CARD_PROTOCOL_VERSION, "card").validate());
        assert!(!request(PROTOCOL_VERSION, "card").validate());

        let mut insecure = request(CARD_PROTOCOL_VERSION, "card");
        insecure.origin = Some("http://localhost:4173".to_string());
        assert!(!insecure.validate());
    }

    #[test]
    fn protocol_v2_does_not_accept_legacy_request_types() {
        let mut capability = request(CARD_PROTOCOL_VERSION, "capabilities");
        capability.origin = None;
        capability.fields = None;
        assert!(!capability.validate());

        let mut fill = request(CARD_PROTOCOL_VERSION, "fill");
        fill.fields = None;
        assert!(!fill.validate());
    }

    #[test]
    fn card_responses_bind_the_version_and_exact_field_set() {
        let request = request(CARD_PROTOCOL_VERSION, "card");
        let allowed = BrowserResponse::card_for(
            &request,
            CardFillFields {
                number: Some("4111111111111111".to_string()),
                security_code: Some("123".to_string()),
                ..CardFillFields::default()
            },
        );
        assert!(allowed.validate_for(&request));

        let extra_field = BrowserResponse::card_for(
            &request,
            CardFillFields {
                number: Some("4111111111111111".to_string()),
                security_code: Some("123".to_string()),
                expiry_month: Some("12".to_string()),
                ..CardFillFields::default()
            },
        );
        assert!(!extra_field.validate_for(&request));
    }
}
