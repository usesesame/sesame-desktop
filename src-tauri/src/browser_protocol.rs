use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

pub const PROTOCOL_VERSION: u8 = 1;
pub const CARD_PROTOCOL_VERSION: u8 = 2;
pub const FILL_MATCH_PROTOCOL_VERSION: u8 = 3;
pub const TOTP_PROTOCOL_VERSION: u8 = 4;
pub const LOOKALIKE_PROTOCOL_VERSION: u8 = 5;
pub const MAX_NATIVE_MESSAGE_BYTES: usize = 16 * 1024;
pub const MAX_CREDENTIAL_FIELD_BYTES: usize = 4096;
pub const MAX_LOOKALIKE_HOST_CHARS: usize = 128;
pub const MAX_TOTP_CODE_DIGITS: usize = 9;
pub const MAX_TOTP_REMAINING_SECONDS: u64 = 3600;

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
    matches!(
        version,
        PROTOCOL_VERSION
            | CARD_PROTOCOL_VERSION
            | FILL_MATCH_PROTOCOL_VERSION
            | TOTP_PROTOCOL_VERSION
            | LOOKALIKE_PROTOCOL_VERSION
    )
}

pub fn fill_carries_match_kind(version: u8) -> bool {
    matches!(
        version,
        FILL_MATCH_PROTOCOL_VERSION | LOOKALIKE_PROTOCOL_VERSION
    )
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
            || (self.version == FILL_MATCH_PROTOCOL_VERSION && self.message_type != "fill")
            || (self.version == TOTP_PROTOCOL_VERSION && self.message_type != "totp")
            || (self.version == LOOKALIKE_PROTOCOL_VERSION && self.message_type != "fill")
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
            "totp" => {
                self.version == TOTP_PROTOCOL_VERSION
                    && self.origin.as_deref().is_some_and(|origin| {
                        !origin.is_empty()
                            && origin.len() <= 2048
                            && !origin.chars().any(char::is_control)
                    })
                    && self.fields.is_none()
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
                let username_ok = self
                    .username
                    .as_deref()
                    .is_none_or(|username| username.len() <= MAX_CREDENTIAL_FIELD_BYTES);
                let title_ok = self
                    .title
                    .as_deref()
                    .is_none_or(|title| !title.is_empty() && title.len() <= 512);
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

    pub fn to_zeroizing_bytes(&self) -> Result<Zeroizing<Vec<u8>>, serde_json::Error> {
        serde_json::to_vec(self).map(Zeroizing::new)
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
    pub match_kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lookalike: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub saved: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity: Option<IdentityFillFields>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub card: Option<CardFillFields>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remaining_seconds: Option<u64>,
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
            match_kind: None,
            reason: None,
            message: None,
            lookalike: None,
            saved: None,
            identity: None,
            card: None,
            code: None,
            remaining_seconds: None,
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
            match_kind: None,
            reason: None,
            message: None,
            lookalike: None,
            saved: None,
            identity: None,
            card: None,
            code: None,
            remaining_seconds: None,
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
            match_kind: None,
            reason: None,
            message: None,
            lookalike: None,
            saved: None,
            identity: None,
            card: None,
            code: None,
            remaining_seconds: None,
        }
    }

    pub fn fill_with_match_kind(
        request: &BrowserRequest,
        username: String,
        password: String,
        match_kind: &'static str,
    ) -> Self {
        let fields = request.fields.as_deref().unwrap_or("both");
        Self {
            version: request.version,
            message_type: "fill".into(),
            request_id: request.request_id.clone(),
            installed: None,
            desktop_available: None,
            locked: None,
            fill_available: None,
            opened: None,
            username: matches!(fields, "username" | "both").then_some(username),
            password: matches!(fields, "password" | "both").then_some(password),
            match_kind: Some(match_kind.into()),
            reason: None,
            message: None,
            lookalike: None,
            saved: None,
            identity: None,
            card: None,
            code: None,
            remaining_seconds: None,
        }
    }

    pub fn unavailable(request: &BrowserRequest, reason: &'static str) -> Self {
        Self {
            version: request.version,
            message_type: "fill-unavailable".into(),
            request_id: request.request_id.clone(),
            installed: None,
            desktop_available: None,
            locked: None,
            fill_available: None,
            opened: None,
            username: None,
            password: None,
            match_kind: None,
            reason: Some(reason.into()),
            message: None,
            lookalike: None,
            saved: None,
            identity: None,
            card: None,
            code: None,
            remaining_seconds: None,
        }
    }

    pub fn lookalike_unavailable(request: &BrowserRequest, lookalike: String) -> Self {
        Self {
            version: LOOKALIKE_PROTOCOL_VERSION,
            message_type: "fill-unavailable".into(),
            request_id: request.request_id.clone(),
            installed: None,
            desktop_available: None,
            locked: None,
            fill_available: None,
            opened: None,
            username: None,
            password: None,
            match_kind: None,
            reason: Some("lookalike".into()),
            message: None,
            lookalike: Some(lookalike),
            saved: None,
            identity: None,
            card: None,
            code: None,
            remaining_seconds: None,
        }
    }

    pub fn error(request_id: &str, message: &'static str) -> Self {
        Self::error_with_version(PROTOCOL_VERSION, request_id, message)
    }

    pub fn error_with_version(version: u8, request_id: &str, message: &'static str) -> Self {
        Self {
            version,
            message_type: "error".into(),
            request_id: request_id.into(),
            installed: None,
            desktop_available: None,
            locked: None,
            fill_available: None,
            opened: None,
            username: None,
            password: None,
            match_kind: None,
            reason: None,
            message: Some(message.into()),
            lookalike: None,
            saved: None,
            identity: None,
            card: None,
            code: None,
            remaining_seconds: None,
        }
    }

    pub fn error_for(request: &BrowserRequest, message: &'static str) -> Self {
        Self::error_with_version(request.version, &request.request_id, message)
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
            match_kind: None,
            reason: None,
            message: None,
            lookalike: None,
            saved: Some(true),
            identity: None,
            card: None,
            code: None,
            remaining_seconds: None,
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
            match_kind: None,
            reason: Some(reason.into()),
            message: None,
            lookalike: None,
            saved: None,
            identity: None,
            card: None,
            code: None,
            remaining_seconds: None,
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
            match_kind: None,
            reason: None,
            message: None,
            lookalike: None,
            saved: None,
            identity: Some(fields),
            card: None,
            code: None,
            remaining_seconds: None,
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
            match_kind: None,
            reason: Some(reason.into()),
            message: None,
            lookalike: None,
            saved: None,
            identity: None,
            card: None,
            code: None,
            remaining_seconds: None,
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
            match_kind: None,
            reason: None,
            message: None,
            lookalike: None,
            saved: None,
            identity: None,
            card: Some(fields),
            code: None,
            remaining_seconds: None,
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
            match_kind: None,
            reason: Some(reason.into()),
            message: None,
            lookalike: None,
            saved: None,
            identity: None,
            card: None,
            code: None,
            remaining_seconds: None,
        }
    }

    pub fn totp_for(request: &BrowserRequest, code: String, remaining_seconds: u64) -> Self {
        Self {
            version: TOTP_PROTOCOL_VERSION,
            message_type: "totp".into(),
            request_id: request.request_id.clone(),
            installed: None,
            desktop_available: None,
            locked: None,
            fill_available: None,
            opened: None,
            username: None,
            password: None,
            match_kind: None,
            reason: None,
            message: None,
            lookalike: None,
            saved: None,
            identity: None,
            card: None,
            code: Some(code),
            remaining_seconds: Some(remaining_seconds),
        }
    }

    pub fn totp_unavailable(request_id: &str, reason: &'static str) -> Self {
        Self {
            version: TOTP_PROTOCOL_VERSION,
            message_type: "totp-unavailable".into(),
            request_id: request_id.into(),
            installed: None,
            desktop_available: None,
            locked: None,
            fill_available: None,
            opened: None,
            username: None,
            password: None,
            match_kind: None,
            reason: Some(reason.into()),
            message: None,
            lookalike: None,
            saved: None,
            identity: None,
            card: None,
            code: None,
            remaining_seconds: None,
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
        let no_code = self.code.is_none() && self.remaining_seconds.is_none();
        if request.message_type != "card" && !no_card {
            return false;
        }
        if self.message_type != "totp" && !no_code {
            return false;
        }
        let match_kind_allowed = fill_carries_match_kind(request.version)
            && request.message_type == "fill"
            && self.message_type == "fill";
        if self.match_kind.is_some() && !match_kind_allowed {
            return false;
        }
        let lookalike_allowed = request.version == LOOKALIKE_PROTOCOL_VERSION
            && request.message_type == "fill"
            && self.message_type == "fill-unavailable"
            && self.reason.as_deref() == Some("lookalike");
        if self.lookalike.is_some() && !lookalike_allowed {
            return false;
        }
        let allowed = match (request.message_type.as_str(), self.message_type.as_str()) {
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
                let match_kind_valid = if fill_carries_match_kind(request.version) {
                    self.match_kind.as_deref().is_some_and(valid_match_kind)
                } else {
                    self.match_kind.is_none()
                };
                no_capability
                    && no_activation
                    && credential_valid
                    && match_kind_valid
                    && self.reason.is_none()
                    && self.message.is_none()
                    && no_saved
                    && no_identity
            }
            ("fill", "fill-unavailable") => {
                let reason_valid = self.reason.as_deref().is_some_and(|reason| {
                    valid_reason(reason)
                        && (reason != "lookalike" || request.version == LOOKALIKE_PROTOCOL_VERSION)
                });
                let lookalike_valid = match self.reason.as_deref() {
                    Some("lookalike") => {
                        self.lookalike.as_deref().is_some_and(valid_lookalike_host)
                    }
                    _ => self.lookalike.is_none(),
                };
                no_capability
                    && no_activation
                    && no_credential
                    && no_saved
                    && no_identity
                    && self.message.is_none()
                    && reason_valid
                    && lookalike_valid
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
            ("totp", "totp") => {
                no_capability
                    && no_activation
                    && no_credential
                    && no_saved
                    && no_identity
                    && no_card
                    && self.reason.is_none()
                    && self.message.is_none()
                    && self.code.as_deref().is_some_and(valid_totp_code)
                    && self.remaining_seconds.is_some_and(valid_totp_remaining)
            }
            ("totp", "totp-unavailable") => {
                no_capability
                    && no_activation
                    && no_credential
                    && no_saved
                    && no_identity
                    && no_card
                    && no_code
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
        };
        allowed && self.within_message_budget()
    }

    /// Every accepted response must fit the frame the host can write.
    fn within_message_budget(&self) -> bool {
        self.to_zeroizing_bytes()
            .map(|bytes| !bytes.is_empty() && bytes.len() <= MAX_NATIVE_MESSAGE_BYTES)
            .unwrap_or(false)
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
        self.match_kind.zeroize();
        self.reason.zeroize();
        self.message.zeroize();
        self.lookalike.zeroize();
        self.identity.zeroize();
        self.card.zeroize();
        self.code.zeroize();
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
            | "lookalike"
    )
}

fn valid_lookalike_host(value: &str) -> bool {
    (1..=MAX_LOOKALIKE_HOST_CHARS).contains(&value.chars().count())
        && !value.chars().any(char::is_control)
        && !value.split('.').any(str::is_empty)
        && matches!(url::Host::parse(value), Ok(url::Host::Domain(domain)) if domain == value)
}

fn valid_match_kind(value: &str) -> bool {
    matches!(value, "exact" | "wwwAlias")
}

fn valid_totp_code(value: &str) -> bool {
    (1..=MAX_TOTP_CODE_DIGITS).contains(&value.len())
        && value.bytes().all(|byte| byte.is_ascii_digit())
}

fn valid_totp_remaining(value: u64) -> bool {
    (1..=MAX_TOTP_REMAINING_SECONDS).contains(&value)
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

    fn fill_request(version: u8) -> BrowserRequest {
        BrowserRequest {
            version,
            message_type: "fill".to_string(),
            request_id: "request-1".to_string(),
            origin: Some("https://example.test".to_string()),
            fields: None,
            username: None,
            password: None,
            title: None,
            kind: None,
        }
    }

    #[test]
    fn fill_match_requests_are_fill_only() {
        assert!(fill_request(FILL_MATCH_PROTOCOL_VERSION).validate());

        let mut capability = fill_request(FILL_MATCH_PROTOCOL_VERSION);
        capability.message_type = "capabilities".to_string();
        capability.origin = None;
        assert!(!capability.validate());

        let mut card = fill_request(FILL_MATCH_PROTOCOL_VERSION);
        card.message_type = "card".to_string();
        card.fields = Some("number".to_string());
        assert!(!card.validate());

        let future = fill_request(LOOKALIKE_PROTOCOL_VERSION + 1);
        assert!(!future.validate());
    }

    #[test]
    fn fill_match_responses_carry_the_rule_only_on_protocol_v3() {
        let request = fill_request(FILL_MATCH_PROTOCOL_VERSION);
        let exact = BrowserResponse::fill_with_match_kind(
            &request,
            "person@example.test".to_string(),
            "fictional-example-value".to_string(),
            "exact",
        );
        assert_eq!(exact.match_kind.as_deref(), Some("exact"));
        assert!(exact.validate_for(&request));

        let alias = BrowserResponse::fill_with_match_kind(
            &request,
            "person@example.test".to_string(),
            "fictional-example-value".to_string(),
            "wwwAlias",
        );
        assert!(alias.validate_for(&request));

        let missing = BrowserResponse::fill_for(
            &request,
            "person@example.test".to_string(),
            "fictional-example-value".to_string(),
        );
        assert_eq!(missing.version, PROTOCOL_VERSION);
        assert!(!missing.validate_for(&request));

        let unknown = BrowserResponse::fill_with_match_kind(
            &request,
            "person@example.test".to_string(),
            "fictional-example-value".to_string(),
            "parentDomain",
        );
        assert!(!unknown.validate_for(&request));

        let unavailable = BrowserResponse::unavailable(&request, "noMatch");
        assert_eq!(unavailable.version, FILL_MATCH_PROTOCOL_VERSION);
        assert!(unavailable.validate_for(&request));
    }

    #[test]
    fn fill_match_responses_do_not_cross_protocol_versions() {
        let v1_request = fill_request(PROTOCOL_VERSION);
        assert!(v1_request.validate());
        let v1_response = BrowserResponse::fill_for(
            &v1_request,
            "person@example.test".to_string(),
            "fictional-example-value".to_string(),
        );
        assert!(v1_response.match_kind.is_none());
        assert!(v1_response.validate_for(&v1_request));

        let mut smuggled = BrowserResponse::fill_for(
            &v1_request,
            "person@example.test".to_string(),
            "fictional-example-value".to_string(),
        );
        smuggled.match_kind = Some("exact".to_string());
        assert!(!smuggled.validate_for(&v1_request));

        let v3_request = fill_request(FILL_MATCH_PROTOCOL_VERSION);
        let v3_response = BrowserResponse::fill_with_match_kind(
            &v3_request,
            "person@example.test".to_string(),
            "fictional-example-value".to_string(),
            "exact",
        );
        assert!(!v3_response.validate_for(&v1_request));
        assert!(!v1_response.validate_for(&v3_request));
    }

    fn lookalike_request() -> BrowserRequest {
        BrowserRequest {
            version: LOOKALIKE_PROTOCOL_VERSION,
            message_type: "fill".to_string(),
            request_id: "fill-5-1".to_string(),
            origin: Some("https://example.test".to_string()),
            fields: None,
            username: None,
            password: None,
            title: None,
            kind: None,
        }
    }

    #[test]
    fn lookalike_requests_are_fill_only_on_protocol_version_five() {
        assert!(lookalike_request().validate());

        let mut capability = lookalike_request();
        capability.message_type = "capabilities".to_string();
        capability.origin = None;
        assert!(!capability.validate());

        let mut totp = lookalike_request();
        totp.message_type = "totp".to_string();
        assert!(!totp.validate());

        let mut with_save_payload = lookalike_request();
        with_save_payload.password = Some("fictional-example-value".to_string());
        assert!(!with_save_payload.validate());

        assert!(!fill_request(LOOKALIKE_PROTOCOL_VERSION + 1).validate());
    }

    #[test]
    fn a_version_five_fill_response_carries_the_rule_and_no_lookalike_field() {
        let request = lookalike_request();
        let fill = BrowserResponse::fill_with_match_kind(
            &request,
            "person@example.test".to_string(),
            "fictional-example-value".to_string(),
            "wwwAlias",
        );
        assert_eq!(fill.version, LOOKALIKE_PROTOCOL_VERSION);
        assert_eq!(fill.match_kind.as_deref(), Some("wwwAlias"));
        assert!(fill.lookalike.is_none());
        assert!(fill.validate_for(&request));

        let missing_rule = BrowserResponse::fill_for(
            &request,
            "person@example.test".to_string(),
            "fictional-example-value".to_string(),
        );
        assert!(!missing_rule.validate_for(&request));

        let mut with_lookalike = BrowserResponse::fill_with_match_kind(
            &request,
            "person@example.test".to_string(),
            "fictional-example-value".to_string(),
            "exact",
        );
        with_lookalike.lookalike = Some("apple.com".to_string());
        assert!(!with_lookalike.validate_for(&request));
    }

    #[test]
    fn only_version_five_carries_the_lookalike_reason_and_field() {
        let request = lookalike_request();
        let response = BrowserResponse::lookalike_unavailable(&request, "apple.com".to_string());
        assert_eq!(response.version, LOOKALIKE_PROTOCOL_VERSION);
        assert_eq!(response.message_type, "fill-unavailable");
        assert_eq!(response.reason.as_deref(), Some("lookalike"));
        assert_eq!(response.lookalike.as_deref(), Some("apple.com"));
        assert!(response.username.is_none() && response.password.is_none());
        assert!(response.validate_for(&request));
        let wire = String::from_utf8(response.to_zeroizing_bytes().expect("encodes").to_vec())
            .expect("utf8");
        assert!(wire.contains("\"lookalike\":\"apple.com\""));
        assert!(!wire.contains("password"));

        let mut without_host = BrowserResponse::unavailable(&request, "lookalike");
        assert!(!without_host.validate_for(&request));
        without_host.lookalike = Some(String::new());
        assert!(!without_host.validate_for(&request));

        let mut unrelated_with_host = BrowserResponse::unavailable(&request, "noMatch");
        unrelated_with_host.lookalike = Some("apple.com".to_string());
        assert!(!unrelated_with_host.validate_for(&request));

        let mut reason_swapped =
            BrowserResponse::lookalike_unavailable(&request, "apple.com".to_string());
        reason_swapped.reason = Some("noMatch".to_string());
        assert!(!reason_swapped.validate_for(&request));

        let mut reason_opened =
            BrowserResponse::lookalike_unavailable(&request, "apple.com".to_string());
        reason_opened.reason = Some("lookalikeDomain".to_string());
        assert!(!reason_opened.validate_for(&request));

        let mut with_match_kind =
            BrowserResponse::lookalike_unavailable(&request, "apple.com".to_string());
        with_match_kind.match_kind = Some("exact".to_string());
        assert!(!with_match_kind.validate_for(&request));

        let mut error = BrowserResponse::error_with_version(
            LOOKALIKE_PROTOCOL_VERSION,
            &request.request_id,
            "Browser response unavailable.",
        );
        error.lookalike = Some("apple.com".to_string());
        assert!(!error.validate_for(&request));

        for version in [PROTOCOL_VERSION, FILL_MATCH_PROTOCOL_VERSION] {
            let mut older = fill_request(version);
            older.message_type = "fill".to_string();
            assert!(older.validate());
            assert!(!BrowserResponse::unavailable(&older, "lookalike").validate_for(&older));
            assert!(
                !BrowserResponse::lookalike_unavailable(&older, "apple.com".to_string())
                    .validate_for(&older)
            );
        }

        assert!(
            !BrowserResponse::lookalike_unavailable(&request, "apple.com".to_string())
                .validate_for(&fill_request(LOOKALIKE_PROTOCOL_VERSION + 1))
        );
    }

    #[test]
    fn a_lookalike_host_is_a_bounded_normalized_domain() {
        let request = lookalike_request();
        let response = |host: &str| {
            BrowserResponse::lookalike_unavailable(&request, host.to_string())
                .validate_for(&request)
        };

        assert!(response("apple.com"));
        assert!(response(&"a".repeat(MAX_LOOKALIKE_HOST_CHARS)));
        assert!(!response(&"a".repeat(MAX_LOOKALIKE_HOST_CHARS + 1)));
        assert!(!response(""));
        assert!(!response("apple.com/sign-in"));
        assert!(!response("apple.com?next=/vault"));
        assert!(!response("casey:fictional@apple.com"));
        assert!(!response("apple.com."));
        assert!(!response("127.0.0.1"));
        assert!(!response("APPLE.COM"));
        assert!(!response("apple com"));
        assert!(!response("apple\u{7f}.com"));
        assert!(!response("[::1]"));
    }

    #[test]
    fn the_lookalike_reason_answers_only_a_fill_request() {
        let request = lookalike_request();
        let card = BrowserRequest {
            version: CARD_PROTOCOL_VERSION,
            message_type: "card".to_string(),
            request_id: request.request_id.clone(),
            origin: Some("https://example.test".to_string()),
            fields: Some("number".to_string()),
            username: None,
            password: None,
            title: None,
            kind: None,
        };
        assert!(card.validate());
        assert!(
            !BrowserResponse::lookalike_unavailable(&request, "apple.com".to_string())
                .validate_for(&card)
        );
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

    #[test]
    fn native_message_payloads_survive_mutations_without_panicking() {
        use rand::rngs::StdRng;
        use rand::RngExt;
        use rand::SeedableRng;

        let seed_request = request(CARD_PROTOCOL_VERSION, "card");
        let mut rng = StdRng::seed_from_u64(4096);
        let mut bytes = serde_json::to_vec(&seed_request).expect("the seed request serializes");
        for _ in 0..900 {
            let mut payload = bytes.clone();
            for _ in 0..rng.random_range(1..=4) {
                if payload.is_empty() {
                    break;
                }
                match rng.random_range(0..6) {
                    0 => {
                        let index = rng.random_range(0..payload.len());
                        payload[index] ^= 1 << rng.random_range(0..8);
                    }
                    1 => {
                        let cut = rng.random_range(0..payload.len());
                        payload.truncate(cut);
                    }
                    2 => {
                        let extra: Vec<u8> = (0..rng.random_range(1..=32))
                            .map(|_| rng.random())
                            .collect();
                        payload.extend_from_slice(&extra);
                    }
                    3 => {
                        let index = rng.random_range(0..payload.len());
                        payload[index] = rng.random();
                    }
                    4 => {
                        let start = rng.random_range(0..payload.len());
                        let end = rng.random_range(start..payload.len());
                        payload[start..end].fill(0);
                    }
                    _ => {
                        let at = rng.random_range(0..=payload.len());
                        let extra: &[u8] = br#","type":"fill","origin":"javascript:alert(1)""#;
                        payload.splice(at..at, extra.iter().copied());
                    }
                }
            }
            bytes = payload;
            if let Ok(request) = serde_json::from_slice::<BrowserRequest>(&bytes) {
                let _ = request.validate();
            }
        }
        assert!(serde_json::from_slice::<BrowserRequest>(&[]).is_err());
        for payload in [
            br#"{"version":"2","type":"card","request_id":"r1"}"#.as_slice(),
            br#"{"version":2,"type":["card"],"request_id":{"r":1}}"#.as_slice(),
            br#"[1,2,3]"#.as_slice(),
            br#""a string""#.as_slice(),
        ] {
            if let Ok(request) = serde_json::from_slice::<BrowserRequest>(payload) {
                let _ = request.validate();
            }
        }
    }

    #[test]
    fn an_identity_response_over_the_message_budget_is_refused() {
        let mut identity_request = request(PROTOCOL_VERSION, "identity");
        identity_request.fields = Some(IDENTITY_FIELD_KEYS.join(","));
        assert!(identity_request.validate());

        let big = "x".repeat(MAX_CREDENTIAL_FIELD_BYTES);
        let oversize = BrowserResponse::identity_for(
            &identity_request,
            IdentityFillFields {
                full_name: Some(big.clone()),
                email: Some(big.clone()),
                phone: Some(big.clone()),
                address_line1: Some(big.clone()),
                address_line2: Some(big.clone()),
                city: Some(big.clone()),
                region: Some(big.clone()),
                postal_code: Some(big.clone()),
                country: Some(big),
            },
        );
        assert!(!oversize.validate_for(&identity_request));

        let mut small_request = request(PROTOCOL_VERSION, "identity");
        small_request.fields = Some("fullName,email".to_string());
        assert!(small_request.validate());
        let typical = BrowserResponse::identity_for(
            &small_request,
            IdentityFillFields {
                full_name: Some("Fictional Person".to_string()),
                email: Some("fictional@example.test".to_string()),
                ..IdentityFillFields::default()
            },
        );
        assert!(typical.validate_for(&small_request));
    }

    #[test]
    fn the_largest_save_request_fits_the_frame_budget() {
        let save = BrowserRequest {
            version: PROTOCOL_VERSION,
            message_type: "save".to_string(),
            request_id: "request-1".to_string(),
            origin: Some(format!("https://{}.example.test", "a".repeat(2000))),
            fields: None,
            username: Some("u".repeat(MAX_CREDENTIAL_FIELD_BYTES)),
            password: Some("p".repeat(MAX_CREDENTIAL_FIELD_BYTES)),
            title: Some("t".repeat(512)),
            kind: Some("new".to_string()),
        };
        assert!(save.validate());
        let bytes = save.to_zeroizing_bytes().expect("the request encodes");
        assert!(bytes.len() <= MAX_NATIVE_MESSAGE_BYTES);
    }

    fn totp_request(version: u8) -> BrowserRequest {
        BrowserRequest {
            version,
            message_type: "totp".to_string(),
            request_id: "totp-1".to_string(),
            origin: Some("https://example.test".to_string()),
            fields: None,
            username: None,
            password: None,
            title: None,
            kind: None,
        }
    }

    #[test]
    fn totp_requests_are_totp_only_on_protocol_version_four() {
        assert!(totp_request(TOTP_PROTOCOL_VERSION).validate());

        for version in [
            PROTOCOL_VERSION,
            CARD_PROTOCOL_VERSION,
            FILL_MATCH_PROTOCOL_VERSION,
        ] {
            assert!(
                !totp_request(version).validate(),
                "version {version} accepted a totp request"
            );
        }

        let mut fill = totp_request(TOTP_PROTOCOL_VERSION);
        fill.message_type = "fill".to_string();
        assert!(!fill.validate());

        let mut with_fields = totp_request(TOTP_PROTOCOL_VERSION);
        with_fields.fields = Some("password".to_string());
        assert!(!with_fields.validate());

        let mut without_origin = totp_request(TOTP_PROTOCOL_VERSION);
        without_origin.origin = None;
        assert!(!without_origin.validate());

        let mut with_credentials = totp_request(TOTP_PROTOCOL_VERSION);
        with_credentials.password = Some("fictional-example-value".to_string());
        assert!(!with_credentials.validate());

        assert!(!totp_request(TOTP_PROTOCOL_VERSION + 1).validate());
    }

    #[test]
    fn totp_responses_bind_the_version_the_code_and_the_window() {
        let request = totp_request(TOTP_PROTOCOL_VERSION);
        let allowed = BrowserResponse::totp_for(&request, "123456".to_string(), 30);
        assert_eq!(allowed.version, TOTP_PROTOCOL_VERSION);
        assert_eq!(allowed.message_type, "totp");
        assert!(allowed.validate_for(&request));
        let wire = String::from_utf8(allowed.to_zeroizing_bytes().expect("encodes").to_vec())
            .expect("utf8");
        assert!(wire.contains("\"code\":\"123456\""));
        assert!(wire.contains("\"remainingSeconds\":30"));

        for code in ["0", "000000", "123456789"] {
            assert!(
                BrowserResponse::totp_for(&request, code.to_string(), 30).validate_for(&request),
                "{code} was refused as a code"
            );
        }
        for code in [
            "",
            "1234567890",
            "12a456",
            "-12345",
            " 123456",
            "１２３４５６",
        ] {
            assert!(
                !BrowserResponse::totp_for(&request, code.to_string(), 30).validate_for(&request),
                "{code} was accepted as a code"
            );
        }

        for remaining in [1, 30, MAX_TOTP_REMAINING_SECONDS] {
            assert!(
                BrowserResponse::totp_for(&request, "123456".to_string(), remaining)
                    .validate_for(&request),
                "{remaining} seconds was refused"
            );
        }
        for remaining in [0, MAX_TOTP_REMAINING_SECONDS + 1, u64::MAX] {
            assert!(
                !BrowserResponse::totp_for(&request, "123456".to_string(), remaining)
                    .validate_for(&request),
                "{remaining} seconds was accepted"
            );
        }

        let mut missing_remaining = BrowserResponse::totp_for(&request, "123456".to_string(), 30);
        missing_remaining.remaining_seconds = None;
        assert!(!missing_remaining.validate_for(&request));

        let mut missing_code = BrowserResponse::totp_for(&request, "123456".to_string(), 30);
        missing_code.code = None;
        assert!(!missing_code.validate_for(&request));
    }

    #[test]
    fn a_totp_response_only_answers_a_totp_request() {
        let request = totp_request(TOTP_PROTOCOL_VERSION);
        let v3_fill = fill_request(FILL_MATCH_PROTOCOL_VERSION);

        assert!(
            !BrowserResponse::totp_for(&request, "123456".to_string(), 30).validate_for(&v3_fill)
        );
        assert!(
            !BrowserResponse::totp_unavailable(&request.request_id, "noMatch")
                .validate_for(&v3_fill)
        );
        assert!(!BrowserResponse::fill_with_match_kind(
            &v3_fill,
            "person@example.test".to_string(),
            "fictional-example-value".to_string(),
            "exact",
        )
        .validate_for(&request));
        assert!(!BrowserResponse::fill_for(
            &v3_fill,
            "person@example.test".to_string(),
            "fictional-example-value".to_string(),
        )
        .validate_for(&request));
        assert!(!BrowserResponse::unavailable(&request, "noMatch").validate_for(&request));

        let unavailable = BrowserResponse::totp_unavailable(&request.request_id, "locked");
        assert_eq!(unavailable.version, TOTP_PROTOCOL_VERSION);
        assert_eq!(unavailable.message_type, "totp-unavailable");
        assert!(unavailable.validate_for(&request));

        let mut smuggled = BrowserResponse::totp_unavailable(&request.request_id, "locked");
        smuggled.code = Some("123456".to_string());
        assert!(!smuggled.validate_for(&request));

        let mut error_with_code = BrowserResponse::error_with_version(
            TOTP_PROTOCOL_VERSION,
            &request.request_id,
            "Browser response unavailable.",
        );
        assert!(error_with_code.validate_for(&request));
        error_with_code.code = Some("123456".to_string());
        assert!(!error_with_code.validate_for(&request));
    }
}
