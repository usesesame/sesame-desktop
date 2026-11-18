use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

pub const CLI_PROTOCOL_VERSION: u8 = 1;
pub const MAX_CLI_REQUEST_BYTES: usize = 4 * 1024;
pub const MAX_CLI_REPLY_BYTES: usize = 64 * 1024;
pub const MAX_CLI_LIST_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_ITEM_CHARS: usize = 256;
pub const MAX_FIELD_CHARS: usize = 128;
pub const MAX_TITLE_CHARS: usize = 1024;
pub const MAX_ITEM_ID_CHARS: usize = 128;
pub const MAX_MESSAGE_CHARS: usize = 512;
pub const MAX_WAITING_FRAMES: usize = 2;
pub const MAX_TOTP_CODE_DIGITS: usize = 9;
pub const MAX_TOTP_REMAINING_SECONDS: u64 = 3_600;
pub const MAX_CLEAR_AFTER_SECONDS: u64 = 3_600;
const REQUEST_ID_CHARS: usize = 32;

const ITEM_KINDS: [&str; 9] = [
    "login",
    "identity",
    "secure_note",
    "card",
    "wifi_network",
    "ssh_key",
    "software_license",
    "document",
    "custom_record",
];

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum CliRequestType {
    List,
    Get,
    Totp,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CliRequest {
    pub version: u8,
    #[serde(rename = "type")]
    pub request_type: CliRequestType,
    pub request_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub item: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub copy: Option<bool>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CliCommand {
    List,
    Get {
        item: String,
        field: Option<String>,
        copy: bool,
    },
    Totp {
        item: String,
        copy: bool,
    },
}

impl CliCommand {
    pub fn to_request(&self, request_id: &str) -> CliRequest {
        let (request_type, item, field, copy) = match self {
            Self::List => (CliRequestType::List, None, None, None),
            Self::Get { item, field, copy } => (
                CliRequestType::Get,
                Some(item.clone()),
                field.clone(),
                (*copy).then_some(true),
            ),
            Self::Totp { item, copy } => (
                CliRequestType::Totp,
                Some(item.clone()),
                None,
                (*copy).then_some(true),
            ),
        };
        CliRequest {
            version: CLI_PROTOCOL_VERSION,
            request_type,
            request_id: request_id.to_string(),
            item,
            field,
            copy,
        }
    }

    pub fn copies(&self) -> bool {
        match self {
            Self::List => false,
            Self::Get { copy, .. } | Self::Totp { copy, .. } => *copy,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum CliErrorCode {
    Invalid,
    UnsupportedVersion,
    Busy,
    Cancelled,
    Timeout,
    Stale,
    NotFound,
    NoField,
    EmptyField,
    NoTotp,
    TooLarge,
    Unavailable,
}

impl CliErrorCode {
    pub fn message(self) -> &'static str {
        match self {
            Self::Invalid => "Sesame could not read this request.",
            Self::UnsupportedVersion => "Update Sesame to use this command.",
            Self::Busy => "Sesame is answering another request. Try again in a moment.",
            Self::Cancelled => "Denied in Sesame.",
            Self::Timeout => "Nobody answered in Sesame.",
            Self::Stale => "Sesame locked before you answered.",
            Self::NotFound => "No item has that name.",
            Self::NoField => "That item has no field with that name.",
            Self::EmptyField => "Nothing is saved in that field.",
            Self::NoTotp => "That item has no one-time code set up.",
            Self::TooLarge => "The value is too large to send. Use --copy instead.",
            Self::Unavailable => "Sesame could not do that right now.",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CliRejection {
    pub code: CliErrorCode,
    pub request_id: Option<String>,
}

#[derive(Deserialize)]
struct VersionProbe {
    version: Option<serde_json::Value>,
    #[serde(rename = "requestId")]
    request_id: Option<serde_json::Value>,
}

pub fn valid_request_id(value: &str) -> bool {
    value.len() == REQUEST_ID_CHARS
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn bounded_text(value: &str, max_chars: usize) -> bool {
    let count = value.chars().count();
    (1..=max_chars).contains(&count)
        && !value.chars().any(char::is_control)
        && !value.trim().is_empty()
}

pub fn parse_request(bytes: &[u8]) -> Result<(String, CliCommand), CliRejection> {
    if bytes.is_empty() || bytes.len() > MAX_CLI_REQUEST_BYTES {
        return Err(CliRejection {
            code: CliErrorCode::Invalid,
            request_id: None,
        });
    }
    let probe = serde_json::from_slice::<VersionProbe>(bytes).ok();
    let echoed = probe
        .as_ref()
        .and_then(|probe| probe.request_id.as_ref())
        .and_then(|value| value.as_str())
        .filter(|value| valid_request_id(value))
        .map(str::to_string);
    let rejection = |code| CliRejection {
        code,
        request_id: echoed.clone(),
    };
    if let Some(version) = probe.as_ref().and_then(|probe| probe.version.as_ref()) {
        if version.as_u64() != Some(u64::from(CLI_PROTOCOL_VERSION)) {
            return Err(rejection(if version.is_u64() {
                CliErrorCode::UnsupportedVersion
            } else {
                CliErrorCode::Invalid
            }));
        }
    }
    let request = serde_json::from_slice::<CliRequest>(bytes)
        .map_err(|_| rejection(CliErrorCode::Invalid))?;
    let command = request
        .command()
        .ok_or_else(|| rejection(CliErrorCode::Invalid))?;
    Ok((request.request_id.clone(), command))
}

impl CliRequest {
    pub fn command(&self) -> Option<CliCommand> {
        if self.version != CLI_PROTOCOL_VERSION || !valid_request_id(&self.request_id) {
            return None;
        }
        let item = match &self.item {
            Some(item) if bounded_text(item, MAX_ITEM_CHARS) => Some(item.clone()),
            Some(_) => return None,
            None => None,
        };
        let field = match &self.field {
            Some(field) if bounded_text(field, MAX_FIELD_CHARS) => Some(field.clone()),
            Some(_) => return None,
            None => None,
        };
        match self.request_type {
            CliRequestType::List => (item.is_none() && field.is_none() && self.copy.is_none())
                .then_some(CliCommand::List),
            CliRequestType::Get => {
                let item = item?;
                if field.is_none() && self.copy.is_some() {
                    return None;
                }
                Some(CliCommand::Get {
                    item,
                    field,
                    copy: self.copy.unwrap_or(false),
                })
            }
            CliRequestType::Totp => {
                if field.is_some() {
                    return None;
                }
                Some(CliCommand::Totp {
                    item: item?,
                    copy: self.copy.unwrap_or(false),
                })
            }
        }
    }

    pub fn to_bytes(&self) -> Result<Zeroizing<Vec<u8>>, serde_json::Error> {
        serde_json::to_vec(self).map(Zeroizing::new)
    }
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum CliReplyType {
    Waiting,
    Items,
    Done,
    Item,
    Value,
    Copied,
    Totp,
    Error,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum WaitReason {
    Unlock,
    Approval,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CliItemSummary {
    pub id: String,
    pub kind: String,
    pub title: String,
}

impl CliItemSummary {
    fn is_valid(&self) -> bool {
        bounded_id(&self.id)
            && ITEM_KINDS.contains(&self.kind.as_str())
            && bounded_title(&self.title)
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CliField {
    pub name: String,
    pub hidden: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
}

impl Drop for CliField {
    fn drop(&mut self) {
        self.value.zeroize();
    }
}

impl CliField {
    fn is_valid(&self) -> bool {
        bounded_text(&self.name, MAX_FIELD_CHARS) && (self.hidden == self.value.is_none())
    }
}

fn bounded_id(value: &str) -> bool {
    !value.is_empty()
        && value.chars().count() <= MAX_ITEM_ID_CHARS
        && !value.chars().any(char::is_control)
}

fn bounded_title(value: &str) -> bool {
    value.chars().count() <= MAX_TITLE_CHARS
}

pub fn bounded_title_text(value: &str) -> String {
    value.chars().take(MAX_TITLE_CHARS).collect()
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CliReply {
    pub version: u8,
    #[serde(rename = "type")]
    pub reply_type: CliReplyType,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<WaitReason>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub items: Option<Vec<CliItemSummary>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fields: Option<Vec<CliField>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hidden: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub clear_after_seconds: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remaining_seconds: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

impl Drop for CliReply {
    fn drop(&mut self) {
        self.value.zeroize();
        self.code.zeroize();
    }
}

impl CliReply {
    fn empty(reply_type: CliReplyType, request_id: Option<&str>) -> Self {
        Self {
            version: CLI_PROTOCOL_VERSION,
            reply_type,
            request_id: request_id.map(str::to_string),
            reason: None,
            items: None,
            id: None,
            kind: None,
            title: None,
            fields: None,
            value: None,
            hidden: None,
            clear_after_seconds: None,
            code: None,
            remaining_seconds: None,
            message: None,
        }
    }

    pub fn waiting(request_id: &str, reason: WaitReason) -> Self {
        let mut reply = Self::empty(CliReplyType::Waiting, Some(request_id));
        reply.reason = Some(reason);
        reply
    }

    pub fn items(request_id: &str, items: Vec<CliItemSummary>) -> Self {
        let mut reply = Self::empty(CliReplyType::Items, Some(request_id));
        reply.items = Some(items);
        reply
    }

    pub fn done(request_id: &str) -> Self {
        Self::empty(CliReplyType::Done, Some(request_id))
    }

    pub fn item(request_id: &str, summary: CliItemSummary, fields: Vec<CliField>) -> Self {
        let mut reply = Self::empty(CliReplyType::Item, Some(request_id));
        reply.id = Some(summary.id);
        reply.kind = Some(summary.kind);
        reply.title = Some(summary.title);
        reply.fields = Some(fields);
        reply
    }

    pub fn value(request_id: &str, value: &str, hidden: bool) -> Self {
        let mut reply = Self::empty(CliReplyType::Value, Some(request_id));
        reply.value = Some(value.to_string());
        reply.hidden = Some(hidden);
        reply
    }

    pub fn copied(request_id: &str, clear_after_seconds: Option<u64>) -> Self {
        let mut reply = Self::empty(CliReplyType::Copied, Some(request_id));
        reply.clear_after_seconds = clear_after_seconds;
        reply
    }

    pub fn totp(request_id: &str, code: &str, remaining_seconds: u64) -> Self {
        let mut reply = Self::empty(CliReplyType::Totp, Some(request_id));
        reply.code = Some(code.to_string());
        reply.remaining_seconds = Some(remaining_seconds);
        reply
    }

    pub fn error(request_id: Option<&str>, code: CliErrorCode) -> Self {
        Self::error_with(request_id, code, code.message())
    }

    pub fn error_with(request_id: Option<&str>, code: CliErrorCode, message: &str) -> Self {
        let code_text = serde_json::to_value(code)
            .ok()
            .and_then(|value| value.as_str().map(str::to_string));
        let mut reply = Self::empty(CliReplyType::Error, request_id);
        reply.code = code_text;
        reply.message = Some(message.chars().take(MAX_MESSAGE_CHARS).collect());
        reply
    }

    pub fn error_code(&self) -> Option<CliErrorCode> {
        if self.reply_type != CliReplyType::Error {
            return None;
        }
        serde_json::from_value(serde_json::Value::String(self.code.clone()?)).ok()
    }

    pub fn to_bytes(&self) -> Result<Zeroizing<Vec<u8>>, serde_json::Error> {
        serde_json::to_vec(self).map(Zeroizing::new)
    }

    pub fn fits_one_frame(&self) -> bool {
        self.to_bytes()
            .is_ok_and(|bytes| !bytes.is_empty() && bytes.len() <= MAX_CLI_REPLY_BYTES)
    }

    fn has_only(&self, allowed: &[&str]) -> bool {
        let present = [
            ("reason", self.reason.is_some()),
            ("items", self.items.is_some()),
            ("id", self.id.is_some()),
            ("kind", self.kind.is_some()),
            ("title", self.title.is_some()),
            ("fields", self.fields.is_some()),
            ("value", self.value.is_some()),
            ("hidden", self.hidden.is_some()),
            ("clearAfterSeconds", self.clear_after_seconds.is_some()),
            ("code", self.code.is_some()),
            ("remainingSeconds", self.remaining_seconds.is_some()),
            ("message", self.message.is_some()),
        ];
        present
            .iter()
            .all(|(name, is_present)| !is_present || allowed.contains(name))
    }

    pub fn answers(&self, request_id: &str, command: &CliCommand) -> bool {
        if self.reply_type == CliReplyType::Error {
            return self.valid_error(request_id);
        }
        if self.version != CLI_PROTOCOL_VERSION || self.request_id.as_deref() != Some(request_id) {
            return false;
        }
        match self.reply_type {
            CliReplyType::Waiting => self.has_only(&["reason"]) && self.reason.is_some(),
            CliReplyType::Items => {
                matches!(command, CliCommand::List)
                    && self.has_only(&["items"])
                    && self
                        .items
                        .as_ref()
                        .is_some_and(|items| items.iter().all(CliItemSummary::is_valid))
            }
            CliReplyType::Done => matches!(command, CliCommand::List) && self.has_only(&[]),
            CliReplyType::Item => {
                matches!(command, CliCommand::Get { field: None, .. })
                    && self.has_only(&["id", "kind", "title", "fields"])
                    && match (&self.id, &self.kind, &self.title, &self.fields) {
                        (Some(id), Some(kind), Some(title), Some(fields)) => {
                            CliItemSummary {
                                id: id.clone(),
                                kind: kind.clone(),
                                title: title.clone(),
                            }
                            .is_valid()
                                && fields.iter().all(CliField::is_valid)
                        }
                        _ => false,
                    }
            }
            CliReplyType::Value => {
                matches!(
                    command,
                    CliCommand::Get {
                        field: Some(_),
                        copy: false,
                        ..
                    }
                ) && self.has_only(&["value", "hidden"])
                    && self.hidden.is_some()
                    && self.value.as_ref().is_some_and(|value| !value.is_empty())
            }
            CliReplyType::Copied => {
                command.copies()
                    && self.has_only(&["clearAfterSeconds"])
                    && self
                        .clear_after_seconds
                        .is_none_or(|seconds| (1..=MAX_CLEAR_AFTER_SECONDS).contains(&seconds))
            }
            CliReplyType::Totp => {
                matches!(command, CliCommand::Totp { copy: false, .. })
                    && self.has_only(&["code", "remainingSeconds"])
                    && self.code.as_deref().is_some_and(valid_totp_code)
                    && self
                        .remaining_seconds
                        .is_some_and(|seconds| (1..=MAX_TOTP_REMAINING_SECONDS).contains(&seconds))
            }
            CliReplyType::Error => false,
        }
    }

    fn valid_error(&self, request_id: &str) -> bool {
        let Some(code) = self.error_code() else {
            return false;
        };
        let id_matches = match &self.request_id {
            Some(id) => id == request_id,
            None => matches!(
                code,
                CliErrorCode::Invalid | CliErrorCode::UnsupportedVersion
            ),
        };
        let version_ok = self.version == CLI_PROTOCOL_VERSION
            || (code == CliErrorCode::UnsupportedVersion && self.version > 0);
        id_matches
            && version_ok
            && self.has_only(&["code", "message"])
            && self
                .message
                .as_deref()
                .is_some_and(|message| bounded_text(message, MAX_MESSAGE_CHARS))
    }
}

fn valid_totp_code(value: &str) -> bool {
    (1..=MAX_TOTP_CODE_DIGITS).contains(&value.len())
        && value.bytes().all(|byte| byte.is_ascii_digit())
}

pub fn parse_reply(bytes: &[u8]) -> Option<CliReply> {
    if bytes.is_empty() || bytes.len() > MAX_CLI_REPLY_BYTES {
        return None;
    }
    serde_json::from_slice(bytes).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    const REQUEST_ID: &str = "3f9a0c1e5b7d2a4c6e8f0a1b2c3d4e5f";

    fn parse(value: serde_json::Value) -> Result<(String, CliCommand), CliRejection> {
        parse_request(&serde_json::to_vec(&value).expect("encodes"))
    }

    #[test]
    fn the_documented_get_request_parses() {
        let parsed = parse(serde_json::json!({
            "version": 1, "type": "get", "requestId": REQUEST_ID,
            "item": "Northwind mail", "field": "password", "copy": false
        }))
        .expect("valid");
        assert_eq!(parsed.0, REQUEST_ID);
        assert_eq!(
            parsed.1,
            CliCommand::Get {
                item: "Northwind mail".to_string(),
                field: Some("password".to_string()),
                copy: false
            }
        );
    }

    #[test]
    fn a_newer_version_is_refused_as_unsupported_and_echoes_a_well_formed_id() {
        let refused = parse(serde_json::json!({
            "version": 2, "type": "list", "requestId": REQUEST_ID, "future": true
        }))
        .expect_err("refused");
        assert_eq!(refused.code, CliErrorCode::UnsupportedVersion);
        assert_eq!(refused.request_id.as_deref(), Some(REQUEST_ID));
    }

    #[test]
    fn a_frame_over_four_kibibytes_is_refused_before_parsing() {
        let mut bytes = serde_json::to_vec(&serde_json::json!({
            "version": 1, "type": "list", "requestId": REQUEST_ID
        }))
        .expect("encodes");
        bytes.resize(MAX_CLI_REQUEST_BYTES + 1, b' ');
        assert_eq!(
            parse_request(&bytes).expect_err("refused").code,
            CliErrorCode::Invalid
        );
    }

    #[test]
    fn replies_are_bound_to_their_request_and_command() {
        let get = CliCommand::Get {
            item: "Northwind mail".to_string(),
            field: Some("password".to_string()),
            copy: false,
        };
        let value = CliReply::value(REQUEST_ID, "fictional-password-canary", true);
        assert!(value.answers(REQUEST_ID, &get));
        assert!(!value.answers("00000000000000000000000000000000", &get));
        assert!(!value.answers(REQUEST_ID, &CliCommand::List));
        let copy = CliCommand::Get {
            item: "Northwind mail".to_string(),
            field: Some("password".to_string()),
            copy: true,
        };
        assert!(!value.answers(REQUEST_ID, &copy));
        assert!(CliReply::copied(REQUEST_ID, Some(30)).answers(REQUEST_ID, &copy));
    }

    #[test]
    fn a_copied_reply_never_carries_a_value() {
        let copy = CliCommand::Totp {
            item: "Northwind mail".to_string(),
            copy: true,
        };
        let mut reply = CliReply::copied(REQUEST_ID, Some(30));
        reply.value = Some("fictional-password-canary".to_string());
        assert!(!reply.answers(REQUEST_ID, &copy));
        let wire = String::from_utf8(
            CliReply::copied(REQUEST_ID, Some(30))
                .to_bytes()
                .expect("encodes")
                .to_vec(),
        )
        .expect("utf8");
        assert!(!wire.contains("value"));
    }

    #[test]
    fn the_version_one_vectors_replay_against_the_desktop_rules() {
        let vectors: serde_json::Value =
            serde_json::from_str(include_str!("../../contracts/cli/v1/vectors.json"))
                .expect("vectors");
        assert_eq!(vectors["fictionalDataOnly"], true);
        for case in vectors["requestCases"].as_array().expect("request cases") {
            let bytes = serde_json::to_vec(&case["message"]).expect("encodes");
            let parsed = parse_request(&bytes);
            assert_eq!(parsed.is_ok(), case["valid"] == true, "{}", case["name"]);
            if let Some(code) = case.get("code") {
                let expected: CliErrorCode =
                    serde_json::from_value(code.clone()).expect("an error code");
                assert_eq!(
                    parsed.expect_err("refused").code,
                    expected,
                    "{}",
                    case["name"]
                );
            }
        }
        for case in vectors["replyCases"].as_array().expect("reply cases") {
            let bytes = serde_json::to_vec(&case["request"]).expect("encodes");
            let (request_id, command) = parse_request(&bytes).expect("a valid request");
            let reply_bytes = serde_json::to_vec(&case["message"]).expect("encodes");
            let accepted =
                parse_reply(&reply_bytes).is_some_and(|reply| reply.answers(&request_id, &command));
            assert_eq!(accepted, case["valid"] == true, "{}", case["name"]);
        }
    }
}
