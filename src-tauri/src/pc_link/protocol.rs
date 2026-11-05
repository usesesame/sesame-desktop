use serde::{Deserialize, Serialize};

pub(crate) const WIRE_VERSION: u8 = 1;
pub(crate) const JSON_MEDIA_TYPE: &str = "application/json";
pub(crate) const SNAPSHOT_MEDIA_TYPE: &str = "application/vnd.sesame.vault";
pub(crate) const MAX_HEADER_BYTES: usize = 8 * 1024;
pub(crate) const MAX_JSON_REQUEST_BYTES: usize = 4 * 1024;
pub(crate) const MAX_JSON_RESPONSE_BYTES: usize = 16 * 1024;
pub(crate) const MAX_SNAPSHOT_BYTES: usize = 64 * 1024 * 1024;
pub(crate) const MAX_HEADERS: usize = 64;
pub(crate) const HEADER_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
pub(crate) const BODY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
pub(crate) const HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
pub(crate) const SNAPSHOT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(120);
pub(crate) const CONCURRENT_CONNECTIONS: usize = 8;

pub(crate) const ENROLL_PATH: &str = "/v1/pair/enroll";
pub(crate) const STATUS_PATH: &str = "/v1/pair/status";
pub(crate) const ACTIVATE_PATH: &str = "/v1/pair/activate";
pub(crate) const COMMIT_PATH: &str = "/v1/pair/commit";

pub(crate) const ERROR_INVALID: &str = "invalid_request";
pub(crate) const ERROR_FORBIDDEN: &str = "forbidden";
pub(crate) const ERROR_UNKNOWN_LINK: &str = "unknown_link";
pub(crate) const ERROR_WRONG_VAULT: &str = "wrong_vault";
pub(crate) const ERROR_EXPIRED: &str = "expired";
pub(crate) const ERROR_LOCKED: &str = "locked";
pub(crate) const ERROR_RATE_LIMITED: &str = "rate_limited";
pub(crate) const ERROR_UNAVAILABLE: &str = "unavailable";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PairingState {
    PendingConfirmation,
    Confirmed,
    PendingCommit,
    Active,
    Rejected,
    Expired,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnrollRequest {
    pub v: u8,
    pub enrollment_id: String,
    pub code: String,
    pub label: String,
    pub phone_public_key: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StatusRequest {
    pub v: u8,
    pub enrollment_id: String,
    pub code: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActivateRequest {
    pub v: u8,
    pub enrollment_id: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommitRequest {
    pub v: u8,
    pub link_id: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevokeRequest {
    pub v: u8,
    pub link_id: String,
}

#[derive(Serialize)]
pub struct EnrollResponse {
    pub v: u8,
    pub enrollment_id: String,
    pub state: PairingState,
    pub expires_at: u64,
}

#[derive(Serialize)]
pub struct StatusResponse {
    pub v: u8,
    pub state: PairingState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_certificate: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_ca: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retrieval_port: Option<u16>,
}

#[derive(Serialize)]
pub struct ActivateResponse {
    pub v: u8,
    pub link_id: String,
    pub vault_id: String,
    pub vault_name: String,
    pub state: PairingState,
}

#[derive(Serialize)]
pub struct CommitResponse {
    pub v: u8,
    pub state: PairingState,
}

#[derive(Serialize)]
pub struct RevokeResponse {
    pub v: u8,
    pub state: &'static str,
}

#[derive(Serialize)]
pub struct ErrorResponse {
    pub v: u8,
    pub error: &'static str,
}

pub(crate) fn is_identifier(value: &str) -> bool {
    value.len() == 22
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}

pub(crate) fn is_pairing_code(value: &str) -> bool {
    const ALPHABET: &[u8; 32] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    value.len() == 10 && value.bytes().all(|byte| ALPHABET.contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifiers_and_codes_are_bounded_to_the_wire_shapes() {
        assert!(is_identifier("ABCDEFGHIJKLMNOPQRSTUV"));
        assert!(!is_identifier("short"));
        assert!(!is_identifier("ABCDEFGHIJKLMNOPQRSTUV.!"));
        assert!(is_pairing_code("ABCDEFGHJK"));
        assert!(!is_pairing_code("ABCDEFGHIJ"));
        assert!(!is_pairing_code("ABCDEFGHJ"));
    }

    #[test]
    fn requests_reject_unknown_and_duplicate_shaped_fields() {
        let request: EnrollRequest = serde_json::from_str(
            r#"{"v":1,"enrollment_id":"ABCDEFGHIJKLMNOPQRSTUV","code":"ABCDEFGHJK","label":"Phone","phone_public_key":"AA"}"#,
        )
        .expect("request");
        assert_eq!(request.v, 1);
        assert!(serde_json::from_str::<EnrollRequest>(
            r#"{"v":1,"enrollment_id":"ABCDEFGHIJKLMNOPQRSTUV","code":"ABCDEFGHJK","label":"Phone","phone_public_key":"AA","extra":true}"#,
        )
        .is_err());
    }
}
