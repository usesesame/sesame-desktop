use chrono::DateTime;

pub fn parse_http_date(value: &str) -> Option<u64> {
    DateTime::parse_from_rfc2822(value)
        .ok()
        .and_then(|moment| u64::try_from(moment.timestamp()).ok())
}
