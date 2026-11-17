use time::format_description::well_known::Rfc2822;
use time::OffsetDateTime;

pub fn parse_http_date(value: &str) -> Option<u64> {
    OffsetDateTime::parse(value, &Rfc2822)
        .ok()
        .and_then(|moment| u64::try_from(moment.unix_timestamp()).ok())
}

#[cfg(test)]
mod tests {
    use super::parse_http_date;

    #[test]
    fn an_http_date_is_read_in_both_zone_spellings() {
        assert_eq!(
            parse_http_date("Sat, 10 Oct 2026 12:00:00 GMT"),
            Some(1_791_633_600)
        );
        assert_eq!(
            parse_http_date("Sat, 10 Oct 2026 12:00:00 +0000"),
            Some(1_791_633_600)
        );
        assert_eq!(
            parse_http_date("Sat, 10 Oct 2026 14:00:00 +0200"),
            Some(1_791_633_600)
        );
    }

    #[test]
    fn a_date_that_is_not_an_http_date_is_refused() {
        assert_eq!(parse_http_date("2026-10-10T12:00:00Z"), None);
        assert_eq!(parse_http_date("Sat, 31 Feb 2026 12:00:00 GMT"), None);
        assert_eq!(parse_http_date(""), None);
    }
}
