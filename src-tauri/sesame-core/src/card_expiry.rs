//! Payment-card expiry classification for the checkup. Cards store a month and
//! a year as free text, so anything unreadable is left without a finding.

use chrono::{Days, NaiveDate};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CardExpiry {
    Unreadable,
    Current,
    Expiring,
    Expired,
}

pub const EXPIRING_WITHIN_DAYS: u64 = 30;

pub fn card_expiry(month: &str, year: &str, today: NaiveDate) -> CardExpiry {
    let Some(month) = parse_month(month) else {
        return CardExpiry::Unreadable;
    };
    let Some(year) = parse_year(year) else {
        return CardExpiry::Unreadable;
    };
    let Some(last_day) = end_of_month(year, month) else {
        return CardExpiry::Unreadable;
    };
    if today > last_day {
        return CardExpiry::Expired;
    }
    if last_day <= today + Days::new(EXPIRING_WITHIN_DAYS) {
        return CardExpiry::Expiring;
    }
    CardExpiry::Current
}

fn parse_month(value: &str) -> Option<u32> {
    let month = value.trim().parse::<u32>().ok()?;
    (1..=12).contains(&month).then_some(month)
}

fn parse_year(value: &str) -> Option<i32> {
    let value = value.trim();
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let year = match value.len() {
        1..=2 => 2000 + value.parse::<i32>().ok()?,
        4 => value.parse::<i32>().ok()?,
        _ => return None,
    };
    (1970..=2200).contains(&year).then_some(year)
}

fn end_of_month(year: i32, month: u32) -> Option<NaiveDate> {
    let (next_year, next_month) = if month == 12 {
        (year + 1, 1)
    } else {
        (year, month + 1)
    };
    NaiveDate::from_ymd_opt(next_year, next_month, 1)?.pred_opt()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn date(year: i32, month: u32, day: u32) -> NaiveDate {
        NaiveDate::from_ymd_opt(year, month, day).expect("test date")
    }

    #[test]
    fn a_passed_month_is_expired() {
        assert_eq!(
            card_expiry("01", "24", date(2026, 9, 27)),
            CardExpiry::Expired
        );
        assert_eq!(
            card_expiry("8", "2026", date(2026, 9, 27)),
            CardExpiry::Expired
        );
        assert_eq!(
            card_expiry("08", "26", date(2026, 9, 27)),
            CardExpiry::Expired
        );
    }

    #[test]
    fn a_month_ending_within_thirty_days_is_expiring() {
        assert_eq!(
            card_expiry("09", "26", date(2026, 9, 27)),
            CardExpiry::Expiring
        );
        assert_eq!(
            card_expiry("10", "26", date(2026, 10, 1)),
            CardExpiry::Expiring
        );
        assert_eq!(
            card_expiry("09", "26", date(2026, 9, 1)),
            CardExpiry::Expiring
        );
    }

    #[test]
    fn a_later_month_is_current() {
        assert_eq!(
            card_expiry("12", "26", date(2026, 9, 27)),
            CardExpiry::Current
        );
        assert_eq!(
            card_expiry("01", "27", date(2026, 9, 27)),
            CardExpiry::Current
        );
    }

    #[test]
    fn missing_or_unreadable_values_have_no_finding() {
        assert_eq!(
            card_expiry("", "", date(2026, 9, 27)),
            CardExpiry::Unreadable
        );
        assert_eq!(
            card_expiry("13", "26", date(2026, 9, 27)),
            CardExpiry::Unreadable
        );
        assert_eq!(
            card_expiry("01", "abc", date(2026, 9, 27)),
            CardExpiry::Unreadable
        );
        assert_eq!(
            card_expiry("01", "26-27", date(2026, 9, 27)),
            CardExpiry::Unreadable
        );
    }
}
