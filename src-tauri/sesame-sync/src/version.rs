pub fn parse(value: &str) -> Option<[u32; 3]> {
    let core = value.split(['-', '+']).next()?;
    let mut parts = core.split('.');
    let mut numbers = [0_u32; 3];
    for number in &mut numbers {
        let part = parts.next()?;
        if part.is_empty() || part.len() > 9 || !part.bytes().all(|byte| byte.is_ascii_digit()) {
            return None;
        }
        *number = part.parse().ok()?;
    }
    parts.next().is_none().then_some(numbers)
}

pub fn display(version: [u32; 3]) -> String {
    format!("{}.{}.{}", version[0], version[1], version[2])
}

pub fn below(current: &str, minimum: &str) -> Option<bool> {
    Some(parse(current)? < parse(minimum)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions_with_a_suffix_compare_by_their_numbers() {
        assert_eq!(parse("1.2.3-beta.1"), Some([1, 2, 3]));
        assert_eq!(parse("1.2.3+build"), Some([1, 2, 3]));
        assert_eq!(parse("0.3.0"), Some([0, 3, 0]));
        assert_eq!(parse(""), None);
    }

    #[test]
    fn malformed_versions_are_refused() {
        for value in [
            "1.2",
            "1.2.3.4",
            "1.2.x",
            "-1.0.0",
            "99999999999.0.0",
            " 1.2.3",
        ] {
            assert_eq!(parse(value), None, "{value}");
        }
    }

    #[test]
    fn display_uses_three_numbers() {
        assert_eq!(display([1, 2, 3]), "1.2.3");
    }
}
