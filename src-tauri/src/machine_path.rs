use std::ffi::OsString;

pub const ADD_ARGUMENT: &str = "--add-to-machine-path";
pub const REMOVE_ARGUMENT: &str = "--remove-from-machine-path";

pub const EXIT_CHANGED: i32 = 0;
pub const EXIT_UNCHANGED: i32 = 10;
pub const EXIT_REFUSED: i32 = 11;
pub const EXIT_FAILED: i32 = 12;

const SEPARATOR: u16 = b';' as u16;
const QUOTE: u16 = b'"' as u16;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Add,
    Remove,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Request {
    Run(Mode),
    Malformed,
}

pub fn requested(arguments: &[OsString]) -> Option<Request> {
    let mode = match arguments.first()?.to_str()? {
        ADD_ARGUMENT => Mode::Add,
        REMOVE_ARGUMENT => Mode::Remove,
        _ => return None,
    };
    if arguments.len() == 1 {
        Some(Request::Run(mode))
    } else {
        Some(Request::Malformed)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Plan {
    Write(Vec<u16>),
    AlreadyPresent,
    Absent,
    NotSesameForm,
    Duplicated,
}

pub fn string_data(bytes: &[u8]) -> Option<Vec<u16>> {
    if !bytes.len().is_multiple_of(2) {
        return None;
    }
    let (pairs, _) = bytes.as_chunks::<2>();
    let mut units: Vec<u16> = pairs.iter().map(|pair| u16::from_le_bytes(*pair)).collect();
    while units.last() == Some(&0) {
        units.pop();
    }
    if units.contains(&0) {
        return None;
    }
    Some(units)
}

pub fn registry_bytes(units: &[u16]) -> Vec<u8> {
    units
        .iter()
        .chain(std::iter::once(&0))
        .flat_map(|unit| unit.to_le_bytes())
        .collect()
}

fn entries(value: &[u16]) -> Vec<&[u16]> {
    value.split(|unit| *unit == SEPARATOR).collect()
}

fn expand_references(text: &str, lookup: &dyn Fn(&str) -> Option<String>) -> String {
    let mut expanded = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(start) = rest.find('%') {
        expanded.push_str(&rest[..start]);
        let after = &rest[start + 1..];
        match after.find('%') {
            Some(end) if end > 0 => match lookup(&after[..end]) {
                Some(value) => {
                    expanded.push_str(&value);
                    rest = &after[end + 1..];
                }
                None => {
                    expanded.push('%');
                    rest = after;
                }
            },
            _ => {
                expanded.push('%');
                rest = after;
            }
        }
    }
    expanded.push_str(rest);
    expanded
}

fn comparable(text: &str) -> String {
    text.replace('/', "\\")
        .trim_end_matches('\\')
        .to_lowercase()
}

pub fn names_folder(
    entry: &[u16],
    folder: &[u16],
    lookup: &dyn Fn(&str) -> Option<String>,
) -> bool {
    let unquoted = match entry {
        [QUOTE, inner @ .., QUOTE] => inner,
        _ => entry,
    };
    let (Ok(entry), Ok(folder)) = (String::from_utf16(unquoted), String::from_utf16(folder)) else {
        return false;
    };
    let target = comparable(&folder);
    !target.is_empty() && comparable(&expand_references(&entry, lookup)) == target
}

pub fn plan_add(value: &[u16], folder: &[u16], lookup: &dyn Fn(&str) -> Option<String>) -> Plan {
    if entries(value)
        .iter()
        .any(|entry| names_folder(entry, folder, lookup))
    {
        return Plan::AlreadyPresent;
    }
    let mut written = value.to_vec();
    if value.is_empty() {
        written.extend_from_slice(folder);
    } else if value.last() == Some(&SEPARATOR) {
        written.extend_from_slice(folder);
        written.push(SEPARATOR);
    } else {
        written.push(SEPARATOR);
        written.extend_from_slice(folder);
    }
    Plan::Write(written)
}

pub fn plan_remove(value: &[u16], folder: &[u16], lookup: &dyn Fn(&str) -> Option<String>) -> Plan {
    let all = entries(value);
    let matching: Vec<usize> = all
        .iter()
        .enumerate()
        .filter(|(_, entry)| names_folder(entry, folder, lookup))
        .map(|(index, _)| index)
        .collect();
    match matching.as_slice() {
        [] => Plan::Absent,
        [index] if all[*index] == folder => {
            let kept: Vec<&[u16]> = all
                .iter()
                .enumerate()
                .filter(|(position, _)| position != index)
                .map(|(_, entry)| *entry)
                .collect();
            Plan::Write(kept.join(&SEPARATOR))
        }
        [_] => Plan::NotSesameForm,
        _ => Plan::Duplicated,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FOLDER: &str = r"C:\Program Files\Sesame\cli";
    const BASE: &str =
        r"%SystemRoot%\system32;%SystemRoot%;%SystemRoot%\System32\Wbem;C:\Fictional Tools\bin";

    fn wide(text: &str) -> Vec<u16> {
        text.encode_utf16().collect()
    }

    fn text(units: &[u16]) -> String {
        String::from_utf16(units).unwrap()
    }

    fn lookup(name: &str) -> Option<String> {
        match name.to_ascii_lowercase().as_str() {
            "programfiles" | "programw6432" => Some(r"C:\Program Files".to_string()),
            "systemroot" => Some(r"C:\Windows".to_string()),
            "sesamehome" => Some(r"C:\Program Files\Sesame".to_string()),
            _ => None,
        }
    }

    fn add(value: &str) -> Plan {
        plan_add(&wide(value), &wide(FOLDER), &lookup)
    }

    fn remove(value: &str) -> Plan {
        plan_remove(&wide(value), &wide(FOLDER), &lookup)
    }

    fn written(plan: Plan) -> String {
        match plan {
            Plan::Write(units) => text(&units),
            other => panic!("expected a write, got {other:?}"),
        }
    }

    #[test]
    fn only_a_single_known_argument_selects_a_mode() {
        let words = |list: &[&str]| list.iter().map(OsString::from).collect::<Vec<_>>();
        assert_eq!(
            requested(&words(&[ADD_ARGUMENT])),
            Some(Request::Run(Mode::Add))
        );
        assert_eq!(
            requested(&words(&[REMOVE_ARGUMENT])),
            Some(Request::Run(Mode::Remove))
        );
        assert_eq!(
            requested(&words(&[ADD_ARGUMENT, r"C:\Fictional"])),
            Some(Request::Malformed)
        );
        assert_eq!(
            requested(&words(&[REMOVE_ARGUMENT, "--"])),
            Some(Request::Malformed)
        );
        assert_eq!(requested(&words(&["list"])), None);
        assert_eq!(requested(&words(&["--help"])), None);
        assert_eq!(requested(&words(&["--ADD-TO-MACHINE-PATH"])), None);
        assert_eq!(requested(&words(&[])), None);
        assert_eq!(requested(&words(&["list", ADD_ARGUMENT])), None);
    }

    #[test]
    fn the_installer_outcomes_are_distinct_and_apart_from_the_terminal_codes() {
        assert_eq!(EXIT_CHANGED, 0);
        let others = [EXIT_UNCHANGED, EXIT_REFUSED, EXIT_FAILED];
        for (index, code) in others.iter().enumerate() {
            assert!(*code > crate::terminal_client::EXIT_OUTDATED, "{code}");
            assert!(!others[index + 1..].contains(code), "{code}");
        }
    }

    #[test]
    fn the_hidden_arguments_never_parse_as_a_terminal_command() {
        for argument in [ADD_ARGUMENT, REMOVE_ARGUMENT] {
            assert!(crate::terminal_client::parse_arguments(&[OsString::from(argument)]).is_err());
        }
    }

    #[test]
    fn adding_appends_the_folder_and_keeps_every_other_entry() {
        assert_eq!(written(add(BASE)), format!("{BASE};{FOLDER}"));
    }

    #[test]
    fn a_path_that_ends_with_a_semicolon_keeps_its_empty_last_entry() {
        let value = format!("{BASE};");
        let after = written(add(&value));
        assert_eq!(after, format!("{BASE};{FOLDER};"));
        assert_eq!(written(remove(&after)), value);
        let doubled = format!("{BASE};;");
        assert_eq!(written(remove(&written(add(&doubled)))), doubled);
    }

    #[test]
    fn an_empty_path_gets_only_the_folder_and_comes_back_empty() {
        assert_eq!(written(add("")), FOLDER);
        assert_eq!(written(remove(FOLDER)), "");
    }

    #[test]
    fn every_form_of_the_folder_counts_as_present() {
        for entry in [
            FOLDER.to_string(),
            format!(r"{FOLDER}\"),
            format!(r"{FOLDER}\\"),
            FOLDER.to_uppercase(),
            FOLDER.to_lowercase(),
            format!("\"{FOLDER}\""),
            format!("\"{FOLDER}\\\""),
            r"%ProgramFiles%\Sesame\cli".to_string(),
            r"%PROGRAMFILES%\Sesame\cli\".to_string(),
            r"%ProgramW6432%\Sesame\cli".to_string(),
            r"%SesameHome%\cli".to_string(),
            "C:/Program Files/Sesame/cli".to_string(),
        ] {
            let value = format!("{BASE};{entry};C:\\Fictional\\After");
            assert_eq!(add(&value), Plan::AlreadyPresent, "{entry}");
            let expected = if entry == FOLDER {
                Plan::Write(wide(&format!("{BASE};C:\\Fictional\\After")))
            } else {
                Plan::NotSesameForm
            };
            assert_eq!(remove(&value), expected, "{entry}");
        }
    }

    #[test]
    fn similar_folders_are_not_the_folder() {
        for entry in [
            r"C:\Program Files\Sesame",
            r"C:\Program Files\Sesame\cli2",
            r"C:\Program Files\Sesame\cli\bin",
            r"D:\Program Files\Sesame\cli",
            r" C:\Program Files\Sesame\cli",
            r"%Undefined%\Sesame\cli",
            r"%ProgramFiles\Sesame\cli",
            "\"C:\\Program Files\\Sesame\\cli",
        ] {
            let value = format!("{BASE};{entry}");
            assert_eq!(
                written(add(&value)),
                format!("{BASE};{entry};{FOLDER}"),
                "{entry}"
            );
            assert_eq!(remove(&value), Plan::Absent, "{entry}");
        }
    }

    #[test]
    fn removal_takes_out_only_the_single_exact_entry_wherever_it_is() {
        assert_eq!(written(remove(&format!("{FOLDER};{BASE}"))), BASE);
        assert_eq!(
            written(remove(&format!(
                "C:\\Fictional\\One;{FOLDER};C:\\Fictional\\Two"
            ))),
            r"C:\Fictional\One;C:\Fictional\Two"
        );
        assert_eq!(written(remove(&format!("{BASE};{FOLDER}"))), BASE);
        assert_eq!(
            written(remove(&format!("{BASE};;{FOLDER};;x"))),
            format!("{BASE};;;x")
        );
    }

    #[test]
    fn two_matches_leave_the_path_alone() {
        assert_eq!(
            remove(&format!("{BASE};{FOLDER};{FOLDER}")),
            Plan::Duplicated
        );
        assert_eq!(
            remove(&format!("{BASE};{FOLDER};%ProgramFiles%\\Sesame\\cli")),
            Plan::Duplicated
        );
        assert_eq!(
            add(&format!("{BASE};{FOLDER};{FOLDER}")),
            Plan::AlreadyPresent
        );
    }

    #[test]
    fn references_stay_unexpanded_in_what_is_written() {
        let after = written(add(BASE));
        assert!(after.starts_with(r"%SystemRoot%\system32;%SystemRoot%;"));
        assert_eq!(written(remove(&after)), BASE);
    }

    #[test]
    fn long_paths_have_no_length_limit() {
        for length in [994_usize, 995, 1022, 1023, 1024, 4096, 40_000] {
            let prefix = format!("{BASE};C:\\Fictional\\Long\\");
            let value = format!("{prefix}{}", "x".repeat(length - prefix.len()));
            assert_eq!(value.len(), length);
            let after = written(add(&value));
            assert_eq!(after, format!("{value};{FOLDER}"));
            assert_eq!(written(remove(&after)), value);
        }
    }

    #[test]
    fn units_that_are_not_valid_text_are_kept_exactly() {
        let mut value = wide(BASE);
        value.push(SEPARATOR);
        value.push(0xd800);
        value.extend(wide(r"\lone"));
        let Plan::Write(after) = plan_add(&value, &wide(FOLDER), &lookup) else {
            panic!("the folder was not added");
        };
        assert_eq!(&after[..value.len()], value.as_slice());
        assert_eq!(
            plan_remove(&after, &wide(FOLDER), &lookup),
            Plan::Write(value)
        );
    }

    #[test]
    fn registry_data_round_trips_and_refuses_what_is_not_one_string() {
        let units = wide(BASE);
        let bytes = registry_bytes(&units);
        assert_eq!(bytes.len(), units.len() * 2 + 2);
        assert_eq!(string_data(&bytes), Some(units.clone()));
        let mut unterminated = bytes.clone();
        unterminated.truncate(bytes.len() - 2);
        assert_eq!(string_data(&unterminated), Some(units.clone()));
        let mut doubly = bytes.clone();
        doubly.extend([0, 0]);
        assert_eq!(string_data(&doubly), Some(units.clone()));
        assert_eq!(string_data(&bytes[..bytes.len() - 1]), None);
        let mut inner = wide("a");
        inner.push(0);
        inner.extend(wide("b"));
        assert_eq!(string_data(&registry_bytes(&inner)), None);
        assert_eq!(string_data(&[]), Some(Vec::new()));
    }
}
