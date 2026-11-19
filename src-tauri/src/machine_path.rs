use std::ffi::OsString;

pub const ADD_ARGUMENT: &str = "--add-to-machine-path";
pub const REMOVE_ARGUMENT: &str = "--remove-from-machine-path";

pub const EXIT_CHANGED: i32 = 0;
pub const EXIT_UNCHANGED: i32 = 10;
pub const EXIT_REFUSED: i32 = 11;
pub const EXIT_FAILED: i32 = 12;
pub const EXIT_LEFT_FOR_PERSON: i32 = 13;
pub const EXIT_NO_ROOM: i32 = 14;

pub const MAX_VALUE_UNITS: usize = 32_767;
pub const COMMAND_SHELL_LIMIT: usize = 8_191;
pub const LONGEST_USER_NAME: usize = 20;
pub const DEFAULT_USER_PATH_ALLOWANCE: usize =
    r"C:\Users\".len() + LONGEST_USER_NAME + r"\AppData\Local\Microsoft\WindowsApps".len() + 2;
pub const MACHINE_PATH_LIMIT: usize = COMMAND_SHELL_LIMIT - DEFAULT_USER_PATH_ALLOWANCE;
pub const ACCESS_DENIED: u32 = 5;

pub fn registry_failure_code(status: u32) -> i32 {
    if status == ACCESS_DENIED {
        EXIT_REFUSED
    } else {
        EXIT_FAILED
    }
}

const SEPARATOR: u16 = b';' as u16;
const QUOTE: u16 = b'"' as u16;
const PERCENT: u16 = b'%' as u16;

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
    TooLong,
    PastCommandShellLimit,
}

pub fn left_alone_code(plan: &Plan) -> i32 {
    match plan {
        Plan::Write(_) => EXIT_CHANGED,
        Plan::AlreadyPresent | Plan::Absent => EXIT_UNCHANGED,
        Plan::NotSesameForm | Plan::Duplicated => EXIT_LEFT_FOR_PERSON,
        Plan::TooLong | Plan::PastCommandShellLimit => EXIT_NO_ROOM,
    }
}

pub struct MachineValue {
    pub text: String,
    pub expands: bool,
}

const SYSTEM_SUPPLIED: [&str; 2] = ["SystemRoot", "SystemDrive"];

fn supplied(
    name: &str,
    program_files: &str,
    system: &dyn Fn(&str) -> Option<String>,
) -> Option<String> {
    if name.eq_ignore_ascii_case("ProgramFiles") || name.eq_ignore_ascii_case("ProgramW6432") {
        Some(program_files.to_string())
    } else if SYSTEM_SUPPLIED
        .iter()
        .any(|known| name.eq_ignore_ascii_case(known))
    {
        system(name)
    } else {
        None
    }
}

pub fn machine_reference(
    name: &str,
    program_files: &str,
    machine: &dyn Fn(&str) -> Option<MachineValue>,
    system: &dyn Fn(&str) -> Option<String>,
) -> Option<String> {
    if let Some(value) = supplied(name, program_files, system) {
        return Some(value);
    }
    let value = machine(name)?;
    if value.expands {
        Some(expand_references(&value.text, &|inner| {
            supplied(inner, program_files, system)
        }))
    } else {
        Some(value.text)
    }
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

fn drive_rooted(text: &str) -> Option<(&str, &str)> {
    let bytes = text.as_bytes();
    if bytes.len() >= 3 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' && bytes[2] == b'\\' {
        Some((&text[..2], &text[3..]))
    } else {
        None
    }
}

fn comparable(text: &str) -> String {
    let text = text.replace('/', "\\").to_lowercase();
    let Some((drive, rest)) = drive_rooted(&text) else {
        return text.trim_end_matches('\\').to_string();
    };
    let mut parts: Vec<&str> = Vec::new();
    for part in rest.split('\\') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            other => parts.push(other),
        }
    }
    format!("{drive}\\{}", parts.join("\\"))
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

fn reaches_folder(entry: &[u16], folder: &[u16], lookup: &dyn Fn(&str) -> Option<String>) -> bool {
    if names_folder(entry, folder, lookup) {
        return true;
    }
    let Ok(text) = String::from_utf16(entry) else {
        return false;
    };
    let expanded = expand_references(&text, lookup);
    expanded.contains(';')
        && expanded.split(';').any(|segment| {
            let units: Vec<u16> = segment.encode_utf16().collect();
            names_folder(&units, folder, &|_| None)
        })
}

fn expanded_length(value: &[u16], lookup: &dyn Fn(&str) -> Option<String>) -> usize {
    let mut length = 0;
    let mut rest = value;
    while let Some(start) = rest.iter().position(|unit| *unit == PERCENT) {
        length += start;
        let after = &rest[start + 1..];
        let resolved = after
            .iter()
            .position(|unit| *unit == PERCENT)
            .filter(|end| *end > 0)
            .and_then(|end| {
                let name = String::from_utf16(&after[..end]).ok()?;
                Some((end, lookup(&name)?))
            });
        match resolved {
            Some((end, expansion)) => {
                length += expansion.encode_utf16().count();
                rest = &after[end + 1..];
            }
            None => {
                length += 1;
                rest = after;
            }
        }
    }
    length + rest.len()
}

pub fn plan_add(value: &[u16], folder: &[u16], lookup: &dyn Fn(&str) -> Option<String>) -> Plan {
    if entries(value)
        .iter()
        .any(|entry| reaches_folder(entry, folder, lookup))
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
    if written.len() > MAX_VALUE_UNITS {
        return Plan::TooLong;
    }
    if expanded_length(value, lookup) <= MACHINE_PATH_LIMIT
        && expanded_length(&written, lookup) > MACHINE_PATH_LIMIT
    {
        return Plan::PastCommandShellLimit;
    }
    Plan::Write(written)
}

pub fn plan_remove(value: &[u16], folder: &[u16], lookup: &dyn Fn(&str) -> Option<String>) -> Plan {
    let all = entries(value);
    let matching: Vec<usize> = all
        .iter()
        .enumerate()
        .filter(|(_, entry)| reaches_folder(entry, folder, lookup))
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

    const PROGRAM_FILES: &str = r"C:\Program Files";

    fn process(name: &str) -> Option<String> {
        match name.to_ascii_lowercase().as_str() {
            "systemroot" => Some(r"C:\Windows".to_string()),
            "systemdrive" => Some("C:".to_string()),
            "sesamehome" => Some(r"C:\Program Files\Sesame".to_string()),
            "fictionalonlyhere" => Some(r"C:\Program Files\Sesame".to_string()),
            _ => None,
        }
    }

    fn machine_with(home: &str, expands: bool) -> impl Fn(&str) -> Option<MachineValue> + '_ {
        move |name: &str| {
            name.eq_ignore_ascii_case("SesameHome")
                .then(|| MachineValue {
                    text: home.to_string(),
                    expands,
                })
        }
    }

    fn lookup(name: &str) -> Option<String> {
        machine_reference(
            name,
            PROGRAM_FILES,
            &machine_with(r"C:\Program Files\Sesame", false),
            &process,
        )
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
        let others = [
            EXIT_UNCHANGED,
            EXIT_REFUSED,
            EXIT_FAILED,
            EXIT_LEFT_FOR_PERSON,
            EXIT_NO_ROOM,
        ];
        for (index, code) in others.iter().enumerate() {
            assert!(*code > crate::terminal_client::EXIT_OUTDATED, "{code}");
            assert!(!others[index + 1..].contains(code), "{code}");
        }
    }

    #[test]
    fn access_denied_is_a_refusal_and_every_other_registry_error_a_failure() {
        assert_eq!(registry_failure_code(ACCESS_DENIED), EXIT_REFUSED);
        for status in [0_u32, 2, 6, 87, 234, 1018, u32::MAX] {
            assert_eq!(registry_failure_code(status), EXIT_FAILED, "{status}");
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

    fn long_value(length: usize) -> String {
        let prefix = r"C:\Fictional Tools\bin;C:\Fictional\Long\";
        let value = format!("{prefix}{}", "x".repeat(length - prefix.len()));
        assert_eq!(value.len(), length);
        value
    }

    #[test]
    fn long_paths_get_the_folder_unless_it_crosses_a_limit() {
        let room = MACHINE_PATH_LIMIT - FOLDER.len() - 1;
        let longest = MAX_VALUE_UNITS - FOLDER.len() - 1;
        for length in [
            994_usize,
            995,
            1022,
            1023,
            1024,
            4096,
            room,
            MACHINE_PATH_LIMIT + 1,
            8300,
            16_384,
            longest,
        ] {
            let value = long_value(length);
            let after = written(add(&value));
            assert_eq!(after, format!("{value};{FOLDER}"));
            assert!(after.len() <= MAX_VALUE_UNITS);
            assert_eq!(written(remove(&after)), value);
        }
    }

    #[test]
    fn an_add_past_the_environment_limit_is_refused_and_removal_still_works() {
        let longest = MAX_VALUE_UNITS - FOLDER.len() - 1;
        for length in [longest + 1, MAX_VALUE_UNITS, 40_000] {
            let value = long_value(length);
            let plan = add(&value);
            assert_eq!(plan, Plan::TooLong, "{length}");
            assert_eq!(left_alone_code(&plan), EXIT_NO_ROOM);
            let holding = format!("{value};{FOLDER}");
            assert_eq!(written(remove(&holding)), value, "{length}");
            assert_eq!(add(&holding), Plan::AlreadyPresent, "{length}");
        }
        let ending = format!("{};", long_value(longest - 1));
        assert_eq!(written(add(&ending)).len(), MAX_VALUE_UNITS);
        let ending = format!("{};", long_value(longest));
        assert_eq!(add(&ending), Plan::TooLong);
    }

    #[test]
    fn an_add_that_takes_the_path_past_what_cmd_can_search_is_refused() {
        let room = MACHINE_PATH_LIMIT - FOLDER.len() - 1;
        assert_eq!(written(add(&long_value(room))).len(), MACHINE_PATH_LIMIT);
        for length in [room + 1, MACHINE_PATH_LIMIT - 1, MACHINE_PATH_LIMIT] {
            let value = long_value(length);
            let plan = add(&value);
            assert_eq!(plan, Plan::PastCommandShellLimit, "{length}");
            assert_eq!(left_alone_code(&plan), EXIT_NO_ROOM);
            let holding = format!("{value};{FOLDER}");
            assert_eq!(add(&holding), Plan::AlreadyPresent, "{length}");
            assert_eq!(written(remove(&holding)), value, "{length}");
        }
        let over = long_value(MACHINE_PATH_LIMIT + 1);
        assert_eq!(written(add(&over)), format!("{over};{FOLDER}"));
        let ending = format!("{};", long_value(room - 1));
        assert_eq!(written(add(&ending)).len(), MACHINE_PATH_LIMIT);
        let ending = format!("{};", long_value(room));
        assert_eq!(add(&ending), Plan::PastCommandShellLimit);
    }

    #[test]
    fn the_command_shell_limit_counts_the_path_as_a_new_session_expands_it() {
        let room = MACHINE_PATH_LIMIT - FOLDER.len() - 1;
        let prefix = r"%SystemRoot%\Fictional;";
        let value = format!("{prefix}{}", &long_value(room)[..room - prefix.len() + 2]);
        assert_eq!(value.len(), room + 2);
        assert_eq!(written(add(&value)), format!("{value};{FOLDER}"));
        let unexpanded = |_: &str| None;
        assert_eq!(
            plan_add(&wide(&value), &wide(FOLDER), &unexpanded),
            Plan::PastCommandShellLimit
        );
        let lengthening = format!("%ProgramFiles%\\x;{}", &long_value(room)[..room - 17]);
        assert_eq!(lengthening.len(), room);
        assert_eq!(add(&lengthening), Plan::PastCommandShellLimit);
        assert_eq!(
            written(plan_add(&wide(&lengthening), &wide(FOLDER), &unexpanded)).len(),
            MACHINE_PATH_LIMIT
        );
    }

    #[test]
    fn a_reference_that_expands_to_several_folders_counts_as_present_but_is_never_removed() {
        let machine = |name: &str| {
            name.eq_ignore_ascii_case("FictionalBins")
                .then(|| MachineValue {
                    text: r"C:\Fictional\One;%ProgramFiles%\Sesame\.\cli;C:\Fictional\Two"
                        .to_string(),
                    expands: true,
                })
        };
        let lookup = |name: &str| machine_reference(name, PROGRAM_FILES, &machine, &process);
        let value = format!("{BASE};%FictionalBins%");
        assert_eq!(
            plan_add(&wide(&value), &wide(FOLDER), &lookup),
            Plan::AlreadyPresent
        );
        assert_eq!(
            plan_remove(&wide(&value), &wide(FOLDER), &lookup),
            Plan::NotSesameForm
        );
        let other = |name: &str| {
            name.eq_ignore_ascii_case("FictionalBins")
                .then(|| MachineValue {
                    text: r"C:\Fictional\One;C:\Program Files\Sesame\cli2".to_string(),
                    expands: false,
                })
        };
        let lookup = |name: &str| machine_reference(name, PROGRAM_FILES, &other, &process);
        assert_eq!(
            plan_add(&wide(&value), &wide(FOLDER), &lookup),
            Plan::Write(wide(&format!("{value};{FOLDER}")))
        );
        assert_eq!(add(&format!("{BASE};{FOLDER}")), Plan::AlreadyPresent);
    }

    #[test]
    fn invalid_text_in_one_entry_does_not_stop_references_in_others_from_counting() {
        let room = MACHINE_PATH_LIMIT - FOLDER.len() - 1;
        let mut value = wide(r"%ProgramFiles%\a;%ProgramFiles%\b;C:\Fictional\");
        value.push(0xd800);
        value.push(SEPARATOR);
        let filler = room - 4 - value.len();
        value.extend(wide(&"x".repeat(filler)));
        assert_eq!(value.len(), room - 4);
        assert_eq!(expanded_length(&value, &lookup), room);
        let Plan::Write(after) = plan_add(&value, &wide(FOLDER), &lookup) else {
            panic!("an add that reaches the limit exactly was refused");
        };
        assert_eq!(&after[..value.len()], value.as_slice());
        value.push(b'x' as u16);
        assert_eq!(expanded_length(&value, &lookup), room + 1);
        assert_eq!(
            plan_add(&value, &wide(FOLDER), &lookup),
            Plan::PastCommandShellLimit
        );
    }

    #[test]
    fn a_multi_folder_reference_beside_the_exact_entry_counts_twice() {
        let machine = |name: &str| {
            name.eq_ignore_ascii_case("FictionalBins")
                .then(|| MachineValue {
                    text: format!(r"C:\Fictional\One;{FOLDER}"),
                    expands: false,
                })
        };
        let lookup = |name: &str| machine_reference(name, PROGRAM_FILES, &machine, &process);
        let value = format!("{BASE};{FOLDER};%FictionalBins%");
        assert_eq!(
            plan_remove(&wide(&value), &wide(FOLDER), &lookup),
            Plan::Duplicated
        );
        let quiet = |_: &str| None;
        assert_eq!(
            written(plan_remove(&wide(&value), &wide(FOLDER), &quiet)),
            format!("{BASE};%FictionalBins%")
        );
    }

    #[test]
    fn references_beside_invalid_text_in_the_same_entry_still_count() {
        let room = MACHINE_PATH_LIMIT - FOLDER.len() - 1;
        let mut value = wide(r"C:\Fictional\%ProgramFiles%\a%ProgramFiles%");
        value.push(0xdc00);
        value.extend(wide(r"\b;C:\Fictional\"));
        let filler = room - 4 - value.len();
        value.extend(wide(&"x".repeat(filler)));
        assert_eq!(expanded_length(&value, &lookup), room);
        assert!(matches!(
            plan_add(&value, &wide(FOLDER), &lookup),
            Plan::Write(_)
        ));
        value.push(b'x' as u16);
        assert_eq!(
            plan_add(&value, &wide(FOLDER), &lookup),
            Plan::PastCommandShellLimit
        );
        let mut name = wide("%Program");
        name.push(0xd800);
        name.extend(wide("Files%"));
        assert_eq!(expanded_length(&name, &lookup), name.len());
    }

    #[test]
    fn the_machine_limit_leaves_room_for_a_default_user_path() {
        let longest = format!(
            r"C:\Users\{}\AppData\Local\Microsoft\WindowsApps",
            "u".repeat(LONGEST_USER_NAME)
        );
        assert_eq!(
            MACHINE_PATH_LIMIT + 1 + longest.len() + 1,
            COMMAND_SHELL_LIMIT
        );
        let room = MACHINE_PATH_LIMIT - FOLDER.len() - 1;
        let after = written(add(&long_value(room)));
        assert_eq!(format!("{after};{longest};").len(), COMMAND_SHELL_LIMIT);
        assert_eq!(add(&long_value(room + 1)), Plan::PastCommandShellLimit);
    }

    #[test]
    fn every_outcome_that_leaves_the_path_has_its_own_code() {
        assert_eq!(left_alone_code(&Plan::AlreadyPresent), EXIT_UNCHANGED);
        assert_eq!(left_alone_code(&Plan::Absent), EXIT_UNCHANGED);
        assert_eq!(left_alone_code(&Plan::NotSesameForm), EXIT_LEFT_FOR_PERSON);
        assert_eq!(left_alone_code(&Plan::Duplicated), EXIT_LEFT_FOR_PERSON);
        assert_eq!(left_alone_code(&Plan::TooLong), EXIT_NO_ROOM);
        assert_eq!(left_alone_code(&Plan::PastCommandShellLimit), EXIT_NO_ROOM);
        assert_eq!(remove(BASE), Plan::Absent);
        assert_eq!(left_alone_code(&remove(BASE)), EXIT_UNCHANGED);
        let other_form = format!("{BASE};%ProgramFiles%\\Sesame\\cli");
        assert_eq!(left_alone_code(&remove(&other_form)), EXIT_LEFT_FOR_PERSON);
        let twice = format!("{BASE};{FOLDER};{FOLDER}");
        assert_eq!(left_alone_code(&remove(&twice)), EXIT_LEFT_FOR_PERSON);
    }

    #[test]
    fn dot_components_name_the_folder_but_only_the_exact_entry_is_removed() {
        for entry in [
            r"C:\Program Files\Sesame\.\cli",
            r"C:\Program Files\.\Sesame\cli\.",
            r"C:\Program Files\Sesame\cli\..\cli",
            r"C:\Program Files\Fictional\..\Sesame\cli",
            r"C:\..\Program Files\Sesame\cli",
            r"C:\Program Files\\Sesame\cli",
            r"C:/Program Files/Sesame/./cli/",
            r"%ProgramFiles%\Sesame\.\cli",
            r"%SystemRoot%\..\Program Files\Sesame\cli",
            r"%SystemDrive%\Program Files\Sesame\cli",
            "\"C:\\Program Files\\Sesame\\.\\cli\"",
        ] {
            let value = format!("{BASE};{entry}");
            assert_eq!(add(&value), Plan::AlreadyPresent, "{entry}");
            assert_eq!(remove(&value), Plan::NotSesameForm, "{entry}");
            assert_eq!(
                remove(&format!("{value};{FOLDER}")),
                Plan::Duplicated,
                "{entry}"
            );
        }
        for entry in [
            r"C:\Program Files\Sesame\cli\..",
            r"C:\Program Files\Sesame\..\cli",
            r"C:\Program Files\Sesame\cli\..\cli2",
            r".\cli",
            r"..\Sesame\cli",
            r"\\Fictional\Share\..\Program Files\Sesame\cli",
        ] {
            let value = format!("{BASE};{entry}");
            assert_eq!(written(add(&value)), format!("{value};{FOLDER}"), "{entry}");
            assert_eq!(remove(&value), Plan::Absent, "{entry}");
        }
    }

    #[test]
    fn references_resolve_with_the_machine_value_and_not_the_installer_process() {
        let entry = r"%SesameHome%\cli";
        let value = format!("{BASE};{entry}");
        let plan_with = |home: &str, expands: bool, mode: Mode| {
            let machine = machine_with(home, expands);
            let lookup = |name: &str| machine_reference(name, PROGRAM_FILES, &machine, &process);
            match mode {
                Mode::Add => plan_add(&wide(&value), &wide(FOLDER), &lookup),
                Mode::Remove => plan_remove(&wide(&value), &wide(FOLDER), &lookup),
            }
        };
        assert_eq!(
            written(plan_with(r"D:\Fictional\Elsewhere", false, Mode::Add)),
            format!("{value};{FOLDER}")
        );
        assert_eq!(
            plan_with(r"D:\Fictional\Elsewhere", false, Mode::Remove),
            Plan::Absent
        );
        assert_eq!(
            plan_with(r"C:\Program Files\Sesame", false, Mode::Add),
            Plan::AlreadyPresent
        );
        assert_eq!(
            plan_with(r"%ProgramFiles%\Sesame", true, Mode::Add),
            Plan::AlreadyPresent
        );
        assert_eq!(
            written(plan_with(r"%ProgramFiles%\Sesame", false, Mode::Add)),
            format!("{value};{FOLDER}")
        );
        assert_eq!(
            written(plan_with(r"%FictionalOnlyHere%", true, Mode::Add)),
            format!("{value};{FOLDER}")
        );

        let nowhere = |_: &str| None;
        let only_process = |name: &str| machine_reference(name, PROGRAM_FILES, &nowhere, &process);
        assert_eq!(
            plan_add(&wide(&value), &wide(FOLDER), &only_process),
            Plan::Write(wide(&format!("{value};{FOLDER}")))
        );
        let elsewhere = format!("{BASE};%FictionalOnlyHere%\\cli");
        assert_eq!(
            plan_remove(&wide(&elsewhere), &wide(FOLDER), &only_process),
            Plan::Absent
        );
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
