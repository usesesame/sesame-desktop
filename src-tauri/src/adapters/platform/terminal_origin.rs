#[cfg(target_os = "linux")]
use crate::application::terminal_allowances::TerminalKey;
use crate::application::terminal_allowances::{TerminalOrigin, UnverifiedProgram};

const MAX_PROGRAM_CHARS: usize = 64;

fn reported(name: &str) -> Option<UnverifiedProgram> {
    printable(name).map(UnverifiedProgram::reported)
}

fn printable(name: &str) -> Option<String> {
    let cleaned: String = name
        .trim()
        .chars()
        .map(|character| {
            if character.is_control() {
                '?'
            } else {
                character
            }
        })
        .take(MAX_PROGRAM_CHARS)
        .collect();
    (!cleaned.is_empty()).then_some(cleaned)
}

#[cfg(target_os = "linux")]
mod platform {
    use super::*;

    pub(super) struct Stat {
        pub(super) parent: u32,
        pub(super) session: u32,
        pub(super) terminal: u64,
        pub(super) started: u64,
    }

    pub(super) fn parse_stat(stat: &str) -> Option<Stat> {
        let fields: Vec<&str> = stat.rsplit_once(')')?.1.split_whitespace().collect();
        let terminal = fields.get(4)?.parse::<i64>().ok()?;
        Some(Stat {
            parent: fields.get(1)?.parse().ok()?,
            session: fields.get(3)?.parse().ok()?,
            terminal: u64::try_from(terminal).ok()?,
            started: fields.get(19)?.parse().ok()?,
        })
    }

    fn stat_of(pid: u32) -> Option<Stat> {
        parse_stat(&std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?)
    }

    fn command_of(pid: u32) -> Option<String> {
        std::fs::read_to_string(format!("/proc/{pid}/comm")).ok()
    }

    pub(super) fn device_name(terminal: u64) -> String {
        let major = (terminal >> 8) & 0xfff;
        let minor = (terminal & 0xff) | ((terminal >> 12) & 0xf_ff00);
        match major {
            136..=143 => format!("pts/{}", (major - 136) * 256 + minor),
            4 if minor < 64 => format!("tty{minor}"),
            4 => format!("ttyS{}", minor - 64),
            _ => format!("tty {major}:{minor}"),
        }
    }

    pub(super) fn is_remote_parent(command: Option<&str>) -> bool {
        command.is_some_and(|name| name.starts_with("sshd"))
    }

    pub(crate) fn origin_of(pid: u32, verified_started: u64) -> TerminalOrigin {
        origin_from(pid, verified_started, &stat_of, &command_of)
    }

    pub(super) fn origin_from(
        pid: u32,
        verified_started: u64,
        stat_of: &dyn Fn(u32) -> Option<Stat>,
        command_of: &dyn Fn(u32) -> Option<String>,
    ) -> TerminalOrigin {
        let Some(stat) = stat_of(pid) else {
            return TerminalOrigin::without_terminal();
        };
        if stat.started != verified_started {
            return TerminalOrigin::without_terminal();
        }
        let program = command_of(stat.parent).as_deref().and_then(reported);
        if stat.terminal == 0 || stat.session == 0 {
            return TerminalOrigin {
                program,
                ..TerminalOrigin::without_terminal()
            };
        }
        let Some(leader) = stat_of(stat.session) else {
            return TerminalOrigin {
                program,
                ..TerminalOrigin::without_terminal()
            };
        };
        if leader.session != stat.session {
            return TerminalOrigin {
                program,
                ..TerminalOrigin::without_terminal()
            };
        }
        let leader_command = command_of(leader.parent);
        TerminalOrigin {
            key: Some(TerminalKey::controlling(
                stat.terminal,
                stat.session,
                leader.started,
            )),
            device: Some(device_name(stat.terminal)),
            program,
            remote: is_remote_parent(leader_command.as_deref().map(str::trim)),
        }
    }
}

#[cfg(windows)]
mod platform {
    use super::*;
    use std::mem::size_of;
    use windows_sys::Win32::{
        Foundation::{CloseHandle, FILETIME, HANDLE, INVALID_HANDLE_VALUE},
        System::{
            Diagnostics::ToolHelp::{
                CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
                TH32CS_SNAPPROCESS,
            },
            Threading::{GetProcessTimes, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION},
        },
    };

    struct Handle(HANDLE);

    impl Drop for Handle {
        fn drop(&mut self) {
            unsafe {
                CloseHandle(self.0);
            }
        }
    }

    struct Entry {
        parent: u32,
        name: String,
    }

    fn entries(wanted: &[u32]) -> Vec<(u32, Entry)> {
        let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
        if snapshot.is_null() || snapshot == INVALID_HANDLE_VALUE {
            return Vec::new();
        }
        let snapshot = Handle(snapshot);
        let mut entry: PROCESSENTRY32W = unsafe { std::mem::zeroed() };
        entry.dwSize = size_of::<PROCESSENTRY32W>() as u32;
        let mut found = Vec::new();
        let mut more = unsafe { Process32FirstW(snapshot.0, &mut entry) } != 0;
        while more {
            if wanted.contains(&entry.th32ProcessID) {
                let length = entry
                    .szExeFile
                    .iter()
                    .position(|unit| *unit == 0)
                    .unwrap_or(entry.szExeFile.len());
                found.push((
                    entry.th32ProcessID,
                    Entry {
                        parent: entry.th32ParentProcessID,
                        name: String::from_utf16_lossy(&entry.szExeFile[..length]),
                    },
                ));
            }
            more = unsafe { Process32NextW(snapshot.0, &mut entry) } != 0;
        }
        found
    }

    fn created(pid: u32) -> Option<u64> {
        let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
        if process.is_null() {
            return None;
        }
        let process = Handle(process);
        let mut creation = FILETIME::default();
        let mut exit = FILETIME::default();
        let mut kernel = FILETIME::default();
        let mut user = FILETIME::default();
        if unsafe { GetProcessTimes(process.0, &mut creation, &mut exit, &mut kernel, &mut user) }
            == 0
        {
            return None;
        }
        Some((u64::from(creation.dwHighDateTime) << 32) | u64::from(creation.dwLowDateTime))
    }

    pub(crate) fn origin_of(pid: u32) -> TerminalOrigin {
        let Some(parent) = entries(&[pid])
            .into_iter()
            .find(|(found, _)| *found == pid)
            .map(|(_, entry)| entry.parent)
        else {
            return TerminalOrigin::without_terminal();
        };
        let (Some(child_created), Some(parent_created)) = (created(pid), created(parent)) else {
            return TerminalOrigin::without_terminal();
        };
        if parent_created >= child_created {
            return TerminalOrigin::without_terminal();
        }
        TerminalOrigin {
            program: entries(&[parent])
                .into_iter()
                .find(|(found, _)| *found == parent)
                .and_then(|(_, entry)| reported(&entry.name)),
            ..TerminalOrigin::without_terminal()
        }
    }
}

#[cfg(any(target_os = "linux", windows))]
pub(crate) use platform::origin_of;

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::platform::*;
    use super::*;

    #[test]
    fn a_stat_line_with_spaces_and_brackets_in_the_name_parses() {
        let line = "4242 (fictional (shell) x) S 4100 4242 4101 34819 4242 4194304 0 0 0 0 1 2 0 0 20 0 1 0 98765 1000 100 18446744073709551615";
        let stat = parse_stat(line).expect("parsed");
        assert_eq!(stat.parent, 4100);
        assert_eq!(stat.session, 4101);
        assert_eq!(stat.terminal, 34_819);
        assert_eq!(stat.started, 98_765);
    }

    #[test]
    fn terminal_numbers_name_their_devices() {
        assert_eq!(device_name(34_819), "pts/3");
        assert_eq!(device_name((137 << 8) | 4), "pts/260");
        assert_eq!(device_name((4 << 8) | 2), "tty2");
        assert_eq!(device_name((4 << 8) | 65), "ttyS1");
    }

    #[test]
    fn a_session_whose_leader_was_started_by_sshd_is_remote() {
        assert!(is_remote_parent(Some("sshd")));
        assert!(is_remote_parent(Some("sshd-session")));
        assert!(!is_remote_parent(Some("gnome-terminal-")));
        assert!(!is_remote_parent(None));
    }

    #[test]
    fn a_reported_program_name_cannot_carry_control_characters() {
        assert_eq!(
            printable("bash\u{1b}]52;c;\u{7}").as_deref(),
            Some("bash?]52;c;?")
        );
        assert_eq!(printable("  "), None);
    }

    fn this_process_started() -> u64 {
        parse_stat(&std::fs::read_to_string("/proc/self/stat").expect("own stat"))
            .expect("parsed")
            .started
    }

    #[test]
    fn this_test_process_reports_a_consistent_origin() {
        let started = this_process_started();
        let first = origin_of(std::process::id(), started);
        let second = origin_of(std::process::id(), started);
        assert_eq!(first, second);
        assert_eq!(first.key.is_some(), first.device.is_some());
    }

    #[test]
    fn a_process_that_is_not_running_has_no_terminal() {
        assert_eq!(origin_of(u32::MAX, 1), TerminalOrigin::without_terminal());
    }

    #[test]
    fn a_pid_whose_start_time_differs_from_the_verified_one_has_no_terminal() {
        let started = this_process_started();
        assert_eq!(
            origin_of(std::process::id(), started + 1),
            TerminalOrigin::without_terminal()
        );
    }

    struct Process {
        pid: u32,
        parent: u32,
        session: u32,
        terminal: u64,
        started: u64,
        command: &'static str,
    }

    fn origin_among(processes: &[Process], pid: u32, verified_started: u64) -> TerminalOrigin {
        let stat_of = |wanted: u32| {
            processes
                .iter()
                .find(|process| process.pid == wanted)
                .map(|process| Stat {
                    parent: process.parent,
                    session: process.session,
                    terminal: process.terminal,
                    started: process.started,
                })
        };
        let command_of = |wanted: u32| {
            processes
                .iter()
                .find(|process| process.pid == wanted)
                .map(|process| format!("{}\n", process.command))
        };
        origin_from(pid, verified_started, &stat_of, &command_of)
    }

    #[test]
    fn a_session_leader_whose_pid_is_reused_does_not_inherit_the_allowance() {
        use crate::application::terminal_allowances::TerminalAllowances;

        let first_shell = [
            Process {
                pid: 3_100,
                parent: 1_000,
                session: 3_100,
                terminal: 34_819,
                started: 100,
                command: "bash",
            },
            Process {
                pid: 3_150,
                parent: 3_100,
                session: 3_100,
                terminal: 34_819,
                started: 180,
                command: "sesame",
            },
        ];
        let allowed = origin_among(&first_shell, 3_150, 180);
        assert_eq!(allowed.device.as_deref(), Some("pts/3"));
        assert_eq!(
            allowed
                .program
                .as_ref()
                .map(|program| program.reported_name.as_str()),
            Some("bash")
        );
        let allowances = TerminalAllowances::default();
        assert!(allowances.grant(&allowed, 7, allowances.revision()));
        assert!(allowances.covers(&origin_among(&first_shell, 3_150, 180), 7));

        let reused = [
            Process {
                pid: 3_100,
                parent: 1_000,
                session: 3_100,
                terminal: 34_819,
                started: 900,
                command: "bash",
            },
            Process {
                pid: 3_150,
                parent: 3_100,
                session: 3_100,
                terminal: 34_819,
                started: 950,
                command: "sesame",
            },
        ];
        let later = origin_among(&reused, 3_150, 950);
        assert!(later.key.is_some());
        assert_eq!(later.device, allowed.device);
        assert_ne!(later.key, allowed.key);
        assert!(!allowances.covers(&later, 7));

        assert_eq!(
            origin_among(&reused, 3_150, 180),
            TerminalOrigin::without_terminal()
        );
    }

    #[test]
    fn a_leader_that_left_its_session_gives_no_terminal() {
        let processes = [
            Process {
                pid: 3_100,
                parent: 1_000,
                session: 2_000,
                terminal: 0,
                started: 100,
                command: "fictional-daemon",
            },
            Process {
                pid: 3_150,
                parent: 3_100,
                session: 3_100,
                terminal: 34_819,
                started: 180,
                command: "sesame",
            },
        ];
        let origin = origin_among(&processes, 3_150, 180);
        assert_eq!(origin.key, None);
        assert_eq!(origin.device, None);
    }
}
