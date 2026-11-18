use std::ffi::OsString;
use std::io::{self, ErrorKind, IsTerminal, Write};

use zeroize::Zeroizing;

use crate::cli_protocol::{
    parse_reply, CliCommand, CliErrorCode, CliReply, CliReplyType, WaitReason, MAX_CLI_LIST_BYTES,
    MAX_FIELD_CHARS, MAX_ITEM_CHARS, MAX_WAITING_FRAMES,
};

pub const EXIT_OK: i32 = 0;
pub const EXIT_FAILED: i32 = 1;
pub const EXIT_USAGE: i32 = 2;
pub const EXIT_UNREACHABLE: i32 = 3;
pub const EXIT_TIMEOUT: i32 = 4;
pub const EXIT_DENIED: i32 = 5;
pub const EXIT_STALE: i32 = 6;
pub const EXIT_MISSING: i32 = 7;
pub const EXIT_BUSY: i32 = 8;
pub const EXIT_OUTDATED: i32 = 9;

const HELP_WORDS: [&str; 3] = ["help", "--help", "-h"];
const VERSION_WORDS: [&str; 2] = ["--version", "-V"];
const VERBS: [&str; 8] = [
    "list",
    "get",
    "totp",
    "help",
    "--help",
    "-h",
    "--version",
    "-V",
];
const NOT_RUNNING: &str = "Sesame is not running. Open Sesame and try again.";
const NOT_SESAME: &str = "This is not the Sesame app this command belongs to.";
const UNREADABLE_REPLY: &str = "Sesame sent a reply this command does not understand.";
const OUTPUT_FAILED: &str = "The output could not be written completely, so this command failed.";

const USAGE_COMMON: &str = "Usage:
  sesame list
  sesame get <item> [field] [--copy]
  sesame totp <item> [--copy]

Each request waits for your approval in the Sesame window. A hidden value also needs your master password, as it does in the window.
With --copy Sesame puts the value on the clipboard instead of printing it, and clears it again after a while.
Sesame never takes a secret as an argument, but the item and field names you type stay in your shell history.
Anything printed in a terminal can be read by other programs that run as you.
";

#[cfg(not(windows))]
const USAGE_PLATFORM: &str = "When you allow a terminal for five minutes, any program started from the shell session you approved there can read what it asks for during that time, and a new shell session in that terminal is asked again. The allowance ends early when the vault locks or almost anything in the vault changes.
With the AppImage, run ./Sesame.AppImage list, or add an alias such as alias sesame=~/Applications/Sesame.AppImage to your shell.
";

#[cfg(windows)]
const USAGE_PLATFORM: &str = "On Windows every request asks in the Sesame window, because Sesame cannot tell one terminal from another there.
";

fn usage() -> String {
    format!("{USAGE_COMMON}{USAGE_PLATFORM}")
}

#[derive(Debug, PartialEq, Eq)]
pub enum Invocation {
    Help,
    Version,
    Run(CliCommand),
}

#[cfg(any(target_os = "linux", test))]
pub fn is_terminal_verb(argument: &OsString) -> bool {
    argument
        .to_str()
        .is_some_and(|argument| VERBS.contains(&argument))
}

fn bounded_argument(value: &str, max_chars: usize, name: &str) -> Result<String, String> {
    let count = value.chars().count();
    if count == 0 || value.trim().is_empty() {
        return Err(format!("The {name} name is empty."));
    }
    if count > max_chars {
        return Err(format!(
            "The {name} name is longer than {max_chars} characters."
        ));
    }
    if value.chars().any(char::is_control) {
        return Err(format!("The {name} name contains a control character."));
    }
    Ok(value.to_string())
}

pub fn parse_arguments(arguments: &[OsString]) -> Result<Invocation, String> {
    let mut words = Vec::with_capacity(arguments.len());
    for argument in arguments {
        words.push(
            argument
                .to_str()
                .ok_or_else(|| "An argument is not valid text.".to_string())?,
        );
    }
    let Some((verb, rest)) = words.split_first() else {
        return Err("Choose list, get or totp.".to_string());
    };
    if HELP_WORDS.contains(verb) {
        return Ok(Invocation::Help);
    }
    if VERSION_WORDS.contains(verb) {
        return Ok(Invocation::Version);
    }
    if !VERBS.contains(verb) {
        return Err(format!("Sesame has no command called {verb}."));
    }
    let mut copy = false;
    let mut positional = Vec::new();
    let mut options_ended = false;
    for word in rest {
        if !options_ended && *word == "--" {
            options_ended = true;
        } else if !options_ended && (*word == "--help" || *word == "-h") {
            return Ok(Invocation::Help);
        } else if !options_ended && *word == "--copy" {
            if copy {
                return Err("--copy is given twice.".to_string());
            }
            copy = true;
        } else if !options_ended && word.starts_with('-') && word.len() > 1 {
            return Err(format!("Sesame has no option called {word}."));
        } else {
            positional.push(*word);
        }
    }
    let command = match (*verb, positional.as_slice()) {
        ("list", []) if !copy => CliCommand::List,
        ("list", []) => return Err("list cannot copy.".to_string()),
        ("list", _) => return Err("list takes no item name.".to_string()),
        ("get", [item]) if !copy => CliCommand::Get {
            item: bounded_argument(item, MAX_ITEM_CHARS, "item")?,
            field: None,
            copy: false,
        },
        ("get", [_]) => return Err("--copy needs a field name.".to_string()),
        ("get", [item, field]) => CliCommand::Get {
            item: bounded_argument(item, MAX_ITEM_CHARS, "item")?,
            field: Some(bounded_argument(field, MAX_FIELD_CHARS, "field")?),
            copy,
        },
        ("get", _) => return Err("get takes an item name and an optional field name.".to_string()),
        ("totp", [item]) => CliCommand::Totp {
            item: bounded_argument(item, MAX_ITEM_CHARS, "item")?,
            copy,
        },
        _ => return Err("totp takes one item name.".to_string()),
    };
    Ok(Invocation::Run(command))
}

pub trait FrameSource {
    fn next_frame(&mut self) -> io::Result<Zeroizing<Vec<u8>>>;
}

pub struct Streams<'a> {
    pub out: &'a mut dyn Write,
    pub err: &'a mut dyn Write,
    pub out_terminal: bool,
    pub err_terminal: bool,
}

impl Streams<'_> {
    fn say(&mut self, message: &str) {
        let _ = writeln!(self.err, "{}", printable_line(message));
    }

    fn delivered(&mut self, written: io::Result<()>) -> i32 {
        match written.and_then(|()| self.out.flush()) {
            Ok(()) => EXIT_OK,
            Err(_) => {
                self.say(OUTPUT_FAILED);
                EXIT_FAILED
            }
        }
    }
}

fn printable_line(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_control() {
                '?'
            } else {
                character
            }
        })
        .collect()
}

fn printable_block(value: &str) -> Zeroizing<String> {
    Zeroizing::new(
        value
            .chars()
            .map(|character| {
                if character.is_control() && character != '\n' && character != '\t' {
                    '?'
                } else {
                    character
                }
            })
            .collect(),
    )
}

fn unsafe_for_terminal(value: &str) -> bool {
    value
        .chars()
        .any(|character| character.is_control() && character != '\n' && character != '\t')
}

pub fn request_id() -> String {
    let mut bytes = [0_u8; 16];
    sesame_core::util::fill_random(&mut bytes);
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn read_failure(error: &io::Error, answered: bool, streams: &mut Streams<'_>) -> i32 {
    match error.kind() {
        ErrorKind::TimedOut | ErrorKind::WouldBlock => {
            streams.say(CliErrorCode::Timeout.message());
            EXIT_TIMEOUT
        }
        ErrorKind::UnexpectedEof | ErrorKind::BrokenPipe if !answered => {
            streams.say(NOT_SESAME);
            EXIT_UNREACHABLE
        }
        _ => {
            streams.say("Sesame stopped answering.");
            EXIT_FAILED
        }
    }
}

pub fn converse(
    source: &mut dyn FrameSource,
    request_id: &str,
    command: &CliCommand,
    streams: &mut Streams<'_>,
) -> i32 {
    let mut waiting = 0;
    let mut answered = false;
    let mut total = 0_usize;
    let mut items = Vec::new();
    loop {
        let frame = match source.next_frame() {
            Ok(frame) => frame,
            Err(error) => return read_failure(&error, answered, streams),
        };
        answered = true;
        total = total.saturating_add(frame.len());
        if total > MAX_CLI_LIST_BYTES {
            streams.say(UNREADABLE_REPLY);
            return EXIT_FAILED;
        }
        let Some(reply) = parse_reply(&frame).filter(|reply| reply.answers(request_id, command))
        else {
            streams.say(UNREADABLE_REPLY);
            return EXIT_FAILED;
        };
        match reply.reply_type {
            CliReplyType::Waiting => {
                waiting += 1;
                if waiting > MAX_WAITING_FRAMES {
                    streams.say(UNREADABLE_REPLY);
                    return EXIT_FAILED;
                }
                streams.say(match reply.reason {
                    Some(WaitReason::Unlock) => "Unlock Sesame to continue.",
                    _ => "Approve this request in Sesame.",
                });
            }
            CliReplyType::Items => items.extend(reply.items.clone().unwrap_or_default()),
            CliReplyType::Done => {
                let written = print_list(&items, streams);
                return streams.delivered(written);
            }
            _ => return finish(&reply, streams),
        }
    }
}

fn print_list(
    items: &[crate::cli_protocol::CliItemSummary],
    streams: &mut Streams<'_>,
) -> io::Result<()> {
    if streams.out_terminal {
        let title_width = items
            .iter()
            .map(|item| printable_line(&item.title).chars().count())
            .max()
            .unwrap_or(0)
            .min(60);
        let kind_width = items
            .iter()
            .map(|item| item.kind.chars().count())
            .max()
            .unwrap_or(0);
        for item in items {
            writeln!(
                streams.out,
                "{:title_width$}  {:kind_width$}  {}",
                printable_line(&item.title),
                item.kind,
                printable_line(&item.id),
            )?;
        }
    } else {
        for item in items {
            writeln!(
                streams.out,
                "{}\t{}\t{}",
                printable_line(&item.id),
                item.kind,
                printable_line(&item.title),
            )?;
        }
    }
    Ok(())
}

fn print_item(reply: &CliReply, streams: &mut Streams<'_>) -> io::Result<()> {
    let fields = reply.fields.as_deref().unwrap_or_default();
    if streams.out_terminal {
        writeln!(
            streams.out,
            "{}",
            printable_line(reply.title.as_deref().unwrap_or_default())
        )?;
        let width = fields
            .iter()
            .map(|field| printable_line(&field.name).chars().count())
            .max()
            .unwrap_or(0);
        for field in fields {
            let value = match (&field.value, field.hidden) {
                (Some(value), false) => printable_block(value),
                _ => Zeroizing::new("hidden".to_string()),
            };
            writeln!(
                streams.out,
                "{:width$}  {}",
                printable_line(&field.name),
                value.as_str()
            )?;
        }
    } else {
        for field in fields {
            let value = match (&field.value, field.hidden) {
                (Some(value), false) => Zeroizing::new(printable_line(value)),
                _ => Zeroizing::new(String::new()),
            };
            writeln!(
                streams.out,
                "{}\t{}\t{}",
                printable_line(&field.name),
                if field.hidden { "hidden" } else { "visible" },
                value.as_str()
            )?;
        }
    }
    Ok(())
}

fn finish(reply: &CliReply, streams: &mut Streams<'_>) -> i32 {
    match reply.reply_type {
        CliReplyType::Item => {
            let written = print_item(reply, streams);
            streams.delivered(written)
        }
        CliReplyType::Value => {
            let value = reply.value.as_deref().unwrap_or_default();
            let hidden = reply.hidden.unwrap_or(true);
            let written = if streams.out_terminal {
                if hidden && unsafe_for_terminal(value) {
                    streams.say("This value contains control characters, so Sesame will not print it to a terminal. Use --copy or send the output to another program.");
                    return EXIT_FAILED;
                }
                let shown = printable_block(value);
                writeln!(streams.out, "{}", shown.as_str())
            } else {
                streams.out.write_all(value.as_bytes())
            };
            streams.delivered(written)
        }
        CliReplyType::Totp => {
            let code = reply.code.as_deref().unwrap_or_default();
            let written = if streams.out_terminal {
                writeln!(streams.out, "{code}")
            } else {
                streams.out.write_all(code.as_bytes())
            };
            let exit = streams.delivered(written);
            if exit == EXIT_OK && streams.err_terminal {
                if let Some(seconds) = reply.remaining_seconds {
                    streams.say(&format!("The code changes in {seconds} seconds."));
                }
            }
            exit
        }
        CliReplyType::Copied => {
            match reply.clear_after_seconds {
                Some(seconds) => {
                    streams.say(&format!("Copied. Sesame clears it in {seconds} seconds."))
                }
                None => streams.say("Copied."),
            }
            EXIT_OK
        }
        CliReplyType::Error => {
            let code = reply.error_code().unwrap_or(CliErrorCode::Unavailable);
            let sesame_message = reply.message.as_deref().unwrap_or(code.message());
            let (exit, message) = match code {
                CliErrorCode::Timeout => (EXIT_TIMEOUT, code.message()),
                CliErrorCode::Cancelled => (EXIT_DENIED, sesame_message),
                CliErrorCode::Stale => (EXIT_STALE, code.message()),
                CliErrorCode::NotFound
                | CliErrorCode::NoField
                | CliErrorCode::EmptyField
                | CliErrorCode::NoTotp => (EXIT_MISSING, sesame_message),
                CliErrorCode::Busy => (EXIT_BUSY, sesame_message),
                CliErrorCode::UnsupportedVersion => (EXIT_OUTDATED, code.message()),
                CliErrorCode::Invalid | CliErrorCode::TooLarge | CliErrorCode::Unavailable => {
                    (EXIT_FAILED, sesame_message)
                }
            };
            streams.say(message);
            exit
        }
        _ => {
            streams.say(UNREADABLE_REPLY);
            EXIT_FAILED
        }
    }
}

#[cfg(any(target_os = "linux", windows))]
impl FrameSource for crate::browser_pipe::TerminalClient {
    fn next_frame(&mut self) -> io::Result<Zeroizing<Vec<u8>>> {
        crate::browser_pipe::TerminalClient::next_frame(self)
    }
}

fn connect_failure(error: &io::Error, streams: &mut Streams<'_>) -> i32 {
    match error.kind() {
        ErrorKind::PermissionDenied => {
            streams.say(NOT_SESAME);
            EXIT_UNREACHABLE
        }
        ErrorKind::NotFound | ErrorKind::ConnectionRefused | ErrorKind::AddrNotAvailable => {
            streams.say(NOT_RUNNING);
            EXIT_UNREACHABLE
        }
        _ => {
            streams.say(NOT_RUNNING);
            EXIT_UNREACHABLE
        }
    }
}

#[cfg(any(target_os = "linux", windows))]
fn send_request(command: &CliCommand, streams: &mut Streams<'_>) -> i32 {
    let request_id = request_id();
    let Ok(payload) = command.to_request(&request_id).to_bytes() else {
        streams.say("Sesame could not prepare this request.");
        return EXIT_FAILED;
    };
    let mut client = match crate::browser_pipe::open_terminal_request(&payload) {
        Ok(client) => client,
        Err(error) => return connect_failure(&error, streams),
    };
    converse(&mut client, &request_id, command, streams)
}

#[cfg(not(any(target_os = "linux", windows)))]
fn send_request(_command: &CliCommand, streams: &mut Streams<'_>) -> i32 {
    let _ = connect_failure;
    streams.say("The Sesame command is not available on this system.");
    EXIT_FAILED
}

pub fn run_with(arguments: &[OsString], streams: &mut Streams<'_>) -> i32 {
    match parse_arguments(arguments) {
        Ok(Invocation::Help) => {
            let written = streams.out.write_all(usage().as_bytes());
            streams.delivered(written)
        }
        Ok(Invocation::Version) => {
            let written = writeln!(streams.out, "sesame {}", env!("CARGO_PKG_VERSION"));
            streams.delivered(written)
        }
        Ok(Invocation::Run(command)) => send_request(&command, streams),
        Err(problem) => {
            streams.say(&problem);
            let _ = streams.err.write_all(usage().as_bytes());
            EXIT_USAGE
        }
    }
}

pub fn run_from_environment(arguments: &[OsString]) -> i32 {
    let stdout = io::stdout();
    let stderr = io::stderr();
    let out_terminal = stdout.is_terminal();
    let err_terminal = stderr.is_terminal();
    let mut out = stdout.lock();
    let mut err = stderr.lock();
    let mut streams = Streams {
        out: &mut out,
        err: &mut err,
        out_terminal,
        err_terminal,
    };
    let code = run_with(arguments, &mut streams);
    match streams.out.flush() {
        Err(_) if code == EXIT_OK => {
            streams.say(OUTPUT_FAILED);
            EXIT_FAILED
        }
        _ => code,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli_protocol::{CliField, CliItemSummary};

    const ID: &str = "3f9a0c1e5b7d2a4c6e8f0a1b2c3d4e5f";

    fn args(words: &[&str]) -> Vec<OsString> {
        words.iter().map(OsString::from).collect()
    }

    struct Frames(Vec<Vec<u8>>);

    impl FrameSource for Frames {
        fn next_frame(&mut self) -> io::Result<Zeroizing<Vec<u8>>> {
            if self.0.is_empty() {
                return Err(io::Error::new(ErrorKind::UnexpectedEof, "closed"));
            }
            Ok(Zeroizing::new(self.0.remove(0)))
        }
    }

    fn frames(replies: &[CliReply]) -> Frames {
        Frames(
            replies
                .iter()
                .map(|reply| reply.to_bytes().expect("encodes").to_vec())
                .collect(),
        )
    }

    fn talk(command: &CliCommand, replies: &[CliReply], terminal: bool) -> (i32, String, String) {
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = {
            let mut streams = Streams {
                out: &mut out,
                err: &mut err,
                out_terminal: terminal,
                err_terminal: terminal,
            };
            converse(&mut frames(replies), ID, command, &mut streams)
        };
        (
            code,
            String::from_utf8(out).expect("utf8"),
            String::from_utf8(err).expect("utf8"),
        )
    }

    fn get(field: Option<&str>, copy: bool) -> CliCommand {
        CliCommand::Get {
            item: "Northwind mail".to_string(),
            field: field.map(str::to_string),
            copy,
        }
    }

    #[test]
    fn only_the_tool_verbs_leave_the_desktop_start_alone() {
        for verb in VERBS {
            assert!(is_terminal_verb(&OsString::from(verb)));
        }
        for other in [
            "--minimized",
            "/home/casey/vault",
            "LIST",
            "-H",
            "-v",
            "--copy",
            "",
        ] {
            assert!(!is_terminal_verb(&OsString::from(other)));
        }
    }

    #[test]
    fn every_first_word_the_parser_answers_is_a_verb_that_never_starts_the_desktop() {
        let candidates = [
            "list",
            "get",
            "totp",
            "help",
            "--help",
            "-h",
            "--version",
            "-V",
            "-H",
            "-v",
            "--copy",
            "--",
            "fetch",
            "--minimized",
        ];
        for word in candidates {
            for rest in [
                &[][..],
                &["Northwind mail"][..],
                &["a", "b", "c"][..],
                &["--bad"][..],
            ] {
                let mut words = vec![word];
                words.extend_from_slice(rest);
                let answered = !matches!(
                    parse_arguments(&args(&words)),
                    Err(problem) if problem.starts_with("Sesame has no command called")
                );
                assert_eq!(
                    answered,
                    is_terminal_verb(&OsString::from(word)),
                    "{words:?}"
                );
            }
        }
        assert_eq!(parse_arguments(&args(&["-h"])), Ok(Invocation::Help));
        assert_eq!(parse_arguments(&args(&["-V"])), Ok(Invocation::Version));
        assert_eq!(
            parse_arguments(&args(&["--version", "extra"])),
            Ok(Invocation::Version)
        );
    }

    #[test]
    fn the_arguments_become_the_documented_commands() {
        assert_eq!(
            parse_arguments(&args(&["list"])),
            Ok(Invocation::Run(CliCommand::List))
        );
        assert_eq!(
            parse_arguments(&args(&["get", "Northwind mail", "password", "--copy"])),
            Ok(Invocation::Run(get(Some("password"), true)))
        );
        assert_eq!(
            parse_arguments(&args(&["get", "--", "-dash item"])),
            Ok(Invocation::Run(CliCommand::Get {
                item: "-dash item".to_string(),
                field: None,
                copy: false
            }))
        );
        assert_eq!(
            parse_arguments(&args(&["totp", "--copy", "Northwind mail"])),
            Ok(Invocation::Run(CliCommand::Totp {
                item: "Northwind mail".to_string(),
                copy: true
            }))
        );
        assert_eq!(
            parse_arguments(&args(&["get", "--help"])),
            Ok(Invocation::Help)
        );
        assert_eq!(
            parse_arguments(&args(&["--version"])),
            Ok(Invocation::Version)
        );
    }

    #[test]
    fn the_help_text_states_the_limits_for_this_platform() {
        let mut out = Vec::new();
        let mut err = Vec::new();
        let mut streams = Streams {
            out: &mut out,
            err: &mut err,
            out_terminal: false,
            err_terminal: false,
        };
        assert_eq!(run_with(&args(&["--help"]), &mut streams), EXIT_OK);
        let help = String::from_utf8(out).expect("help is text");
        assert!(err.is_empty());
        assert!(help.contains("sesame get <item> [field] [--copy]"));
        assert!(help.contains("stay in your shell history"));
        assert!(help.contains("can be read by other programs that run as you"));
        if cfg!(windows) {
            assert!(help.contains("On Windows every request asks in the Sesame window"));
            assert!(!help.contains("five minutes"));
            assert!(!help.contains("AppImage"));
        } else {
            assert!(help.contains("any program started from the shell session you approved"));
            assert!(help.contains("./Sesame.AppImage list"));
        }
        assert!(!help.contains('\u{2014}') && !help.contains('(') && !help.contains(')'));
    }

    #[test]
    fn bad_arguments_are_refused_with_the_usage_exit_code() {
        for words in [
            vec![],
            vec!["list", "Northwind mail"],
            vec!["list", "--copy"],
            vec!["get"],
            vec!["get", "Northwind mail", "--copy"],
            vec!["get", "a", "b", "c"],
            vec!["get", "Northwind mail", "--password=fictional"],
            vec!["totp"],
            vec!["totp", "a", "b"],
            vec!["get", "North\u{1b}wind"],
            vec!["fetch", "Northwind mail"],
        ] {
            let mut out = Vec::new();
            let mut err = Vec::new();
            let mut streams = Streams {
                out: &mut out,
                err: &mut err,
                out_terminal: false,
                err_terminal: false,
            };
            assert_eq!(
                run_with(&args(&words), &mut streams),
                EXIT_USAGE,
                "{words:?}"
            );
            assert!(out.is_empty());
        }
        let long = "n".repeat(MAX_ITEM_CHARS + 1);
        assert!(parse_arguments(&args(&["get", &long])).is_err());
    }

    #[test]
    fn a_request_id_is_thirty_two_lowercase_hex_characters_and_never_repeats() {
        let first = request_id();
        assert!(crate::cli_protocol::valid_request_id(&first));
        assert_ne!(first, request_id());
    }

    #[test]
    fn a_value_goes_to_standard_output_and_the_waiting_messages_to_standard_error() {
        let replies = [
            CliReply::waiting(ID, WaitReason::Unlock),
            CliReply::waiting(ID, WaitReason::Approval),
            CliReply::value(ID, "fictional-password-canary", true),
        ];
        let (code, out, err) = talk(&get(Some("password"), false), &replies, false);
        assert_eq!(code, EXIT_OK);
        assert_eq!(out, "fictional-password-canary");
        assert!(err.contains("Unlock Sesame to continue."));
        assert!(err.contains("Approve this request in Sesame."));
        assert!(!err.contains("canary"));

        let (_, out, _) = talk(&get(Some("password"), false), &replies, true);
        assert_eq!(out, "fictional-password-canary\n");
    }

    #[test]
    fn a_hidden_value_with_control_characters_is_refused_on_a_terminal_and_passed_exactly_to_a_pipe(
    ) {
        let value = "fictional\u{1b}]52;c;Zm9v\u{7}canary";
        let replies = [CliReply::value(ID, value, true)];
        let (code, out, err) = talk(&get(Some("password"), false), &replies, true);
        assert_eq!(code, EXIT_FAILED);
        assert!(out.is_empty());
        assert!(err.contains("--copy"));

        let (code, out, _) = talk(&get(Some("password"), false), &replies, false);
        assert_eq!(code, EXIT_OK);
        assert_eq!(out, value);
    }

    #[test]
    fn titles_and_visible_values_cannot_send_escape_sequences_to_a_terminal() {
        let title = "Northwind\u{1b}]52;c;Zm9v\u{7}";
        let items = vec![CliItemSummary {
            id: "fictional-login".to_string(),
            kind: "login".to_string(),
            title: title.to_string(),
        }];
        let list = [CliReply::items(ID, items), CliReply::done(ID)];
        for terminal in [true, false] {
            let (code, out, _) = talk(&CliCommand::List, &list, terminal);
            assert_eq!(code, EXIT_OK);
            assert!(out.contains("Northwind?]52;c;Zm9v?"));
            assert!(!out.contains('\u{1b}'));
        }

        let item = CliReply::item(
            ID,
            CliItemSummary {
                id: "fictional-login".to_string(),
                kind: "login".to_string(),
                title: title.to_string(),
            },
            vec![
                CliField {
                    name: "username".to_string(),
                    hidden: false,
                    value: Some("casey\u{1b}[2J".to_string()),
                },
                CliField {
                    name: "password".to_string(),
                    hidden: true,
                    value: None,
                },
            ],
        );
        let (code, out, _) = talk(&get(None, false), &[item], true);
        assert_eq!(code, EXIT_OK);
        assert!(!out.contains('\u{1b}'));
        assert!(out.contains("casey?[2J"));
        assert!(out.contains("password  hidden"));
    }

    #[test]
    fn a_copy_prints_no_value_and_names_the_clearing_time() {
        let (code, out, err) = talk(
            &get(Some("password"), true),
            &[CliReply::copied(ID, Some(30))],
            true,
        );
        assert_eq!(code, EXIT_OK);
        assert!(out.is_empty());
        assert_eq!(err, "Copied. Sesame clears it in 30 seconds.\n");
    }

    #[test]
    fn each_error_code_has_its_documented_exit_code() {
        for (code, exit) in [
            (CliErrorCode::Timeout, EXIT_TIMEOUT),
            (CliErrorCode::Cancelled, EXIT_DENIED),
            (CliErrorCode::Stale, EXIT_STALE),
            (CliErrorCode::NotFound, EXIT_MISSING),
            (CliErrorCode::NoField, EXIT_MISSING),
            (CliErrorCode::EmptyField, EXIT_MISSING),
            (CliErrorCode::NoTotp, EXIT_MISSING),
            (CliErrorCode::Busy, EXIT_BUSY),
            (CliErrorCode::UnsupportedVersion, EXIT_OUTDATED),
            (CliErrorCode::TooLarge, EXIT_FAILED),
            (CliErrorCode::Unavailable, EXIT_FAILED),
            (CliErrorCode::Invalid, EXIT_FAILED),
        ] {
            let (actual, out, err) = talk(
                &get(Some("password"), false),
                &[CliReply::error(Some(ID), code)],
                false,
            );
            assert_eq!(actual, exit, "{code:?}");
            assert!(out.is_empty());
            assert!(!err.is_empty());
        }
    }

    #[test]
    fn a_reply_for_another_request_or_command_is_not_trusted() {
        let other = "00000000000000000000000000000000";
        let (code, out, _) = talk(
            &get(Some("password"), false),
            &[CliReply::value(other, "fictional-password-canary", true)],
            false,
        );
        assert_eq!(code, EXIT_FAILED);
        assert!(out.is_empty());

        let (code, out, _) = talk(
            &get(Some("password"), true),
            &[CliReply::value(ID, "fictional-password-canary", true)],
            false,
        );
        assert_eq!(code, EXIT_FAILED);
        assert!(out.is_empty());

        let waits = [
            CliReply::waiting(ID, WaitReason::Unlock),
            CliReply::waiting(ID, WaitReason::Approval),
            CliReply::waiting(ID, WaitReason::Approval),
        ];
        assert_eq!(talk(&CliCommand::List, &waits, false).0, EXIT_FAILED);
    }

    struct ShortWrite {
        room: usize,
        written: Vec<u8>,
    }

    impl Write for ShortWrite {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if self.room == 0 {
                return Err(io::Error::from(ErrorKind::BrokenPipe));
            }
            let taken = bytes.len().min(self.room);
            self.room -= taken;
            self.written.extend_from_slice(&bytes[..taken]);
            Ok(taken)
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    struct FailingFlush(Vec<u8>);

    impl Write for FailingFlush {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0.extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Err(io::Error::from(ErrorKind::BrokenPipe))
        }
    }

    fn deliver_into(
        out: &mut dyn Write,
        command: &CliCommand,
        replies: &[CliReply],
        terminal: bool,
    ) -> (i32, String) {
        let mut err = Vec::new();
        let code = {
            let mut streams = Streams {
                out,
                err: &mut err,
                out_terminal: terminal,
                err_terminal: terminal,
            };
            converse(&mut frames(replies), ID, command, &mut streams)
        };
        (code, String::from_utf8(err).expect("utf8"))
    }

    #[test]
    fn output_that_cannot_be_written_completely_fails_without_naming_the_value() {
        let summary = CliItemSummary {
            id: "fictional-login".to_string(),
            kind: "login".to_string(),
            title: "Northwind mail".to_string(),
        };
        let item = CliReply::item(
            ID,
            summary.clone(),
            vec![CliField {
                name: "username".to_string(),
                hidden: false,
                value: Some("casey@northwind.example".to_string()),
            }],
        );
        let cases = [
            (
                get(Some("password"), false),
                vec![CliReply::value(ID, "fictional-password-canary", true)],
            ),
            (get(None, false), vec![item]),
            (
                CliCommand::List,
                vec![CliReply::items(ID, vec![summary]), CliReply::done(ID)],
            ),
            (
                CliCommand::Totp {
                    item: "Northwind mail".to_string(),
                    copy: false,
                },
                vec![CliReply::totp(ID, "287082", 12)],
            ),
        ];
        for (command, replies) in &cases {
            for terminal in [false, true] {
                let mut short = ShortWrite {
                    room: 4,
                    written: Vec::new(),
                };
                let (code, err) = deliver_into(&mut short, command, replies, terminal);
                assert_eq!(code, EXIT_FAILED, "{command:?}");
                assert!(err.contains(OUTPUT_FAILED));
                assert!(!err.contains("canary") && !err.contains("287082"));

                let mut flushing = FailingFlush(Vec::new());
                let (code, err) = deliver_into(&mut flushing, command, replies, terminal);
                assert_eq!(code, EXIT_FAILED, "{command:?}");
                assert!(err.contains(OUTPUT_FAILED));
            }
        }

        for words in [&["--help"][..], &["--version"][..]] {
            let mut short = ShortWrite {
                room: 4,
                written: Vec::new(),
            };
            let mut err = Vec::new();
            let mut streams = Streams {
                out: &mut short,
                err: &mut err,
                out_terminal: false,
                err_terminal: false,
            };
            assert_eq!(run_with(&args(words), &mut streams), EXIT_FAILED);
        }

        let mut roomy = ShortWrite {
            room: usize::MAX,
            written: Vec::new(),
        };
        let (code, _) = deliver_into(&mut roomy, &cases[0].0, &cases[0].1, false);
        assert_eq!(code, EXIT_OK);
        assert_eq!(roomy.written, b"fictional-password-canary");
    }

    #[test]
    fn a_closed_connection_before_any_reply_means_another_program_answered() {
        let (code, _, err) = talk(&CliCommand::List, &[], false);
        assert_eq!(code, EXIT_UNREACHABLE);
        assert!(err.contains(NOT_SESAME));
    }

    struct Closed(io::Error);

    impl FrameSource for Closed {
        fn next_frame(&mut self) -> io::Result<Zeroizing<Vec<u8>>> {
            Err(io::Error::new(self.0.kind(), "closed"))
        }
    }

    fn closed_with(error: io::Error) -> (i32, String) {
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = {
            let mut streams = Streams {
                out: &mut out,
                err: &mut err,
                out_terminal: false,
                err_terminal: false,
            };
            converse(&mut Closed(error), ID, &CliCommand::List, &mut streams)
        };
        (code, String::from_utf8(err).expect("utf8"))
    }

    #[test]
    fn a_pipe_closed_before_any_reply_exits_as_unreachable_on_every_platform() {
        let (code, err) = closed_with(io::Error::from(ErrorKind::BrokenPipe));
        assert_eq!(code, EXIT_UNREACHABLE);
        assert!(err.contains(NOT_SESAME));
        let (code, _) = closed_with(io::Error::from(ErrorKind::ConnectionReset));
        assert_eq!(code, EXIT_FAILED);
    }

    #[cfg(windows)]
    #[test]
    fn the_native_closed_pipe_error_exits_as_unreachable() {
        const ERROR_BROKEN_PIPE: i32 = 109;
        let native = io::Error::from_raw_os_error(ERROR_BROKEN_PIPE);
        assert_eq!(native.kind(), ErrorKind::BrokenPipe);
        assert_eq!(closed_with(native).0, EXIT_UNREACHABLE);
    }

    #[test]
    fn no_running_desktop_and_a_refused_peer_both_exit_with_three() {
        let mut out = Vec::new();
        let mut err = Vec::new();
        let mut streams = Streams {
            out: &mut out,
            err: &mut err,
            out_terminal: false,
            err_terminal: false,
        };
        assert_eq!(
            connect_failure(&io::Error::from(ErrorKind::NotFound), &mut streams),
            EXIT_UNREACHABLE
        );
        assert_eq!(
            connect_failure(&io::Error::from(ErrorKind::PermissionDenied), &mut streams),
            EXIT_UNREACHABLE
        );
        let err = String::from_utf8(err).expect("utf8");
        assert!(err.contains(NOT_RUNNING));
        assert!(err.contains(NOT_SESAME));
    }
}
