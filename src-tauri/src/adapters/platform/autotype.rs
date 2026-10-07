//! Auto-type: sends a login's credentials as keystrokes to the foreground window.
//! Never targets a window by name; the caller must let the person switch focus first.

use tauri::State;
use zeroize::Zeroizing;

use crate::commands::require_release_presence;
use crate::release::ReleasePresence;
use crate::vault::{TaggedItem, VaultResult, VaultState};

#[cfg(any(windows, test))]
const CHUNK_CHARS: usize = 8;

#[cfg(any(windows, test))]
const NO_WINDOW_MESSAGE: &str =
    "Sesame could not find a focused window to type into. Click the target field first.";
#[cfg(any(windows, test))]
const OWN_WINDOW_MESSAGE: &str =
    "Switch to the window you want to fill in, then try auto-type again.";
#[cfg(any(windows, test))]
const FOCUS_MOVED_MESSAGE: &str =
    "Typing stopped because the focused window changed. Click the target field and try again.";
#[cfg(any(windows, test))]
const SEND_FAILED_MESSAGE: &str =
    "Sesame could not finish typing. The target window may be running with higher privileges.";

#[tauri::command]
pub fn auto_type(
    id: String,
    state: State<'_, VaultState>,
    presence: State<'_, ReleasePresence>,
) -> VaultResult<()> {
    let (username, password) = login_credentials(&state, &presence, &id)?;
    send_credentials(&username, &password)
}

fn login_credentials(
    state: &VaultState,
    presence: &ReleasePresence,
    id: &str,
) -> VaultResult<(Zeroizing<String>, Zeroizing<String>)> {
    require_release_presence(state, presence)?;
    let session = state
        .session
        .lock()
        .map_err(|_| "Sesame could not read the vault session.".to_string())?;
    let session = session.as_ref().ok_or("Unlock your vault first.")?;
    let item = session.open_item(id)?;
    let TaggedItem::Login(entry) = &*item else {
        return Err("That saved login no longer exists.".into());
    };
    if entry.username.is_empty() && entry.password.is_empty() {
        return Err("This login has nothing saved to type.".to_string());
    }
    Ok((
        Zeroizing::new(entry.username.clone()),
        Zeroizing::new(entry.password.clone()),
    ))
}

#[cfg(any(windows, test))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ForegroundWindow {
    window: isize,
    process_id: u32,
}

#[cfg(any(windows, test))]
trait TypingTarget {
    fn foreground(&self) -> Option<ForegroundWindow>;
    fn own_process_id(&self) -> u32;
    fn type_text(&mut self, text: &[char]) -> VaultResult<()>;
    fn press_tab(&mut self) -> VaultResult<()>;
}

#[cfg(any(windows, test))]
fn type_credentials(
    target: &mut impl TypingTarget,
    username: &str,
    password: &str,
) -> VaultResult<()> {
    let window = target
        .foreground()
        .ok_or_else(|| NO_WINDOW_MESSAGE.to_string())?;
    if window.process_id == target.own_process_id() {
        return Err(OWN_WINDOW_MESSAGE.to_string());
    }
    if !username.is_empty() {
        let characters = Zeroizing::new(username.chars().collect::<Vec<_>>());
        for chunk in characters.chunks(CHUNK_CHARS) {
            ensure_still_focused(target, window)?;
            target.type_text(chunk)?;
        }
        ensure_still_focused(target, window)?;
        target.press_tab()?;
    }
    let characters = Zeroizing::new(password.chars().collect::<Vec<_>>());
    for chunk in characters.chunks(CHUNK_CHARS) {
        ensure_still_focused(target, window)?;
        target.type_text(chunk)?;
    }
    Ok(())
}

#[cfg(any(windows, test))]
fn ensure_still_focused(target: &impl TypingTarget, window: ForegroundWindow) -> VaultResult<()> {
    if target.foreground() == Some(window) {
        Ok(())
    } else {
        Err(FOCUS_MOVED_MESSAGE.to_string())
    }
}

#[cfg(windows)]
struct WindowsKeyboard;

#[cfg(windows)]
impl WindowsKeyboard {
    fn send(
        events: Vec<windows_sys::Win32::UI::Input::KeyboardAndMouse::INPUT>,
    ) -> VaultResult<()> {
        use windows_sys::Win32::UI::Input::KeyboardAndMouse::{SendInput, INPUT};

        let sent = unsafe {
            SendInput(
                events.len() as u32,
                events.as_ptr(),
                std::mem::size_of::<INPUT>() as i32,
            )
        };
        if sent as usize == events.len() {
            Ok(())
        } else {
            Err(SEND_FAILED_MESSAGE.to_string())
        }
    }
}

#[cfg(windows)]
fn key_input(
    virtual_key: u16,
    scan_code: u16,
    flags: u32,
) -> windows_sys::Win32::UI::Input::KeyboardAndMouse::INPUT {
    use windows_sys::Win32::UI::Input::KeyboardAndMouse::{
        INPUT, INPUT_0, INPUT_KEYBOARD, KEYBDINPUT,
    };

    INPUT {
        r#type: INPUT_KEYBOARD,
        Anonymous: INPUT_0 {
            ki: KEYBDINPUT {
                wVk: virtual_key,
                wScan: scan_code,
                dwFlags: flags,
                time: 0,
                dwExtraInfo: 0,
            },
        },
    }
}

#[cfg(windows)]
impl TypingTarget for WindowsKeyboard {
    fn foreground(&self) -> Option<ForegroundWindow> {
        use windows_sys::Win32::UI::WindowsAndMessaging::{
            GetForegroundWindow, GetWindowThreadProcessId,
        };

        let window = unsafe { GetForegroundWindow() };
        if window.is_null() {
            return None;
        }
        let mut process_id = 0u32;
        unsafe { GetWindowThreadProcessId(window, &mut process_id) };
        Some(ForegroundWindow {
            window: window as isize,
            process_id,
        })
    }

    fn own_process_id(&self) -> u32 {
        unsafe { windows_sys::Win32::System::Threading::GetCurrentProcessId() }
    }

    fn type_text(&mut self, text: &[char]) -> VaultResult<()> {
        use windows_sys::Win32::UI::Input::KeyboardAndMouse::{KEYEVENTF_KEYUP, KEYEVENTF_UNICODE};

        let mut events = Vec::with_capacity(text.len() * 4);
        for character in text {
            let mut units = [0u16; 2];
            for unit in character.encode_utf16(&mut units).iter() {
                events.push(key_input(0, *unit, KEYEVENTF_UNICODE));
                events.push(key_input(0, *unit, KEYEVENTF_UNICODE | KEYEVENTF_KEYUP));
            }
        }
        Self::send(events)
    }

    fn press_tab(&mut self) -> VaultResult<()> {
        use windows_sys::Win32::UI::Input::KeyboardAndMouse::{KEYEVENTF_KEYUP, VK_TAB};

        Self::send(vec![
            key_input(VK_TAB, 0, 0),
            key_input(VK_TAB, 0, KEYEVENTF_KEYUP),
        ])
    }
}

#[cfg(windows)]
fn send_credentials(username: &str, password: &str) -> VaultResult<()> {
    type_credentials(&mut WindowsKeyboard, username, password)
}

#[cfg(not(windows))]
fn send_credentials(_username: &str, _password: &str) -> VaultResult<()> {
    Err("Auto-type is available on Windows only.".to_string())
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::collections::VecDeque;

    use super::*;
    use crate::commands::test_support::TestVault;
    use crate::release::PRESENCE_REQUIRED;

    const BROWSER: ForegroundWindow = ForegroundWindow {
        window: 100,
        process_id: 4100,
    };
    const CHAT: ForegroundWindow = ForegroundWindow {
        window: 200,
        process_id: 4200,
    };
    const SESAME: ForegroundWindow = ForegroundWindow {
        window: 300,
        process_id: 4300,
    };

    #[derive(Debug, PartialEq, Eq)]
    enum Sent {
        Text(String),
        Tab,
    }

    struct FakeTarget {
        foreground: RefCell<VecDeque<Option<ForegroundWindow>>>,
        last: RefCell<Option<ForegroundWindow>>,
        sent: Vec<Sent>,
        fail_sending_after: Option<usize>,
    }

    impl FakeTarget {
        fn staying_on(window: ForegroundWindow) -> Self {
            Self::with_foreground(vec![Some(window)])
        }

        fn with_foreground(sequence: Vec<Option<ForegroundWindow>>) -> Self {
            Self {
                foreground: RefCell::new(sequence.into()),
                last: RefCell::new(None),
                sent: Vec::new(),
                fail_sending_after: None,
            }
        }

        fn record(&mut self, sent: Sent) -> VaultResult<()> {
            if self
                .fail_sending_after
                .is_some_and(|limit| self.sent.len() >= limit)
            {
                return Err(SEND_FAILED_MESSAGE.to_string());
            }
            self.sent.push(sent);
            Ok(())
        }

        fn typed(&self) -> String {
            self.sent
                .iter()
                .map(|sent| match sent {
                    Sent::Text(text) => text.clone(),
                    Sent::Tab => "<tab>".to_string(),
                })
                .collect()
        }
    }

    impl TypingTarget for FakeTarget {
        fn foreground(&self) -> Option<ForegroundWindow> {
            let mut queue = self.foreground.borrow_mut();
            let mut last = self.last.borrow_mut();
            if queue.len() > 1 {
                *last = queue.pop_front().expect("queued foreground");
            } else {
                *last = *queue.front().expect("final foreground");
            }
            *last
        }

        fn own_process_id(&self) -> u32 {
            SESAME.process_id
        }

        fn type_text(&mut self, text: &[char]) -> VaultResult<()> {
            self.record(Sent::Text(text.iter().collect()))
        }

        fn press_tab(&mut self) -> VaultResult<()> {
            self.record(Sent::Tab)
        }
    }

    #[test]
    fn credentials_are_typed_in_order_in_chunks_of_eight_characters() {
        let mut target = FakeTarget::staying_on(BROWSER);

        type_credentials(&mut target, "fictional-user", "fictional-password-1").expect("typed");

        assert_eq!(
            target.sent,
            vec![
                Sent::Text("fictiona".to_string()),
                Sent::Text("l-user".to_string()),
                Sent::Tab,
                Sent::Text("fictiona".to_string()),
                Sent::Text("l-passwo".to_string()),
                Sent::Text("rd-1".to_string()),
            ]
        );
    }

    #[test]
    fn a_chunk_never_splits_a_character_outside_the_basic_plane() {
        let mut target = FakeTarget::staying_on(BROWSER);

        type_credentials(&mut target, "", "pass\u{1F511}word\u{1F511}x").expect("typed");

        assert_eq!(
            target.sent,
            vec![
                Sent::Text("pass\u{1F511}wor".to_string()),
                Sent::Text("d\u{1F511}x".to_string()),
            ]
        );
    }

    #[test]
    fn auto_type_refuses_to_type_into_sesame() {
        let mut target = FakeTarget::staying_on(SESAME);

        let error = type_credentials(&mut target, "fictional-user", "fictional-password")
            .expect_err("own window");

        assert_eq!(error, OWN_WINDOW_MESSAGE);
        assert!(target.sent.is_empty());
    }

    #[test]
    fn auto_type_refuses_when_no_window_has_focus() {
        let mut target = FakeTarget::with_foreground(vec![None]);

        let error = type_credentials(&mut target, "fictional-user", "fictional-password")
            .expect_err("no window");

        assert_eq!(error, NO_WINDOW_MESSAGE);
        assert!(target.sent.is_empty());
    }

    #[test]
    fn focus_moving_between_the_username_and_the_password_stops_typing() {
        let mut target = FakeTarget::with_foreground(vec![
            Some(BROWSER),
            Some(BROWSER),
            Some(BROWSER),
            Some(CHAT),
        ]);

        let error = type_credentials(&mut target, "fictional", "fictional-password")
            .expect_err("focus moved");

        assert_eq!(error, FOCUS_MOVED_MESSAGE);
        assert!(!target.typed().contains("fictional-password"));
        assert_eq!(
            target.sent,
            vec![
                Sent::Text("fictiona".to_string()),
                Sent::Text("l".to_string())
            ]
        );
    }

    #[test]
    fn focus_moving_partway_through_the_password_stops_after_the_chunk_in_flight() {
        let mut target = FakeTarget::with_foreground(vec![
            Some(BROWSER),
            Some(BROWSER),
            Some(BROWSER),
            Some(BROWSER),
            Some(BROWSER),
            Some(CHAT),
        ]);

        let error = type_credentials(&mut target, "fictional-user", "abcdefghijklmnopqrstuvwx")
            .expect_err("focus moved");

        assert_eq!(error, FOCUS_MOVED_MESSAGE);
        assert_eq!(
            target.typed(),
            "fictiona".to_string() + "l-user" + "<tab>" + "abcdefgh"
        );
    }

    #[test]
    fn a_switch_to_another_window_of_the_same_program_stops_typing() {
        let other_window = ForegroundWindow {
            window: 101,
            process_id: BROWSER.process_id,
        };
        let mut target =
            FakeTarget::with_foreground(vec![Some(BROWSER), Some(BROWSER), Some(other_window)]);

        let error = type_credentials(&mut target, "", "abcdefghijklmnop").expect_err("window");

        assert_eq!(error, FOCUS_MOVED_MESSAGE);
        assert_eq!(target.typed(), "abcdefgh");
    }

    #[test]
    fn a_moment_with_no_foreground_window_stops_typing() {
        let mut target =
            FakeTarget::with_foreground(vec![Some(BROWSER), Some(BROWSER), None, Some(BROWSER)]);

        let error = type_credentials(&mut target, "", "abcdefghijklmnop").expect_err("gap");

        assert_eq!(error, FOCUS_MOVED_MESSAGE);
        assert_eq!(target.typed(), "abcdefgh");
    }

    #[test]
    fn a_failed_send_stops_typing() {
        let mut target = FakeTarget::staying_on(BROWSER);
        target.fail_sending_after = Some(1);

        let error = type_credentials(&mut target, "fictional-user", "fictional-password")
            .expect_err("send failed");

        assert_eq!(error, SEND_FAILED_MESSAGE);
        assert_eq!(target.sent.len(), 1);
    }

    #[test]
    fn a_login_with_only_a_username_types_the_username_and_a_tab() {
        let mut target = FakeTarget::staying_on(BROWSER);

        type_credentials(&mut target, "fictional-user", "").expect("typed");

        assert_eq!(target.typed(), "fictiona".to_string() + "l-user" + "<tab>");
    }

    #[test]
    fn credentials_need_release_presence() {
        let vault = TestVault::with_login("login-a", "https://northwind.example");

        let error = login_credentials(&vault.state, &ReleasePresence::default(), "login-a")
            .expect_err("no presence");

        assert_eq!(error, PRESENCE_REQUIRED);
    }

    #[test]
    fn credentials_are_read_once_presence_is_granted() {
        let vault = TestVault::with_login("login-a", "https://northwind.example");
        let presence = ReleasePresence::default();
        {
            let session = vault.state.session.lock().expect("session lock");
            presence
                .grant_with_password(
                    session.as_ref().expect("session"),
                    vault.state.session_epoch(),
                    "fictional master password",
                )
                .expect("granted presence");
        }

        let (username, password) =
            login_credentials(&vault.state, &presence, "login-a").expect("credentials");

        assert_eq!(username.as_str(), "fictional-user");
        assert_eq!(password.as_str(), "fictional-stored-secret");
    }

    #[test]
    fn a_vault_change_after_presence_was_granted_requires_presence_again() {
        let vault = TestVault::with_login("login-a", "https://northwind.example");
        let presence = ReleasePresence::default();
        {
            let session = vault.state.session.lock().expect("session lock");
            presence
                .grant_with_password(
                    session.as_ref().expect("session"),
                    vault.state.session_epoch(),
                    "fictional master password",
                )
                .expect("granted presence");
        }
        vault.state.advance_session_epoch();

        let error = login_credentials(&vault.state, &presence, "login-a").expect_err("stale");

        assert_eq!(error, PRESENCE_REQUIRED);
    }

    #[test]
    fn an_unknown_login_is_refused_even_with_presence() {
        let vault = TestVault::with_login("login-a", "https://northwind.example");
        let presence = ReleasePresence::default();
        {
            let session = vault.state.session.lock().expect("session lock");
            presence
                .grant_with_password(
                    session.as_ref().expect("session"),
                    vault.state.session_epoch(),
                    "fictional master password",
                )
                .expect("granted presence");
        }

        assert!(login_credentials(&vault.state, &presence, "login-missing").is_err());
    }
}
