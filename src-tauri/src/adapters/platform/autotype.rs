//! Auto-type: sends a login's credentials as keystrokes to the foreground window.
//! Never targets a window by name; the caller must let the person switch focus first.

use tauri::State;
use zeroize::Zeroize;

use crate::vault::{VaultPayload, VaultResult, VaultState};

fn credentials_for(payload: &VaultPayload, id: &str) -> VaultResult<(String, String)> {
    let entry = payload
        .entries
        .iter()
        .find(|entry| entry.id == id)
        .ok_or("That saved login no longer exists.")?;
    if entry.username.is_empty() && entry.password.is_empty() {
        return Err("This login has nothing saved to type.".to_string());
    }
    Ok((entry.username.clone(), entry.password.clone()))
}

#[tauri::command]
pub fn auto_type(id: String, state: State<'_, VaultState>) -> VaultResult<()> {
    let (mut username, mut password) = {
        let session = state
            .session
            .lock()
            .map_err(|_| "Sesame could not read the vault session.".to_string())?;
        let session = session.as_ref().ok_or("Unlock your vault first.")?;
        credentials_for(&session.payload, &id)?
    };
    let result = send_credentials(&username, &password);
    username.zeroize();
    password.zeroize();
    result
}

#[cfg(windows)]
fn send_credentials(username: &str, password: &str) -> VaultResult<()> {
    use windows_sys::Win32::System::Threading::GetCurrentProcessId;
    use windows_sys::Win32::UI::Input::KeyboardAndMouse::{
        SendInput, INPUT, INPUT_0, INPUT_KEYBOARD, KEYBDINPUT, KEYEVENTF_KEYUP, KEYEVENTF_UNICODE,
        VK_TAB,
    };
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        GetForegroundWindow, GetWindowThreadProcessId,
    };

    fn key_input(virtual_key: u16, scan_code: u16, flags: u32) -> INPUT {
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

    fn push_text(events: &mut Vec<INPUT>, text: &str) {
        for unit in text.encode_utf16() {
            events.push(key_input(0, unit, KEYEVENTF_UNICODE));
            events.push(key_input(0, unit, KEYEVENTF_UNICODE | KEYEVENTF_KEYUP));
        }
    }

    // Never type into Sesame's own window: a password could land in a search box.
    let foreground = unsafe { GetForegroundWindow() };
    if foreground.is_null() {
        return Err(
            "Sesame could not find a focused window to type into. Click the target field first."
                .to_string(),
        );
    }
    let mut foreground_process_id = 0u32;
    unsafe { GetWindowThreadProcessId(foreground, &mut foreground_process_id) };
    if foreground_process_id == unsafe { GetCurrentProcessId() } {
        return Err(
            "Switch to the window you want to fill in, then try auto-type again.".to_string(),
        );
    }

    let mut events = Vec::new();
    if !username.is_empty() {
        push_text(&mut events, username);
        events.push(key_input(VK_TAB, 0, 0));
        events.push(key_input(VK_TAB, 0, KEYEVENTF_KEYUP));
    }
    if !password.is_empty() {
        push_text(&mut events, password);
    }

    let sent = unsafe {
        SendInput(
            events.len() as u32,
            events.as_ptr(),
            std::mem::size_of::<INPUT>() as i32,
        )
    };
    if sent as usize != events.len() {
        return Err(
            "Sesame could not finish typing. The target window may be running with higher privileges."
                .to_string(),
        );
    }
    Ok(())
}

#[cfg(not(windows))]
fn send_credentials(_username: &str, _password: &str) -> VaultResult<()> {
    Err("Auto-type is available on Windows only.".to_string())
}
