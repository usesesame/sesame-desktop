use std::collections::HashSet;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use zeroize::{Zeroize, Zeroizing};

use crate::crypto::{
    decrypt_bytes, default_kdf_params, derive_key, encrypt_bytes, serialize_payload,
};
use crate::platform::{protect_for_windows_profile, replace_file, unprotect_for_windows_profile};
use crate::snapshot::duplicate_key;
use crate::{
    payload_aad_for_file,
    throttle::{PersistedPinThrottle, PinAttemptGuard},
    UnlockedVault, VaultResult, PIN_WRAP_AAD, RECOVERY_WRAP_AAD, VAULT_FORMAT_VERSION, WRAP_AAD,
};
use crate::{
    types::*,
    util::{fill_random, generate_recovery_kit, random_id, unix_timestamp},
};

/// A PIN-enabled vault always has one; absence reads as tampering.
pub const PIN_THROTTLE_FILE: &str = "pin-throttle.sesame";

/// Every unlock path runs this before deriving a key from the file's parameters.
pub fn check_supported_vault_format(file: &VaultFile) -> VaultResult<()> {
    if file.format_version == 0
        || file.format_version > VAULT_FORMAT_VERSION
        || file.kdf.algorithm != "argon2id"
    {
        return Err("This vault uses a format Sesame does not understand yet.".into());
    }
    Ok(())
}

/// Absent reads as tampering, not a fresh count: setting a PIN always writes it.
pub fn read_pin_throttle_state_at(path: &Path) -> VaultResult<Option<PersistedPinThrottle>> {
    let bytes = match crate::util::read_file_with_limit(path, 16 * 1024) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) if error.kind() == std::io::ErrorKind::InvalidData => {
            return Err(
                "The PIN protection state is not valid. Use your master password instead.".into(),
            )
        }
        Err(_) => return Err("Sesame could not read the PIN protection state.".into()),
    };
    let mut plain = unprotect_for_windows_profile(&bytes).map_err(|_| {
        "Windows could not open the PIN protection state. Use your master password instead."
            .to_string()
    })?;
    let state = serde_json::from_slice::<PersistedPinThrottle>(&plain).map_err(|_| {
        "The PIN protection state is not valid. Use your master password instead.".to_string()
    });
    plain.zeroize();
    state.map(Some)
}

pub fn write_pin_throttle_state_at(path: &Path, guard: &PinAttemptGuard) -> VaultResult<()> {
    let state = guard.persisted();
    let mut plain = serde_json::to_vec(&state)
        .map_err(|_| "Sesame could not save the PIN protection state.".to_string())?;
    let protected = protect_for_windows_profile(&plain)?;
    plain.zeroize();
    write_export_file(path, &protected)
}

pub fn clear_pin_throttle_state_at(path: &Path) -> VaultResult<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err("Sesame could not clear the PIN protection state.".into()),
    }
}

pub fn write_vault_file(path: &Path, file: &VaultFile) -> VaultResult<()> {
    write_vault_file_inner(path, file, true)
}

/// No `.prev` copy: one would sit decryptable under the old password.
pub fn write_vault_file_without_previous(path: &Path, file: &VaultFile) -> VaultResult<()> {
    let previous = path.with_extension("sesame.prev");
    match fs::remove_file(previous) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err("Sesame could not remove the previous vault wrapper.".into()),
    }
    write_vault_file_inner(path, file, false)
}

fn write_vault_file_inner(path: &Path, file: &VaultFile, retain_previous: bool) -> VaultResult<()> {
    let parent = path
        .parent()
        .ok_or("Sesame could not find the local vault folder.")?;
    fs::create_dir_all(parent)
        .map_err(|_| "Sesame could not prepare its local vault folder.".to_string())?;
    let bytes = serde_json::to_vec(file)
        .map_err(|_| "Sesame could not save the local vault.".to_string())?;
    let tmp_path = path.with_extension("sesame.tmp");
    let mut tmp = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(&tmp_path)
        .map_err(|_| "Sesame could not prepare the local vault save.".to_string())?;
    tmp.write_all(&bytes)
        .and_then(|_| tmp.sync_all())
        .map_err(|_| "Sesame could not write the local vault.".to_string())?;
    drop(tmp);

    if retain_previous && path.exists() {
        let previous = path.with_extension("sesame.prev");
        fs::copy(path, previous)
            .map_err(|_| "Sesame could not protect the previous vault copy.".to_string())?;
    }
    replace_file(&tmp_path, path)
}

pub fn persist_session(session: &mut UnlockedVault) -> VaultResult<()> {
    if !session.setup_complete {
        return Err("Verify your recovery kit before using this vault.".into());
    }
    session.payload.revision += 1;
    let result = persist_session_internal(session, true);
    if result.is_err() {
        session.payload.revision -= 1;
    }
    result
}

pub fn persist_session_without_previous(session: &mut UnlockedVault) -> VaultResult<()> {
    if !session.setup_complete {
        return Err("Verify your recovery kit before using this vault.".into());
    }
    session.payload.revision += 1;
    let result = persist_session_internal(session, false);
    if result.is_err() {
        session.payload.revision -= 1;
    }
    result
}

fn persist_session_internal(session: &UnlockedVault, keep_previous: bool) -> VaultResult<()> {
    let payload_aad = payload_aad_for_file(VAULT_FORMAT_VERSION, session.setup_complete)?;
    let file = VaultFile {
        format_version: VAULT_FORMAT_VERSION,
        kdf: session.kdf.clone(),
        key_wrap: session.key_wrap.clone(),
        legacy_device_wrap: session.legacy_device_wrap.clone(),
        recovery_kdf: session.recovery_kdf.clone(),
        recovery_wrap: session.recovery_wrap.clone(),
        pin_wrap: session.pin_wrap.clone(),
        hello_wrap: session.hello_wrap.clone(),
        setup_complete: session.setup_complete,
        payload: encrypt_bytes(
            &session.key,
            &serialize_payload(&session.payload)?,
            payload_aad,
        )?,
    };
    if keep_previous {
        write_vault_file(&session.path, &file)
    } else {
        write_vault_file_without_previous(&session.path, &file)
    }
}

fn pending_setup_is_empty(session: &UnlockedVault) -> bool {
    session.payload.folders.is_empty()
        && session.payload.entries.is_empty()
        && session.payload.identities.is_empty()
        && session.payload.secure_notes.is_empty()
        && session.payload.cards.is_empty()
        && session.payload.wifi_networks.is_empty()
        && session.payload.ssh_keys.is_empty()
        && session.payload.software_licenses.is_empty()
        && session.payload.documents.is_empty()
        && session.payload.custom_records.is_empty()
        && session.payload.trash.is_empty()
        && session.payload.history.is_empty()
}

/// Replaces the abandoned kit; only the new one can finish or recover the pending vault.
pub fn resume_recovery_setup_for_session(session: &mut UnlockedVault) -> VaultResult<String> {
    if session.setup_complete {
        return Err("This vault has already finished recovery setup.".into());
    }
    if !pending_setup_is_empty(session) {
        return Err("This unfinished vault contains data and cannot restart setup safely.".into());
    }

    let recovery_kit = Zeroizing::new(generate_recovery_kit());
    let recovery_kit_for_display = recovery_kit.to_string();
    let recovery_kdf = default_kdf_params();
    let recovery_wrapping_key = Zeroizing::new(derive_key(&recovery_kit, &recovery_kdf)?);
    let recovery_wrap = encrypt_bytes(
        &recovery_wrapping_key,
        session.key.as_slice(),
        RECOVERY_WRAP_AAD,
    )?;

    let previous_kdf = session.recovery_kdf.replace(recovery_kdf);
    let previous_wrap = session.recovery_wrap.replace(recovery_wrap);
    session.payload.revision += 1;
    if let Err(error) = persist_session_internal(session, false) {
        session.payload.revision -= 1;
        session.recovery_kdf = previous_kdf;
        session.recovery_wrap = previous_wrap;
        return Err(error);
    }
    Ok(recovery_kit_for_display)
}

/// The kit must authenticate before the completion bit, which selects the payload AEAD, changes.
pub fn complete_recovery_setup_for_session(
    session: &mut UnlockedVault,
    recovery_kit: &str,
) -> VaultResult<()> {
    if session.setup_complete {
        return Err("This vault has already finished recovery setup.".into());
    }
    let recovery_kdf = session
        .recovery_kdf
        .as_ref()
        .ok_or("This vault does not have a recovery wrapper.")?;
    let recovery_wrap = session
        .recovery_wrap
        .as_ref()
        .ok_or("This vault does not have a recovery wrapper.")?;
    let normalized = Zeroizing::new(recovery_kit.trim().to_ascii_uppercase());
    let recovery_wrapping_key = Zeroizing::new(derive_key(&normalized, recovery_kdf)?);
    let mut recovered = decrypt_bytes(&recovery_wrapping_key, recovery_wrap, RECOVERY_WRAP_AAD)
        .map_err(|_| "That recovery kit is not correct.".to_string())?;
    let matches = recovered.as_slice() == session.key.as_slice();
    recovered.zeroize();
    if !matches {
        return Err("That recovery kit is not correct.".into());
    }

    session.setup_complete = true;
    if let Err(error) = persist_session(session) {
        session.setup_complete = false;
        return Err(error);
    }
    Ok(())
}

/// Atomic rotation of password, kit, and data key; PIN and Hello wraps are dropped because they protect the retired key.
pub fn rotate_master_password_for_session(
    session: &mut UnlockedVault,
    current_password: &str,
    new_password: &str,
) -> VaultResult<String> {
    if new_password.chars().count() < 12 {
        return Err("Use a new master password with at least 12 characters.".into());
    }

    let current_wrapping_key = Zeroizing::new(derive_key(current_password, &session.kdf)?);
    let mut confirmed_key = decrypt_bytes(&current_wrapping_key, &session.key_wrap, WRAP_AAD)
        .map_err(|_| "Your current master password is not correct.".to_string())?;
    let matches_session = confirmed_key.as_slice() == session.key.as_slice();
    confirmed_key.zeroize();
    if !matches_session {
        return Err("Your current master password is not correct.".into());
    }

    let mut new_vault_key = Zeroizing::new([0_u8; 32]);
    fill_random(&mut *new_vault_key);

    let new_kdf = default_kdf_params();
    let new_wrapping_key = Zeroizing::new(derive_key(new_password, &new_kdf)?);
    let new_key_wrap = encrypt_bytes(&new_wrapping_key, &*new_vault_key, WRAP_AAD)?;

    let mut recovery_kit = generate_recovery_kit();
    let recovery_kit_for_display = recovery_kit.clone();
    let new_recovery_kdf = default_kdf_params();
    let recovery_wrapping_key = Zeroizing::new(derive_key(&recovery_kit, &new_recovery_kdf)?);
    recovery_kit.zeroize();
    let new_recovery_wrap =
        encrypt_bytes(&recovery_wrapping_key, &*new_vault_key, RECOVERY_WRAP_AAD)?;

    let previous_key = std::mem::replace(&mut session.key, new_vault_key);
    let previous_kdf = std::mem::replace(&mut session.kdf, new_kdf);
    let previous_key_wrap = std::mem::replace(&mut session.key_wrap, new_key_wrap);
    let previous_recovery_kdf =
        std::mem::replace(&mut session.recovery_kdf, Some(new_recovery_kdf));
    let previous_recovery_wrap =
        std::mem::replace(&mut session.recovery_wrap, Some(new_recovery_wrap));
    let previous_pin_wrap = session.pin_wrap.take();
    let previous_hello_wrap = session.hello_wrap.take();

    if let Err(error) = persist_session_without_previous(session) {
        session.key = previous_key;
        session.kdf = previous_kdf;
        session.key_wrap = previous_key_wrap;
        session.recovery_kdf = previous_recovery_kdf;
        session.recovery_wrap = previous_recovery_wrap;
        session.pin_wrap = previous_pin_wrap;
        session.hello_wrap = previous_hello_wrap;
        return Err(error);
    }
    if let Some(old) = previous_hello_wrap {
        crate::windows_hello::delete_key(&old.key_name);
    }
    Ok(recovery_kit_for_display)
}

pub fn set_pin_for_session(session: &mut UnlockedVault, pin: &str) -> VaultResult<()> {
    validate_new_unlock_pin(pin)?;

    let mut pepper = [0_u8; 32];
    fill_random(&mut pepper);
    let protected_pepper = URL_SAFE_NO_PAD.encode(protect_for_windows_profile(&pepper)?);
    let kdf = default_kdf_params();
    let secret = Zeroizing::new(format!("{}:{}", pin, URL_SAFE_NO_PAD.encode(pepper)));
    pepper.zeroize();
    let wrapping_key = Zeroizing::new(derive_key(secret.as_str(), &kdf)?);
    let key_wrap = encrypt_bytes(&wrapping_key, session.key.as_slice(), PIN_WRAP_AAD)?;

    let previous = session.pin_wrap.replace(PinWrap {
        kdf,
        protected_pepper,
        key_wrap,
    });
    if let Err(error) = persist_session(session) {
        session.pin_wrap = previous;
        return Err(error);
    }
    Ok(())
}

pub fn remove_pin_for_session(session: &mut UnlockedVault) -> VaultResult<()> {
    let previous = session.pin_wrap.take();
    if let Err(error) = persist_session(session) {
        session.pin_wrap = previous;
        return Err(error);
    }
    Ok(())
}

/// The old KSP key is deleted only after the file no longer references it.
pub fn set_hello_for_session(session: &mut UnlockedVault, wrap: HelloWrap) -> VaultResult<()> {
    let previous = session.hello_wrap.replace(wrap);
    if let Err(error) = persist_session(session) {
        session.hello_wrap = previous;
        return Err(error);
    }
    if let Some(old) = previous {
        crate::windows_hello::delete_key(&old.key_name);
    }
    Ok(())
}

/// KSP key deleted only after the vault remains usable by password or kit.
pub fn remove_hello_for_session(session: &mut UnlockedVault) -> VaultResult<()> {
    let previous = session.hello_wrap.take();
    if let Err(error) = persist_session(session) {
        session.hello_wrap = previous;
        return Err(error);
    }
    if let Some(old) = previous {
        crate::windows_hello::delete_key(&old.key_name);
    }
    Ok(())
}

pub fn validate_unlock_pin(pin: &str) -> VaultResult<()> {
    if pin.len() != 6 || !pin.bytes().all(|value| value.is_ascii_digit()) {
        return Err("Use a 6-digit PIN.".into());
    }
    Ok(())
}

/// Only for choosing a PIN. Unlocking still accepts whatever was already set,
/// so tightening this never locks anyone out of a vault they already have.
pub fn validate_new_unlock_pin(pin: &str) -> VaultResult<()> {
    validate_unlock_pin(pin)?;
    let digits: Vec<u8> = pin.bytes().map(|value| value - b'0').collect();
    if digits.windows(2).all(|pair| pair[0] == pair[1]) {
        return Err("Choose a PIN that is not the same digit six times.".into());
    }
    let ascending = digits.windows(2).all(|pair| pair[1] == pair[0] + 1);
    let descending = digits.windows(2).all(|pair| pair[0] == pair[1] + 1);
    if ascending || descending {
        return Err("Choose a PIN that is not six digits in a row.".into());
    }
    Ok(())
}

pub fn derive_pin_wrapping_key(pin: &str, pin_wrap: &PinWrap) -> VaultResult<[u8; 32]> {
    validate_unlock_pin(pin)?;
    let protected_pepper = URL_SAFE_NO_PAD
        .decode(&pin_wrap.protected_pepper)
        .map_err(|_| "The PIN unlock data is invalid. Use another unlock method.".to_string())?;
    let mut pepper = unprotect_for_windows_profile(&protected_pepper)
        .map_err(|_| "Windows could not open the PIN unlock data for this profile.".to_string())?;
    let secret = Zeroizing::new(format!("{}:{}", pin, URL_SAFE_NO_PAD.encode(&pepper)));
    pepper.zeroize();
    derive_key(secret.as_str(), &pin_wrap.kdf)
}

pub fn commit_payload_change(
    session: &mut UnlockedVault,
    next_payload: VaultPayload,
) -> VaultResult<()> {
    let previous_payload = std::mem::replace(&mut session.payload, next_payload);
    if let Err(error) = persist_session(session) {
        session.payload = previous_payload;
        return Err(error);
    }
    Ok(())
}

pub fn payload_without_login(payload: &VaultPayload, id: &str) -> VaultResult<VaultPayload> {
    if !payload.entries.iter().any(|entry| entry.id == id) {
        return Err("That saved login no longer exists.".into());
    }
    let mut next_payload = payload.clone();
    next_payload.entries.retain(|entry| entry.id != id);
    Ok(next_payload)
}

pub fn payload_with_login_folders(
    payload: &VaultPayload,
    ids: &HashSet<String>,
    folder: &str,
) -> VaultResult<VaultPayload> {
    let mut next_payload = payload.clone();
    let folder_id = ensure_folder_named(&mut next_payload, folder)?;
    let now = unix_timestamp();
    for id in ids {
        let item = next_payload
            .item_metadata_mut(id)
            .ok_or("One of the selected items no longer exists.")?;
        item.set_item_folder_id(folder_id.clone());
        item.mark_item_changed(now);
    }
    Ok(next_payload)
}

pub fn payload_with_item_folder_id(
    payload: &VaultPayload,
    ids: &HashSet<String>,
    folder_id: Option<&str>,
) -> VaultResult<VaultPayload> {
    let mut next_payload = payload.clone();
    let folder_id = folder_id.map(str::trim).filter(|id| !id.is_empty());
    if folder_id.is_some_and(|id| !next_payload.folders.iter().any(|folder| folder.id == id)) {
        return Err("That folder no longer exists.".into());
    }
    let now = unix_timestamp();
    for id in ids {
        let item = next_payload
            .item_metadata_mut(id)
            .ok_or("One of the selected items no longer exists.")?;
        item.set_item_folder_id(folder_id.map(str::to_string));
        item.mark_item_changed(now);
    }
    Ok(next_payload)
}

/// A supplied ID must already exist; callers never create arbitrary IDs.
pub fn materialize_entry_folder(
    payload: &mut VaultPayload,
    entry: &mut VaultEntry,
) -> VaultResult<()> {
    if let Some(folder_id) = entry
        .folder_id
        .as_deref()
        .map(str::trim)
        .filter(|id| !id.is_empty())
    {
        if !payload.folders.iter().any(|folder| folder.id == folder_id) {
            return Err("That folder no longer exists.".into());
        }
        entry.folder_id = Some(folder_id.to_string());
        entry.folder.clear();
        return Ok(());
    }

    entry.folder_id = ensure_folder_named(payload, &entry.folder)?;
    entry.folder.clear();
    Ok(())
}

pub fn ensure_folder_named(payload: &mut VaultPayload, name: &str) -> VaultResult<Option<String>> {
    let name = name.trim();
    if name.is_empty() {
        return Ok(None);
    }
    if name.chars().count() > 100 {
        return Err("Keep folder names under 100 characters.".into());
    }
    if let Some(folder) = payload
        .folders
        .iter()
        .find(|folder| folder.name.eq_ignore_ascii_case(name))
    {
        return Ok(Some(folder.id.clone()));
    }
    let id = random_id();
    payload.folders.push(Folder {
        id: id.clone(),
        name: name.to_string(),
    });
    Ok(Some(id))
}

pub fn create_folder_in_payload(payload: &VaultPayload, name: &str) -> VaultResult<VaultPayload> {
    let mut next_payload = payload.clone();
    let before = next_payload.folders.len();
    ensure_folder_named(&mut next_payload, name)?;
    if next_payload.folders.len() == before {
        return Err("A folder with that name already exists.".into());
    }
    Ok(next_payload)
}

pub fn rename_folder_in_payload(
    payload: &VaultPayload,
    folder_id: &str,
    name: &str,
) -> VaultResult<VaultPayload> {
    let name = name.trim();
    if name.is_empty() {
        return Err("Give this folder a name.".into());
    }
    if name.chars().count() > 100 {
        return Err("Keep folder names under 100 characters.".into());
    }
    if payload
        .folders
        .iter()
        .any(|folder| folder.id != folder_id && folder.name.eq_ignore_ascii_case(name))
    {
        return Err("A folder with that name already exists.".into());
    }
    let mut next_payload = payload.clone();
    let folder = next_payload
        .folders
        .iter_mut()
        .find(|folder| folder.id == folder_id)
        .ok_or("That folder no longer exists.")?;
    folder.name = name.to_string();
    Ok(next_payload)
}

pub fn delete_folder_from_payload(
    payload: &VaultPayload,
    folder_id: &str,
) -> VaultResult<VaultPayload> {
    if !payload.folders.iter().any(|folder| folder.id == folder_id) {
        return Err("That folder no longer exists.".into());
    }
    let mut next_payload = payload.clone();
    next_payload.folders.retain(|folder| folder.id != folder_id);
    let now = unix_timestamp();
    let filed: Vec<String> = next_payload
        .item_views()
        .iter()
        .filter(|item| item.metadata().item_folder_id() == Some(folder_id))
        .map(|item| item.id().to_string())
        .collect();
    for id in filed {
        if let Some(item) = next_payload.item_metadata_mut(&id) {
            item.set_item_folder_id(None);
            item.mark_item_changed(now);
        }
    }
    Ok(next_payload)
}

pub fn payload_with_item_favourite(
    payload: &VaultPayload,
    id: &str,
    favourite: bool,
) -> VaultResult<VaultPayload> {
    let mut next_payload = payload.clone();
    let item = next_payload
        .item_metadata_mut(id)
        .ok_or("That saved item no longer exists.")?;
    item.set_item_favourite(favourite);
    item.mark_item_changed(unix_timestamp());
    Ok(next_payload)
}

pub fn payload_with_recorded_item_use(
    payload: &VaultPayload,
    id: &str,
) -> VaultResult<VaultPayload> {
    let mut next_payload = payload.clone();
    let now = unix_timestamp();
    let item = next_payload
        .item_metadata_mut(id)
        .ok_or("That saved item no longer exists.")?;
    item.set_item_last_used_at(Some(now));
    item.mark_item_changed(now);
    Ok(next_payload)
}

pub fn merged_duplicate_payload(
    payload: &VaultPayload,
    keep_id: &str,
    remove_ids: &[String],
    choices: &MergeChoices,
) -> VaultResult<VaultPayload> {
    if remove_ids.is_empty() {
        return Err("Choose at least one duplicate to merge.".into());
    }
    if remove_ids.len() > payload.entries.len() {
        return Err("Too many duplicate logins were selected.".into());
    }

    let mut selected_ids = HashSet::new();
    for id in remove_ids {
        if id.is_empty() {
            return Err("One of the selected duplicate logins is invalid.".into());
        }
        if id == keep_id {
            return Err("The login being kept cannot also be removed.".into());
        }
        if !selected_ids.insert(id.as_str()) {
            return Err("The same duplicate login was selected more than once.".into());
        }
    }

    let kept = payload
        .entries
        .iter()
        .find(|entry| entry.id == keep_id)
        .ok_or("The login you chose to keep no longer exists.")?;
    let kept_key = duplicate_key(kept);
    if kept_key == ":" {
        return Err(
            "These logins need a website or username before they can be merged safely.".into(),
        );
    }

    let mut removed_entries = Vec::with_capacity(remove_ids.len());
    for id in remove_ids {
        let entry = payload
            .entries
            .iter()
            .find(|entry| entry.id == *id)
            .ok_or("One of the duplicate logins no longer exists.")?;
        if duplicate_key(entry) != kept_key {
            return Err("Only logins for the same website and username can be merged.".into());
        }
        removed_entries.push(entry);
    }

    let group: Vec<&VaultEntry> = std::iter::once(kept)
        .chain(removed_entries.iter().copied())
        .collect();
    // A choice must name an entry inside this group: the merge never pulls from an unrelated login.
    let chosen = |choice: &Option<String>| -> VaultResult<Option<&VaultEntry>> {
        match choice.as_deref().map(str::trim).filter(|id| !id.is_empty()) {
            None => Ok(None),
            Some(id) => group
                .iter()
                .copied()
                .find(|entry| entry.id == id)
                .map(Some)
                .ok_or_else(|| {
                    "A field was taken from a login that is not part of this merge.".to_string()
                }),
        }
    };

    let mut merged = kept.clone();
    if let Some(source) = chosen(&choices.title)? {
        merged.title = source.title.clone();
    }
    if let Some(source) = chosen(&choices.url)? {
        merged.url = source.url.clone();
    }
    if let Some(source) = chosen(&choices.username)? {
        merged.username = source.username.clone();
    }
    if let Some(source) = chosen(&choices.email)? {
        merged.email = source.email.clone();
    }
    if let Some(source) = chosen(&choices.password)? {
        merged.password = source.password.clone();
    }
    if let Some(source) = chosen(&choices.totp)? {
        merged.totp = source.totp.clone();
    }
    if let Some(source) = chosen(&choices.notes)? {
        merged.notes = source.notes.clone();
    }
    if let Some(source) = chosen(&choices.recovery_email)? {
        merged.recovery_email = source.recovery_email.clone();
    }
    if let Some(source) = chosen(&choices.recovery_phone)? {
        merged.recovery_phone = source.recovery_phone.clone();
    }
    let chosen_backup_codes = chosen(&choices.backup_codes)?;
    if let Some(source) = chosen_backup_codes {
        merged.backup_codes = source.backup_codes.clone();
    }

    // Undecided fields keep the survivor's value, blanks filled from the first duplicate.
    for source in &removed_entries {
        if choices.title.is_none() {
            fill_string_if_blank(&mut merged.title, &source.title);
        }
        if choices.url.is_none() {
            fill_string_if_blank(&mut merged.url, &source.url);
        }
        if choices.username.is_none() {
            fill_string_if_blank(&mut merged.username, &source.username);
        }
        if choices.email.is_none() {
            fill_string_if_blank(&mut merged.email, &source.email);
        }
        if choices.password.is_none() {
            fill_string_if_blank(&mut merged.password, &source.password);
        }
        if merged.folder_id.is_none() {
            merged.folder_id = source.folder_id.clone();
        }
        if choices.totp.is_none() {
            fill_option_if_blank(&mut merged.totp, &source.totp);
        }
        if !merged.recovery_not_applicable {
            if choices.recovery_email.is_none() {
                fill_option_if_blank(&mut merged.recovery_email, &source.recovery_email);
            }
            if choices.recovery_phone.is_none() {
                fill_option_if_blank(&mut merged.recovery_phone, &source.recovery_phone);
            }
            if chosen_backup_codes.is_none() {
                merged
                    .backup_codes
                    .extend(source.backup_codes.iter().cloned());
            }
        }
        if choices.notes.is_none() {
            fill_option_if_blank(&mut merged.notes, &source.notes);
        }
    }
    if merged.recovery_not_applicable {
        merged.backup_codes.clear();
    }
    merged.backup_codes = unique_backup_codes(merged.backup_codes);
    merged.updated_at = unix_timestamp();
    merged.revision = merged.revision.saturating_add(1);

    let mut next_payload = payload.clone();
    next_payload
        .entries
        .retain(|entry| !selected_ids.contains(entry.id.as_str()));
    let kept_entry = next_payload
        .entries
        .iter_mut()
        .find(|entry| entry.id == keep_id)
        .ok_or("The login you chose to keep no longer exists.")?;
    *kept_entry = merged;
    Ok(next_payload)
}

fn fill_string_if_blank(target: &mut String, source: &str) {
    if target.trim().is_empty() && !source.trim().is_empty() {
        *target = source.to_string();
    }
}

fn fill_option_if_blank(target: &mut Option<String>, source: &Option<String>) {
    let target_is_blank = target
        .as_deref()
        .map(str::trim)
        .unwrap_or_default()
        .is_empty();
    if target_is_blank {
        if let Some(source) = source.as_deref().filter(|value| !value.trim().is_empty()) {
            *target = Some(source.to_string());
        }
    }
}

fn unique_backup_codes(codes: Vec<String>) -> Vec<String> {
    let mut seen = HashSet::new();
    codes
        .into_iter()
        .map(|code| code.trim().to_string())
        .filter(|code| !code.is_empty() && seen.insert(code.clone()))
        .collect()
}

pub fn write_export_file(destination: &Path, bytes: &[u8]) -> VaultResult<()> {
    atomic_replace(destination, bytes)
}

pub fn atomic_replace(destination: &Path, bytes: &[u8]) -> VaultResult<()> {
    let parent = destination
        .parent()
        .ok_or("Sesame could not find the destination folder.")?;
    let name = destination
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or("Sesame could not read the destination file name.")?;
    let temporary = parent.join(format!(".{name}.{}.tmp", random_id()));
    let mut file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(&temporary)
        .map_err(|_| "Sesame could not prepare the temporary file.".to_string())?;
    if file.write_all(bytes).and_then(|_| file.sync_all()).is_err() {
        drop(file);
        let _ = fs::remove_file(&temporary);
        return Err("Sesame could not write the file.".into());
    }
    drop(file);
    if let Err(error) = replace_file(&temporary, destination) {
        let _ = fs::remove_file(&temporary);
        return Err(error);
    }
    Ok(())
}
