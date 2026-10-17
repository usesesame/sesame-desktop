use std::sync::OnceLock;

use super::checkpoint::Checkpoint;
use super::devicelist::{DeviceList, DeviceListEntry};
use super::engine::ServedHeader;
use super::header::{verify_header, Header};
use super::keys::{open_vault_key, EncryptionKeypair};
use super::pake;
use super::request::KeyPackageV3;

const FIXTURE: &str = include_str!("../../contracts/sync/v3/v3-fixture.json");
const VAULT: &str = "vaultAAAAAAAAAAAA01";

fn fixed_list() -> &'static DeviceList {
    static LIST: OnceLock<DeviceList> = OnceLock::new();
    LIST.get_or_init(|| {
        let fixture: serde_json::Value = serde_json::from_str(FIXTURE).unwrap_or_default();
        let entries: Vec<DeviceListEntry> = fixture["chain"]
            .as_array()
            .map(|items| {
                items
                    .iter()
                    .filter_map(|item| serde_json::from_value(item["entry"].clone()).ok())
                    .collect()
            })
            .unwrap_or_default();
        DeviceList::verify(&entries).unwrap_or_default()
    })
}

pub fn envelope(data: &[u8]) -> Option<Header> {
    if let Ok(served) = serde_json::from_slice::<ServedHeader>(data) {
        let _ = served.accepted_at_unix();
        let _ = served.header.digest();
    }
    if let Ok(checkpoint) = serde_json::from_slice::<Checkpoint>(data) {
        let _ = checkpoint.validate();
        let _ = checkpoint.signing_payload();
    }
    let header = serde_json::from_slice::<Header>(data).ok()?;
    let _ = header.validate();
    let _ = header.digest();
    let _ = header.aad();
    let _ = header.verify_ciphertext(data);
    verify_header(fixed_list(), None, &header)
        .ok()
        .map(|()| header)
}

pub fn key_package(data: &[u8]) -> Option<Vec<u8>> {
    if let Ok(package) = serde_json::from_slice::<KeyPackageV3>(data) {
        let _ = package.validate();
        let _ = package.digest();
    }
    let recipient = EncryptionKeypair::from_secret_bytes([7u8; 32]);
    open_vault_key(data, &recipient, VAULT).ok()
}

pub fn device_list(data: &[u8]) -> Option<usize> {
    if let Ok(entry) = serde_json::from_slice::<DeviceListEntry>(data) {
        let _ = entry.validate();
        let _ = entry.digest();
    }
    let entries = serde_json::from_slice::<Vec<DeviceListEntry>>(data).ok()?;
    DeviceList::verify(&entries)
        .ok()
        .map(|list| list.current().len())
}

pub fn pairing_message(data: &[u8]) {
    let _ = pake::answer("ABCDEFGHJK", data, b"approver");
}
