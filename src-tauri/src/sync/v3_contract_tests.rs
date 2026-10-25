use ed25519_dalek::SigningKey;
use serde::Deserialize;

use super::canonical::ProofKind;
use super::checkpoint::Checkpoint;
use super::devicelist::{DeviceList, DeviceListEntry, ENTRY_ADD, ENTRY_REMOVE};
use super::header::{verify_header, verify_header_chain, Header};
use super::request::{KeyPackageV3, Receipt, RequestSignature};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct FixtureEntry {
    entry: DeviceListEntry,
    signing_payload_hex: String,
    digest: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct FixtureHeader {
    header: Header,
    signing_payload_hex: String,
    digest: String,
    aad_hex: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct FixtureRequest {
    method: String,
    target: String,
    body: String,
    token: String,
    timestamp: u64,
    nonce: String,
    signing_payload_hex: String,
    signature: String,
    signer_key: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct FixtureReceipt {
    vault_id: String,
    revision: u64,
    header_digest: String,
    vault_epoch: u64,
    accepted_at: u64,
    signing_payload_hex: String,
    signature: String,
    signer_key: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct FixtureKeyPackage {
    vault_id: String,
    sender_device_id: String,
    recipient_device_id: String,
    vault_epoch: u64,
    entry_digest: String,
    ciphertext: String,
    signature: String,
    signing_payload_hex: String,
    digest: String,
    signer_key: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct FixtureCheckpoint {
    checkpoint: Checkpoint,
    signing_payload_hex: String,
    signer_key: String,
}

#[derive(Deserialize)]
struct BrokenChain {
    name: String,
    chain: Vec<DeviceListEntry>,
}

#[derive(Deserialize)]
struct BrokenHeader {
    name: String,
    previous: Option<Header>,
    header: Header,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Fixture {
    chain: Vec<FixtureEntry>,
    removal_chain: Vec<FixtureEntry>,
    key_chain: Vec<FixtureEntry>,
    headers: Vec<FixtureHeader>,
    request: FixtureRequest,
    receipt: FixtureReceipt,
    key_package: FixtureKeyPackage,
    checkpoint: FixtureCheckpoint,
    broken_chains: Vec<BrokenChain>,
    broken_headers: Vec<BrokenHeader>,
    seed_hex_by_device: std::collections::HashMap<String, String>,
}

fn fixture() -> Fixture {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("contracts")
        .join("sync")
        .join("v3")
        .join("v3-fixture.json");
    let bytes = std::fs::read(path).expect("read the v3 fixture");
    serde_json::from_slice(&bytes).expect("parse the v3 fixture")
}

fn unhex(value: &str) -> Vec<u8> {
    (0..value.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&value[index..index + 2], 16).expect("hex"))
        .collect()
}

fn key_for(fixture: &Fixture, device: &str) -> SigningKey {
    let seed: [u8; 32] = unhex(&fixture.seed_hex_by_device[device])
        .try_into()
        .expect("seed length");
    SigningKey::from_bytes(&seed)
}

fn entries(items: &[FixtureEntry]) -> Vec<DeviceListEntry> {
    items.iter().map(|item| item.entry.clone()).collect()
}

#[test]
fn every_device_list_entry_matches_the_go_bytes_and_digest() {
    let fixture = fixture();
    for item in fixture
        .chain
        .iter()
        .chain(fixture.removal_chain.iter())
        .chain(fixture.key_chain.iter())
    {
        assert_eq!(
            item.entry.signing_payload(),
            unhex(&item.signing_payload_hex)
        );
        assert_eq!(item.entry.digest(), item.digest);
    }
}

#[test]
fn the_go_device_lists_verify() {
    let fixture = fixture();
    let list = DeviceList::verify(&entries(&fixture.chain)).expect("chain");
    assert_eq!((list.head(), list.epoch(), list.current().len()), (3, 1, 3));
    let removal = DeviceList::verify(&entries(&fixture.removal_chain)).expect("removal chain");
    assert_eq!(
        (removal.head(), removal.epoch(), removal.current().len()),
        (4, 2, 2)
    );
}

#[test]
fn every_broken_device_list_is_refused() {
    for broken in fixture().broken_chains {
        assert!(
            DeviceList::verify(&broken.chain).is_err(),
            "{} verified",
            broken.name
        );
    }
}

#[test]
fn every_header_matches_the_go_bytes_digest_and_aad() {
    let fixture = fixture();
    for item in &fixture.headers {
        assert_eq!(
            item.header.signing_payload(),
            unhex(&item.signing_payload_hex)
        );
        assert_eq!(item.header.digest(), item.digest);
        assert_eq!(item.header.aad(), unhex(&item.aad_hex));
    }
}

#[test]
fn the_go_header_chain_verifies_and_every_broken_header_is_refused() {
    let fixture = fixture();
    let list = DeviceList::verify(&entries(&fixture.chain)).expect("chain");
    let headers: Vec<Header> = fixture
        .headers
        .iter()
        .map(|item| item.header.clone())
        .collect();
    verify_header_chain(&list, None, &headers).expect("header chain");
    for broken in &fixture.broken_headers {
        assert!(
            verify_header(&list, broken.previous.as_ref(), &broken.header).is_err(),
            "{} verified",
            broken.name
        );
    }
}

#[test]
fn a_header_chain_failure_reports_that_devices_disagree_about_history() {
    let fixture = fixture();
    let list = DeviceList::verify(&entries(&fixture.chain)).expect("chain");
    let broken = &fixture.broken_headers[0];
    let error = verify_header(&list, broken.previous.as_ref(), &broken.header).unwrap_err();
    assert_eq!(error.kind, ProofKind::History);
    assert!(error.to_string().contains("disagree about history"));
}

#[test]
fn the_request_and_receipt_bytes_and_signatures_match_go() {
    let fixture = fixture();
    let request = RequestSignature {
        method: &fixture.request.method,
        target: &fixture.request.target,
        body: fixture.request.body.as_bytes(),
        token: &fixture.request.token,
        timestamp: fixture.request.timestamp,
        nonce: &fixture.request.nonce,
    };
    assert_eq!(
        request.signing_payload(),
        unhex(&fixture.request.signing_payload_hex)
    );
    let laptop = fixture
        .seed_hex_by_device
        .keys()
        .find(|device| device.contains("Laptop"))
        .expect("laptop");
    assert_eq!(
        request.sign(&key_for(&fixture, laptop)),
        fixture.request.signature
    );
    super::devicelist::verify_with_key(
        &fixture.request.signer_key,
        &fixture.request.signature,
        &request.signing_payload(),
        super::canonical::ProofError::history("request"),
    )
    .expect("request signature");

    let receipt = Receipt {
        vault_id: &fixture.receipt.vault_id,
        revision: fixture.receipt.revision,
        header_digest: &fixture.receipt.header_digest,
        vault_epoch: fixture.receipt.vault_epoch,
        accepted_at: fixture.receipt.accepted_at,
    };
    assert_eq!(
        receipt.signing_payload(),
        unhex(&fixture.receipt.signing_payload_hex)
    );
    receipt
        .verify(&fixture.receipt.signer_key, &fixture.receipt.signature)
        .expect("receipt");
    let changed = Receipt {
        revision: fixture.receipt.revision + 1,
        ..receipt
    };
    assert!(changed
        .verify(&fixture.receipt.signer_key, &fixture.receipt.signature)
        .is_err());
}

#[test]
fn a_rust_signed_device_list_extends_and_a_rust_signature_matches_the_go_one() {
    let fixture = fixture();
    let mut list = DeviceList::verify(&entries(&fixture.chain)).expect("chain");
    let laptop_id = fixture
        .seed_hex_by_device
        .keys()
        .find(|device| device.contains("Laptop"))
        .expect("laptop")
        .clone();
    let laptop = key_for(&fixture, &laptop_id);
    let last = &fixture.chain[2].entry;
    let remove = DeviceListEntry {
        vault_id: last.vault_id.clone(),
        index: last.index + 1,
        previous_digest: last.digest(),
        kind: ENTRY_REMOVE.to_string(),
        signer_device_id: laptop_id,
        subject_device_id: last.subject_device_id.clone(),
        subject_signing_key: String::new(),
        subject_package_key: String::new(),
        sealed_label: String::new(),
        epoch_after: 2,
        snapshot_floor: 0,
        signature: String::new(),
    }
    .sign(&laptop);
    assert_eq!(remove.digest(), fixture.removal_chain[3].entry.digest());
    list.extend(&remove).expect("rust removal");
    assert_eq!(list.epoch(), 2);

    let again = DeviceListEntry {
        kind: ENTRY_ADD.to_string(),
        index: 5,
        previous_digest: remove.digest(),
        epoch_after: 2,
        subject_signing_key: fixture.chain[2].entry.subject_signing_key.clone(),
        subject_package_key: fixture.chain[2].entry.subject_package_key.clone(),
        sealed_label: fixture.chain[2].entry.sealed_label.clone(),
        subject_device_id: last.subject_device_id.clone(),
        ..remove
    }
    .sign(&laptop);
    let head = list.head();
    assert!(list.extend(&again).is_err());
    assert_eq!(list.head(), head);
}

#[test]
fn the_key_package_bytes_digest_and_signature_match_go_and_changes_are_refused() {
    let fixture = fixture();
    let item = &fixture.key_package;
    let package = KeyPackageV3 {
        vault_id: item.vault_id.clone(),
        sender_device_id: item.sender_device_id.clone(),
        recipient_device_id: item.recipient_device_id.clone(),
        vault_epoch: item.vault_epoch,
        entry_digest: item.entry_digest.clone(),
        ciphertext: item.ciphertext.clone(),
        signature: item.signature.clone(),
    };
    assert_eq!(package.signing_payload(), unhex(&item.signing_payload_hex));
    assert_eq!(package.digest(), item.digest);
    package.verify(&item.signer_key).expect("verifies");
    let other_epoch = KeyPackageV3 {
        vault_epoch: 2,
        ..package.clone()
    };
    assert!(other_epoch.verify(&item.signer_key).is_err());
    let other_recipient = KeyPackageV3 {
        recipient_device_id: "deviceSomeoneElse00001".to_string(),
        ..package.clone()
    };
    assert!(other_recipient.verify(&item.signer_key).is_err());
    let other_entry = KeyPackageV3 {
        entry_digest: fixture.chain[0].digest.clone(),
        ..package.clone()
    };
    assert!(other_entry.verify(&item.signer_key).is_err());
    assert_eq!(package.entry_digest, fixture.chain[1].digest);
}

#[test]
fn the_go_checkpoint_matches_the_rust_bytes_and_verifies_against_the_go_chain() {
    let fixture = fixture();
    let item = &fixture.checkpoint;
    assert_eq!(
        item.checkpoint.signing_payload(),
        unhex(&item.signing_payload_hex)
    );
    item.checkpoint
        .verify_signature(&item.signer_key)
        .expect("the Go signature verifies in Rust");
    let list = DeviceList::verify(&entries(&fixture.chain)).expect("chain");
    let signer = list
        .member_at(
            &item.checkpoint.device_id,
            item.checkpoint.device_list_index,
        )
        .expect("the signer is a member");
    assert_eq!(signer.signing_key, item.signer_key);
    assert_eq!(
        list.digest_at(item.checkpoint.device_list_index),
        Some(item.checkpoint.device_list_digest.as_str())
    );
    assert_eq!(
        item.checkpoint.header_digest,
        fixture.headers[2].header.digest()
    );
}

#[test]
fn a_rust_checkpoint_reproduces_the_go_signature() {
    let fixture = fixture();
    let item = &fixture.checkpoint;
    let key = key_for(&fixture, &item.checkpoint.device_id);
    let mut unsigned = item.checkpoint.clone();
    unsigned.signature = String::new();
    assert_eq!(unsigned.sign(&key), item.checkpoint);
}

#[test]
fn an_edited_go_checkpoint_never_verifies() {
    let fixture = fixture();
    let item = &fixture.checkpoint;
    let edits: Vec<Box<dyn Fn(&mut Checkpoint)>> = vec![
        Box::new(|c| c.observed_at += 1),
        Box::new(|c| c.header_revision += 1),
        Box::new(|c| c.device_list_index -= 1),
        Box::new(|c| c.device_id = fixture_other_device()),
        Box::new(|c| c.version = 2),
        Box::new(|c| c.header_digest = c.device_list_digest.clone()),
    ];
    for edit in edits {
        let mut edited = item.checkpoint.clone();
        edit(&mut edited);
        assert!(edited.verify_signature(&item.signer_key).is_err());
    }
}

fn fixture_other_device() -> String {
    "devicePhone000000001".to_string()
}

#[test]
fn the_wire_fixture_names_the_checkpoint_request_and_response() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("contracts")
        .join("sync")
        .join("v3")
        .join("wire-fixture.json");
    let wire: serde_json::Value =
        serde_json::from_slice(&std::fs::read(path).expect("read the wire fixture"))
            .expect("parse the wire fixture");
    assert!(wire["requests"]["checkpoint"]["checkpoint"]["observedAt"].is_u64());
    assert!(wire["responses"]["checkpoints"]["checkpoints"][0]["acceptedAt"].is_string());
}

#[test]
fn the_go_key_replacement_and_rotation_chain_verifies_and_rust_signs_the_same_entries() {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    let fixture = fixture();
    let list = DeviceList::verify(&entries(&fixture.key_chain)).expect("key chain");
    assert_eq!((list.head(), list.epoch(), list.current().len()), (5, 2, 3));
    let replaced = &fixture.key_chain[3].entry;
    let desktop = list.member(&replaced.signer_device_id).expect("desktop");
    assert_eq!(desktop.package_key, replaced.subject_package_key);
    assert_eq!(
        URL_SAFE_NO_PAD
            .decode(&desktop.package_key)
            .expect("key")
            .len(),
        crate::sync::xwing::PUBLIC_KEY_BYTES
    );

    let signed = |index: usize, template: DeviceListEntry| {
        let key = key_for(&fixture, &template.signer_device_id);
        let entry = DeviceListEntry {
            signature: String::new(),
            ..template
        }
        .sign(&key);
        assert_eq!(entry, fixture.key_chain[index].entry);
        assert_eq!(entry.digest(), fixture.key_chain[index].digest);
    };
    signed(
        3,
        DeviceListEntry {
            index: 4,
            previous_digest: fixture.key_chain[2].digest.clone(),
            ..replaced.clone()
        },
    );
    let rotation = &fixture.key_chain[4].entry;
    signed(
        4,
        DeviceListEntry {
            index: 5,
            previous_digest: fixture.key_chain[3].digest.clone(),
            ..rotation.clone()
        },
    );
}
