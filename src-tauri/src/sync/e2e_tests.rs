use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;

use super::client::SyncClient;
use super::devicelist::DeviceList;
use super::engine::*;
use super::identity::DeviceIdentity;
use super::pairing::{ApproverIdentity, NewDeviceIdentity};
use super::pake::{self, Offer};
use super::request::KeyPackageV3;
use super::state::SyncState;

const VAULT: &str = "vault0000000000000009";

fn run<T>(future: impl std::future::Future<Output = T>) -> T {
    tauri::async_runtime::block_on(future)
}

fn key_of(identity: &DeviceIdentity) -> String {
    URL_SAFE_NO_PAD.encode(identity.signing_public_key())
}

fn package_key_of(identity: &DeviceIdentity) -> String {
    URL_SAFE_NO_PAD.encode(identity.package_public_key())
}

#[test]
#[ignore = "needs the Go test server named by SESAME_SYNC_E2E_URL and SESAME_SYNC_E2E_KEY"]
fn the_rust_client_and_engine_round_trip_against_the_real_service() {
    let url = std::env::var("SESAME_SYNC_E2E_URL").expect("url");
    let instance = std::env::var("SESAME_SYNC_E2E_KEY").expect("key");
    let laptop = DeviceIdentity::generate().expect("identity");
    let phone = DeviceIdentity::generate().expect("identity");
    let laptop_client = SyncClient::for_tests(&url, "token-a", &instance);
    let phone_client = SyncClient::for_tests(&url, "token-b", &instance);
    let vault_key = [9u8; 32];

    let missing = run(laptop_client.state());
    assert!(matches!(missing, Err(super::client::SyncError::NotFound)));

    let sealed = seal_label(&vault_key, VAULT, &laptop.device_id, "Laptop").expect("label");
    let create = create_entry(&laptop, VAULT, &sealed);
    run(laptop_client.create_vault(&laptop, &create)).expect("create vault");
    let mut laptop_state = SyncState::new(VAULT, &laptop.device_id);
    laptop_state.entries = vec![create.clone()];
    laptop_state.activated_epoch = 1;

    let list = laptop_state.list().expect("list");
    let plan = plan_header(&laptop.device_id, &list, None).expect("plan");
    let ciphertext = vec![5u8; 128];
    let first = build_header(&laptop, &plan, &[1u8; 24], &ciphertext);
    let accepted = run(laptop_client.upload(&laptop, &first, &ciphertext)).expect("upload");
    verify_accepted(
        &first,
        &accepted.digest,
        accepted.revision,
        &accepted.receipt,
        &accepted.accepted_at,
        &instance,
    )
    .expect("the receipt verifies under the instance key");
    laptop_state.head = Some(first.clone());

    let code = pake::generate_code().expect("code");
    let phone_ad = NewDeviceIdentity {
        device_id: phone.device_id.clone(),
        signing_key: key_of(&phone),
        package_key: super::pairing::package_key_commitment(&package_key_of(&phone)),
        label: "Phone".to_string(),
    }
    .encode()
    .expect("ad");
    let offer = Offer::begin(&code, &phone_ad).expect("offer");
    run(phone_client.begin_pairing(
        &phone,
        &phone.device_id,
        &key_of(&phone),
        &package_key_of(&phone),
        &offer.message,
    ))
    .expect("begin pairing");

    let view = run(laptop_client.devices()).expect("devices");
    let offered = view
        .pairings
        .iter()
        .find(|pairing| pairing.state == "offered")
        .expect("offered pairing");
    assert!(offered.confirm.is_none());
    let received = URL_SAFE_NO_PAD.decode(&offered.offer).expect("offer bytes");
    let approver_ad = ApproverIdentity {
        device_id: laptop.device_id.clone(),
        signing_key: key_of(&laptop),
        vault_id: VAULT.to_string(),
        head_digest: list.head_digest().to_string(),
    }
    .encode()
    .expect("ad");
    let (answered, seen) = pake::answer(&code, &received, &approver_ad).expect("answer");
    assert_eq!(
        NewDeviceIdentity::decode(&seen).expect("decode").label,
        "Phone"
    );
    run(laptop_client.answer_pairing(&laptop, &offered.device_id, &answered.message))
        .expect("answer pairing");

    let status = run(phone_client.pairing_status()).expect("status");
    assert_eq!(status.state, "answered");
    let answer = URL_SAFE_NO_PAD
        .decode(status.answer.expect("answer"))
        .expect("answer bytes");
    let completed = offer.finish(&answer).expect("the codes match");
    run(phone_client.confirm_pairing(&phone, &completed.confirmation)).expect("confirm");

    let view = run(laptop_client.devices()).expect("devices");
    let confirmed = view
        .pairings
        .iter()
        .find(|pairing| pairing.device_id == phone.device_id)
        .and_then(|pairing| pairing.confirm.clone())
        .expect("confirmation");
    answered
        .verify_confirmation(&URL_SAFE_NO_PAD.decode(confirmed).expect("bytes"))
        .expect("the phone proved the code");

    let recipient = phone.package_public_key();
    assert_eq!(recipient.len(), super::xwing::PUBLIC_KEY_BYTES);
    let add = add_entry(
        &laptop,
        &list,
        &NewDevice {
            device_id: &phone.device_id,
            signing_key: &key_of(&phone),
            package_key: &package_key_of(&phone),
        },
        &seal_label(&vault_key, VAULT, &phone.device_id, "Phone").expect("label"),
        1,
    )
    .expect("add");
    let package_bytes =
        super::keys::seal_for_recipient(&vault_key, &recipient, VAULT, list.epoch()).expect("seal");
    let package = laptop.sign_key_package(KeyPackageV3 {
        vault_id: VAULT.to_string(),
        sender_device_id: laptop.device_id.clone(),
        recipient_device_id: phone.device_id.clone(),
        vault_epoch: list.epoch(),
        entry_digest: add.digest(),
        ciphertext: URL_SAFE_NO_PAD.encode(&package_bytes),
        signature: String::new(),
    });
    run(laptop_client.approve(&laptop, &add, &package)).expect("approve");
    laptop_state.entries.push(add.clone());

    let received_package = run(phone_client.key_package()).expect("key package");
    let entries = run(phone_client.device_list(0)).expect("device list");
    let approver = ApproverIdentity::decode(&completed.approver_ad).expect("approver");
    let phone_key = key_of(&phone);
    let phone_package_key = package_key_of(&phone);
    verify_join(
        &JoinCheck {
            device_id: &phone.device_id,
            signing_key: &phone_key,
            package_key: &phone_package_key,
            approver: &approver,
        },
        &entries,
        &received_package,
    )
    .expect("the join verifies against the real device list");
    let opened = phone
        .open_key_package(
            &URL_SAFE_NO_PAD
                .decode(&received_package.ciphertext)
                .expect("bytes"),
            VAULT,
            received_package.vault_epoch,
        )
        .expect("open");
    assert_eq!(opened, vault_key);
    run(phone_client.activate(&phone, &received_package.digest())).expect("activate");

    let state = run(phone_client.state()).expect("state");
    assert_eq!(
        (state.device_state.as_str(), state.current_revision),
        ("approved", 1)
    );
    let headers = run(phone_client.headers(0)).expect("headers");
    let mut phone_state = SyncState::new(VAULT, &phone.device_id);
    phone_state.entries = entries.clone();
    let update = verify_server_view(
        &phone_state,
        &instance,
        &ServerView {
            entries_after: &[],
            headers: &headers,
            latest_revision: state.current_revision,
        },
    )
    .expect("the phone verifies the real history");
    let snapshot = run(phone_client.snapshot()).expect("snapshot");
    assert_eq!(
        snapshot.header.digest(),
        update.head.as_ref().expect("head").digest()
    );
    let bytes = URL_SAFE_NO_PAD.decode(&snapshot.ciphertext).expect("bytes");
    snapshot
        .header
        .verify_ciphertext(&bytes)
        .expect("ciphertext matches its header");
    phone_state.head = update.head.clone();

    let phone_list = DeviceList::verify(&entries).expect("list");
    let plan = plan_header(&phone.device_id, &phone_list, phone_state.head.as_ref()).expect("plan");
    let second_ciphertext = vec![6u8; 160];
    let second = build_header(&phone, &plan, &[2u8; 24], &second_ciphertext);
    run(phone_client.upload(&phone, &second, &second_ciphertext)).expect("phone uploads");

    let latest = run(laptop_client.state()).expect("state");
    let headers = run(laptop_client.headers(0)).expect("headers");
    let update = verify_server_view(
        &laptop_state,
        &instance,
        &ServerView {
            entries_after: &[],
            headers: &headers,
            latest_revision: latest.current_revision,
        },
    )
    .expect("the laptop verifies the phone's revision");
    assert_eq!(update.head.as_ref().map(|header| header.revision), Some(2));
    laptop_state.head = update.head.clone();

    let observed_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_secs();
    let phone_checkpoint = phone.sign_checkpoint(super::checkpoint::Checkpoint::observe(
        &phone_list,
        update.head.as_ref(),
        &phone.device_id,
        observed_at,
    ));
    run(phone_client.post_checkpoint(&phone, &phone_checkpoint)).expect("the phone posts");
    let stale_checkpoint = run(phone_client.post_checkpoint(&phone, &phone_checkpoint));
    assert!(
        matches!(stale_checkpoint, Err(super::client::SyncError::Conflict)),
        "{stale_checkpoint:?}"
    );
    let served = run(laptop_client.checkpoints()).expect("the laptop reads checkpoints");
    assert_eq!(served.len(), 1);
    let confirmed = super::engine::check_peer_checkpoints(
        &update.list,
        update.head.as_ref(),
        &laptop.device_id,
        &super::engine::PeerView {
            checkpoints: &served,
            history: &[],
        },
        observed_at,
    )
    .expect("the real service's checkpoint agrees with the laptop");
    assert_eq!(confirmed, Some(observed_at));
    let frozen = super::engine::check_peer_checkpoints(
        &update.list,
        Some(&first),
        &laptop.device_id,
        &super::engine::PeerView {
            checkpoints: &served,
            history: &[],
        },
        observed_at,
    )
    .expect_err("a service that shows an older head than the phone saw is caught");
    assert_eq!(frozen.kind, super::canonical::ProofKind::History);

    let stale = run(phone_client.upload(&phone, &second, &second_ciphertext));
    assert!(
        matches!(stale, Err(super::client::SyncError::Conflict)),
        "{stale:?}"
    );

    let list = laptop_state.list().expect("list");
    let removal = remove_entry(&laptop, &list, &phone.device_id).expect("remove");
    let journal = super::rekey_journal::Journal::new(&removal, list.head_digest(), &[4u8; 32], 1);
    let served = |entries: Vec<super::devicelist::DeviceListEntry>| {
        DeviceList::verify(&entries).expect("the served list verifies")
    };
    assert_eq!(
        journal.outcome(&served(run(laptop_client.device_list(0)).expect("list"))),
        super::rekey_journal::Outcome::Discard
    );
    run(laptop_client.remove(&laptop, &removal, &[])).expect("remove the phone");
    assert_eq!(
        journal.outcome(&served(run(laptop_client.device_list(0)).expect("list"))),
        super::rekey_journal::Outcome::Adopt,
        "the journal recognises the removal in the list the real service serves"
    );
    let after = run(phone_client.state()).expect("state");
    assert_eq!(after.device_state, "none");
    assert!(run(phone_client.snapshot()).is_err());

    run(laptop_client.reset(&laptop, 2)).expect("reset");
    assert!(matches!(
        run(laptop_client.state()),
        Err(super::client::SyncError::NotFound)
    ));
}
