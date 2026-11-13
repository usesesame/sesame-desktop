use std::cell::{Cell, RefCell};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Instant;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde_json::{json, Value};

use crate::adapters::network::test_server::{Recorded, Reply, TestServer};
use crate::application::sync::SyncStore;
use crate::application::sync_join::{
    check_join_available, complete_join, finish_join_transaction, join_preflight_in_state,
    join_with_code_in_state, prepare_join, JoinRequest, PreparedJoin,
};
use crate::application::sync_pairing::{
    approve_in_state, newcomer_matches_offer, refuse_classical_downgrade, reset_cancellation,
    set_cancelled, ApproveRequest, CLASSICAL_KEY_REFUSAL,
};
use crate::application::tests::FakeEffects;
use crate::commands::test_support::{block_on, TestVault};
use crate::sync::client::{PairingRecord, SyncClient};
use crate::sync::devicelist::DeviceList;
use crate::sync::engine::{
    add_entry, build_header, create_entry, plan_header, seal_label, NewDevice,
};
use crate::sync::header::Header;
use crate::sync::identity::DeviceIdentity;
use crate::sync::pairing::{ApproverIdentity, NewDeviceIdentity};
use crate::sync::pake::{self, Offer};
use crate::sync::request::KeyPackageV3;
use crate::sync::state::{read_protected, state_path, write_protected, SyncState};
use crate::vault::random_id;

const PASSWORD: &str = "fictional master password";
const WRONG_PASSWORD: &str = "fictional wrong password";

async fn no_wait() {}

fn vault_id_of_test_vault(vault: &TestVault) -> String {
    let session = vault.state.session.lock().expect("session lock");
    session
        .as_ref()
        .expect("unlocked")
        .open_payload()
        .expect("payload")
        .vault_id
        .clone()
        .expect("vault id")
}

struct Scratch {
    path: PathBuf,
}

impl Scratch {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("sesame-pairing-{}", random_id()));
        std::fs::create_dir_all(&path).expect("scratch directory");
        Self { path }
    }

    fn store(&self) -> SyncStore {
        SyncStore::new(self.path.clone())
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

fn vault_state_json(vault_id: &str, epoch: u64, revision: u64, activated: u64) -> Value {
    json!({
        "vaultId": vault_id,
        "vaultEpoch": epoch,
        "currentRevision": revision,
        "deviceState": "approved",
        "activatedEpoch": activated,
    })
}

fn served_header(identity: &DeviceIdentity, list: &DeviceList) -> (Header, Value) {
    let plan = plan_header(&identity.device_id, list, None).expect("plan");
    let header = build_header(identity, &plan, &[1u8; 24], &[5u8; 64]);
    let mut value = serde_json::to_value(&header).expect("header json");
    value["digest"] = json!(header.digest());
    value["receipt"] = json!("fictional-receipt");
    value["acceptedAt"] = json!("2026-01-01T00:00:00Z");
    (header, value)
}

struct Approver {
    vault: TestVault,
    scratch: Scratch,
    identity: DeviceIdentity,
    state: SyncState,
    header: Value,
}

impl Approver {
    fn new() -> Self {
        let vault = TestVault::with_login("fictional-login", "https://northwind.example");
        let vault_id = vault_id_of_test_vault(&vault);
        let scratch = Scratch::new();
        let store = scratch.store();
        let identity = DeviceIdentity::generate().expect("identity");
        identity
            .save(&store.identity_path())
            .expect("saved identity");
        let entries = vec![create_entry(
            &identity,
            &vault_id,
            &seal_label(
                &[9u8; 32],
                &vault_id,
                &identity.device_id,
                "Fictional laptop",
            )
            .expect("label"),
        )];
        let list = DeviceList::verify(&entries).expect("list");
        let (header, header_json) = served_header(&identity, &list);
        let mut state = SyncState::new(&vault_id, &identity.device_id);
        state.entries = entries;
        state.head = Some(header);
        state.activated_epoch = 1;
        store.save_state(&state).expect("saved state");
        Self {
            vault,
            scratch,
            identity,
            state,
            header: header_json,
        }
    }

    fn store(&self) -> SyncStore {
        self.scratch.store()
    }

    fn client(&self, server: &TestServer) -> SyncClient {
        SyncClient::for_tests(&server.base(), "fictional-token", "unused")
    }

    fn server(&self, pairings: Vec<Value>) -> TestServer {
        let state = vault_state_json(&self.state.vault_id, 1, 1, 1);
        let header = self.header.clone();
        TestServer::start(move |request: &Recorded| match request.path.as_str() {
            "/v1/sync/checkpoints" => Reply::json(404, &json!({"error":{"code":"sync_not_found"}})),
            "/v1/sync/state" => Reply::json(200, &state),
            path if path.starts_with("/v1/sync/device-list") => {
                Reply::json(200, &json!({"entries": []}))
            }
            path if path.starts_with("/v1/sync/headers") => {
                Reply::json(200, &json!({"headers": [header.clone()]}))
            }
            "/v1/sync/devices" => Reply::json(200, &json!({"pairings": pairings.clone()})),
            path if path.starts_with("/v1/sync/pairings/") => Reply::bytes(204, Vec::new()),
            other => panic!("unexpected route {other}"),
        })
    }
}

fn pairing_json(pairing: &PairingRecord) -> Value {
    json!({
        "deviceId": pairing.device_id,
        "signingKey": pairing.signing_key,
        "packageKey": pairing.package_key,
        "state": pairing.state,
        "offer": pairing.offer,
        "confirm": pairing.confirm,
    })
}

fn newcomer_offer(newcomer: &DeviceIdentity, label: &str) -> (String, String, Vec<u8>) {
    let signing_key = URL_SAFE_NO_PAD.encode(newcomer.signing_public_key());
    let package_key = URL_SAFE_NO_PAD.encode(newcomer.package_public_key());
    let ad = NewDeviceIdentity {
        device_id: newcomer.device_id.clone(),
        signing_key: signing_key.clone(),
        package_key: crate::sync::pairing::package_key_commitment(&package_key),
        label: label.to_string(),
    }
    .encode()
    .expect("advertisement");
    (signing_key, package_key, ad)
}

fn refusal<T>(result: Result<T, String>) -> String {
    match result {
        Ok(_) => panic!("the operation unexpectedly succeeded"),
        Err(message) => message,
    }
}

#[test]
fn a_device_can_begin_pairing_before_it_is_approved_to_read_sync_state() {
    let server = TestServer::start(|request| {
        assert_eq!(request.method, "GET");
        assert_eq!(request.path, "/v1/sync/state");
        Reply::json(403, &serde_json::json!({"error":{"code":"sync_forbidden"}}))
    });
    let client = SyncClient::for_tests(&server.base(), "fictional-token", "unused");
    assert_eq!(block_on(check_join_available(&client)), Ok(()));
    assert_eq!(server.requests().len(), 1);
}

#[test]
fn joining_stops_when_the_account_has_no_vault_or_the_service_refuses_access() {
    for (status, code) in [
        (404, "sync_vault_not_found"),
        (401, "desktop_token_invalid"),
        (403, "sync_unavailable"),
        (403, "sync_not_entitled"),
        (503, "sync_failed"),
    ] {
        let server = TestServer::start(move |_| {
            Reply::json(status, &serde_json::json!({"error":{"code":code}}))
        });
        let client = SyncClient::for_tests(&server.base(), "fictional-token", "unused");
        let result = block_on(check_join_available(&client));
        assert!(result.is_err(), "{code}");
        assert_eq!(server.requests().len(), 1, "{code}");
    }
}

fn pending() -> (DeviceIdentity, SyncState, KeyPackageV3) {
    let approver = DeviceIdentity::generate().expect("approver");
    let identity = DeviceIdentity::generate().expect("joining device");
    let vault_id = "fictionalVault00000001";
    let first = create_entry(&approver, vault_id, &URL_SAFE_NO_PAD.encode([7; 40]));
    let list = DeviceList::verify(std::slice::from_ref(&first)).expect("list");
    let signing_key = URL_SAFE_NO_PAD.encode(identity.signing_public_key());
    let package_key = URL_SAFE_NO_PAD.encode(identity.package_public_key());
    let added = add_entry(
        &approver,
        &list,
        &NewDevice {
            device_id: &identity.device_id,
            signing_key: &signing_key,
            package_key: &package_key,
        },
        &URL_SAFE_NO_PAD.encode([8; 40]),
        1,
    )
    .expect("add");
    let package = approver.sign_key_package(KeyPackageV3 {
        vault_id: vault_id.into(),
        sender_device_id: approver.device_id.clone(),
        recipient_device_id: identity.device_id.clone(),
        vault_epoch: 1,
        entry_digest: added.digest(),
        ciphertext: URL_SAFE_NO_PAD.encode([9; 64]),
        signature: String::new(),
    });
    let mut pending = SyncState::new(vault_id, &identity.device_id);
    pending.entries = vec![first, added];
    pending.floor = 1;
    pending.pending_join = Some(ApproverIdentity {
        device_id: approver.device_id.clone(),
        signing_key: URL_SAFE_NO_PAD.encode(approver.signing_public_key()),
        vault_id: vault_id.into(),
        head_digest: list.head_digest().into(),
    });
    (identity, pending, package)
}

#[test]
fn a_lost_activation_response_preserves_the_join_and_retry_uses_the_same_device() {
    let (identity, pending, package) = pending();
    let requests = Arc::new(AtomicUsize::new(0));
    let attempts = requests.clone();
    let server = TestServer::start(move |request| {
        assert_eq!(request.path, "/v1/sync/activate");
        if attempts.fetch_add(1, Ordering::SeqCst) == 0 {
            Reply::disconnect()
        } else {
            Reply::bytes(204, Vec::new())
        }
    });
    let client = SyncClient::for_tests(&server.base(), "fictional-token", "unused");
    let directory = std::env::temp_dir().join(format!("sesame-join-{}", identity.device_id));
    let path = state_path(&directory);
    let adopted = Cell::new(0);
    let first = block_on(finish_join_transaction(
        &client,
        &identity,
        &package,
        pending.clone(),
        |state| write_protected(&path, state),
        || {
            adopted.set(adopted.get() + 1);
            Ok(())
        },
    ));
    assert!(first.is_err());
    assert_eq!(adopted.get(), 0);
    let retained = read_protected(&path).expect("pending join persists");
    assert_eq!(retained, pending);
    assert!(retained.require_join_complete().is_err());
    let mut altered = serde_json::to_value(&retained).expect("stored state");
    altered["pendingJoin"] = serde_json::Value::Null;
    std::fs::write(&path, serde_json::to_vec(&altered).expect("altered state"))
        .expect("write altered state");
    assert!(read_protected(&path).is_none());
    write_protected(&path, &retained).expect("restore approved state");
    block_on(finish_join_transaction(
        &client,
        &identity,
        &package,
        retained,
        |state| write_protected(&path, state),
        || {
            adopted.set(adopted.get() + 1);
            Ok(())
        },
    ))
    .expect("retry completes");
    let saved = read_protected(&path).expect("completed state");
    assert_eq!(saved.device_id, identity.device_id);
    assert_eq!(saved.entries, pending.entries);
    assert_eq!(saved.activated_epoch, 1);
    assert!(saved.pending_join.is_none());
    assert!(saved.require_join_complete().is_ok());
    assert_eq!(adopted.get(), 1);
    let recorded = server.requests();
    assert_eq!(recorded.len(), 2);
    assert_eq!(recorded[0].body, recorded[1].body);
    assert_ne!(
        recorded[0].headers["sesame-request-signature"],
        recorded[1].headers["sesame-request-signature"]
    );
    std::fs::remove_dir_all(directory).expect("remove fixture");
}

#[test]
fn a_pending_join_that_cannot_be_saved_does_not_activate_or_replace_the_vault() {
    let (identity, pending, package) = pending();
    let server = TestServer::start(|_| Reply::bytes(204, Vec::new()));
    let client = SyncClient::for_tests(&server.base(), "fictional-token", "unused");
    let result = block_on(finish_join_transaction(
        &client,
        &identity,
        &package,
        pending,
        |_| Err("fictional write failure".into()),
        || -> Result<(), String> { panic!("the local vault must remain untouched") },
    ));
    assert_eq!(result, Err("fictional write failure".into()));
    assert!(server.requests().is_empty());
}

#[test]
fn a_failed_vault_replacement_preserves_the_pending_join() {
    let (identity, pending, package) = pending();
    let server = TestServer::start(|_| Reply::bytes(204, Vec::new()));
    let client = SyncClient::for_tests(&server.base(), "fictional-token", "unused");
    let saved = RefCell::new(None);
    let result = block_on(finish_join_transaction(
        &client,
        &identity,
        &package,
        pending.clone(),
        |state| {
            *saved.borrow_mut() = Some(state.clone());
            Ok(())
        },
        || -> Result<(), String> { Err("fictional vault replacement failure".into()) },
    ));
    assert_eq!(result, Err("fictional vault replacement failure".into()));
    assert_eq!(*saved.borrow(), Some(pending));
    assert_eq!(server.requests().len(), 1);
}

#[test]
fn lost_pairing_responses_keep_the_authenticated_context_and_resume_without_pairing_again() {
    for lost in ["confirmation", "package", "device-list"] {
        let (identity, approved, package) = pending();
        let mut unfinished = approved.clone();
        unfinished.entries.clear();
        unfinished.floor = 0;
        unfinished.pending_confirmation = Some(URL_SAFE_NO_PAD.encode([7; pake::TAG_BYTES]));
        let confirmed = Arc::new(AtomicBool::new(false));
        let remote_confirmed = confirmed.clone();
        let package_reads = Arc::new(AtomicUsize::new(0));
        let remote_reads = package_reads.clone();
        let list_reads = Arc::new(AtomicUsize::new(0));
        let remote_lists = list_reads.clone();
        let served_package = package.clone();
        let entries = approved.entries.clone();
        let server = TestServer::start(move |request| match request.path.as_str() {
            "/v1/sync/key-package" => {
                if lost != "device-list" && !remote_confirmed.load(Ordering::SeqCst) {
                    return Reply::json(
                        403,
                        &serde_json::json!({"error":{"code":"sync_forbidden"}}),
                    );
                }
                if lost == "package" && remote_reads.fetch_add(1, Ordering::SeqCst) == 0 {
                    return Reply::disconnect();
                }
                Reply::json(200, &serde_json::json!({"package":served_package}))
            }
            "/v1/sync/pairings/mine" => Reply::json(
                200,
                &serde_json::json!({
                    "state": if remote_confirmed.load(Ordering::SeqCst) { "confirmed" } else { "answered" }
                }),
            ),
            "/v1/sync/pairings/mine/confirm" => {
                remote_confirmed.store(true, Ordering::SeqCst);
                if lost == "confirmation" {
                    Reply::disconnect()
                } else {
                    Reply::bytes(204, Vec::new())
                }
            }
            "/v1/sync/device-list?after=0" => {
                if lost == "device-list" && remote_lists.fetch_add(1, Ordering::SeqCst) == 0 {
                    return Reply::disconnect();
                }
                Reply::json(200, &serde_json::json!({"entries":entries}))
            }
            other => panic!("unexpected route {other}"),
        });
        let client = SyncClient::for_tests(&server.base(), "fictional-token", "unused");
        let directory =
            std::env::temp_dir().join(format!("sesame-join-{lost}-{}", identity.device_id));
        let path = state_path(&directory);
        let first = block_on(prepare_join(
            &client,
            &identity,
            unfinished.clone(),
            |state| write_protected(&path, state),
            &no_wait,
        ));
        assert!(first.is_err(), "{lost}");
        let retained = read_protected(&path).expect("the authenticated context persists");
        assert_eq!(retained, unfinished, "{lost}");
        if lost != "device-list" {
            assert!(confirmed.load(Ordering::SeqCst));
        }
        let (resumed, received) = block_on(prepare_join(
            &client,
            &identity,
            retained,
            |state| write_protected(&path, state),
            &no_wait,
        ))
        .expect("retry resumes the same pairing");
        assert_eq!(received, package);
        assert_eq!(resumed.device_id, identity.device_id);
        assert_eq!(resumed.entries, approved.entries);
        assert_eq!(resumed.pending_join, approved.pending_join);
        assert!(resumed.pending_confirmation.is_none());
        assert!(resumed.require_join_complete().is_err());
        assert_eq!(read_protected(&path), Some(resumed));
        assert!(server
            .requests()
            .iter()
            .all(|request| request.path != "/v1/sync/pairings"));
        assert_eq!(
            server
                .requests()
                .iter()
                .filter(|request| request.path == "/v1/sync/pairings/mine/confirm")
                .count(),
            usize::from(lost != "device-list")
        );
        std::fs::remove_dir_all(directory).expect("remove fixture");
    }
}

#[test]
fn a_join_with_the_wrong_master_password_is_refused_before_any_service_request() {
    let vault = TestVault::with_login("fictional-login", "https://northwind.example");
    let scratch = Scratch::new();
    let store = scratch.store();
    let server = TestServer::start(|_| panic!("the preflight must not contact the service"));

    assert_eq!(
        join_preflight_in_state(&vault.state, &store, "Fictional tablet", WRONG_PASSWORD)
            .expect_err("a wrong password is refused"),
        "That master password is not correct."
    );
    assert!(server.requests().is_empty());
    assert!(store.load_join_state().expect("state").is_none());
}

#[test]
fn a_locked_vault_is_refused_before_the_other_device_is_contacted() {
    let vault = TestVault::with_login("fictional-login", "https://northwind.example");
    *vault.state.session.lock().expect("session lock") = None;
    let scratch = Scratch::new();
    let store = scratch.store();

    assert_eq!(
        join_preflight_in_state(&vault.state, &store, "Fictional tablet", PASSWORD)
            .expect_err("a locked vault cannot join"),
        "Unlock Sesame before joining a synced vault."
    );
    assert!(store.load_join_state().expect("state").is_none());
}

#[test]
fn a_cancelled_pairing_stops_the_approve_loop_before_it_asks_for_devices() {
    let approver = Approver::new();
    let store = approver.store();
    let server = approver.server(Vec::new());
    let client = approver.client(&server);
    reset_cancellation();
    let first = AtomicBool::new(true);
    let pause = || {
        if first.swap(false, Ordering::SeqCst) {
            set_cancelled();
        }
        std::future::ready(())
    };

    let result = block_on(approve_in_state(
        &approver.vault.state,
        &store,
        &client,
        &approver.identity,
        ApproveRequest {
            code: "ABCDEFGHJK",
            started: Instant::now(),
            allow_classical: false,
        },
        pause,
    ));
    reset_cancellation();

    assert_eq!(refusal(result), "Pairing was cancelled.");
    assert_eq!(
        server
            .requests()
            .iter()
            .filter(|request| request.method == "GET" && request.path == "/v1/sync/devices")
            .count(),
        1
    );
    assert_eq!(
        store.load_state().expect("state"),
        Some(approver.state.clone())
    );
}

#[test]
fn a_cancelled_pairing_stops_the_join_loop_before_it_asks_for_the_answer() {
    let vault = TestVault::with_login("fictional-login", "https://northwind.example");
    let scratch = Scratch::new();
    let store = scratch.store();
    let effects = FakeEffects::new(PathBuf::new());
    let server = TestServer::start(|request: &Recorded| match request.path.as_str() {
        "/v1/sync/state" => Reply::json(403, &json!({"error":{"code":"sync_forbidden"}})),
        "/v1/sync/pairings" => Reply::bytes(204, Vec::new()),
        "/v1/sync/pairings/mine" => Reply::json(200, &json!({"state": "offered"})),
        other => panic!("unexpected route {other}"),
    });
    let client = SyncClient::for_tests(&server.base(), "fictional-token", "unused");
    reset_cancellation();
    let first = AtomicBool::new(true);
    let pause = || {
        if first.swap(false, Ordering::SeqCst) {
            set_cancelled();
        }
        std::future::ready(())
    };

    let result = block_on(join_with_code_in_state(
        &vault.state,
        &store,
        &effects,
        &client,
        JoinRequest {
            code: "ABCDEFGHJK",
            label: "Fictional tablet",
            master_password: PASSWORD,
            pending: None,
        },
        pause,
    ));
    reset_cancellation();

    assert_eq!(refusal(result), "Pairing was cancelled.");
    assert_eq!(
        server
            .requests()
            .iter()
            .filter(|request| request.path == "/v1/sync/pairings/mine")
            .count(),
        1
    );
    assert!(store.load_join_state().expect("state").is_none());
    assert!(effects.calls().is_empty());
}

#[test]
fn an_offer_whose_newcomer_does_not_match_is_refused_without_adding_a_device() {
    let approver = Approver::new();
    let store = approver.store();
    let newcomer = DeviceIdentity::generate()
        .expect("newcomer")
        .without_hybrid_key();
    let (signing_key, _package_key, ad) = newcomer_offer(&newcomer, "Fictional tablet");
    let offer = Offer::begin("ABCDEFGHJK", &ad).expect("offer");
    let other = DeviceIdentity::generate().expect("other device");
    let offered = PairingRecord {
        device_id: newcomer.device_id.clone(),
        signing_key,
        package_key: URL_SAFE_NO_PAD.encode(other.package_public_key()),
        state: "offered".to_string(),
        offer: URL_SAFE_NO_PAD.encode(&offer.message),
        confirm: None,
    };
    let server = approver.server(vec![pairing_json(&offered)]);
    let client = approver.client(&server);
    reset_cancellation();

    assert_eq!(
        refusal(block_on(approve_in_state(
            &approver.vault.state,
            &store,
            &client,
            &approver.identity,
            ApproveRequest {
                code: "ABCDEFGHJK",
                started: Instant::now(),
                allow_classical: false,
            },
            no_wait,
        ))),
        "The device and the service disagree about the new device's keys. Pairing stopped."
    );
    assert!(server
        .requests()
        .iter()
        .all(|request| !(request.method == "POST" && request.path == "/v1/sync/devices")));
    assert!(server
        .paths()
        .iter()
        .any(|path| path.as_str() == format!("/v1/sync/pairings/{}", newcomer.device_id).as_str()));
    assert_eq!(
        store.load_state().expect("state"),
        Some(approver.state.clone())
    );
}

#[test]
fn a_classical_newcomer_is_refused_for_a_hybrid_vault_unless_the_person_allows_it() {
    let approver = Approver::new();
    let store = approver.store();
    let newcomer = DeviceIdentity::generate()
        .expect("newcomer")
        .without_hybrid_key();
    let (signing_key, package_key, _ad) = newcomer_offer(&newcomer, "Fictional tablet");
    let offered = PairingRecord {
        device_id: newcomer.device_id.clone(),
        signing_key,
        package_key,
        state: "offered".to_string(),
        offer: String::new(),
        confirm: None,
    };
    let server = approver.server(vec![pairing_json(&offered)]);
    let client = approver.client(&server);
    reset_cancellation();

    assert_eq!(
        refusal(block_on(approve_in_state(
            &approver.vault.state,
            &store,
            &client,
            &approver.identity,
            ApproveRequest {
                code: "ABCDEFGHJK",
                started: Instant::now(),
                allow_classical: false,
            },
            no_wait,
        ))),
        CLASSICAL_KEY_REFUSAL
    );
    assert!(server
        .paths()
        .iter()
        .any(|path| path.as_str() == format!("/v1/sync/pairings/{}", newcomer.device_id).as_str()));

    let allowed = refusal(block_on(approve_in_state(
        &approver.vault.state,
        &store,
        &client,
        &approver.identity,
        ApproveRequest {
            code: "ABCDEFGHJK",
            started: Instant::now(),
            allow_classical: true,
        },
        no_wait,
    )));
    assert_ne!(allowed, CLASSICAL_KEY_REFUSAL);
    assert!(server
        .requests()
        .iter()
        .all(|request| !(request.method == "POST" && request.path == "/v1/sync/devices")));
}

#[test]
fn a_join_that_loses_the_key_package_keeps_the_pending_join_and_leaves_the_vault_alone() {
    let vault = TestVault::with_login("fictional-login", "https://northwind.example");
    let (identity, pending, _package) = pending();
    let scratch = Scratch::new();
    let store = scratch.store();
    identity
        .save(&store.identity_path())
        .expect("saved identity");
    store.save_state(&pending).expect("saved pending join");
    let before = std::fs::read(vault.path()).expect("vault bytes");
    let server = TestServer::start(|request: &Recorded| {
        assert_eq!(request.path, "/v1/sync/key-package");
        Reply::disconnect()
    });
    let client = SyncClient::for_tests(&server.base(), "fictional-token", "unused");

    assert!(block_on(prepare_join(
        &client,
        &identity,
        pending.clone(),
        |state| store.save_state(state),
        &no_wait,
    ))
    .is_err());
    assert_eq!(
        store.load_join_state().expect("state"),
        Some(pending.clone())
    );
    assert!(pending.require_join_complete().is_err());
    assert_eq!(std::fs::read(vault.path()).expect("vault bytes"), before);
    assert!(!server
        .paths()
        .iter()
        .any(|path| path == "/v1/sync/activate"));
}

#[test]
fn a_join_whose_device_list_changed_never_reaches_activation_or_adoption() {
    let vault = TestVault::with_login("fictional-login", "https://northwind.example");
    let (identity, pending, package) = pending();
    let scratch = Scratch::new();
    let store = scratch.store();
    store.save_state(&pending).expect("saved pending join");
    let effects = FakeEffects::new(PathBuf::new());
    let before = std::fs::read(vault.path()).expect("vault bytes");
    let server = TestServer::start(|request: &Recorded| {
        assert_eq!(request.path, "/v1/sync/device-list?after=0");
        Reply::json(200, &json!({"entries": []}))
    });
    let client = SyncClient::for_tests(&server.base(), "fictional-token", "unused");

    let refused = block_on(complete_join(
        &vault.state,
        &store,
        &effects,
        &client,
        &identity,
        PreparedJoin {
            pending: pending.clone(),
            package,
        },
        PASSWORD,
    ))
    .expect_err("a changed device list stops the join");
    assert!(refused.starts_with("sync_fork:"));
    assert_eq!(std::fs::read(vault.path()).expect("vault bytes"), before);
    assert_eq!(
        store.load_join_state().expect("state"),
        Some(pending.clone())
    );
    assert!(pending.require_join_complete().is_err());
    assert!(effects.calls().is_empty());
    assert!(!server
        .paths()
        .iter()
        .any(|path| path == "/v1/sync/activate"));
}

fn key(length: usize) -> String {
    URL_SAFE_NO_PAD.encode(vec![5u8; length])
}

#[test]
fn a_classical_key_is_refused_once_the_vault_holds_a_hybrid_key() {
    let members = [key(32), key(1216)];
    let result = refuse_classical_downgrade(&key(32), members.iter().map(String::as_str), false);
    assert_eq!(result, Err(CLASSICAL_KEY_REFUSAL.to_string()));
}

#[test]
fn the_person_can_allow_the_older_key_exchange() {
    let members = [key(1216)];
    assert!(refuse_classical_downgrade(&key(32), members.iter().map(String::as_str), true).is_ok());
}

#[test]
fn a_classical_key_is_fine_while_no_member_has_a_hybrid_key() {
    let members = [key(32), key(32)];
    assert!(
        refuse_classical_downgrade(&key(32), members.iter().map(String::as_str), false).is_ok()
    );
}

fn offered_record(package_key: &str) -> PairingRecord {
    PairingRecord {
        device_id: "deviceBBBBBBBBBBBB01".to_string(),
        signing_key: key(32),
        package_key: package_key.to_string(),
        state: "offered".to_string(),
        offer: String::new(),
        confirm: None,
    }
}

fn advertisement(package_key: &str) -> NewDeviceIdentity {
    NewDeviceIdentity {
        device_id: "deviceBBBBBBBBBBBB01".to_string(),
        signing_key: key(32),
        package_key: crate::sync::pairing::package_key_commitment(package_key),
        label: "Phone".to_string(),
    }
}

#[test]
fn the_key_the_service_offers_must_be_the_key_the_new_device_committed_to() {
    let hybrid = URL_SAFE_NO_PAD.encode(vec![5u8; 1216]);
    let other_hybrid = URL_SAFE_NO_PAD.encode(vec![6u8; 1216]);
    let truncated = URL_SAFE_NO_PAD.encode(vec![5u8; 1215]);
    let classical = key(32);

    assert!(newcomer_matches_offer(
        &advertisement(&hybrid),
        &offered_record(&hybrid)
    ));
    assert!(newcomer_matches_offer(
        &advertisement(&classical),
        &offered_record(&classical)
    ));
    for swapped in [&other_hybrid, &truncated, &classical] {
        assert!(!newcomer_matches_offer(
            &advertisement(&hybrid),
            &offered_record(swapped)
        ));
    }
    assert!(!newcomer_matches_offer(
        &advertisement(&classical),
        &offered_record(&hybrid)
    ));

    let mut other_device = offered_record(&hybrid);
    other_device.device_id = "deviceCCCCCCCCCCCC01".to_string();
    assert!(!newcomer_matches_offer(
        &advertisement(&hybrid),
        &other_device
    ));
    let mut other_signer = offered_record(&hybrid);
    other_signer.signing_key = key(33);
    assert!(!newcomer_matches_offer(
        &advertisement(&hybrid),
        &other_signer
    ));
}

#[test]
fn a_key_of_an_unknown_length_is_not_taken_for_a_classical_downgrade() {
    let members = [key(1216)];
    for length in [0, 31, 33, 1215, 1217] {
        assert!(refuse_classical_downgrade(
            &key(length),
            members.iter().map(String::as_str),
            false
        )
        .is_ok());
    }
    assert!(
        refuse_classical_downgrade("not base64!", members.iter().map(String::as_str), false)
            .is_ok()
    );
}

#[test]
fn a_hybrid_key_is_never_refused() {
    let members = [key(1216)];
    assert!(
        refuse_classical_downgrade(&key(1216), members.iter().map(String::as_str), false).is_ok()
    );
    assert!(
        refuse_classical_downgrade(&key(1216), [key(32)].iter().map(String::as_str), false).is_ok()
    );
}
