use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};

use super::canonical::ProofKind;
use super::devicelist::{DeviceList, DeviceListEntry};
use super::engine::*;
use super::header::Header;
use super::identity::DeviceIdentity;
use super::state::SyncState;

const VAULT: &str = "vault0000000000000001";

struct World {
    instance: SigningKey,
    laptop: DeviceIdentity,
    desktop: DeviceIdentity,
    entries: Vec<DeviceListEntry>,
    list: DeviceList,
}

fn identity() -> DeviceIdentity {
    DeviceIdentity::generate().expect("identity")
}

fn key(identity: &DeviceIdentity) -> String {
    URL_SAFE_NO_PAD.encode(identity.signing_public_key())
}

fn package_key(identity: &DeviceIdentity) -> String {
    URL_SAFE_NO_PAD.encode(identity.package_public_key())
}

fn instance_key(world: &World) -> String {
    URL_SAFE_NO_PAD.encode(world.instance.verifying_key().to_bytes())
}

fn world() -> World {
    let laptop = identity();
    let desktop = identity();
    let vault_key = [9u8; 32];
    let label = seal_label(&vault_key, VAULT, &laptop.device_id, "Laptop").expect("label");
    let first = create_entry(&laptop, VAULT, &label);
    let mut list = DeviceList::verify(std::slice::from_ref(&first)).expect("create");
    let desktop_label =
        seal_label(&vault_key, VAULT, &desktop.device_id, "Desktop").expect("label");
    let second = add_entry(
        &laptop,
        &list,
        &NewDevice {
            device_id: &desktop.device_id,
            signing_key: &key(&desktop),
            package_key: &package_key(&desktop),
        },
        &desktop_label,
        3,
    )
    .expect("add");
    list.extend(&second).expect("extend");
    World {
        instance: SigningKey::from_bytes(&[5u8; 32]),
        laptop,
        desktop,
        entries: vec![first, second],
        list,
    }
}

fn header_by(
    world: &World,
    signer: &DeviceIdentity,
    previous: Option<&Header>,
    seed: u8,
) -> Header {
    let plan = plan_header(&signer.device_id, &world.list, previous).expect("plan");
    build_header(signer, &plan, &[seed; 24], &[seed; 64])
}

fn served(world: &World, header: &Header) -> ServedHeader {
    let accepted_at = 1_800_000_000u64;
    let receipt = super::request::Receipt {
        vault_id: &header.vault_id,
        revision: header.revision,
        header_digest: &header.digest(),
        vault_epoch: header.vault_epoch,
        accepted_at,
    };
    ServedHeader {
        header: header.clone(),
        digest: header.digest(),
        receipt: URL_SAFE_NO_PAD.encode(world.instance.sign(&receipt.signing_payload()).to_bytes()),
        accepted_at: chrono::DateTime::from_timestamp(accepted_at as i64, 0)
            .expect("time")
            .to_rfc3339(),
    }
}

fn state_for(world: &World, device: &DeviceIdentity) -> SyncState {
    let mut state = SyncState::new(VAULT, &device.device_id);
    state.entries = world.entries.clone();
    state
}

fn view<'a>(headers: &'a [ServedHeader], latest: u64) -> ServerView<'a> {
    ServerView {
        entries_after: &[],
        headers,
        latest_revision: latest,
    }
}

#[test]
fn a_new_device_accepts_the_newest_header_above_its_floor_and_keeps_the_receipt() {
    let world = world();
    let first = header_by(&world, &world.laptop, None, 1);
    let second = header_by(&world, &world.laptop, Some(&first), 2);
    let third = header_by(&world, &world.laptop, Some(&second), 3);
    let headers = vec![served(&world, &third)];
    let state = state_for(&world, &world.desktop);
    let update =
        verify_server_view(&state, &instance_key(&world), &view(&headers, 3)).expect("update");
    assert_eq!(update.head.as_ref().map(|header| header.revision), Some(3));
    assert!(update.receipt.is_some());
}

#[test]
fn a_new_device_refuses_a_revision_older_than_the_one_it_was_added_at() {
    let world = world();
    let first = header_by(&world, &world.laptop, None, 1);
    let headers = vec![served(&world, &first)];
    let state = state_for(&world, &world.desktop);
    let error = verify_server_view(&state, &instance_key(&world), &view(&headers, 1)).unwrap_err();
    assert_eq!(error.kind, ProofKind::History);
    assert!(error
        .to_string()
        .contains("older than the one this device was added at"));
}

#[test]
fn an_existing_device_advances_over_a_verified_chain() {
    let world = world();
    let first = header_by(&world, &world.laptop, None, 1);
    let second = header_by(&world, &world.desktop, Some(&first), 2);
    let third = header_by(&world, &world.laptop, Some(&second), 3);
    let mut state = state_for(&world, &world.laptop);
    state.head = Some(first.clone());
    let headers = vec![
        served(&world, &first),
        served(&world, &second),
        served(&world, &third),
    ];
    let update =
        verify_server_view(&state, &instance_key(&world), &view(&headers, 3)).expect("update");
    assert_eq!(update.head.expect("head").revision, 3);
}

#[test]
fn a_device_already_current_changes_nothing() {
    let world = world();
    let first = header_by(&world, &world.laptop, None, 1);
    let mut state = state_for(&world, &world.laptop);
    state.head = Some(first.clone());
    let headers = vec![served(&world, &first)];
    let update =
        verify_server_view(&state, &instance_key(&world), &view(&headers, 1)).expect("update");
    assert_eq!(update.head.as_ref().map(|header| header.revision), Some(1));
}

#[test]
fn every_way_the_server_can_lie_about_history_is_refused() {
    let world = world();
    let first = header_by(&world, &world.laptop, None, 1);
    let second = header_by(&world, &world.desktop, Some(&first), 2);
    let third = header_by(&world, &world.laptop, Some(&second), 3);
    let forked_first = header_by(&world, &world.desktop, None, 8);
    let forked_second = header_by(&world, &world.desktop, Some(&forked_first), 9);
    let mut state = state_for(&world, &world.laptop);
    state.head = Some(second.clone());
    let key = instance_key(&world);

    let older = vec![served(&world, &first)];
    assert!(
        verify_server_view(&state, &key, &view(&older, 1)).is_err(),
        "an older revision"
    );

    let fork = vec![served(&world, &forked_second)];
    assert!(
        verify_server_view(&state, &key, &view(&fork, 2)).is_err(),
        "a different revision 2"
    );

    let on_the_fork = vec![
        served(&world, &forked_second),
        served(
            &world,
            &header_by(&world, &world.desktop, Some(&forked_second), 10),
        ),
    ];
    assert!(
        verify_server_view(&state, &key, &view(&on_the_fork, 3)).is_err(),
        "a branch"
    );

    let silent: Vec<ServedHeader> = Vec::new();
    assert!(
        verify_server_view(&state, &key, &view(&silent, 3)).is_err(),
        "no history for revision 3"
    );

    let short = vec![served(&world, &second)];
    assert!(
        verify_server_view(&state, &key, &view(&short, 3)).is_err(),
        "history stops early"
    );

    let skipped = vec![
        served(&world, &second),
        served(&world, &header_by(&world, &world.laptop, Some(&third), 4)),
    ];
    assert!(
        verify_server_view(&state, &key, &view(&skipped, 4)).is_err(),
        "a skipped revision"
    );
}

#[test]
fn receipts_must_verify_under_the_pinned_instance_key() {
    let world = world();
    let first = header_by(&world, &world.laptop, None, 1);
    let second = header_by(&world, &world.desktop, Some(&first), 2);
    let mut state = state_for(&world, &world.laptop);
    state.head = Some(first.clone());
    let honest = vec![served(&world, &first), served(&world, &second)];
    let attacker = SigningKey::from_bytes(&[6u8; 32]);
    let wrong_key = URL_SAFE_NO_PAD.encode(attacker.verifying_key().to_bytes());
    assert!(verify_server_view(&state, &wrong_key, &view(&honest, 2)).is_err());

    let mut renamed = honest.clone();
    renamed[1].digest = first.digest();
    assert!(verify_server_view(&state, &instance_key(&world), &view(&renamed, 2)).is_err());

    let mut later = honest.clone();
    later[1].accepted_at = chrono::DateTime::from_timestamp(1_800_000_999, 0)
        .expect("time")
        .to_rfc3339();
    assert!(verify_server_view(&state, &instance_key(&world), &view(&later, 2)).is_err());

    let mut unreadable = honest;
    unreadable[1].accepted_at = "yesterday".to_string();
    assert!(verify_server_view(&state, &instance_key(&world), &view(&unreadable, 2)).is_err());
}

#[test]
fn new_device_list_entries_extend_the_chain_or_are_refused() {
    let world = world();
    let stranger = identity();
    let vault_key = [9u8; 32];
    let label = seal_label(&vault_key, VAULT, &stranger.device_id, "Stranger").expect("label");
    let forged = add_entry(
        &stranger,
        &world.list,
        &NewDevice {
            device_id: &stranger.device_id,
            signing_key: &key(&stranger),
            package_key: &package_key(&stranger),
        },
        &label,
        0,
    )
    .expect("entry");
    let state = state_for(&world, &world.laptop);
    let entries = [forged];
    let bad = ServerView {
        entries_after: &entries,
        headers: &[],
        latest_revision: 0,
    };
    let error = verify_server_view(&state, &instance_key(&world), &bad).unwrap_err();
    assert_eq!(error.kind, ProofKind::DeviceList);

    let phone = identity();
    let phone_label = seal_label(&vault_key, VAULT, &phone.device_id, "Phone").expect("label");
    let honest = add_entry(
        &world.desktop,
        &world.list,
        &NewDevice {
            device_id: &phone.device_id,
            signing_key: &key(&phone),
            package_key: &package_key(&phone),
        },
        &phone_label,
        0,
    )
    .expect("entry");
    let entries = [honest];
    let good = ServerView {
        entries_after: &entries,
        headers: &[],
        latest_revision: 0,
    };
    let update = verify_server_view(&state, &instance_key(&world), &good).expect("extended");
    assert_eq!(update.list.head(), 3);
    assert_eq!(update.entries.len(), 3);
}

#[test]
fn a_removal_raises_the_epoch_and_a_header_under_the_old_one_is_refused() {
    let mut world = world();
    let before = header_by(&world, &world.laptop, None, 1);
    let removal =
        remove_entry(&world.laptop, &world.list, &world.desktop.device_id).expect("remove");
    world.list.extend(&removal).expect("extend");
    world.entries.push(removal);
    let mut state = state_for(&world, &world.laptop);
    state.head = Some(before.clone());
    let after = header_by(&world, &world.laptop, Some(&before), 2);
    assert_eq!(after.vault_epoch, 2);
    let headers = vec![served(&world, &before), served(&world, &after)];
    let update = verify_server_view(&state, &instance_key(&world), &view(&headers, 2)).expect("ok");
    assert_eq!(update.list.epoch(), 2);

    let from_removed = header_by(&world, &world.desktop, Some(&after), 3);
    let late = vec![served(&world, &after), served(&world, &from_removed)];
    let mut current = state_for(&world, &world.laptop);
    current.head = Some(after);
    assert!(verify_server_view(&current, &instance_key(&world), &view(&late, 3)).is_err());
}

#[test]
fn labels_seal_under_the_vault_key_and_bind_the_vault_and_device() {
    let key = [3u8; 32];
    let sealed = seal_label(&key, VAULT, "deviceAAAAAAAAAAAAAA01", "Kitchen laptop").expect("seal");
    assert_eq!(
        open_label(&key, VAULT, "deviceAAAAAAAAAAAAAA01", &sealed).as_deref(),
        Some("Kitchen laptop")
    );
    assert_eq!(
        open_label(&[4u8; 32], VAULT, "deviceAAAAAAAAAAAAAA01", &sealed),
        None
    );
    assert_eq!(
        open_label(&key, VAULT, "deviceBBBBBBBBBBBBBB01", &sealed),
        None
    );
    assert_eq!(
        open_label(
            &key,
            "vault0000000000000002",
            "deviceAAAAAAAAAAAAAA01",
            &sealed
        ),
        None
    );
    assert!(seal_label(&key, VAULT, "deviceAAAAAAAAAAAAAA01", "   ").is_err());
    assert!(seal_label(&key, VAULT, "deviceAAAAAAAAAAAAAA01", &"x".repeat(65)).is_err());
    let again = seal_label(&key, VAULT, "deviceAAAAAAAAAAAAAA01", "Kitchen laptop").expect("seal");
    assert_ne!(sealed, again);
}

#[test]
fn the_planned_aad_is_the_aad_of_the_header_that_gets_built_and_signed() {
    let world = world();
    let first = header_by(&world, &world.laptop, None, 1);
    let plan = plan_header(&world.laptop.device_id, &world.list, Some(&first)).expect("plan");
    let built = build_header(&world.laptop, &plan, &[7u8; 24], &[7u8; 64]);
    assert_eq!(plan.aad(), built.aad());
    assert_eq!(built.revision, 2);
    assert_eq!(built.previous_digest, first.digest());
    built.verify_ciphertext(&[7u8; 64]).expect("digest");
    assert!(built.verify_ciphertext(&[8u8; 64]).is_err());
}

#[test]
fn an_upload_receipt_for_another_header_is_refused() {
    let world = world();
    let first = header_by(&world, &world.laptop, None, 1);
    let other = header_by(&world, &world.laptop, None, 2);
    let accepted = served(&world, &first);
    let key = instance_key(&world);
    assert!(verify_accepted(
        &first,
        &accepted.digest,
        1,
        &accepted.receipt,
        &accepted.accepted_at,
        &key
    )
    .is_ok());
    assert!(verify_accepted(
        &other,
        &accepted.digest,
        1,
        &accepted.receipt,
        &accepted.accepted_at,
        &key
    )
    .is_err());
    assert!(verify_accepted(
        &first,
        &accepted.digest,
        2,
        &accepted.receipt,
        &accepted.accepted_at,
        &key
    )
    .is_err());
}

mod join {
    use super::*;
    use crate::sync::pairing::ApproverIdentity;
    use crate::sync::request::KeyPackageV3;

    struct Setup {
        vault_key: [u8; 32],
        approver: DeviceIdentity,
        newcomer: DeviceIdentity,
        entries: Vec<DeviceListEntry>,
        identity: ApproverIdentity,
        package: KeyPackageV3,
    }

    fn setup() -> Setup {
        let approver = identity();
        let newcomer = identity();
        let vault_key = [9u8; 32];
        let first = create_entry(
            &approver,
            VAULT,
            &seal_label(&vault_key, VAULT, &approver.device_id, "Laptop").expect("label"),
        );
        let list = DeviceList::verify(std::slice::from_ref(&first)).expect("create");
        let add = add_entry(
            &approver,
            &list,
            &NewDevice {
                device_id: &newcomer.device_id,
                signing_key: &key(&newcomer),
                package_key: &package_key(&newcomer),
            },
            &seal_label(&vault_key, VAULT, &newcomer.device_id, "Phone").expect("label"),
            1,
        )
        .expect("add");
        let package = approver.sign_key_package(KeyPackageV3 {
            vault_id: VAULT.to_string(),
            sender_device_id: approver.device_id.clone(),
            recipient_device_id: newcomer.device_id.clone(),
            vault_epoch: 1,
            entry_digest: add.digest(),
            ciphertext: URL_SAFE_NO_PAD.encode([3u8; 96]),
            signature: String::new(),
        });
        let identity_view = ApproverIdentity {
            device_id: approver.device_id.clone(),
            signing_key: key(&approver),
            vault_id: VAULT.to_string(),
            head_digest: first.digest(),
        };
        Setup {
            vault_key,
            approver,
            newcomer,
            entries: vec![first, add],
            identity: identity_view,
            package,
        }
    }

    fn check(setup: &Setup) -> JoinCheck<'_> {
        JoinCheck {
            device_id: &setup.newcomer.device_id,
            signing_key: "",
            package_key: "",
            approver: &setup.identity,
        }
    }

    fn run(
        setup: &Setup,
        entries: &[DeviceListEntry],
        package: &KeyPackageV3,
    ) -> Result<(), String> {
        let signing = key(&setup.newcomer);
        let package_key = package_key(&setup.newcomer);
        let mut probe = check(setup);
        probe.signing_key = &signing;
        probe.package_key = &package_key;
        verify_join(&probe, entries, package)
            .map(|_| ())
            .map_err(|error| error.to_string())
    }

    #[test]
    fn an_honest_service_lets_the_device_join() {
        let setup = setup();
        assert_eq!(run(&setup, &setup.entries, &setup.package), Ok(()));
        let _ = setup.vault_key;
    }

    #[test]
    fn a_service_that_makes_up_an_approver_cannot_get_a_device_to_join() {
        let setup = setup();
        let attacker = identity();
        let vault_key = [1u8; 32];
        let fake_first = create_entry(
            &attacker,
            VAULT,
            &seal_label(&vault_key, VAULT, &attacker.device_id, "Fake").expect("label"),
        );
        let fake_list = DeviceList::verify(std::slice::from_ref(&fake_first)).expect("fake");
        let fake_add = add_entry(
            &attacker,
            &fake_list,
            &NewDevice {
                device_id: &setup.newcomer.device_id,
                signing_key: &key(&setup.newcomer),
                package_key: &package_key(&setup.newcomer),
            },
            &seal_label(&vault_key, VAULT, &setup.newcomer.device_id, "Phone").expect("label"),
            1,
        )
        .expect("add");
        let package = attacker.sign_key_package(KeyPackageV3 {
            vault_id: VAULT.to_string(),
            sender_device_id: attacker.device_id.clone(),
            recipient_device_id: setup.newcomer.device_id.clone(),
            vault_epoch: 1,
            entry_digest: fake_add.digest(),
            ciphertext: URL_SAFE_NO_PAD.encode([3u8; 96]),
            signature: String::new(),
        });
        let error = run(&setup, &[fake_first, fake_add], &package).unwrap_err();
        assert!(
            error.contains("not the device that gave the code"),
            "{error}"
        );
    }

    #[test]
    fn every_other_way_to_swap_the_vault_or_the_package_is_refused() {
        let setup = setup();
        let other_vault = ApproverIdentity {
            vault_id: "vault0000000000000002".to_string(),
            ..setup.identity.clone()
        };
        let mut probe = check(&setup);
        let signing = key(&setup.newcomer);
        let packaging = package_key(&setup.newcomer);
        probe.signing_key = &signing;
        probe.package_key = &packaging;
        probe.approver = &other_vault;
        assert!(verify_join(&probe, &setup.entries, &setup.package).is_err());

        let moved_head = ApproverIdentity {
            head_digest: setup.entries[1].digest(),
            ..setup.identity.clone()
        };
        probe.approver = &moved_head;
        assert!(verify_join(&probe, &setup.entries, &setup.package).is_err());
        probe.approver = &setup.identity;

        let stranger_keys = ApproverIdentity {
            signing_key: key(&setup.newcomer),
            ..setup.identity.clone()
        };
        probe.approver = &stranger_keys;
        assert!(verify_join(&probe, &setup.entries, &setup.package).is_err());

        assert!(
            run(&setup, &setup.entries[..1], &setup.package).is_err(),
            "never added"
        );

        let mut other_recipient = setup.package.clone();
        other_recipient.recipient_device_id = "deviceSomeoneElse000001".to_string();
        let other_recipient = setup.approver.sign_key_package(KeyPackageV3 {
            signature: String::new(),
            ..other_recipient
        });
        assert!(run(&setup, &setup.entries, &other_recipient).is_err());

        let stale_epoch = setup.approver.sign_key_package(KeyPackageV3 {
            vault_epoch: 5,
            signature: String::new(),
            ..setup.package.clone()
        });
        assert!(run(&setup, &setup.entries, &stale_epoch).is_err());

        let forged = KeyPackageV3 {
            ciphertext: URL_SAFE_NO_PAD.encode([4u8; 96]),
            ..setup.package.clone()
        };
        assert!(run(&setup, &setup.entries, &forged).is_err());

        let other_entry = setup.approver.sign_key_package(KeyPackageV3 {
            entry_digest: setup.entries[0].digest(),
            signature: String::new(),
            ..setup.package.clone()
        });
        let error = run(&setup, &setup.entries, &other_entry).unwrap_err();
        assert!(error.contains("different device list entry"), "{error}");
    }
}

mod peers {
    use super::*;
    use crate::sync::checkpoint::Checkpoint;

    const NOW: u64 = 1_800_000_600;

    fn observed(
        world: &World,
        signer: &DeviceIdentity,
        head: Option<&Header>,
        at: u64,
    ) -> Checkpoint {
        signer.sign_checkpoint(Checkpoint::observe(
            &world.list,
            head,
            &signer.device_id,
            at,
        ))
    }

    fn served_checkpoint(checkpoint: Checkpoint) -> ServedCheckpoint {
        ServedCheckpoint { checkpoint }
    }

    fn check(
        world: &World,
        head: Option<&Header>,
        checkpoints: &[ServedCheckpoint],
        history: &[Header],
    ) -> super::super::canonical::ProofResult<Option<u64>> {
        check_peer_checkpoints(
            &world.list,
            head,
            &world.laptop.device_id,
            &PeerView {
                checkpoints,
                history,
            },
            NOW,
        )
    }

    fn grown_list(world: &World) -> DeviceList {
        let phone = identity();
        let label = seal_label(&[9u8; 32], VAULT, &phone.device_id, "Phone").expect("label");
        let entry = add_entry(
            &world.desktop,
            &world.list,
            &NewDevice {
                device_id: &phone.device_id,
                signing_key: &key(&phone),
                package_key: &package_key(&phone),
            },
            &label,
            0,
        )
        .expect("add");
        let mut list = world.list.clone();
        list.extend(&entry).expect("extend");
        list
    }

    #[test]
    fn a_peer_that_saw_the_same_head_confirms_the_vault() {
        let world = world();
        let first = header_by(&world, &world.laptop, None, 1);
        let checkpoint = observed(&world, &world.desktop, Some(&first), NOW - 30);
        let confirmed = check(&world, Some(&first), &[served_checkpoint(checkpoint)], &[]);
        assert_eq!(confirmed, Ok(Some(NOW - 30)));
    }

    #[test]
    fn the_newest_confirmation_wins_and_a_peer_with_no_snapshot_yet_still_counts() {
        let world = world();
        let older = observed(&world, &world.desktop, None, NOW - 500);
        let newer = observed(&world, &world.desktop, None, NOW - 20);
        let confirmed = check(
            &world,
            None,
            &[served_checkpoint(older), served_checkpoint(newer)],
            &[],
        );
        assert_eq!(confirmed, Ok(Some(NOW - 20)));
    }

    #[test]
    fn a_peer_a_little_behind_agrees_when_the_history_matches_and_forks_when_it_does_not() {
        let world = world();
        let first = header_by(&world, &world.laptop, None, 1);
        let second = header_by(&world, &world.desktop, Some(&first), 2);
        let behind = observed(&world, &world.desktop, Some(&first), NOW - 60);
        assert_eq!(
            check(
                &world,
                Some(&second),
                &[served_checkpoint(behind.clone())],
                &[first.clone(), second.clone()]
            ),
            Ok(Some(NOW - 60))
        );

        let other_first = header_by(&world, &world.laptop, None, 7);
        let other_second = header_by(&world, &world.desktop, Some(&other_first), 8);
        let error = check(
            &world,
            Some(&other_second),
            &[served_checkpoint(behind)],
            &[other_first, other_second.clone()],
        )
        .unwrap_err();
        assert_eq!(error.kind, ProofKind::History);
    }

    #[test]
    fn a_peer_too_far_behind_to_compare_is_neither_an_alarm_nor_a_confirmation() {
        let world = world();
        let first = header_by(&world, &world.laptop, None, 1);
        let second = header_by(&world, &world.desktop, Some(&first), 2);
        let behind = observed(&world, &world.desktop, Some(&first), NOW - 60);
        assert_eq!(
            check(&world, Some(&second), &[served_checkpoint(behind)], &[]),
            Ok(None)
        );
    }

    #[test]
    fn a_peer_at_the_same_revision_with_another_digest_raises_the_fork_alarm() {
        let world = world();
        let ours = header_by(&world, &world.laptop, None, 1);
        let theirs = header_by(&world, &world.laptop, None, 2);
        let checkpoint = observed(&world, &world.desktop, Some(&theirs), NOW - 30);
        let error = check(&world, Some(&ours), &[served_checkpoint(checkpoint)], &[]).unwrap_err();
        assert_eq!(error.kind, ProofKind::History);
    }

    #[test]
    fn a_service_that_shows_less_than_a_peer_saw_raises_the_alarm() {
        let world = world();
        let first = header_by(&world, &world.laptop, None, 1);
        let second = header_by(&world, &world.desktop, Some(&first), 2);
        let ahead = observed(&world, &world.desktop, Some(&second), NOW - 30);
        let error = check(
            &world,
            Some(&first),
            &[served_checkpoint(ahead.clone())],
            &[],
        )
        .unwrap_err();
        assert_eq!(error.kind, ProofKind::History);
        let error = check(&world, None, &[served_checkpoint(ahead)], &[]).unwrap_err();
        assert_eq!(error.kind, ProofKind::History);
    }

    #[test]
    fn a_peer_that_saw_a_newer_device_list_than_the_service_shows_raises_the_alarm() {
        let world = world();
        let grown = grown_list(&world);
        let checkpoint = world.desktop.sign_checkpoint(Checkpoint::observe(
            &grown,
            None,
            &world.desktop.device_id,
            NOW - 30,
        ));
        let error = check(&world, None, &[served_checkpoint(checkpoint)], &[]).unwrap_err();
        assert_eq!(error.kind, ProofKind::DeviceList);
    }

    #[test]
    fn a_peer_that_saw_another_device_list_at_the_same_index_raises_the_alarm() {
        let world = world();
        let mut other = Checkpoint::observe(&world.list, None, &world.desktop.device_id, NOW - 30);
        other.device_list_digest = world.list.digest_at(1).expect("first").to_string();
        let signed = world.desktop.sign_checkpoint(other);
        let error = check(&world, None, &[served_checkpoint(signed)], &[]).unwrap_err();
        assert_eq!(error.kind, ProofKind::DeviceList);
    }

    #[test]
    fn a_forged_or_edited_checkpoint_is_invalid_and_never_a_fork_alarm() {
        let world = world();
        let first = header_by(&world, &world.laptop, None, 1);
        let impostor = identity();
        let mut forged = Checkpoint::observe(
            &world.list,
            Some(&first),
            &world.desktop.device_id,
            NOW - 30,
        );
        forged = impostor.sign_checkpoint(forged);
        let error = check(&world, Some(&first), &[served_checkpoint(forged)], &[]).unwrap_err();
        assert_eq!(error.kind, ProofKind::Invalid);

        let mut edited = observed(&world, &world.desktop, Some(&first), NOW - 30);
        edited.observed_at += 1;
        let error = check(&world, Some(&first), &[served_checkpoint(edited)], &[]).unwrap_err();
        assert_eq!(error.kind, ProofKind::Invalid);

        let mut malformed = observed(&world, &world.desktop, Some(&first), NOW - 30);
        malformed.header_digest = "short".to_string();
        let error = check(&world, Some(&first), &[served_checkpoint(malformed)], &[]).unwrap_err();
        assert_eq!(error.kind, ProofKind::Invalid);
    }

    #[test]
    fn strangers_and_this_device_are_ignored() {
        let world = world();
        let first = header_by(&world, &world.laptop, None, 1);
        let stranger = identity();
        let from_stranger = stranger.sign_checkpoint(Checkpoint::observe(
            &world.list,
            Some(&first),
            &stranger.device_id,
            NOW - 30,
        ));
        let own = observed(&world, &world.laptop, Some(&first), NOW - 30);
        assert_eq!(
            check(
                &world,
                Some(&first),
                &[served_checkpoint(from_stranger), served_checkpoint(own)],
                &[]
            ),
            Ok(None)
        );
    }

    #[test]
    fn a_checkpoint_from_the_future_is_not_counted_and_is_not_an_alarm() {
        let world = world();
        let first = header_by(&world, &world.laptop, None, 1);
        let ahead = observed(&world, &world.desktop, Some(&first), NOW + 7_200);
        assert_eq!(
            check(&world, Some(&first), &[served_checkpoint(ahead)], &[]),
            Ok(None)
        );
    }

    #[test]
    fn a_checkpoint_for_another_vault_is_refused() {
        let world = world();
        let mut other = Checkpoint::observe(&world.list, None, &world.desktop.device_id, NOW - 30);
        other.vault_id = "vault0000000000000002".to_string();
        let signed = world.desktop.sign_checkpoint(other);
        let error = check(&world, None, &[served_checkpoint(signed)], &[]).unwrap_err();
        assert_eq!(error.kind, ProofKind::Invalid);
    }

    #[test]
    fn the_headers_to_fetch_start_at_the_oldest_revision_a_peer_names() {
        let world = world();
        let first = header_by(&world, &world.laptop, None, 1);
        let second = header_by(&world, &world.desktop, Some(&first), 2);
        let third = header_by(&world, &world.laptop, Some(&second), 3);
        let at_first = served_checkpoint(observed(&world, &world.desktop, Some(&first), NOW - 30));
        let at_second =
            served_checkpoint(observed(&world, &world.desktop, Some(&second), NOW - 20));
        let own = served_checkpoint(observed(&world, &world.laptop, None, NOW - 20));
        assert_eq!(
            oldest_revision_to_compare(
                Some(&third),
                &world.laptop.device_id,
                &[at_second.clone(), at_first.clone(), own]
            ),
            Some(1)
        );
        assert_eq!(
            oldest_revision_to_compare(Some(&second), &world.laptop.device_id, &[at_second]),
            None
        );
        assert_eq!(
            oldest_revision_to_compare(None, &world.laptop.device_id, &[at_first]),
            None
        );
    }
}

mod removal_packages {
    use super::*;
    use crate::sync::request::KeyPackageV3;

    fn package_for(
        world: &World,
        signer: &DeviceIdentity,
        epoch: u64,
        entry_digest: &str,
    ) -> KeyPackageV3 {
        signer.sign_key_package(KeyPackageV3 {
            vault_id: VAULT.to_string(),
            sender_device_id: signer.device_id.clone(),
            recipient_device_id: world.desktop.device_id.clone(),
            vault_epoch: epoch,
            entry_digest: entry_digest.to_string(),
            ciphertext: URL_SAFE_NO_PAD.encode([3u8; 96]),
            signature: String::new(),
        })
    }

    #[test]
    fn a_survivor_takes_a_key_only_from_the_removal_that_made_it() {
        let world = world();
        let removal = remove_entry(&world.laptop, &world.list, "deviceSomeoneElse000001")
            .expect("removal entry");
        let mut entries = world.entries.clone();
        entries.push(removal.clone());
        let epoch = removal.epoch_after;

        let bound = package_for(&world, &world.laptop, epoch, &removal.digest());
        assert!(verify_package_for_removal(&entries, &bound).is_ok());

        let earlier_attempt = package_for(&world, &world.laptop, epoch, &entries[0].digest());
        let error = verify_package_for_removal(&entries, &earlier_attempt).unwrap_err();
        assert!(error.to_string().contains("different device list entry"));

        let from_someone_else = package_for(&world, &world.desktop, epoch, &removal.digest());
        assert!(verify_package_for_removal(&entries, &from_someone_else).is_err());

        let for_another_epoch = package_for(&world, &world.laptop, epoch + 1, &removal.digest());
        assert!(verify_package_for_removal(&entries, &for_another_epoch).is_err());

        assert!(verify_package_for_removal(&world.entries, &bound).is_err());
    }
}
