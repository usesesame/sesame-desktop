use std::fs;
use std::path::PathBuf;

use sesame_core::api::create_vault;
use sesame_core::loader::VaultLoader;
use sesame_core::platform::protect_for_device;
use sesame_core::storage::{
    persist_session, remove_hello_for_session, remove_pin_for_session, set_hello_for_session,
    set_pin_for_session,
};
use sesame_core::{random_id, HelloWrap, PinWrap, UnlockedVault};

const PASSWORD: &str = "fictional master password";
const PIN: &str = "472913";

fn test_directory(name: &str) -> PathBuf {
    let directory = std::env::temp_dir().join(format!("sesame-wrap-prev-{name}-{}", random_id()));
    fs::create_dir_all(&directory).expect("test directory");
    directory
}

fn unlocked_session(path: &PathBuf) -> UnlockedVault {
    let (opened, _) = create_vault(PASSWORD, "Fictional vault").expect("created vault");
    let mut session = UnlockedVault::from_opened(path.clone(), &opened).expect("session");
    session.setup_complete = true;
    session
}

fn fictional_hello_wrap() -> HelloWrap {
    HelloWrap {
        key_name: "sesame-vault-hello-fictional".to_string(),
        ciphertext: "ZmljdGlvbmFsIGhlbGxvIGNpcGhlcnRleHQ".to_string(),
    }
}

#[test]
fn setting_then_removing_a_pin_leaves_no_previous_copy() {
    let directory = test_directory("pin");
    let path = directory.join("vault.sesame");
    let previous = path.with_extension("sesame.prev");
    let mut session = unlocked_session(&path);

    persist_session(&mut session).expect("initial save");
    persist_session(&mut session).expect("create a previous copy");
    assert!(previous.exists());

    let device_protection = protect_for_device(b"fictional device protection probe");
    let set_result = set_pin_for_session(&mut session, PIN);
    if device_protection.is_err() {
        assert!(
            set_result.is_err(),
            "a vault without device protection accepted a PIN"
        );
        assert!(session.pin_wrap.is_none());
        assert!(
            VaultLoader::read(&path)
                .expect("read vault")
                .pin_wrap
                .is_none(),
            "the saved vault gained a PIN wrap without device protection"
        );
        fs::remove_dir_all(&directory).expect("cleanup");
        return;
    }
    set_result.expect("set pin");

    assert!(session.pin_wrap.is_some());
    assert!(
        VaultLoader::read(&path)
            .expect("read vault")
            .pin_wrap
            .is_some(),
        "the saved vault lost the PIN wrap"
    );
    assert!(!previous.exists(), "setting a PIN left a previous copy");

    persist_session(&mut session).expect("create a previous copy");
    assert!(previous.exists());

    remove_pin_for_session(&mut session).expect("remove pin");

    assert!(session.pin_wrap.is_none());
    assert!(
        VaultLoader::read(&path)
            .expect("read vault")
            .pin_wrap
            .is_none(),
        "the saved vault kept the removed PIN wrap"
    );
    assert!(!previous.exists(), "removing a PIN left a previous copy");
    fs::remove_dir_all(&directory).expect("cleanup");
}

#[test]
fn removing_a_pin_removes_an_existing_previous_copy() {
    let directory = test_directory("pin-remove");
    let path = directory.join("vault.sesame");
    let previous = path.with_extension("sesame.prev");
    let mut session = unlocked_session(&path);
    session.pin_wrap = Some(PinWrap {
        kdf: session.kdf.clone(),
        protected_pepper: "ZmljdGlvbmFs".to_string(),
        key_wrap: session.key_wrap.clone(),
    });

    persist_session(&mut session).expect("save with a pin wrap");
    persist_session(&mut session).expect("create a previous copy");
    assert!(previous.exists());

    remove_pin_for_session(&mut session).expect("remove pin");

    assert!(session.pin_wrap.is_none());
    assert!(
        VaultLoader::read(&path)
            .expect("read vault")
            .pin_wrap
            .is_none(),
        "the saved vault kept the removed PIN wrap"
    );
    assert!(!previous.exists(), "removing a PIN left a previous copy");
    fs::remove_dir_all(&directory).expect("cleanup");
}

#[test]
fn setting_then_removing_a_hello_wrap_leaves_no_previous_copy() {
    let directory = test_directory("hello");
    let path = directory.join("vault.sesame");
    let previous = path.with_extension("sesame.prev");
    let mut session = unlocked_session(&path);

    persist_session(&mut session).expect("initial save");
    persist_session(&mut session).expect("create a previous copy");
    assert!(previous.exists());

    set_hello_for_session(&mut session, fictional_hello_wrap()).expect("set hello");

    assert!(session.hello_wrap.is_some());
    assert!(
        VaultLoader::read(&path)
            .expect("read vault")
            .hello_wrap
            .is_some(),
        "the saved vault lost the Hello wrap"
    );
    assert!(
        !previous.exists(),
        "setting a Hello wrap left a previous copy"
    );

    persist_session(&mut session).expect("create a previous copy");
    assert!(previous.exists());

    remove_hello_for_session(&mut session).expect("remove hello");

    assert!(session.hello_wrap.is_none());
    assert!(
        VaultLoader::read(&path)
            .expect("read vault")
            .hello_wrap
            .is_none(),
        "the saved vault kept the removed Hello wrap"
    );
    assert!(
        !previous.exists(),
        "removing a Hello wrap left a previous copy"
    );
    fs::remove_dir_all(&directory).expect("cleanup");
}
