use super::devicelist::DeviceListEntry;
use super::fuzz_entry::{device_list, envelope, key_package, pairing_message};
use super::header::Header;
use super::keys::{seal_vault_key, seal_vault_key_hybrid, EncryptionKeypair};
use super::pake::Offer;
use super::xwing::{SecretKey, SEED_BYTES};

const ITERATIONS: usize = 4_000;

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, limit: usize) -> usize {
        if limit == 0 {
            return 0;
        }
        usize::try_from(self.next() % limit as u64).unwrap_or(0)
    }
}

fn mutate(seed: &[u8], rng: &mut Rng) -> Vec<u8> {
    let mut data = seed.to_vec();
    for _ in 0..=rng.below(4) {
        match rng.below(6) {
            0 if !data.is_empty() => {
                let at = rng.below(data.len());
                data[at] ^= 1 << rng.below(8);
            }
            1 if !data.is_empty() => {
                let at = rng.below(data.len());
                data[at] = rng.next() as u8;
            }
            2 => {
                let keep = rng.below(data.len() + 1);
                data.truncate(keep);
            }
            3 => {
                let at = rng.below(data.len() + 1);
                let extra: Vec<u8> = (0..=rng.below(16)).map(|_| rng.next() as u8).collect();
                data.splice(at..at, extra);
            }
            4 if !data.is_empty() => {
                let from = rng.below(data.len());
                let to = (from + rng.below(32)).min(data.len());
                let chunk = data[from..to].to_vec();
                let at = rng.below(data.len() + 1);
                data.splice(at..at, chunk);
            }
            _ if data.len() > 1 => {
                let at = rng.below(data.len() - 1);
                data.remove(at);
            }
            _ => {}
        }
    }
    data
}

fn fixture() -> serde_json::Value {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("contracts")
        .join("sync")
        .join("v3")
        .join("v3-fixture.json");
    serde_json::from_slice(&std::fs::read(path).expect("read the fixture")).expect("parse")
}

#[test]
fn mutated_headers_never_panic_and_never_verify_as_anything_else() {
    let fixture = fixture();
    let original: Header =
        serde_json::from_value(fixture["headers"][2]["header"].clone()).expect("header");
    let seed = serde_json::to_vec(&original).expect("encode");
    assert_eq!(envelope(&seed).as_ref(), Some(&original));
    let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
    for _ in 0..ITERATIONS {
        let data = mutate(&seed, &mut rng);
        if let Some(accepted) = envelope(&data) {
            assert_eq!(accepted, original, "a changed header verified");
        }
    }
}

#[test]
fn mutated_key_packages_never_panic_and_only_the_exact_package_opens() {
    let recipient = EncryptionKeypair::from_secret_bytes([7u8; 32]);
    let package =
        seal_vault_key(&[9u8; 32], &recipient.public_key(), "vaultAAAAAAAAAAAA01").expect("seal");
    assert_eq!(key_package(&package), Some(vec![9u8; 32]));
    let mut rng = Rng(0x1234_5678_9abc_def1);
    for _ in 0..ITERATIONS {
        let data = mutate(&package, &mut rng);
        if key_package(&data).is_some() {
            assert_eq!(data, package, "a changed package opened");
        }
    }
    let wrapper = serde_json::json!({
        "vaultId": "vaultAAAAAAAAAAAA01", "senderDeviceId": "deviceAAAAAAAAAAAA01",
        "recipientDeviceId": "deviceBBBBBBBBBBBB01", "vaultEpoch": 1,
        "ciphertext": "AAAAAAAAAAAAAAAAAAAAAAAA", "signature": "AAAA",
    });
    let seed = serde_json::to_vec(&wrapper).expect("encode");
    for _ in 0..ITERATIONS {
        let _ = key_package(&mutate(&seed, &mut rng));
    }
}

#[test]
fn mutated_hybrid_key_packages_never_panic_and_only_the_exact_package_opens() {
    let recipient = SecretKey::from_seed([7u8; SEED_BYTES]);
    let package = seal_vault_key_hybrid(
        &[9u8; 32],
        &recipient.public_key(),
        "vaultAAAAAAAAAAAA01",
        1,
    )
    .expect("seal");
    assert_eq!(key_package(&package), Some(vec![9u8; 32]));
    let mut rng = Rng(0x2468_ace0_1357_9bdf);
    for _ in 0..ITERATIONS {
        let data = mutate(&package, &mut rng);
        if key_package(&data).is_some() {
            assert_eq!(data, package, "a changed hybrid package opened");
        }
    }
}

#[test]
fn mutated_device_lists_never_panic_and_never_verify_as_another_list() {
    let fixture = fixture();
    let chain: Vec<DeviceListEntry> = fixture["chain"]
        .as_array()
        .expect("chain")
        .iter()
        .map(|item| serde_json::from_value(item["entry"].clone()).expect("entry"))
        .collect();
    let seed = serde_json::to_vec(&chain).expect("encode");
    assert_eq!(device_list(&seed), Some(3));
    let mut rng = Rng(0x0fed_cba9_8765_4321);
    for _ in 0..ITERATIONS {
        let data = mutate(&seed, &mut rng);
        if device_list(&data).is_some() {
            let parsed: Vec<DeviceListEntry> =
                serde_json::from_slice(&data).expect("an accepted list parses");
            assert_eq!(parsed, chain, "a changed device list verified");
        }
    }
    let single = serde_json::to_vec(&chain[1]).expect("encode");
    for _ in 0..ITERATIONS {
        let _ = device_list(&mutate(&single, &mut rng));
    }
}

#[test]
fn mutated_pairing_messages_never_panic() {
    let offer = Offer::begin("ABCDEFGHJK", b"new device").expect("offer");
    let mut rng = Rng(0xdead_beef_cafe_f00d);
    for _ in 0..ITERATIONS {
        pairing_message(&mutate(&offer.message, &mut rng));
    }
    pairing_message(&[]);
    pairing_message(&[0u8; 4096]);
}
