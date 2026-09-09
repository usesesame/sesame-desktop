use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use rand::rngs::StdRng;
use rand::{RngExt, SeedableRng};
use sesame_core::imports::parse_import_entries;
use sesame_core::loader::VaultLoader;
use sesame_core::types::CipherBlob;

const IMPORT_SOURCES: &[&str] = &[
    "bitwarden-csv",
    "bitwarden-json",
    "otpauth-txt",
    "aegis-json",
    "2fas-json",
    "lastpass-csv",
    "dashlane-csv",
    "onepassword-csv",
    "keepass-csv",
    "chrome-csv",
    "edge-csv",
    "brave-csv",
    "google-csv",
    "apple-csv",
    "firefox-csv",
    "proton-pass-csv",
    "keeper-csv",
    "nordpass-csv",
];

const MAX_MUTATED_BYTES: usize = 16 * 1024;

struct Mutator {
    rng: StdRng,
}

impl Mutator {
    fn new(seed: u64) -> Self {
        Self {
            rng: StdRng::seed_from_u64(seed),
        }
    }

    fn random_bytes(&mut self, length: usize) -> Vec<u8> {
        let mut bytes = vec![0_u8; length];
        for byte in bytes.iter_mut() {
            *byte = self.rng.random();
        }
        bytes
    }

    fn mutate(&mut self, input: &[u8]) -> Vec<u8> {
        let mut data = input.to_vec();
        for _ in 0..self.rng.random_range(1..=4) {
            if data.is_empty() {
                let extra = self.rng.random_range(1..=64);
                data = self.random_bytes(extra);
                continue;
            }
            match self.rng.random_range(0..8) {
                0 => {
                    let index = self.rng.random_range(0..data.len());
                    data[index] ^= 1 << self.rng.random_range(0..8);
                }
                1 => {
                    let index = self.rng.random_range(0..data.len());
                    data[index] = self.rng.random();
                }
                2 => {
                    let cut = self.rng.random_range(0..data.len());
                    data.truncate(cut);
                }
                3 => {
                    let length = self.rng.random_range(1..=256);
                    let extra = self.random_bytes(length);
                    data.extend_from_slice(&extra);
                }
                4 => {
                    let start = self.rng.random_range(0..data.len());
                    let end = self.rng.random_range(start..data.len());
                    let slice = data[start..end].to_vec();
                    let at = self.rng.random_range(0..=data.len());
                    data.splice(at..at, slice);
                }
                5 => {
                    let start = self.rng.random_range(0..data.len());
                    let end = self.rng.random_range(start..data.len());
                    for byte in &mut data[start..end] {
                        *byte = 0;
                    }
                }
                6 => {
                    let at = self.rng.random_range(0..=data.len());
                    let length = self.rng.random_range(1..=32);
                    let extra = self.random_bytes(length);
                    data.splice(at..at, extra);
                }
                _ => {
                    let fill = self.rng.random();
                    for byte in data.iter_mut() {
                        *byte = fill;
                    }
                }
            }
            if data.len() > MAX_MUTATED_BYTES {
                data.truncate(MAX_MUTATED_BYTES);
            }
        }
        data
    }
}

fn structured_seeds() -> Vec<&'static [&'static [u8]]> {
    vec![
        &[
            b"{\"version\":10,\"nonce\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\",\"ciphertext\":\"AAAA\"}" as &[u8],
            b"{\"entries\":[{\"login\":{\"username\":\"user\",\"password\":\"pass\"}}]}",
        ],
        &[
            b"title,url,username,password\nsite,https://site.test,user,pass\n",
            b"otpauth://totp/Site:user?secret=JBSWY3DPEHPK3PXP&issuer=Site\n",
        ],
        &[b"AAAA", b"{", b"\x00\x01\x02\x03", b"1.2.3"],
    ]
}

#[test]
fn the_inspector_survives_every_mutation_of_plausible_envelopes() {
    for seed_group in structured_seeds() {
        for (seed, candidate) in seed_group.iter().enumerate() {
            let mut mutator = Mutator::new(1000 + seed as u64);
            for _ in 0..150 {
                let mutated = mutator.mutate(candidate);
                let _ = VaultLoader::inspect(&mutated);
            }
        }
    }
    let mut mutator = Mutator::new(7);
    for _ in 0..200 {
        let length = mutator.rng.random_range(0..=MAX_MUTATED_BYTES);
        let random = mutator.random_bytes(length);
        let _ = VaultLoader::inspect(&random);
    }
    assert!(VaultLoader::inspect(&[]).is_err());
}

#[test]
fn snapshot_opening_reports_typed_failures_instead_of_panics() {
    let key = [7_u8; 32];
    let mut mutator = Mutator::new(31);
    for _ in 0..250 {
        let nonce = match mutator.rng.random_range(0..4) {
            0 => {
                let length = mutator.rng.random_range(0..=64);
                URL_SAFE_NO_PAD.encode(mutator.random_bytes(length))
            }
            1 => String::new(),
            2 => URL_SAFE_NO_PAD.encode(mutator.random_bytes(24)),
            _ => "not base64!!!".to_string(),
        };
        let ciphertext = match mutator.rng.random_range(0..3) {
            0 => {
                let length = mutator.rng.random_range(0..=512);
                URL_SAFE_NO_PAD.encode(mutator.random_bytes(length))
            }
            1 => String::new(),
            _ => "%%%".to_string(),
        };
        let blob = CipherBlob { nonce, ciphertext };
        let result = VaultLoader::open_snapshot(2, &key, &blob, &mutator.random_bytes(16));
        if let Ok(authenticated) = result {
            let _ = authenticated.payload();
        }
    }
    for version in [0_u32, 1, 3, u32::MAX] {
        let blob = CipherBlob {
            nonce: String::new(),
            ciphertext: String::new(),
        };
        assert!(VaultLoader::open_snapshot(version, &key, &blob, &[]).is_err());
    }
}

#[test]
fn import_parsers_survive_mutations_of_every_supported_source() {
    let seeds: Vec<(&str, &[u8])> = vec![
        ("json", b"{\"items\":[{\"login\":{\"username\":\"user\",\"password\":\"pass\",\"totp\":\"JBSWY3DPEHPK3PXP\"}}],\"folders\":[]}"),
        ("csv", b"title,url,username,password,note\nsite,https://site.test,user,pass,note\n"),
        ("otpauth", b"otpauth://totp/Site:user?secret=JBSWY3DPEHPK3PXP&issuer=Site\n"),
        ("text", b"name\tsite\tuser\tpass\textra\n"),
    ];
    let mut mutator = Mutator::new(97);
    for source in IMPORT_SOURCES {
        for (_, seed) in &seeds {
            for _ in 0..12 {
                let mutated = mutator.mutate(seed);
                let content = String::from_utf8_lossy(&mutated).into_owned();
                let _ = parse_import_entries(&content, source);
            }
        }
    }
    for _ in 0..200 {
        let length = mutator.rng.random_range(0..=4096);
        let random = mutator.random_bytes(length);
        let content = String::from_utf8_lossy(&random).into_owned();
        let source = IMPORT_SOURCES[mutator.rng.random_range(0..IMPORT_SOURCES.len())];
        let _ = parse_import_entries(&content, source);
    }
}

#[test]
fn the_import_size_limit_rejects_oversized_files_before_parsing() {
    let oversized = "a".repeat(25 * 1024 * 1024 + 1);
    assert!(parse_import_entries(&oversized, "bitwarden-csv").is_err());
}

#[test]
fn every_source_rejects_an_empty_import_with_a_typed_error() {
    for source in IMPORT_SOURCES {
        assert!(
            parse_import_entries("", source).is_err(),
            "{source} accepted an empty file"
        );
    }
}
