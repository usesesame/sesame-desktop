//! The boundary from bounded, untrusted envelopes to authenticated vault contents.

use std::{fmt, io::Read, path::Path};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use zeroize::Zeroizing;

use crate::{
    api::OpenedVault,
    crypto::{decrypt_bytes, derive_key, validate_kdf_params},
    migration::{migrate_payload, migrate_vault_file, MIN_SUPPORTED_VAULT_FORMAT},
    payload_aad_for_file, CipherBlob, VaultFile, VaultPayload, MAX_VAULT_FILE_BYTES,
    RECOVERY_WRAP_AAD, VAULT_FORMAT_VERSION, WRAP_AAD,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LoadFailure {
    WrongPassword,
    WrongRecoveryKit,
    WrongSecret,
    Authentication,
    RecoveryRequired { format: u8 },
    NewerFormat { format: u8 },
    UnsupportedFormat { format: u8 },
    InvalidStructure,
    UnsafeKdf,
    SizeLimit,
    LocalIo,
}

impl fmt::Display for LoadFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::WrongPassword => "Sesame could not unlock this vault. Check your master password.",
            Self::WrongRecoveryKit => "That recovery kit is not correct.",
            Self::WrongSecret => "That master password or recovery kit does not open this backup.",
            Self::Authentication => "The vault data could not be authenticated. Restore a known-good encrypted backup.",
            Self::RecoveryRequired { .. } => "The authenticated vault schema needs a recovery path. Keep the original backup and contact support.",
            Self::NewerFormat { .. } => "This vault requires a newer version of Sesame.",
            Self::UnsupportedFormat { .. } => "This vault uses a format Sesame does not understand yet.",
            Self::InvalidStructure => "This vault file is not valid. Restore a known-good encrypted backup.",
            Self::UnsafeKdf => "The vault key-derivation settings are outside Sesame's safe limits.",
            Self::SizeLimit => "This vault file exceeds Sesame's size limit.",
            Self::LocalIo => "Sesame could not read the vault file.",
        })
    }
}

impl std::error::Error for LoadFailure {}

impl From<LoadFailure> for String {
    fn from(value: LoadFailure) -> Self {
        value.to_string()
    }
}

pub type LoadResult<T> = Result<T, LoadFailure>;

pub enum Credential<'a> {
    MasterPassword(&'a str),
    RecoveryKit(&'a str),
    /// Preserves the existing backup/FFI single-field credential contract.
    PasswordOrRecoveryKit(&'a str),
    /// The host has already authorized and opened a PIN or device wrapper.
    VaultKey(&'a [u8; 32]),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FormatState {
    Current,
    NeedsMigration,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Inspection {
    pub format: u8,
    pub state: FormatState,
    pub setup_complete: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MigrationPlan {
    pub source_format: u8,
    pub target_format: u8,
    pub envelope_changed: bool,
    pub payload_changed: bool,
}

impl MigrationPlan {
    pub fn required(self) -> bool {
        self.envelope_changed || self.payload_changed
    }
}

pub struct AuthenticatedPayload {
    bytes: Zeroizing<Vec<u8>>,
    payload: Zeroizing<VaultPayload>,
}

impl AuthenticatedPayload {
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn payload(&self) -> &VaultPayload {
        &self.payload
    }
}

pub struct VaultLoader;

impl VaultLoader {
    pub fn read(path: &Path) -> LoadResult<VaultFile> {
        let bytes = Self::read_bytes(path)?;
        Self::parse(&bytes)
    }

    pub fn read_bytes(path: &Path) -> LoadResult<Zeroizing<Vec<u8>>> {
        let file = std::fs::File::open(path).map_err(|_| LoadFailure::LocalIo)?;
        if file.metadata().map_err(|_| LoadFailure::LocalIo)?.len() > MAX_VAULT_FILE_BYTES {
            return Err(LoadFailure::SizeLimit);
        }
        let mut bytes = Vec::new();
        file.take(MAX_VAULT_FILE_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| LoadFailure::LocalIo)?;
        if bytes.len() as u64 > MAX_VAULT_FILE_BYTES {
            return Err(LoadFailure::SizeLimit);
        }
        Ok(Zeroizing::new(bytes))
    }

    pub fn parse(bytes: &[u8]) -> LoadResult<VaultFile> {
        if bytes.len() as u64 > MAX_VAULT_FILE_BYTES {
            return Err(LoadFailure::SizeLimit);
        }
        let file = serde_json::from_slice(bytes).map_err(|_| LoadFailure::InvalidStructure)?;
        Self::validate(&file)?;
        Ok(file)
    }

    pub fn inspect(bytes: &[u8]) -> LoadResult<Inspection> {
        let file = Self::parse(bytes)?;
        Ok(Inspection {
            format: file.format_version,
            state: if file.format_version < VAULT_FORMAT_VERSION {
                FormatState::NeedsMigration
            } else {
                FormatState::Current
            },
            setup_complete: file.setup_complete,
        })
    }

    pub fn validate(file: &VaultFile) -> LoadResult<()> {
        let format = file.format_version;
        if format > VAULT_FORMAT_VERSION {
            return Err(LoadFailure::NewerFormat { format });
        }
        if format < MIN_SUPPORTED_VAULT_FORMAT {
            return Err(LoadFailure::UnsupportedFormat { format });
        }
        payload_aad_for_file(format, file.setup_complete)
            .map_err(|_| LoadFailure::InvalidStructure)?;
        for kdf in std::iter::once(&file.kdf)
            .chain(file.recovery_kdf.iter())
            .chain(file.pin_wrap.iter().map(|wrap| &wrap.kdf))
        {
            validate_kdf_params(kdf).map_err(|_| LoadFailure::UnsafeKdf)?;
            argon2::Params::new(kdf.memory_kib, kdf.iterations, kdf.parallelism, Some(32))
                .map_err(|_| LoadFailure::UnsafeKdf)?;
        }
        if file.recovery_kdf.is_some() != file.recovery_wrap.is_some() {
            return Err(LoadFailure::InvalidStructure);
        }
        for blob in std::iter::once(&file.key_wrap)
            .chain(std::iter::once(&file.payload))
            .chain(file.recovery_wrap.iter())
            .chain(file.pin_wrap.iter().map(|wrap| &wrap.key_wrap))
        {
            validate_blob(blob)?;
        }
        Ok(())
    }

    pub fn load(bytes: &[u8], credential: Credential<'_>) -> LoadResult<OpenedVault> {
        Self::open(&Self::parse(bytes)?, credential)
    }

    pub fn unwrap_key(
        file: &VaultFile,
        credential: Credential<'_>,
    ) -> LoadResult<Zeroizing<[u8; 32]>> {
        Self::validate(file)?;
        match credential {
            Credential::VaultKey(key) => Ok(Zeroizing::new(*key)),
            Credential::MasterPassword(password) => unwrap(
                password,
                &file.kdf,
                &file.key_wrap,
                WRAP_AAD,
                LoadFailure::WrongPassword,
            ),
            Credential::RecoveryKit(kit) => {
                let normalized = Zeroizing::new(kit.trim().to_ascii_uppercase());
                match (&file.recovery_kdf, &file.recovery_wrap) {
                    (Some(kdf), Some(wrap)) => unwrap(
                        &normalized,
                        kdf,
                        wrap,
                        RECOVERY_WRAP_AAD,
                        LoadFailure::WrongRecoveryKit,
                    ),
                    _ if file.format_version < VAULT_FORMAT_VERSION => unwrap(
                        &normalized,
                        &file.kdf,
                        &file.key_wrap,
                        WRAP_AAD,
                        LoadFailure::WrongRecoveryKit,
                    ),
                    _ => Err(LoadFailure::InvalidStructure),
                }
            }
            Credential::PasswordOrRecoveryKit(secret) => {
                match Self::unwrap_key(file, Credential::MasterPassword(secret)) {
                    Err(LoadFailure::WrongPassword) => {
                        match Self::unwrap_key(file, Credential::RecoveryKit(secret)) {
                            Err(LoadFailure::WrongRecoveryKit | LoadFailure::InvalidStructure) => {
                                Err(LoadFailure::WrongSecret)
                            }
                            other => other,
                        }
                    }
                    other => other,
                }
            }
        }
    }

    pub fn authenticate(
        file: &VaultFile,
        credential: Credential<'_>,
    ) -> LoadResult<AuthenticatedPayload> {
        let key = Self::unwrap_key(file, credential)?;
        authenticate_payload(file, &key)
    }

    pub fn open(file: &VaultFile, credential: Credential<'_>) -> LoadResult<OpenedVault> {
        let key = Self::unwrap_key(file, credential)?;
        let authenticated = authenticate_payload(file, &key)?;
        let mut payload = authenticated.payload().clone();
        let mut next_file = file.clone();
        let envelope_changed =
            migrate_vault_file(&mut next_file).map_err(|_| LoadFailure::UnsupportedFormat {
                format: file.format_version,
            })?;
        let payload_changed = migrate_payload(&mut payload);
        let migration = MigrationPlan {
            source_format: file.format_version,
            target_format: next_file.format_version,
            envelope_changed,
            payload_changed,
        };
        Ok(OpenedVault {
            key,
            payload,
            file: next_file,
            migrated: migration.required(),
            migration,
        })
    }

    /// Sync signatures, membership, revision and epoch checks remain at the host seam.
    /// The caller supplies the exact protocol AAD, never a fallback vault-file label.
    pub fn open_snapshot(
        version: u32,
        key: &[u8; 32],
        blob: &CipherBlob,
        aad: &[u8],
    ) -> LoadResult<AuthenticatedPayload> {
        if version != 2 {
            return Err(LoadFailure::InvalidStructure);
        }
        validate_blob(blob)?;
        let bytes =
            Zeroizing::new(decrypt_bytes(key, blob, aad).map_err(|_| LoadFailure::Authentication)?);
        decode(bytes, VAULT_FORMAT_VERSION)
    }
}

fn authenticate_payload(file: &VaultFile, key: &[u8; 32]) -> LoadResult<AuthenticatedPayload> {
    let aad = payload_aad_for_file(file.format_version, file.setup_complete)
        .map_err(|_| LoadFailure::InvalidStructure)?;
    let bytes = Zeroizing::new(
        decrypt_bytes(key, &file.payload, aad).map_err(|_| LoadFailure::Authentication)?,
    );
    decode(bytes, file.format_version)
}

fn decode(bytes: Zeroizing<Vec<u8>>, format: u8) -> LoadResult<AuthenticatedPayload> {
    let payload =
        serde_json::from_slice(&bytes).map_err(|_| LoadFailure::RecoveryRequired { format })?;
    Ok(AuthenticatedPayload {
        bytes,
        payload: Zeroizing::new(payload),
    })
}

fn unwrap(
    secret: &str,
    kdf: &crate::KdfParams,
    blob: &CipherBlob,
    aad: &[u8],
    failure: LoadFailure,
) -> LoadResult<Zeroizing<[u8; 32]>> {
    let wrapping_key = Zeroizing::new(derive_key(secret, kdf).map_err(|_| LoadFailure::UnsafeKdf)?);
    // AEAD cannot distinguish an incorrect credential from a damaged wrapper.
    let bytes = Zeroizing::new(decrypt_bytes(&wrapping_key, blob, aad).map_err(|_| failure)?);
    bytes
        .as_slice()
        .try_into()
        .map(Zeroizing::new)
        .map_err(|_| LoadFailure::InvalidStructure)
}

fn validate_blob(blob: &CipherBlob) -> LoadResult<()> {
    if blob.ciphertext.len() as u64 > MAX_VAULT_FILE_BYTES || blob.nonce.len() > 32 {
        return Err(LoadFailure::SizeLimit);
    }
    let nonce = URL_SAFE_NO_PAD
        .decode(&blob.nonce)
        .map_err(|_| LoadFailure::InvalidStructure)?;
    let ciphertext = URL_SAFE_NO_PAD
        .decode(&blob.ciphertext)
        .map_err(|_| LoadFailure::InvalidStructure)?;
    if nonce.len() != 24 || ciphertext.len() < 16 {
        return Err(LoadFailure::InvalidStructure);
    }
    Ok(())
}
