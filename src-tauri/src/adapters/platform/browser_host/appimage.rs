use std::fs::{self, File, OpenOptions};
use std::io::{self, ErrorKind, Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::{RegistrationError, HOST_FILE_NAME};

const RECORD_FILE_NAME: &str = "app.json";
const MAX_RECORD_BYTES: u64 = 4096;
const DIRECTORY_MODE: u32 = 0o700;
const HOST_MODE: u32 = 0o700;
const RECORD_MODE: u32 = 0o600;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecutableIdentity {
    bytes: u64,
    sha256: [u8; 32],
}

impl ExecutableIdentity {
    fn of_reader(mut reader: impl Read) -> io::Result<Self> {
        let mut hasher = Sha256::new();
        let mut bytes = 0_u64;
        let mut chunk = vec![0_u8; 64 * 1024];
        loop {
            let read = match reader.read(&mut chunk) {
                Ok(0) => break,
                Ok(read) => read,
                Err(error) if error.kind() == ErrorKind::Interrupted => continue,
                Err(error) => return Err(error),
            };
            hasher.update(&chunk[..read]);
            bytes += read as u64;
        }
        Ok(Self {
            bytes,
            sha256: hasher.finalize().into(),
        })
    }

    pub fn of_file(path: &Path) -> io::Result<Self> {
        Self::of_reader(File::open(path)?)
    }

    pub fn matches_file(&self, file: File) -> io::Result<bool> {
        if file.metadata()?.len() != self.bytes {
            return Ok(false);
        }
        Ok(&Self::of_reader(file.take(self.bytes))? == self)
    }

    pub fn key(&self) -> (u64, [u8; 32]) {
        (self.bytes, self.sha256)
    }
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AppRecord {
    app_image: PathBuf,
}

pub fn running_from_appimage() -> bool {
    std::env::var_os("APPIMAGE").is_some_and(|value| !value.is_empty())
}

pub fn stage_directory() -> Option<PathBuf> {
    let data = std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .or_else(|| {
            std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".local").join("share"))
        })?;
    Some(data.join("sesame").join("browser-host"))
}

pub fn staged_host() -> Option<PathBuf> {
    stage_directory().map(|directory| directory.join(HOST_FILE_NAME))
}

pub fn staged_files() -> Vec<PathBuf> {
    stage_directory()
        .map(|directory| {
            vec![
                directory.join(HOST_FILE_NAME),
                directory.join(RECORD_FILE_NAME),
            ]
        })
        .unwrap_or_default()
}

pub fn stage_running_app() -> Result<(), RegistrationError> {
    let app = std::env::current_exe().map_err(|_| host_missing())?;
    let source = app.with_file_name(HOST_FILE_NAME);
    let image = std::env::var_os("APPIMAGE")
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .ok_or_else(|| {
            RegistrationError::new(
                "registration_manifest_failed",
                "Sesame could not locate its AppImage file.",
            )
        })?;
    let directory = stage_directory().ok_or_else(|| {
        RegistrationError::new(
            "registration_manifest_failed",
            "Sesame could not locate your home directory.",
        )
    })?;
    stage_into(&directory, &source, &image)
}

pub fn launch_target_beside(host: &Path) -> Option<PathBuf> {
    let directory = stage_directory()?;
    let app_image = staged_app_image_in(&directory, host).ok().flatten()?;
    app_image.is_file().then_some(app_image)
}

fn stage_into(
    directory: &Path,
    source_host: &Path,
    app_image: &Path,
) -> Result<(), RegistrationError> {
    let host_bytes = fs::read(source_host).map_err(|_| host_missing())?;
    prepare_directory(directory)?;
    replace_file(directory, HOST_FILE_NAME, &host_bytes, HOST_MODE)?;
    let record = serde_json::to_vec_pretty(&AppRecord {
        app_image: app_image.to_path_buf(),
    })
    .map_err(|_| stage_failed())?;
    replace_file(directory, RECORD_FILE_NAME, &record, RECORD_MODE)
}

fn staged_app_image_in(directory: &Path, host: &Path) -> io::Result<Option<PathBuf>> {
    let Some(host_directory) = host.parent() else {
        return Ok(None);
    };
    let Ok(stage) = fs::canonicalize(directory) else {
        return Ok(None);
    };
    if fs::canonicalize(host_directory)? != stage {
        return Ok(None);
    }
    let mut bytes = Vec::new();
    File::open(stage.join(RECORD_FILE_NAME))?
        .take(MAX_RECORD_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_RECORD_BYTES {
        return Err(invalid_record());
    }
    let record: AppRecord = serde_json::from_slice(&bytes).map_err(|_| invalid_record())?;
    Ok(Some(record.app_image))
}

fn prepare_directory(directory: &Path) -> Result<(), RegistrationError> {
    fs::DirBuilder::new()
        .recursive(true)
        .mode(DIRECTORY_MODE)
        .create(directory)
        .map_err(|_| stage_failed())?;
    let metadata = fs::symlink_metadata(directory).map_err(|_| stage_failed())?;
    // SAFETY: geteuid cannot fail and touches no memory.
    let own = unsafe { libc::geteuid() };
    if !metadata.is_dir() || metadata.uid() != own {
        return Err(stage_failed());
    }
    fs::set_permissions(directory, fs::Permissions::from_mode(DIRECTORY_MODE))
        .map_err(|_| stage_failed())
}

fn replace_file(
    directory: &Path,
    name: &str,
    bytes: &[u8],
    mode: u32,
) -> Result<(), RegistrationError> {
    let pending = directory.join(format!(".{name}.new"));
    match fs::remove_file(&pending) {
        Ok(()) => {}
        Err(error) if error.kind() == ErrorKind::NotFound => {}
        Err(_) => return Err(stage_failed()),
    }
    let written = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(&pending)
        .and_then(|mut file| {
            file.write_all(bytes)?;
            file.sync_all()?;
            fs::set_permissions(&pending, fs::Permissions::from_mode(mode))
        })
        .and_then(|()| fs::rename(&pending, directory.join(name)));
    if written.is_err() {
        let _ = fs::remove_file(&pending);
        return Err(stage_failed());
    }
    Ok(())
}

fn host_missing() -> RegistrationError {
    RegistrationError::new(
        "registration_host_missing",
        "Sesame's browser helper is missing from this build.",
    )
}

fn stage_failed() -> RegistrationError {
    RegistrationError::new(
        "registration_manifest_failed",
        "Sesame could not save its browser helper.",
    )
}

fn invalid_record() -> io::Error {
    io::Error::new(ErrorKind::InvalidData, "browser helper record rejected")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "sesame-appimage-test-{}-{name}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).expect("a scratch directory");
        root
    }

    fn fixtures(root: &Path) -> (PathBuf, PathBuf) {
        let mount = root.join("mount");
        fs::create_dir_all(&mount).expect("a mount directory");
        let host = mount.join(HOST_FILE_NAME);
        fs::write(&host, b"fictional host").expect("a host");
        (host, root.join("sesame.AppImage"))
    }

    struct UmaskGuard(libc::mode_t);

    impl UmaskGuard {
        fn permissive() -> Self {
            // SAFETY: umask reads and writes a process attribute and touches no memory.
            Self(unsafe { libc::umask(0) })
        }
    }

    impl Drop for UmaskGuard {
        fn drop(&mut self) {
            // SAFETY: restores the mode returned by the matching umask call.
            unsafe {
                libc::umask(self.0);
            }
        }
    }

    fn mode_of(path: &Path) -> u32 {
        fs::metadata(path).expect("metadata").permissions().mode() & 0o777
    }

    #[test]
    fn staging_copies_the_host_and_records_the_app_image() {
        let root = scratch("stage");
        let (host, image) = fixtures(&root);
        let stage = root.join("data").join("sesame").join("browser-host");
        let umask = UmaskGuard::permissive();
        stage_into(&stage, &host, &image).expect("staged");
        drop(umask);

        assert_eq!(
            fs::read(stage.join(HOST_FILE_NAME)).expect("a staged host"),
            b"fictional host"
        );
        assert_eq!(mode_of(&stage), 0o700);
        assert_eq!(mode_of(&stage.join(HOST_FILE_NAME)), 0o700);
        assert_eq!(mode_of(&stage.join(RECORD_FILE_NAME)), 0o600);

        assert_eq!(
            staged_app_image_in(&stage, &stage.join(HOST_FILE_NAME)).expect("a readable record"),
            Some(image)
        );
    }

    #[test]
    fn staging_again_replaces_the_host_and_leaves_no_pending_file() {
        let root = scratch("restage");
        let (host, image) = fixtures(&root);
        let stage = root.join("stage");
        stage_into(&stage, &host, &image).expect("first stage");
        fs::write(&host, b"newer host").expect("a newer host");
        fs::write(stage.join(".app.json.new"), b"stale").expect("a stale pending file");
        stage_into(&stage, &host, &image).expect("second stage");

        assert_eq!(
            fs::read(stage.join(HOST_FILE_NAME)).expect("a staged host"),
            b"newer host"
        );
        assert!(staged_app_image_in(&stage, &stage.join(HOST_FILE_NAME))
            .expect("a readable record")
            .is_some());
        let mut names: Vec<String> = fs::read_dir(&stage)
            .expect("a listing")
            .map(|entry| {
                entry
                    .expect("an entry")
                    .file_name()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect();
        names.sort();
        assert_eq!(names, [RECORD_FILE_NAME, HOST_FILE_NAME]);
    }

    #[test]
    fn staging_without_a_bundled_host_fails_and_writes_nothing() {
        let root = scratch("no-host");
        let (host, image) = fixtures(&root);
        fs::remove_file(&host).expect("a removed host");
        let stage = root.join("stage");

        let error = stage_into(&stage, &host, &image).expect_err("a missing host");
        assert_eq!(error.diagnostic_code(), "registration_host_missing");
        assert!(!stage.exists());
    }

    #[test]
    fn a_stage_directory_that_is_a_symlink_is_refused() {
        let root = scratch("symlink");
        let (host, image) = fixtures(&root);
        let elsewhere = root.join("elsewhere");
        fs::create_dir_all(&elsewhere).expect("a target directory");
        let stage = root.join("stage");
        std::os::unix::fs::symlink(&elsewhere, &stage).expect("a symlink");

        assert!(stage_into(&stage, &host, &image).is_err());
        assert_eq!(fs::read_dir(&elsewhere).expect("a listing").count(), 0);
    }

    #[test]
    fn a_host_outside_the_stage_directory_has_no_staged_app() {
        let root = scratch("outside");
        let (host, image) = fixtures(&root);
        let stage = root.join("stage");
        stage_into(&stage, &host, &image).expect("staged");

        assert!(staged_app_image_in(&stage, &host)
            .expect("no error outside the stage")
            .is_none());
    }

    #[test]
    fn a_staged_host_with_a_damaged_record_is_an_error() {
        let root = scratch("damaged");
        let (host, image) = fixtures(&root);
        let stage = root.join("stage");
        stage_into(&stage, &host, &image).expect("staged");
        let staged_host = stage.join(HOST_FILE_NAME);
        let record = stage.join(RECORD_FILE_NAME);

        for damaged in [
            b"not json".to_vec(),
            br#"{"appImage":"/x","extra":1}"#.to_vec(),
            br#"{"appImage":1}"#.to_vec(),
            br#"{}"#.to_vec(),
            vec![b' '; MAX_RECORD_BYTES as usize + 1],
        ] {
            fs::write(&record, damaged).expect("a damaged record");
            assert!(staged_app_image_in(&stage, &staged_host).is_err());
        }
        fs::remove_file(&record).expect("a removed record");
        assert!(staged_app_image_in(&stage, &staged_host).is_err());
    }

    #[test]
    fn an_identity_matches_only_the_same_length_and_contents() {
        let this = std::env::current_exe().expect("this test binary");
        let identity = ExecutableIdentity::of_file(&this).expect("an identity");
        let running = || File::open("/proc/self/exe").expect("this process's executable");
        assert!(identity.matches_file(running()).expect("a check"));

        let shorter = ExecutableIdentity {
            bytes: identity.bytes - 1,
            sha256: identity.sha256,
        };
        assert!(!shorter.matches_file(running()).expect("a check"));

        let altered = ExecutableIdentity {
            bytes: identity.bytes,
            sha256: [0_u8; 32],
        };
        assert!(!altered.matches_file(running()).expect("a check"));
    }
}
