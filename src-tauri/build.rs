use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-env-changed=SESAME_API_BASE_URL");
    println!("cargo:rerun-if-env-changed=SESAME_CAPABILITY_PUBLIC_KEY");
    println!("cargo:rerun-if-env-changed=SESAME_UPDATER_PUBLIC_KEY");
    println!("cargo:rerun-if-env-changed=SESAME_UPDATE_MANIFEST_URL");
    println!("cargo:rerun-if-env-changed=SESAME_ALLOW_INSECURE_UPDATE_LOOPBACK");
    println!("cargo:rerun-if-env-changed=SESAME_RELEASE_CANDIDATE_PUBLIC_KEY");
    println!("cargo:rerun-if-env-changed=SESAME_RELEASE_CANDIDATE_KEY_ID");
    println!("cargo:rerun-if-env-changed=VITE_SESAME_SITE_ORIGIN");
    let local_config =
        PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").expect("Cargo manifest directory"))
            .join(".env.local");
    println!("cargo:rerun-if-changed={}", local_config.display());

    let configured = std::env::var("SESAME_API_BASE_URL").ok().or_else(|| {
        // A checked-in release build must be configured explicitly. The local
        // file exists only to make `tauri dev` usable without baking a
        // developer endpoint into any distributable binary.
        (std::env::var("PROFILE").as_deref() == Ok("debug"))
            .then(|| read_local_value(&local_config, "SESAME_API_BASE_URL"))
            .flatten()
    });
    if let Some(value) = configured {
        println!("cargo:rustc-env=SESAME_API_BASE_URL={value}");
    }
    let capability = std::env::var("SESAME_CAPABILITY_PUBLIC_KEY")
        .ok()
        .or_else(|| {
            (std::env::var("PROFILE").as_deref() == Ok("debug"))
                .then(|| read_local_value(&local_config, "SESAME_CAPABILITY_PUBLIC_KEY"))
                .flatten()
        });
    if let Some(value) = capability {
        println!("cargo:rustc-env=SESAME_CAPABILITY_PUBLIC_KEY={value}");
    }
    for key in [
        "SESAME_UPDATE_MANIFEST_URL",
        "SESAME_ALLOW_INSECURE_UPDATE_LOOPBACK",
    ] {
        if let Ok(value) = std::env::var(key) {
            if !value.trim().is_empty() {
                println!("cargo:rustc-env={key}={value}");
            }
        }
    }
    let site_origin = std::env::var("VITE_SESAME_SITE_ORIGIN").ok().or_else(|| {
        (std::env::var("PROFILE").as_deref() == Ok("debug"))
            .then(|| read_local_value(&local_config, "VITE_SESAME_SITE_ORIGIN"))
            .flatten()
    });
    if let Some(value) = site_origin {
        // Rust and the renderer must authorize the same configured support
        // origin. The external-URL command rejects support destinations when
        // this is absent or malformed.
        println!("cargo:rustc-env=VITE_SESAME_SITE_ORIGIN={value}");
    }
    let attributes = tauri_build::Attributes::new().app_manifest(tauri_build::AppManifest::new());
    if let Err(error) = tauri_build::try_build(attributes) {
        eprintln!("{error:#}");
        std::process::exit(1);
    }
}

fn read_local_value(path: &std::path::Path, key: &str) -> Option<String> {
    let contents = std::fs::read_to_string(path).ok()?;
    contents.lines().find_map(|line| {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            return None;
        }
        let (name, value) = line.split_once('=')?;
        (name.trim() == key)
            .then(|| value.trim().trim_matches(['\"', '\'']).to_owned())
            .filter(|value| !value.is_empty())
    })
}
