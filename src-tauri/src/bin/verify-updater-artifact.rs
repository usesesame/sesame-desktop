use base64::{engine::general_purpose::STANDARD, Engine as _};
use minisign_verify::{PublicKey, Signature};
use std::{env, fs, process};

fn fail(message: &str) -> ! {
    eprintln!("updater artifact verification failed: {message}");
    process::exit(1);
}

fn verify_updater_artifact(
    updater_public_key: &str,
    detached_signature: &str,
    artifact: &[u8],
) -> Result<(), &'static str> {
    let public_key_text = STANDARD
        .decode(updater_public_key.trim())
        .ok()
        .and_then(|bytes| String::from_utf8(bytes).ok())
        .ok_or("SESAME_UPDATER_PUBLIC_KEY is not a Tauri updater public key")?;
    let signature_text = STANDARD
        .decode(detached_signature.trim())
        .ok()
        .and_then(|bytes| String::from_utf8(bytes).ok())
        .ok_or("the detached Tauri signature is malformed")?;
    let public_key =
        PublicKey::decode(&public_key_text).map_err(|_| "the updater public key is malformed")?;
    let signature = Signature::decode(&signature_text)
        .map_err(|_| "the detached Tauri signature is malformed")?;
    public_key
        .verify(artifact, &signature, true)
        .map_err(|_| "the detached Tauri signature does not match the artifact")
}

fn main() {
    let mut arguments = env::args().skip(1);
    let artifact_path = arguments
        .next()
        .unwrap_or_else(|| fail("usage: verify-updater-artifact <artifact> <signature-file>"));
    let signature_path = arguments
        .next()
        .unwrap_or_else(|| fail("usage: verify-updater-artifact <artifact> <signature-file>"));
    if arguments.next().is_some() {
        fail("usage: verify-updater-artifact <artifact> <signature-file>");
    }

    let public_key = env::var("SESAME_UPDATER_PUBLIC_KEY")
        .ok()
        .filter(|key| !key.trim().is_empty())
        .unwrap_or_else(|| fail("SESAME_UPDATER_PUBLIC_KEY is required"));
    let signature_outer = fs::read_to_string(&signature_path)
        .unwrap_or_else(|_| fail("the detached Tauri signature could not be read"));
    let artifact =
        fs::read(&artifact_path).unwrap_or_else(|_| fail("the updater artifact could not be read"));
    if let Err(message) = verify_updater_artifact(&public_key, &signature_outer, &artifact) {
        fail(message);
    }
    println!("Tauri updater signature verified.");
}
