use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use serde_json::json;

use crate::vault::VaultResult;

use super::updater::{
    download_failure_message, require_available_update, update_status, updater_platform_for,
    valid_base64url_sha256, verify_artifact_digest, verify_candidate_receipt, DownloadFailureKind,
    ReceiptArtifact, SizeRefusal, UpdateRelease,
};

fn sign_payload(payload: &str) -> (String, String) {
    let signing_key = SigningKey::from_bytes(&[7_u8; 32]);
    (
        URL_SAFE_NO_PAD.encode(signing_key.sign(payload.as_bytes()).to_bytes()),
        URL_SAFE_NO_PAD.encode(signing_key.verifying_key().to_bytes()),
    )
}

fn signed_manifest() -> (serde_json::Value, String, String) {
    let artifact_sha256 = "a".repeat(64);
    let updater_signature = "s".repeat(64);
    let payload = [
        "sesame-release-set-candidate-v1".to_owned(),
        "1.2.3".to_owned(),
        "beta".to_owned(),
        "windows".to_owned(),
        "x86_64".to_owned(),
        "Windows 10,Windows 11".to_owned(),
        "https://example.invalid/releases/1.2.3".to_owned(),
        "b".repeat(64),
        "updater".to_owned(),
        "nsis".to_owned(),
        "x86_64".to_owned(),
        "https://downloads.example.invalid/Sesame.exe".to_owned(),
        "windows/1.2.3/Sesame.exe".to_owned(),
        artifact_sha256.clone(),
        "42".to_owned(),
        updater_signature.clone(),
        "fictional-updater-key".to_owned(),
    ]
    .join("\n");
    let (signature, public_key) = sign_payload(&payload);
    let manifest = json!({
        "url": "https://downloads.example.invalid/Sesame.exe",
        "candidateReceipt": {
            "payload": payload,
            "signingKeyId": "fictional-candidate-key",
            "signature": signature,
        }
    });
    (manifest, public_key, updater_signature)
}

#[test]
fn verifies_the_signed_updater_binding() {
    let (manifest, public_key, updater_signature) = signed_manifest();
    let artifact = verify_candidate_receipt(
        &manifest,
        "1.2.3",
        &updater_signature,
        &public_key,
        "fictional-candidate-key",
        "windows",
        "x86_64",
    )
    .expect("verify receipt");
    assert_eq!(artifact.sha256, "a".repeat(64));
    assert_eq!(artifact.bytes, 42);
}

#[test]
fn rejects_a_redirected_or_relabelled_updater() {
    let (mut manifest, public_key, updater_signature) = signed_manifest();
    manifest["url"] = json!("https://downloads.example.invalid/other.exe");
    assert!(verify_candidate_receipt(
        &manifest,
        "1.2.3",
        &updater_signature,
        &public_key,
        "fictional-candidate-key",
        "windows",
        "x86_64",
    )
    .is_err());
    let (manifest, _, _) = signed_manifest();
    assert!(verify_candidate_receipt(
        &manifest,
        "9.9.9",
        &updater_signature,
        &public_key,
        "fictional-candidate-key",
        "windows",
        "x86_64",
    )
    .is_err());
}

#[test]
fn rejects_a_candidate_for_another_platform_or_architecture() {
    for (manifest, public_key, updater_signature) in [signed_manifest(), signed_v3_manifest()] {
        for (platform, architecture) in [("linux", "x86_64"), ("windows", "aarch64")] {
            let error = verify_candidate_receipt(
                &manifest,
                "1.2.3",
                &updater_signature,
                &public_key,
                "fictional-candidate-key",
                platform,
                architecture,
            )
            .expect_err("another target");
            assert!(
                error.contains("did not match its signed release receipt"),
                "{error}"
            );
        }
    }
}

#[test]
fn rejects_a_candidate_whose_artifact_digest_does_not_match_its_receipt() {
    let (manifest, public_key, updater_signature) = signed_manifest();
    let artifact = verify_candidate_receipt(
        &manifest,
        "1.2.3",
        &updater_signature,
        &public_key,
        "fictional-candidate-key",
        "windows",
        "x86_64",
    )
    .expect("verify receipt");
    assert_eq!(
        verify_artifact_digest(artifact.sha256.as_str(), &artifact),
        Ok(())
    );
    let error = verify_artifact_digest(&"0".repeat(64), &artifact).expect_err("digest mismatch");
    assert!(
        error.contains("did not match its signed release receipt"),
        "{error}"
    );
}

#[test]
fn rejects_a_v3_receipt_with_a_malformed_base64url_digest() {
    let mut claims = v3_claims(&"a".repeat(64), &"s".repeat(64));
    claims[18] = "not-a-base64url-digest".to_owned();
    let payload = claims.join("\n");
    let (signature, public_key) = sign_payload(&payload);
    let manifest = json!({
        "url": "https://downloads.example.invalid/Sesame.exe",
        "candidateReceipt": {
            "payload": payload,
            "signingKeyId": "fictional-candidate-key",
            "signature": signature,
        }
    });
    let error = verify_candidate_receipt(
        &manifest,
        "1.2.3",
        &"s".repeat(64),
        &public_key,
        "fictional-candidate-key",
        "windows",
        "x86_64",
    )
    .expect_err("malformed digest");
    assert!(
        error.contains("did not match its signed release receipt"),
        "{error}"
    );
    assert!(!valid_base64url_sha256("not-a-base64url-digest"));
    assert!(!valid_base64url_sha256(&"A".repeat(42)));
    assert!(valid_base64url_sha256(&"A".repeat(43)));
}

#[test]
fn updater_support_matches_the_release_pipeline() {
    assert_eq!(updater_platform_for("windows").ok(), Some("windows"));
    assert!(updater_platform_for("linux").is_err());
}

fn v3_claims(artifact_sha256: &str, updater_signature: &str) -> Vec<String> {
    let sigstore_identity =
        "https://github.com/usesesame/sesame-desktop/.github/workflows/release-early-access.yml@refs/tags/v1.2.3";
    vec![
        "sesame-release-candidate-v3".to_owned(),
        "1.2.3".to_owned(),
        "beta".to_owned(),
        "windows".to_owned(),
        "x86_64".to_owned(),
        "Windows 10,Windows 11".to_owned(),
        "https://example.invalid/releases/1.2.3".to_owned(),
        "https://downloads.example.invalid/Sesame.exe".to_owned(),
        "windows/1.2.3/Sesame.exe".to_owned(),
        artifact_sha256.to_owned(),
        "42".to_owned(),
        updater_signature.to_owned(),
        "fictional-updater-key".to_owned(),
        "early_access".to_owned(),
        "true".to_owned(),
        "https://token.actions.githubusercontent.com".to_owned(),
        sigstore_identity.to_owned(),
        "c".repeat(64),
        "A".repeat(43),
        "false".to_owned(),
        String::new(),
        String::new(),
        String::new(),
    ]
}

fn signed_v3_manifest() -> (serde_json::Value, String, String) {
    let artifact_sha256 = "a".repeat(64);
    let updater_signature = "s".repeat(64);
    let payload = v3_claims(&artifact_sha256, &updater_signature).join("\n");
    let (signature, public_key) = sign_payload(&payload);
    let manifest = json!({
        "url": "https://downloads.example.invalid/Sesame.exe",
        "candidateReceipt": {
            "payload": payload,
            "signingKeyId": "fictional-candidate-key",
            "signature": signature,
        }
    });
    (manifest, public_key, updater_signature)
}

#[test]
fn verifies_a_v3_receipt_from_clients_before_0_2_3() {
    let (manifest, public_key, updater_signature) = signed_v3_manifest();
    let artifact = verify_candidate_receipt(
        &manifest,
        "1.2.3",
        &updater_signature,
        &public_key,
        "fictional-candidate-key",
        "windows",
        "x86_64",
    )
    .expect("verify v3 receipt");
    assert_eq!(artifact.sha256, "a".repeat(64));
    assert_eq!(artifact.bytes, 42);
}

#[test]
fn rejects_a_v3_receipt_bound_to_another_version_or_download() {
    let (manifest, public_key, updater_signature) = signed_v3_manifest();
    assert!(verify_candidate_receipt(
        &manifest,
        "9.9.9",
        &updater_signature,
        &public_key,
        "fictional-candidate-key",
        "windows",
        "x86_64",
    )
    .is_err());
    let (mut manifest, public_key, updater_signature) = signed_v3_manifest();
    manifest["url"] = json!("https://downloads.example.invalid/other.exe");
    assert!(verify_candidate_receipt(
        &manifest,
        "1.2.3",
        &updater_signature,
        &public_key,
        "fictional-candidate-key",
        "windows",
        "x86_64",
    )
    .is_err());
}

const RELEASE_SET_FIXTURE: &str =
    include_str!("../../tests/fixtures/update-manifests/release-set-early-access.latest.json");
const V3_EARLY_ACCESS_FIXTURE: &str =
    include_str!("../../tests/fixtures/update-manifests/v3-early-access.latest.json");
const V3_PRODUCTION_FIXTURE: &str =
    include_str!("../../tests/fixtures/update-manifests/v3-production.latest.json");
const RECEIPT_KEY_FIXTURE: &str =
    include_str!("../../tests/fixtures/update-manifests/receipt-key.json");
const TOOL_FIXTURES: [&str; 3] = [
    RELEASE_SET_FIXTURE,
    V3_EARLY_ACCESS_FIXTURE,
    V3_PRODUCTION_FIXTURE,
];

struct ToolManifest {
    manifest: serde_json::Value,
    public_key: String,
    key_id: String,
}

impl ToolManifest {
    fn load(source: &str) -> Self {
        let key: serde_json::Value =
            serde_json::from_str(RECEIPT_KEY_FIXTURE).expect("receipt key fixture");
        Self {
            manifest: serde_json::from_str(source).expect("manifest fixture"),
            public_key: key["publicKey"].as_str().expect("public key").to_owned(),
            key_id: key["keyId"].as_str().expect("key id").to_owned(),
        }
    }

    fn updater_signature(&self) -> String {
        self.manifest["platforms"]["windows-x86_64-nsis"]["signature"]
            .as_str()
            .expect("updater signature")
            .to_owned()
    }

    fn verify(
        &self,
        version: &str,
        platform: &str,
        architecture: &str,
    ) -> VaultResult<ReceiptArtifact> {
        verify_candidate_receipt(
            &self.manifest,
            version,
            &self.updater_signature(),
            &self.public_key,
            &self.key_id,
            platform,
            architecture,
        )
    }
}

#[test]
fn accepts_every_receipt_layout_the_release_tool_writes() {
    for source in TOOL_FIXTURES {
        let fixture = ToolManifest::load(source);
        let artifact = fixture
            .verify("1.2.3", "windows", "x86_64")
            .expect("verify tool manifest");
        assert_eq!(artifact.sha256, "a".repeat(64));
        assert_eq!(artifact.bytes, 42);
    }
}

#[test]
fn rejects_a_tool_manifest_without_its_top_level_download_url() {
    for source in TOOL_FIXTURES {
        let mut fixture = ToolManifest::load(source);
        fixture
            .manifest
            .as_object_mut()
            .expect("object")
            .remove("url");
        assert!(fixture.verify("1.2.3", "windows", "x86_64").is_err());
    }
}

#[test]
fn rejects_a_tool_manifest_for_another_version_platform_or_download() {
    for source in TOOL_FIXTURES {
        let fixture = ToolManifest::load(source);
        assert!(fixture.verify("1.2.4", "windows", "x86_64").is_err());
        assert!(fixture.verify("1.2.2", "windows", "x86_64").is_err());
        assert!(fixture.verify("1.2.3", "linux", "x86_64").is_err());
        assert!(fixture.verify("1.2.3", "windows", "aarch64").is_err());
        let mut redirected = ToolManifest::load(source);
        redirected.manifest["url"] = json!("https://downloads.example.test/v1.2.3/other.exe");
        assert!(redirected.verify("1.2.3", "windows", "x86_64").is_err());
        let mut relabelled = ToolManifest::load(source);
        relabelled.manifest["platforms"]["windows-x86_64-nsis"]["signature"] =
            json!("B".repeat(64));
        assert!(relabelled.verify("1.2.3", "windows", "x86_64").is_err());
    }
}

#[test]
fn rejects_a_stale_receipt_attached_to_a_newer_manifest() {
    let stale = ToolManifest::load(V3_EARLY_ACCESS_FIXTURE);
    let mut newer = ToolManifest::load(V3_EARLY_ACCESS_FIXTURE);
    newer.manifest["version"] = json!("1.2.4");
    newer.manifest["candidateReceipt"] = stale.manifest["candidateReceipt"].clone();
    assert!(newer.verify("1.2.4", "windows", "x86_64").is_err());
}

#[test]
fn rejects_a_truncated_or_tampered_tool_receipt() {
    for source in TOOL_FIXTURES {
        let mut truncated = ToolManifest::load(source);
        let payload = truncated.manifest["candidateReceipt"]["payload"]
            .as_str()
            .expect("payload")
            .to_owned();
        let cut = payload.rfind('\n').expect("claim separator");
        truncated.manifest["candidateReceipt"]["payload"] = json!(&payload[..cut]);
        assert!(truncated.verify("1.2.3", "windows", "x86_64").is_err());

        let mut forged_signature = ToolManifest::load(source);
        let signature = forged_signature.manifest["candidateReceipt"]["signature"]
            .as_str()
            .expect("signature")
            .to_owned();
        let flipped = if signature.starts_with('A') { 'B' } else { 'A' };
        forged_signature.manifest["candidateReceipt"]["signature"] =
            json!(format!("{flipped}{}", &signature[1..]));
        assert!(forged_signature
            .verify("1.2.3", "windows", "x86_64")
            .is_err());

        let mut other_key = ToolManifest::load(source);
        other_key.key_id = "another-key".to_owned();
        assert!(other_key.verify("1.2.3", "windows", "x86_64").is_err());

        let mut other_public_key = ToolManifest::load(source);
        other_public_key.public_key = URL_SAFE_NO_PAD.encode(
            SigningKey::from_bytes(&[9_u8; 32])
                .verifying_key()
                .to_bytes(),
        );
        assert!(other_public_key
            .verify("1.2.3", "windows", "x86_64")
            .is_err());

        let mut missing = ToolManifest::load(source);
        missing
            .manifest
            .as_object_mut()
            .expect("object")
            .remove("candidateReceipt");
        assert!(missing.verify("1.2.3", "windows", "x86_64").is_err());
    }
}

#[test]
fn the_production_receipt_carries_the_publisher_signature_claims() {
    let production = ToolManifest::load(V3_PRODUCTION_FIXTURE);
    let payload = production.manifest["candidateReceipt"]["payload"]
        .as_str()
        .expect("payload");
    let claims: Vec<&str> = payload.split('\n').collect();
    assert_eq!(claims[13], "production");
    assert_eq!(claims[19], "true");
    assert!(!claims[20].is_empty() && !claims[21].is_empty());
}

#[test]
fn download_failures_report_the_size_and_timeout_messages() {
    assert_eq!(
        download_failure_message(DownloadFailureKind::Refused(SizeRefusal::AnnouncedLength)),
        "The update server announced a download size that differs from the signed size, so Sesame stopped it."
    );
    assert_eq!(
        download_failure_message(DownloadFailureKind::Refused(
            SizeRefusal::ExceededSignedSize
        )),
        "The update download was larger than its signed size, so Sesame stopped it."
    );
    assert_eq!(
        download_failure_message(DownloadFailureKind::Refused(SizeRefusal::ReceivedLength)),
        "The update download was shorter than its signed size, so Sesame stopped it."
    );
    assert_eq!(
        download_failure_message(DownloadFailureKind::TimedOut),
        "The update download took too long and was stopped."
    );
    assert_eq!(
        download_failure_message(DownloadFailureKind::Failed),
        "Sesame could not download or verify the update."
    );
}

#[test]
fn a_verified_update_becomes_an_available_status_and_no_update_becomes_unavailable() {
    let available = update_status(Some(UpdateRelease {
        version: "1.2.3".to_owned(),
        body: Some("fictional release notes".to_owned()),
    }));
    assert!(available.available);
    assert_eq!(available.version.as_deref(), Some("1.2.3"));
    assert_eq!(available.body.as_deref(), Some("fictional release notes"));

    let up_to_date = update_status(None);
    assert!(!up_to_date.available);
    assert!(up_to_date.version.is_none());
    assert!(up_to_date.body.is_none());
}

#[test]
fn installing_without_a_verified_update_is_refused() {
    let error = require_available_update::<()>(None).expect_err("no update");
    assert_eq!(error, "Sesame is already up to date.");
    assert_eq!(require_available_update(Some(7)).expect("available"), 7);
}
