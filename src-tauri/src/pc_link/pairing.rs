use chrono::{Datelike, TimeDelta};
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose, PublicKeyData, SignatureAlgorithm, PKCS_ECDSA_P256_SHA256,
};
use zeroize::Zeroize;

use crate::vault::VaultResult;

const LINK_CERTIFICATE_VALIDITY_DAYS: i64 = 365;
const CERTIFICATE_BACKDATE_DAYS: i64 = 1;
const CA_COMMON_NAME: &str = "Sesame PC link CA";
const LEAF_COMMON_NAME: &str = "Sesame PC link phone";
const ISSUE_FAILED: &str = "Sesame could not issue the PC link certificate.";

pub(crate) struct IssuedClientCertificate {
    pub(crate) certificate_authority_der: Vec<u8>,
    pub(crate) leaf_certificate_der: Vec<u8>,
    pub(crate) not_after_unix: i64,
}

struct PhonePublicKey {
    point: Vec<u8>,
}

impl PublicKeyData for PhonePublicKey {
    fn der_bytes(&self) -> &[u8] {
        &self.point
    }

    fn algorithm(&self) -> &'static SignatureAlgorithm {
        &PKCS_ECDSA_P256_SHA256
    }
}

pub(crate) fn issue_client_certificate(
    phone_public_key: &[u8],
) -> VaultResult<IssuedClientCertificate> {
    issue_with_eku(phone_public_key, &[ExtendedKeyUsagePurpose::ClientAuth])
}

fn issue_with_eku(
    phone_public_key: &[u8],
    extended_key_usages: &[ExtendedKeyUsagePurpose],
) -> VaultResult<IssuedClientCertificate> {
    let now = chrono::Utc::now();
    let not_before_time = now
        .checked_sub_signed(
            TimeDelta::try_days(CERTIFICATE_BACKDATE_DAYS)
                .ok_or_else(|| ISSUE_FAILED.to_string())?,
        )
        .ok_or_else(|| ISSUE_FAILED.to_string())?;
    let not_after_time = now
        .checked_add_signed(
            TimeDelta::try_days(LINK_CERTIFICATE_VALIDITY_DAYS)
                .ok_or_else(|| ISSUE_FAILED.to_string())?,
        )
        .ok_or_else(|| ISSUE_FAILED.to_string())?;
    let not_before = rcgen::date_time_ymd(
        not_before_time.year(),
        not_before_time.month() as u8,
        not_before_time.day() as u8,
    );
    let not_after = rcgen::date_time_ymd(
        not_after_time.year(),
        not_after_time.month() as u8,
        not_after_time.day() as u8,
    );

    let mut ca_params = CertificateParams::default();
    ca_params.distinguished_name = rcgen::DistinguishedName::new();
    ca_params
        .distinguished_name
        .push(DnType::CommonName, CA_COMMON_NAME);
    ca_params.not_before = not_before;
    ca_params.not_after = not_after;
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];

    let mut ca_key = KeyPair::generate().map_err(|_| ISSUE_FAILED.to_string())?;
    let certificate_authority = ca_params
        .self_signed(&ca_key)
        .map_err(|_| ISSUE_FAILED.to_string())?;

    let mut leaf_params = CertificateParams::default();
    leaf_params.distinguished_name = rcgen::DistinguishedName::new();
    leaf_params
        .distinguished_name
        .push(DnType::CommonName, LEAF_COMMON_NAME);
    leaf_params.not_before = not_before;
    leaf_params.not_after = not_after;
    leaf_params.is_ca = IsCa::NoCa;
    leaf_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    leaf_params.extended_key_usages = extended_key_usages.to_vec();

    let phone_key = PhonePublicKey {
        point: phone_public_key.to_vec(),
    };
    let leaf_certificate = {
        let issuer = Issuer::from_params(&ca_params, &ca_key);
        leaf_params
            .signed_by(&phone_key, &issuer)
            .map_err(|_| ISSUE_FAILED.to_string())?
    };
    ca_key.zeroize();

    Ok(IssuedClientCertificate {
        certificate_authority_der: certificate_authority.der().to_vec(),
        leaf_certificate_der: leaf_certificate.der().to_vec(),
        not_after_unix: not_after.unix_timestamp(),
    })
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use rustls::pki_types::{CertificateDer, UnixTime};
    use rustls::server::danger::ClientCertVerifier;
    use rustls::server::WebPkiClientVerifier;

    use super::*;

    fn phone_public_key() -> Vec<u8> {
        let key = KeyPair::generate().expect("phone key");
        key.der_bytes().to_vec()
    }

    fn verifier(certificate_authority_der: &[u8]) -> Arc<dyn ClientCertVerifier> {
        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(CertificateDer::from(certificate_authority_der.to_vec()))
            .expect("trusted CA");
        WebPkiClientVerifier::builder(Arc::new(roots))
            .build()
            .expect("client verifier")
    }

    #[test]
    fn issued_leaf_is_accepted_by_the_standard_client_verifier() {
        let issued = issue_client_certificate(&phone_public_key()).expect("issued");
        let verifier = verifier(&issued.certificate_authority_der);
        let leaf = CertificateDer::from(issued.leaf_certificate_der);
        assert!(verifier
            .verify_client_cert(&leaf, &[], UnixTime::now())
            .is_ok());
    }

    #[test]
    fn a_server_auth_leaf_is_rejected_by_the_client_verifier() {
        let issued = issue_with_eku(&phone_public_key(), &[ExtendedKeyUsagePurpose::ServerAuth])
            .expect("issued");
        let verifier = verifier(&issued.certificate_authority_der);
        let leaf = CertificateDer::from(issued.leaf_certificate_der);
        assert!(verifier
            .verify_client_cert(&leaf, &[], UnixTime::now())
            .is_err());
    }

    #[test]
    fn a_leaf_from_another_pairing_ca_is_rejected() {
        let issued = issue_client_certificate(&phone_public_key()).expect("issued");
        let other = issue_client_certificate(&phone_public_key()).expect("other");
        let verifier = verifier(&issued.certificate_authority_der);
        let other_leaf = CertificateDer::from(other.leaf_certificate_der);
        assert!(verifier
            .verify_client_cert(&other_leaf, &[], UnixTime::now())
            .is_err());
    }

    #[test]
    fn an_expired_link_leaf_is_rejected() {
        let issued = issue_client_certificate(&phone_public_key()).expect("issued");
        let verifier = verifier(&issued.certificate_authority_der);
        let leaf = CertificateDer::from(issued.leaf_certificate_der);
        let after_expiry = UnixTime::since_unix_epoch(std::time::Duration::from_secs(
            issued.not_after_unix as u64 + 60,
        ));
        assert!(verifier
            .verify_client_cert(&leaf, &[], after_expiry)
            .is_err());
    }

    #[test]
    fn issuance_backdates_and_bounds_the_link_validity() {
        let before = crate::vault::unix_timestamp() as i64;
        let issued = issue_client_certificate(&phone_public_key()).expect("issued");
        let expected_min = before + 360 * 24 * 60 * 60;
        let expected_max = before + 370 * 24 * 60 * 60;
        assert!(issued.not_after_unix > expected_min);
        assert!(issued.not_after_unix < expected_max);
    }
}
