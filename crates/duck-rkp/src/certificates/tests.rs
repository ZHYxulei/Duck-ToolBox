use p256::{SecretKey, pkcs8::DecodePrivateKey as _};
use rcgen::{BasicConstraints, CertificateParams, CertifiedIssuer, IsCa, KeyPair, KeyUsagePurpose};

use super::select_chain_for_p256;

fn params(name: &str) -> CertificateParams {
    let mut value = CertificateParams::default();
    value
        .distinguished_name
        .push(rcgen::DnType::CommonName, name);
    value
}

fn attestation_target(name: &str) -> CertificateParams {
    let mut value = params(name);
    value.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    value.key_usages = vec![KeyUsagePurpose::KeyCertSign];
    value
}

pub(super) fn issuer(name: &str) -> CertifiedIssuer<'static, KeyPair> {
    let mut value = params(name);
    value.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    value.key_usages = vec![KeyUsagePurpose::KeyCertSign];
    CertifiedIssuer::self_signed(value, KeyPair::generate().unwrap()).unwrap()
}

fn chain() -> (SecretKey, Vec<u8>, Vec<u8>) {
    chain_with_target(attestation_target("leaf"))
}

fn chain_with_target(target: CertificateParams) -> (SecretKey, Vec<u8>, Vec<u8>) {
    let root = issuer("root");
    let pair = KeyPair::generate().unwrap();
    let secret = SecretKey::from_pkcs8_der(pair.serialized_der()).unwrap();
    let leaf = target.signed_by(&pair, &root).unwrap();
    (secret, leaf.der().to_vec(), root.der().to_vec())
}

#[test]
fn rejects_target_certificate_without_ca_authorization() {
    let (secret, leaf, root) = chain_with_target(params("non-ca-target"));
    assert!(
        select_chain_for_p256(
            &[[leaf, root].concat()],
            &secret.public_key().to_sec1_bytes()
        )
        .is_err()
    );
}

#[test]
fn rejects_target_certificate_whose_key_usage_forbids_signing_certificates() {
    let mut target = params("wrong-key-usage");
    target.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    target.key_usages = vec![KeyUsagePurpose::KeyEncipherment];
    let (secret, leaf, root) = chain_with_target(target);
    assert!(
        select_chain_for_p256(
            &[[leaf, root].concat()],
            &secret.public_key().to_sec1_bytes()
        )
        .is_err()
    );
}

#[test]
fn rejects_target_certificate_with_noncritical_ca_constraints() {
    let mut target = params("noncritical-ca");
    target
        .custom_extensions
        .push(rcgen::CustomExtension::from_oid_content(
            &[2, 5, 29, 19],
            vec![0x30, 0x03, 0x01, 0x01, 0xff],
        ));
    let (secret, leaf, root) = chain_with_target(target);
    assert!(
        select_chain_for_p256(
            &[[leaf, root].concat()],
            &secret.public_key().to_sec1_bytes()
        )
        .is_err()
    );
}

#[test]
fn reserves_ancestor_path_length_for_the_future_application_certificate() {
    for limit in [1, 0] {
        let mut root_params = params("root");
        root_params.is_ca = IsCa::Ca(BasicConstraints::Constrained(limit));
        root_params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        let root = CertifiedIssuer::self_signed(root_params, KeyPair::generate().unwrap()).unwrap();
        let pair = KeyPair::generate().unwrap();
        let target = attestation_target("attestation-target")
            .signed_by(&pair, &root)
            .unwrap();
        let stream = [target.der().as_ref(), root.der().as_ref()].concat();
        let result = select_chain_for_p256(&[stream], pair.public_key_raw());
        if limit == 1 {
            assert!(result.is_ok());
        } else {
            assert!(
                result.is_err(),
                "root pathLen=0 cannot accommodate an attestation CA and future app leaf"
            );
        }
    }
}

#[test]
fn selects_matching_key_from_all_responses_and_orders_leaf_first() {
    let (_, other_leaf, other_root) = chain();
    let (secret, leaf, root) = chain();
    let responses = [
        [other_root, other_leaf].concat(),
        [root.clone(), leaf.clone()].concat(),
    ];
    let selected = select_chain_for_p256(&responses, &secret.public_key().to_sec1_bytes()).unwrap();
    assert_eq!(selected.len(), 2);
    assert_eq!(selected[0].der, leaf);
    assert_eq!(selected[1].der, root);
}

#[test]
fn rejects_signature_corruption_and_ambiguous_matching_responses() {
    let (secret, leaf, root) = chain();
    let valid = [leaf.clone(), root.clone()].concat();
    let public = secret.public_key().to_sec1_bytes();
    assert!(select_chain_for_p256(&[valid.clone(), valid], &public).is_err());
    let mut corrupt = leaf;
    *corrupt.last_mut().unwrap() ^= 1;
    assert!(select_chain_for_p256(&[[corrupt, root].concat()], &public).is_err());
}

#[test]
fn rejects_non_ca_issuers_and_unrelated_certificates() {
    let root = CertifiedIssuer::self_signed(params("root"), KeyPair::generate().unwrap()).unwrap();
    let pair = KeyPair::generate().unwrap();
    let secret = SecretKey::from_pkcs8_der(pair.serialized_der()).unwrap();
    let leaf = attestation_target("leaf").signed_by(&pair, &root).unwrap();
    let invalid = [leaf.der().as_ref(), root.der().as_ref()].concat();
    assert!(select_chain_for_p256(&[invalid], &secret.public_key().to_sec1_bytes()).is_err());

    let (secret, leaf, root) = chain();
    let (_, unrelated, _) = chain();
    assert!(
        select_chain_for_p256(
            &[[leaf, root, unrelated].concat()],
            &secret.public_key().to_sec1_bytes()
        )
        .is_err()
    );
}

#[test]
fn keybox_preserves_self_issued_key_rotation_certificates() {
    let root = issuer("shared-name");
    let mut rotated_params = params("shared-name");
    rotated_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    rotated_params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
    let rotated =
        CertifiedIssuer::signed_by(rotated_params, KeyPair::generate().unwrap(), &root).unwrap();
    let pair = KeyPair::generate().unwrap();
    let secret = SecretKey::from_pkcs8_der(pair.serialized_der()).unwrap();
    let leaf = attestation_target("leaf")
        .signed_by(&pair, &rotated)
        .unwrap();
    let stream = [
        root.der().as_ref(),
        leaf.der().as_ref(),
        rotated.der().as_ref(),
    ]
    .concat();
    let chain = select_chain_for_p256(&[stream], &secret.public_key().to_sec1_bytes()).unwrap();
    assert_eq!(chain.len(), 3);
    let xml = crate::keybox_xml::build_keybox_xml(&secret, &chain, "device").unwrap();
    crate::keybox_xml::validate_keybox_roundtrip(&xml, &secret, &chain, "device").unwrap();
}

#[test]
fn rejects_issuer_key_usage_and_path_length_violations() {
    for (usage, path_limit) in [
        (
            KeyUsagePurpose::DigitalSignature,
            BasicConstraints::Unconstrained,
        ),
        (
            KeyUsagePurpose::KeyCertSign,
            BasicConstraints::Constrained(0),
        ),
    ] {
        let mut root_params = params("root");
        root_params.is_ca = IsCa::Ca(path_limit);
        root_params.key_usages = vec![usage];
        let root = CertifiedIssuer::self_signed(root_params, KeyPair::generate().unwrap()).unwrap();
        let mut intermediate_params = params("intermediate");
        intermediate_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        intermediate_params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        let intermediate =
            CertifiedIssuer::signed_by(intermediate_params, KeyPair::generate().unwrap(), &root)
                .unwrap();
        let pair = KeyPair::generate().unwrap();
        let leaf = attestation_target("leaf")
            .signed_by(&pair, &intermediate)
            .unwrap();
        let stream = [
            leaf.der().as_ref(),
            intermediate.der().as_ref(),
            root.der().as_ref(),
        ]
        .concat();
        assert!(select_chain_for_p256(&[stream], pair.public_key_raw()).is_err());
    }
}

#[test]
fn rejects_expired_certificates_and_unknown_critical_constraints() {
    for expired in [false, true] {
        let root = issuer("root");
        let pair = KeyPair::generate().unwrap();
        let mut leaf_params = attestation_target("leaf");
        if expired {
            leaf_params.not_after = rcgen::date_time_ymd(2001, 1, 1);
        } else {
            let mut extension = rcgen::CustomExtension::from_oid_content(&[1, 2, 3, 4], vec![5, 0]);
            extension.set_criticality(true);
            leaf_params.custom_extensions.push(extension);
        }
        let leaf = leaf_params.signed_by(&pair, &root).unwrap();
        let stream = [leaf.der().as_ref(), root.der().as_ref()].concat();
        assert!(select_chain_for_p256(&[stream], pair.public_key_raw()).is_err());
    }
}
