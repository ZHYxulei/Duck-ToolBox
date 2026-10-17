use super::*;
use ciborium::value::Value;
use duck_rkp::{
    cbor::{bytes, int},
    cose::{DeviceKeys, RPC_CURVE_25519, build_csr},
    profile::{DeviceInfo, DiceCurve},
};
use p256::elliptic_curve::sec1::ToSec1Point as _;

fn csr(challenge: &[u8], keys: &[Value]) -> Vec<u8> {
    let device = DeviceInfo {
        brand: "google".into(),
        model: "Pixel".into(),
        device: "pixel".into(),
        product: "pixel".into(),
        manufacturer: "Google".into(),
        ..DeviceInfo::default()
    };
    build_csr(
        &DeviceKeys::from_seed_with_curve([0x11; 32], DiceCurve::Ed25519),
        challenge,
        keys,
        &[0x55; 32],
        &[0x66; 8],
        &device,
        RPC_CURVE_25519,
    )
    .unwrap()
    .csr_bytes
}

fn append(output: &mut Vec<u8>, value: &[u8]) {
    output.extend_from_slice(&(value.len() as i32).to_be_bytes());
    output.extend_from_slice(value);
}

fn reply(challenge: &[u8]) -> Vec<u8> {
    let mut output = Vec::new();
    for value in [0i32, 3, 0, 3] {
        output.extend_from_slice(&value.to_be_bytes());
    }
    for value in [
        b"Example".to_vec(),
        b"private-id".to_vec(),
        csr(&[], &[]),
        csr(challenge, &[]),
    ] {
        append(&mut output, &value);
    }
    output
}

#[test]
fn validates_both_zero_key_csrs_without_exposing_device_identifiers() {
    let challenge = [7; 32];
    let report = decode_report(&reply(&challenge), "default", &challenge).unwrap();
    assert_eq!(report.hardware_version, 3);
    assert_eq!(report.checks[0].challenge_bytes, 0);
    assert_eq!(report.checks[1].challenge_bytes, 32);
    assert!(
        report.checks.iter().all(|check| check.signature_valid
            && check.challenge_matches
            && check.keys_to_sign == 0)
    );
    let json = serde_json::to_string(&report).unwrap();
    assert!(!json.contains("private-id"));
    assert!(!json.contains("uds_pub_hex"));
    assert!(!report.server_acceptance_checked);
}

#[test]
fn valid_signatures_do_not_bypass_challenge_or_key_count_checks() {
    let valid = csr(&[7; 32], &[]);
    assert!(verify_csr(&valid).unwrap().signature_valid);
    assert!(validate_csr(&valid, &[8; 32]).is_err());
    assert!(validate_csr(&valid, &[]).is_err());
    assert!(validate_csr(&csr(&[], &[]), &[7; 32]).is_err());
    let key = p256::SecretKey::from_slice(&[0x22; 32]).unwrap();
    let point = key.public_key().to_sec1_point(false);
    let key = Value::Map(vec![
        (int(1), int(2)),
        (int(3), int(-7)),
        (int(-1), int(1)),
        (int(-2), bytes(point.x().unwrap().to_vec())),
        (int(-3), bytes(point.y().unwrap().to_vec())),
    ]);
    let signed_with_key = csr(&[7; 32], &[key]);
    assert_eq!(verify_csr(&signed_with_key).unwrap().keys_to_sign, 1);
    assert!(validate_csr(&signed_with_key, &[7; 32]).is_err());
}

#[test]
fn malformed_replies_and_csrs_fail_closed() {
    let challenge = [7; 32];
    let encoded = reply(&challenge);
    for cut in 0..encoded.len() {
        assert!(decode_report(&encoded[..cut], "default", &challenge).is_err());
    }
    let mut trailing = encoded;
    trailing.push(0);
    assert!(decode_report(&trailing, "default", &challenge).is_err());
    for value in [vec![], vec![0x80], vec![0xff]] {
        assert!(validate_csr(&value, &challenge).is_err());
    }
    let mut tampered = csr(&challenge, &[]);
    let last = tampered.last_mut().unwrap();
    *last ^= 1;
    assert!(validate_csr(&tampered, &challenge).is_err());
}

#[test]
fn errors_preserve_their_layer_and_service_specific_code() {
    for (status, expected) in [
        (1i32, "ta_rejected"),
        (2, "ta_transport_error"),
        (3, "invalid_ta_response"),
        (4, "unsupported_protocol"),
    ] {
        let mut output = status.to_be_bytes().to_vec();
        if status == 1 {
            output.extend_from_slice(&2i32.to_be_bytes());
        }
        append(&mut output, b"check failed");
        let error = decode_report(&output, "default", &[7; 32]).unwrap_err();
        assert_eq!(crate::error::code_of(&error), expected);
        if status == 1 {
            assert!(error.chain().any(|cause| matches!(
                cause.downcast_ref::<DeviceRkpError>(),
                Some(DeviceRkpError::Rejected(2))
            )));
        }
        output.push(0);
        assert!(decode_report(&output, "default", &[7; 32]).is_err());
    }
}

#[test]
fn instance_names_cannot_inject_service_paths_or_options() {
    for value in ["", "../default", "default/strongbox", "a b"] {
        assert!(parse_instance(value).is_err());
    }
    assert!(parse_instance(&"a".repeat(65)).is_err());
    for value in ["default", "strongbox", "vendor_1.test-2"] {
        assert!(parse_instance(value).is_ok());
    }
}
