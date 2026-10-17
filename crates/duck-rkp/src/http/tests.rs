use super::{
    COSE_ALGORITHM_ECDH_ES_HKDF_256, COSE_CURVE_P256, COSE_CURVE_X25519, MAX_RKP_CHALLENGE_LEN,
    parse_fetch_eek_response, validate_challenge,
};
use crate::{
    cbor::{bytes, encode, int},
    cose::{RPC_CURVE_25519, RPC_CURVE_P256},
};
use ciborium::value::Value;

#[test]
fn v3_challenge_does_not_require_legacy_eek_material() {
    let response = encode(&Value::Array(vec![
        Value::Array(vec![]),
        bytes(vec![7; 32]),
    ]))
    .unwrap();
    assert_eq!(
        super::parse_challenge_response(&response).unwrap(),
        vec![7; 32]
    );
}

fn eek_payload_x25519(key_id: Option<&[u8]>, public_key: &[u8]) -> Value {
    let mut entries = vec![
        (int(1), int(1)),
        (int(3), int(COSE_ALGORITHM_ECDH_ES_HKDF_256)),
        (int(-1), int(COSE_CURVE_X25519)),
        (int(-2), bytes(public_key.to_vec())),
    ];
    if let Some(key_id) = key_id {
        entries.insert(1, (int(2), bytes(key_id.to_vec())));
    }
    Value::Map(entries)
}

fn eek_payload_p256(key_id: Option<&[u8]>, x: &[u8], y: &[u8]) -> Value {
    let mut entries = vec![
        (int(1), int(2)),
        (int(3), int(COSE_ALGORITHM_ECDH_ES_HKDF_256)),
        (int(-1), int(COSE_CURVE_P256)),
        (int(-2), bytes(x.to_vec())),
        (int(-3), bytes(y.to_vec())),
    ];
    if let Some(key_id) = key_id {
        entries.insert(1, (int(2), bytes(key_id.to_vec())));
    }
    Value::Map(entries)
}

fn eek_chain_entry(curve: i128, payload: Value) -> Value {
    Value::Array(vec![
        int(curve),
        Value::Array(vec![Value::Array(vec![
            Value::Null,
            Value::Null,
            bytes(encode(&payload).unwrap()),
        ])]),
    ])
}

fn fetch_eek_response(chains: Vec<Value>, challenge: &[u8]) -> Vec<u8> {
    encode(&Value::Array(vec![
        Value::Array(chains),
        bytes(challenge.to_vec()),
    ]))
    .unwrap()
}

#[test]
fn validate_challenge_rejects_oversized_values() {
    let error = validate_challenge(&[0_u8; MAX_RKP_CHALLENGE_LEN + 1]).unwrap_err();
    assert!(error.to_string().contains("challenge"));
}

#[test]
fn parse_fetch_eek_response_prefers_x25519_over_p256() {
    let challenge = [0xAA; 32];
    let x25519_key_id = [0x11; 4];
    let p256_key_id = [0x22; 4];
    let x = [0x44; 32];
    let y = [0x55; 32];

    let body = fetch_eek_response(
        vec![
            eek_chain_entry(RPC_CURVE_P256, eek_payload_p256(Some(&p256_key_id), &x, &y)),
            eek_chain_entry(
                RPC_CURVE_25519,
                eek_payload_x25519(Some(&x25519_key_id), &[0x33; 32]),
            ),
        ],
        &challenge,
    );

    let parsed = parse_fetch_eek_response(&body).unwrap();
    assert_eq!(parsed.eek_curve, RPC_CURVE_25519);
    assert_eq!(parsed.eek_public, vec![0x33; 32]);
    assert_eq!(parsed.eek_id, x25519_key_id);
    assert_eq!(parsed.eek_chains.len(), 2);
    for chain in &parsed.eek_chains {
        let chain_value = crate::cbor::decode(&chain.encoded).unwrap();
        let original = crate::cbor::decode(&body).unwrap();
        let outer = crate::cbor::as_array(&original, "response").unwrap();
        let entries = crate::cbor::as_array(&outer[0], "chains").unwrap();
        let entry = entries
            .iter()
            .find(|entry| crate::cbor::as_array(entry, "entry").unwrap()[0] == int(chain.curve))
            .unwrap();
        assert_eq!(
            chain_value,
            crate::cbor::as_array(entry, "entry").unwrap()[1]
        );
    }
}

#[test]
fn parse_fetch_eek_response_accepts_p256_coordinates() {
    let challenge = [0xAB; 32];
    let key_id = [0x77; 4];
    let x = [0x10; 32];
    let y = [0x20; 32];

    let body = fetch_eek_response(
        vec![eek_chain_entry(
            RPC_CURVE_P256,
            eek_payload_p256(Some(&key_id), &x, &y),
        )],
        &challenge,
    );

    let parsed = parse_fetch_eek_response(&body).unwrap();
    let mut expected_public = Vec::from(x);
    expected_public.extend_from_slice(&y);

    assert_eq!(parsed.eek_curve, RPC_CURVE_P256);
    assert_eq!(parsed.eek_public, expected_public);
    assert_eq!(parsed.eek_id, key_id);
    assert_eq!(parsed.challenge, challenge);
}

#[test]
fn retaining_legacy_chains_does_not_reject_unusable_trailing_entries() {
    let valid = eek_chain_entry(RPC_CURVE_25519, eek_payload_x25519(None, &[0x33; 32]));
    let body = fetch_eek_response(vec![valid, Value::Null, Value::Array(vec![])], &[1; 32]);
    let response = parse_fetch_eek_response(&body).unwrap();
    assert_eq!(response.eek_public, [0x33; 32]);
    assert_eq!(response.eek_chains.len(), 1);
}

#[test]
fn parse_fetch_eek_response_skips_malformed_preferred_chain() {
    let challenge = [0xAC; 32];
    let key_id = [0x88; 4];
    let x = [0x21; 32];
    let y = [0x43; 32];

    let body = fetch_eek_response(
        vec![
            eek_chain_entry(
                RPC_CURVE_25519,
                eek_payload_x25519(Some(&[0x99; 4]), &[0x31; 31]),
            ),
            eek_chain_entry(RPC_CURVE_P256, eek_payload_p256(Some(&key_id), &x, &y)),
        ],
        &challenge,
    );

    let parsed = parse_fetch_eek_response(&body).unwrap();
    assert_eq!(parsed.eek_curve, RPC_CURVE_P256);
    assert_eq!(parsed.eek_id, key_id);
    assert_eq!(parsed.eek_public.len(), 64);
}

#[test]
fn parse_fetch_eek_response_allows_missing_key_identifier() {
    let challenge = [0xAD; 32];
    let body = fetch_eek_response(
        vec![eek_chain_entry(
            RPC_CURVE_25519,
            eek_payload_x25519(None, &[0x42; 32]),
        )],
        &challenge,
    );

    let parsed = parse_fetch_eek_response(&body).unwrap();
    assert_eq!(parsed.eek_curve, RPC_CURVE_25519);
    assert_eq!(parsed.eek_public, vec![0x42; 32]);
    assert!(parsed.eek_id.is_empty());
}

#[test]
fn an_empty_certificate_result_is_a_server_response_error() {
    for nested in [false, true] {
        let result = Value::Array(vec![bytes(vec![1, 2]), Value::Array(vec![])]);
        let result = if nested {
            Value::Array(vec![result])
        } else {
            result
        };
        let error = super::parse_sign_certificates_response(&encode(&result).unwrap()).unwrap_err();
        assert_eq!(crate::error::code_of(&error), "invalid_rkp_response");
    }
}

#[test]
fn certificate_results_preserve_every_chain_in_both_response_shapes() {
    for nested in [false, true] {
        let result = Value::Array(vec![
            bytes(vec![1, 2]),
            Value::Array(vec![bytes(vec![3]), bytes(vec![4, 5])]),
        ]);
        let result = if nested {
            Value::Array(vec![result])
        } else {
            result
        };
        let chains = super::parse_sign_certificates_response(&encode(&result).unwrap()).unwrap();
        assert_eq!(chains, vec![vec![1, 2, 3], vec![1, 2, 4, 5]]);
    }
}
