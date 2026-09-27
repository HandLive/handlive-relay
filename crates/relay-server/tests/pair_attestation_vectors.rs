//! `POST /v1/pairs` checks (PAIR-01 API 8) against the cross-platform
//! pairing vectors `shared/test-vectors/pair-handshake.json`: the request
//! bodies the devices send must verify, and every tampered form must fail.

mod common;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use common::{hex32, load_vectors};
use relay_server::attestation::{ATTESTATION_LEN, Attestation, PairClaim, verify_pair_claim};
use relay_server::error::ApiError;
use relay_server::routes::pairs::{PairFields, PairRequest, decode_pair_request};
use serde_json::Value;

struct Case {
    req: PairRequest,
    fields: PairFields,
    key_a: [u8; 32],
    key_b: [u8; 32],
}

fn cases() -> Vec<(Value, Case)> {
    let doc = load_vectors("pair-handshake.json");
    doc["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| {
            let req: PairRequest =
                serde_json::from_str(v["pairs_request"].as_str().unwrap()).unwrap();
            let fields = decode_pair_request(&req).expect("vector request decodes");
            let key_a = hex32(v["android_ik_sig_pub"].as_str().unwrap());
            let key_b = hex32(v["client_ik_sig_pub"].as_str().unwrap());
            (
                v.clone(),
                Case {
                    req,
                    fields,
                    key_a,
                    key_b,
                },
            )
        })
        .collect()
}

fn check(
    case: &Case,
    attestation: &[u8],
    sig_a: &[u8; 64],
    sig_b: &[u8; 64],
) -> Result<(), ApiError> {
    let claim = PairClaim {
        pair_id: case.req.pair_id,
        device_a: case.req.device_a,
        device_b: case.req.device_b,
        created_at_ms: case.req.created_at,
        attestation,
        sig_a,
        sig_b,
    };
    verify_pair_claim(&claim, &case.key_a, &case.key_b)
}

#[test]
fn vector_pair_requests_verify() {
    let cases = cases();
    assert!(cases.len() >= 2);
    for (v, case) in &cases {
        let f = &case.fields;
        assert_eq!(
            hex::encode(&f.attestation),
            v["attestation"].as_str().unwrap()
        );
        assert_eq!(f.attestation.len(), ATTESTATION_LEN);
        // sig_a is the Android signature (sig_s), sig_b the client's (sig_c).
        assert_eq!(hex::encode(f.sig_a), v["sig_s"].as_str().unwrap());
        assert_eq!(hex::encode(f.sig_b), v["sig_c"].as_str().unwrap());
        assert_eq!(
            check(case, &f.attestation, &f.sig_a, &f.sig_b),
            Ok(()),
            "{}",
            v["name"]
        );
    }
}

#[test]
fn attestation_layout_matches_vector_parts() {
    for (v, case) in cases() {
        let parsed = Attestation::parse(&case.fields.attestation).unwrap();
        assert_eq!(parsed.pair_id, case.req.pair_id);
        assert_eq!(parsed.device_a, case.req.device_a);
        assert_eq!(parsed.device_b, case.req.device_b);
        assert_eq!(parsed.created_at_ms, v["created_at"].as_i64().unwrap());
        assert_eq!(parsed.to_bytes(), case.fields.attestation);
        let joined: String = v["attestation_parts"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| p["hex"].as_str().unwrap())
            .collect();
        assert_eq!(joined, v["attestation"].as_str().unwrap());
    }
}

#[test]
fn tampered_requests_are_rejected() {
    for (_, case) in cases() {
        let f = &case.fields;
        // Signatures swapped between the two devices.
        assert_eq!(
            check(&case, &f.attestation, &f.sig_b, &f.sig_a),
            Err(ApiError::SignatureInvalid)
        );
        // One bit of the signed attestation changed (inside the created_at field):
        // the body no longer matches it.
        let mut changed = f.attestation.clone();
        changed[ATTESTATION_LEN - 1] ^= 1;
        assert_eq!(
            check(&case, &changed, &f.sig_a, &f.sig_b),
            Err(ApiError::BadRequest)
        );
        // A key inside the attestation that is not the registered key.
        let mut other_key = f.attestation.clone();
        other_key[7 + 48] ^= 1;
        assert_eq!(
            check(&case, &other_key, &f.sig_a, &f.sig_b),
            Err(ApiError::SignatureInvalid)
        );
        // Wrong label or length.
        let mut label = f.attestation.clone();
        label[0] = b'X';
        assert_eq!(
            check(&case, &label, &f.sig_a, &f.sig_b),
            Err(ApiError::BadRequest)
        );
        assert_eq!(
            check(
                &case,
                &f.attestation[..ATTESTATION_LEN - 1],
                &f.sig_a,
                &f.sig_b
            ),
            Err(ApiError::BadRequest)
        );
        // The stored keys of the relay are those of other devices.
        let swapped = Case {
            req: clone_req(&case.req),
            fields: PairFields {
                attestation: f.attestation.clone(),
                sig_a: f.sig_a,
                sig_b: f.sig_b,
            },
            key_a: case.key_b,
            key_b: case.key_a,
        };
        assert_eq!(
            check(&swapped, &f.attestation, &f.sig_a, &f.sig_b),
            Err(ApiError::SignatureInvalid)
        );
    }
}

#[test]
fn body_that_disagrees_with_the_attestation_is_rejected() {
    for (_, case) in cases() {
        let f = &case.fields;
        let mut req = clone_req(&case.req);
        req.created_at += 1;
        let other = Case {
            req,
            fields: PairFields {
                attestation: f.attestation.clone(),
                sig_a: f.sig_a,
                sig_b: f.sig_b,
            },
            key_a: case.key_a,
            key_b: case.key_b,
        };
        assert_eq!(
            check(&other, &f.attestation, &f.sig_a, &f.sig_b),
            Err(ApiError::BadRequest)
        );
    }
}

/// The negative client-signature vectors (a signature over a wrongly built
/// attestation, or S + L) must not pass as `sig_b`.
#[test]
fn invalid_client_signature_vectors_are_rejected() {
    let doc = load_vectors("pair-handshake.json");
    let cases = cases();
    let mut seen = 0;
    for inv in doc["invalid_vectors"].as_array().unwrap() {
        if inv["check"] != "sig_c" {
            continue;
        }
        let (_, case) = cases
            .iter()
            .find(|(v, _)| v["name"] == inv["vector"])
            .expect("vector of the negative case");
        let envelope: Value = serde_json::from_str(inv["envelope"].as_str().unwrap()).unwrap();
        let plain = STANDARD
            .decode(envelope["payload"].as_str().unwrap())
            .unwrap();
        let confirm: Value = serde_json::from_slice(&plain).unwrap();
        let sig_b: [u8; 64] =
            relay_server::b64u::decode_fixed(confirm["data"]["sig"].as_str().unwrap()).unwrap();
        let f = &case.fields;
        assert_eq!(
            check(case, &f.attestation, &f.sig_a, &sig_b),
            Err(ApiError::SignatureInvalid),
            "{}",
            inv["name"]
        );
        seen += 1;
    }
    assert!(seen >= 3, "negative sig_c vectors: {seen}");
}

#[test]
fn request_shape_errors_are_bad_request() {
    let (_, case) = cases().remove(0);
    let base = &case.req;
    let mut same = clone_req(base);
    same.device_b = same.device_a;
    assert!(matches!(
        decode_pair_request(&same),
        Err(ApiError::BadRequest)
    ));
    let mut short = clone_req(base);
    short.attestation.pop();
    assert!(matches!(
        decode_pair_request(&short),
        Err(ApiError::BadRequest)
    ));
    let mut sig = clone_req(base);
    sig.sig_a.pop();
    assert!(matches!(
        decode_pair_request(&sig),
        Err(ApiError::BadRequest)
    ));
}

fn clone_req(r: &PairRequest) -> PairRequest {
    PairRequest {
        pair_id: r.pair_id,
        device_a: r.device_a,
        device_b: r.device_b,
        created_at: r.created_at,
        attestation: r.attestation.clone(),
        sig_a: r.sig_a.clone(),
        sig_b: r.sig_b.clone(),
    }
}
