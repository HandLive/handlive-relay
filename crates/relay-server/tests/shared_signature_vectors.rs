//! Registration (`HLREG1`) and token (`HLAUTH1`) signature checks against the
//! shared vectors `relay-auth.json` and `ed25519.json` (spec 0.6.4, CONN-03
//! API 1 and API 3, RFC 8032 §7.1). Every request goes through the same pure
//! functions the routes call: `verify_registration` and `check_token_proof`.

mod common;

use common::{hex32, load_vectors};
use ed25519_dalek::{Signer, SigningKey};
use relay_server::b64u;
use relay_server::device_identity::device_id_from_public_key;
use relay_server::error::ApiError;
use relay_server::routes::auth::{TokenRequest, check_token_proof};
use relay_server::routes::devices::{RegisterRequest, verify_registration};
use relay_server::signatures::{auth_message, registration_message, verify_device_signature};
use relay_server::store::devices::DeviceKey;
use serde_json::Value;
use std::collections::BTreeSet;

fn text<'a>(v: &'a Value, field: &str) -> &'a str {
    v[field]
        .as_str()
        .unwrap_or_else(|| panic!("{field} missing in {v}"))
}

fn bytes(v: &Value, field: &str) -> Vec<u8> {
    hex::decode(text(v, field)).expect("hex")
}

fn registered(ik_sig_pub: &[u8; 32]) -> Option<DeviceKey> {
    Some(DeviceKey {
        ik_sig_pub: ik_sig_pub.to_vec(),
        revoked: false,
    })
}

fn vectors<'a>(file: &'a Value, list: &str) -> &'a Vec<Value> {
    file[list].as_array().expect("vector list")
}

/// What the relay answers to the token request of a vector, as the route does:
/// decode `sig` (400 when it is not b64u of 64 bytes), then the proof check
/// with the stored challenge and the stored key.
fn token_decision(v: &Value) -> Result<(), ApiError> {
    let req: TokenRequest = serde_json::from_str(text(v, "request")).expect("token request");
    let sig: [u8; 64] = b64u::decode_field(&req.sig)?;
    let challenge: [u8; 32] = bytes(v, "challenge").try_into().expect("32-byte challenge");
    let stored = b64u::encode(&challenge);
    let ik_sig_pub = hex32(text(v, "ik_sig_pub"));
    check_token_proof(Some(&stored), &req, &sig, registered(&ik_sig_pub))
}

/// What the relay answers to the registration request of a vector, with the
/// relay clock at the request's own `ts` (no skew).
fn registration_decision(v: &Value) -> Result<[u8; 32], ApiError> {
    let req: RegisterRequest =
        serde_json::from_str(text(v, "request")).expect("registration request");
    let now = req.ts;
    verify_registration(&req, now)
}

#[test]
fn ed25519_rfc8032_vectors_sign_and_verify() {
    let file = load_vectors("ed25519.json");
    let valid = vectors(&file, "vectors");
    assert_eq!(valid.len(), 3, "RFC 8032 §7.1 TEST 1-3");
    for v in valid {
        let name = text(v, "name");
        let key = SigningKey::from_bytes(&hex32(text(v, "seed")));
        let public = hex32(text(v, "public_key"));
        assert_eq!(key.verifying_key().to_bytes(), public, "{name}");
        let message = bytes(v, "message");
        let signature: [u8; 64] = bytes(v, "signature").try_into().expect("64 bytes");
        assert_eq!(key.sign(&message).to_bytes(), signature, "{name}");
        let id = device_id_from_public_key(&public);
        assert_eq!(
            verify_device_signature(&id, &public, &message, &signature),
            Ok(()),
            "{name}"
        );
    }
}

#[test]
fn ed25519_invalid_vectors_are_rejected() {
    let file = load_vectors("ed25519.json");
    let invalid = vectors(&file, "invalid_vectors");
    assert!(invalid.len() >= 6);
    for v in invalid {
        let name = text(v, "name");
        let public = hex32(text(v, "public_key"));
        let message = bytes(v, "message");
        let raw = bytes(v, "signature");
        let Ok(signature) = <[u8; 64]>::try_from(raw.as_slice()) else {
            assert_eq!(text(v, "reason"), "signature_length", "{name}");
            continue;
        };
        let id = device_id_from_public_key(&public);
        assert_eq!(
            verify_device_signature(&id, &public, &message, &signature),
            Err(ApiError::SignatureInvalid),
            "{name} ({})",
            text(v, "reason")
        );
    }
}

#[test]
fn relay_auth_registrations_are_accepted() {
    let file = load_vectors("relay-auth.json");
    let mut platforms = BTreeSet::new();
    for v in vectors(&file, "vectors")
        .iter()
        .filter(|v| v["kind"] == "register")
    {
        let name = text(v, "name");
        let public = hex32(text(v, "ik_sig_pub"));
        let key = SigningKey::from_bytes(&hex32(text(v, "ik_sig_seed")));
        assert_eq!(key.verifying_key().to_bytes(), public, "{name}");
        let req: RegisterRequest = serde_json::from_str(text(v, "request")).expect("request");
        assert_eq!(req.device_id.to_string(), text(v, "device_id"), "{name}");
        assert_eq!(req.device_id, device_id_from_public_key(&public), "{name}");
        let message = registration_message(&req.device_id, &public, &req.platform, req.ts);
        assert_eq!(hex::encode(&message), text(v, "message"), "{name}");
        assert_eq!(
            hex::encode(key.sign(&message).to_bytes()),
            text(v, "sig"),
            "{name}"
        );
        assert_eq!(registration_decision(v), Ok(public), "{name}");
        platforms.insert(req.platform);
    }
    assert_eq!(
        platforms,
        BTreeSet::from(["android".into(), "ios".into(), "macos".into()])
    );
}

#[test]
fn relay_auth_token_proofs_are_accepted() {
    let file = load_vectors("relay-auth.json");
    let mut count = 0;
    for v in vectors(&file, "vectors")
        .iter()
        .filter(|v| v["kind"] == "auth")
    {
        let name = text(v, "name");
        let public = hex32(text(v, "ik_sig_pub"));
        let req: TokenRequest = serde_json::from_str(text(v, "request")).expect("request");
        assert_eq!(req.device_id, device_id_from_public_key(&public), "{name}");
        assert_eq!(req.challenge, text(v, "challenge_b64u"), "{name}");
        let challenge: [u8; 32] = bytes(v, "challenge").try_into().expect("32 bytes");
        let message = auth_message(&challenge, &req.device_id);
        assert_eq!(hex::encode(&message), text(v, "message"), "{name}");
        assert_eq!(token_decision(v), Ok(()), "{name}");
        count += 1;
    }
    assert_eq!(count, 3);
}

#[test]
fn relay_auth_invalid_requests_are_rejected() {
    let file = load_vectors("relay-auth.json");
    let mut reasons = BTreeSet::new();
    for v in vectors(&file, "invalid_vectors") {
        let name = text(v, "name");
        let reason = text(v, "reason");
        reasons.insert(reason.to_owned());
        let expected = if reason == "signature_length" {
            ApiError::BadRequest
        } else {
            ApiError::SignatureInvalid
        };
        match text(v, "kind") {
            "register" => assert_eq!(registration_decision(v), Err(expected), "{name} ({reason})"),
            "auth" => assert_eq!(token_decision(v), Err(expected), "{name} ({reason})"),
            other => panic!("{name}: unknown kind {other}"),
        }
    }
    let expected: BTreeSet<String> = [
        "device_id_mismatch",
        "message_tampered",
        "signature_length",
        "signature_not_canonical",
        "wrong_key",
        "wrong_label",
    ]
    .into_iter()
    .map(String::from)
    .collect();
    assert_eq!(reasons, expected);
}

#[test]
fn relay_auth_keys_match_device_id_vectors() {
    let ids = load_vectors("device-id.json");
    let known: BTreeSet<(String, String)> = vectors(&ids, "vectors")
        .iter()
        .map(|v| (text(v, "ik_sig_pub").into(), text(v, "device_id").into()))
        .collect();
    let file = load_vectors("relay-auth.json");
    for v in vectors(&file, "vectors") {
        let pair = (text(v, "ik_sig_pub").into(), text(v, "device_id").into());
        assert!(known.contains(&pair), "{}", text(v, "name"));
    }
}
