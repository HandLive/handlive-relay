//! Signed revocation (`HLREVOKE1`, spec 0.6.2, PAIR-03 API 3, SET-02 API 2)
//! against `shared/test-vectors/revoke.json`: the message bytes, the relay's
//! checks of `POST /v1/pairs/{pair_id}/revoke` and `DELETE /v1/devices/me`
//! statements, and the forwarded `pair_revoked` frame — without services.

mod common;

use common::{TestDevice, hex32, load_vectors};
use relay_server::error::ApiError;
use relay_server::relay::bus::BusMessage;
use relay_server::relay::wire;
use relay_server::revocation::{
    DeleteRequest, REVOKE_CLOCK_SKEW_MS, RevokeRequest, RevokeStatement, verify_revocations,
    verify_statement,
};
use relay_server::signatures::revoke_message;
use serde_json::Value;
use uuid::Uuid;

fn uuid(v: &Value, field: &str) -> Uuid {
    Uuid::parse_str(v[field].as_str().unwrap()).unwrap()
}

fn parse<T: serde::de::DeserializeOwned>(v: &Value, field: &str) -> T {
    serde_json::from_str(v[field].as_str().unwrap()).unwrap()
}

#[test]
fn valid_statements_are_accepted_and_forwarded_as_signed() {
    let doc = load_vectors("revoke.json");
    let vectors = doc["vectors"].as_array().unwrap();
    assert!(vectors.len() >= 3);
    for v in vectors {
        let name = v["name"].as_str().unwrap();
        let pair_id = uuid(v, "pair_id");
        let by = uuid(v, "device_id");
        let public = hex32(v["ik_sig_pub"].as_str().unwrap());
        let revoked_at = v["revoked_at"].as_i64().unwrap();
        let now = v["relay_now"].as_i64().unwrap();
        assert_eq!(
            hex::encode(revoke_message(&pair_id, &by, revoked_at as u64)),
            v["message"].as_str().unwrap(),
            "{name}"
        );
        // The signing side agrees with the vector (RFC 8032 keys).
        let signer = TestDevice::from_seed(hex32(v["ik_sig_seed"].as_str().unwrap()));
        assert_eq!(signer.device_id, by, "{name}");
        let sig = signer.sign(&revoke_message(&pair_id, &by, revoked_at as u64));
        assert_eq!(hex::encode(sig), v["sig"].as_str().unwrap(), "{name}");

        let req: RevokeRequest = parse(v, "revoke_request");
        let statement = verify_statement(
            &pair_id,
            &by,
            &public,
            req.revoked_at,
            req.sig.as_deref(),
            now,
        )
        .unwrap_or_else(|e| panic!("{name}: {e:?}"));
        let expected = RevokeStatement {
            pair_id,
            by,
            revoked_at,
            sig,
        };
        assert_eq!(statement, expected, "{name}");

        // The same statement as one item of DELETE /v1/devices/me.
        let item: Value = parse(v, "revocation");
        let body: DeleteRequest =
            serde_json::from_value(serde_json::json!({ "revocations": [item] })).unwrap();
        let peer = uuid(v, "peer_device_id");
        let held = [(pair_id, peer)];
        assert_eq!(
            verify_revocations(&held, &body.revocations, &by, &public, now),
            Ok(vec![(expected.clone(), peer)]),
            "{name}"
        );

        // Forwarded frame and the bus between instances carry it unchanged.
        let frame: Value = serde_json::from_str(&wire::pair_revoked_message(&expected)).unwrap();
        assert_eq!(frame, parse::<Value>(v, "pair_revoked"), "{name}");
        let msg = BusMessage::PairRevoked(expected);
        assert_eq!(BusMessage::decode(&msg.encode()), Some(msg), "{name}");
    }
}

#[test]
fn relay_side_negatives_are_bad_requests() {
    let doc = load_vectors("revoke.json");
    let mut checked = 0;
    for v in doc["invalid_vectors"].as_array().unwrap() {
        if v["check"] != "relay" {
            continue;
        }
        let name = v["name"].as_str().unwrap();
        let pair_id = uuid(v, "pair_id");
        let caller = uuid(v, "caller_device_id");
        let public = hex32(v["caller_ik_sig_pub"].as_str().unwrap());
        let now = v["relay_now"].as_i64().unwrap();
        let req: RevokeRequest = parse(v, "revoke_request");
        assert_eq!(
            verify_statement(
                &pair_id,
                &caller,
                &public,
                req.revoked_at,
                req.sig.as_deref(),
                now
            ),
            Err(ApiError::BadRequest),
            "{name}"
        );
        checked += 1;
    }
    assert_eq!(checked, 6);
}

#[test]
fn clock_skew_is_ten_minutes_inclusive() {
    assert_eq!(REVOKE_CLOCK_SKEW_MS, 600_000);
    let device = TestDevice::random();
    let pair_id = Uuid::new_v4();
    let at = 1_727_160_000_000_i64;
    let sig = device.sign(&revoke_message(&pair_id, &device.device_id, at as u64));
    let sig = relay_server::b64u::encode(&sig);
    let check = |now: i64, revoked_at: Option<i64>, sig: Option<&str>| {
        verify_statement(
            &pair_id,
            &device.device_id,
            &device.public,
            revoked_at,
            sig,
            now,
        )
        .map(|_| ())
    };
    assert_eq!(check(at + 600_000, Some(at), Some(&sig)), Ok(()));
    assert_eq!(check(at - 600_000, Some(at), Some(&sig)), Ok(()));
    assert_eq!(
        check(at + 600_001, Some(at), Some(&sig)),
        Err(ApiError::BadRequest)
    );
    assert_eq!(check(at, None, Some(&sig)), Err(ApiError::BadRequest));
    assert_eq!(check(at, Some(at), None), Err(ApiError::BadRequest));
    // revoked_at is an unsigned time on the wire.
    assert_eq!(check(-1, Some(-1), Some(&sig)), Err(ApiError::BadRequest));
    // Another pair's statement does not revoke this one.
    assert_eq!(
        verify_statement(
            &Uuid::new_v4(),
            &device.device_id,
            &device.public,
            Some(at),
            Some(&sig),
            at
        ),
        Err(ApiError::BadRequest)
    );
}

#[test]
fn deleting_everything_needs_one_statement_per_held_pair() {
    let device = TestDevice::random();
    let now = 1_727_160_000_000_i64;
    let (p1, p2, stranger) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
    let (peer1, peer2) = (Uuid::new_v4(), Uuid::new_v4());
    let item = |pair_id: Uuid| {
        let sig = device.sign(&revoke_message(&pair_id, &device.device_id, now as u64));
        serde_json::json!({
            "pair_id": pair_id,
            "revoked_at": now,
            "sig": relay_server::b64u::encode(&sig),
        })
    };
    let body = |items: Vec<Value>| -> DeleteRequest {
        serde_json::from_value(serde_json::json!({ "revocations": items })).unwrap()
    };
    let held = [(p1, peer1), (p2, peer2)];
    let verify = |b: &DeleteRequest| {
        verify_revocations(
            &held,
            &b.revocations,
            &device.device_id,
            &device.public,
            now,
        )
    };

    // A statement for a pair the relay does not hold is ignored.
    let ok = verify(&body(vec![item(p2), item(stranger), item(p1)])).unwrap();
    let pairs: Vec<(Uuid, Uuid)> = ok.iter().map(|(s, peer)| (s.pair_id, *peer)).collect();
    assert_eq!(pairs, vec![(p1, peer1), (p2, peer2)]);
    // Missing for a held pair.
    assert_eq!(verify(&body(vec![item(p1)])), Err(ApiError::BadRequest));
    // A bad one for a held pair.
    let mut bad = item(p2);
    bad["revoked_at"] = serde_json::json!(now + 1);
    assert_eq!(
        verify(&body(vec![item(p1), bad])),
        Err(ApiError::BadRequest)
    );
    // Two statements for the same pair are ambiguous.
    assert_eq!(
        verify(&body(vec![item(p1), item(p1), item(p2)])),
        Err(ApiError::BadRequest)
    );
    // Nothing held: nothing needed.
    assert_eq!(
        verify_revocations(&[], &[], &device.device_id, &device.public, now),
        Ok(vec![])
    );
}
