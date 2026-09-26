//! The relay's wire handling against `shared/test-vectors/relay-frame.json`
//! (0.4.3: `HR` frames and the `to` → `from` rewrite) and the `POST /v1/push`
//! bodies of `shared/test-vectors/push-envelope.json` (CONN-04 API 2).

mod common;

use common::load_vectors;
use relay_push::{Kind, Reason};
use relay_server::relay::wire;
use relay_server::routes::push::{PushRequest, validate_push};
use serde_json::Value;
use uuid::Uuid;

fn bytes(v: &Value, field: &str) -> Vec<u8> {
    hex::decode(v[field].as_str().unwrap()).unwrap()
}

fn uuid(v: &Value, field: &str) -> Uuid {
    Uuid::parse_str(v[field].as_str().unwrap()).unwrap()
}

#[test]
fn hr_frames_and_rewrites_match_the_vectors() {
    let doc = load_vectors("relay-frame.json");
    let (mut frames, mut rewrites) = (0, 0);
    for v in doc["vectors"].as_array().unwrap() {
        match v["kind"].as_str().unwrap() {
            // Outbound the id is the destination, inbound the source: the
            // same header layout either way.
            "frame" => {
                let frame = bytes(v, "frame");
                assert_eq!(
                    wire::parse_hr(&frame),
                    Some(uuid(v, "device_id")),
                    "{}",
                    v["name"]
                );
                assert_eq!(hex::encode(&frame[..wire::HR_HEADER_LEN]), v["header"]);
                assert_eq!(&frame[wire::HR_HEADER_LEN..], &bytes(v, "inner")[..]);
                frames += 1;
            }
            "rewrite" => {
                let outbound = bytes(v, "outbound");
                assert_eq!(
                    wire::parse_hr(&outbound),
                    Some(uuid(v, "recipient_device_id"))
                );
                let delivered = wire::rewrite_hr(&outbound, &uuid(v, "sender_device_id"));
                assert_eq!(delivered, bytes(v, "inbound"), "{}", v["name"]);
                rewrites += 1;
            }
            "text_rewrite" => {
                let outbound = v["outbound"].as_str().unwrap();
                let inbound = wire::parse_inbound(outbound).expect("wrapper parses");
                assert_eq!(inbound.to, Some(uuid(v, "recipient_device_id")));
                let env = inbound.env.expect("env");
                assert_eq!(
                    env.get(),
                    v["env"].as_str().unwrap(),
                    "env kept byte for byte"
                );
                // A `from` sent by the device plays no part.
                let delivered = wire::forwarded_text(&uuid(v, "sender_device_id"), env);
                assert_eq!(delivered, v["inbound"].as_str().unwrap(), "{}", v["name"]);
                rewrites += 1;
            }
            other => panic!("unknown vector kind {other}"),
        }
    }
    assert!(frames >= 4 && rewrites >= 5);
}

#[test]
fn malformed_frames_get_the_vector_errors() {
    let doc = load_vectors("relay-frame.json");
    let mut seen = 0;
    for v in doc["invalid_vectors"].as_array().unwrap() {
        let expected = v["expected_error"].as_str().unwrap();
        let answer = match v["kind"].as_str().unwrap() {
            "frame" => match wire::parse_hr(&bytes(v, "frame")) {
                None => wire::RelayError::BadRequest,
                Some(_) => panic!("{} parsed", v["name"]),
            },
            "text" => match wire::parse_inbound(v["outbound"].as_str().unwrap()) {
                Some(w) if w.env.is_some_and(wire::is_object) => {
                    // A device is never its own peer.
                    assert_eq!(w.to, Some(uuid(v, "sender_device_id")));
                    wire::RelayError::NotPaired
                }
                _ => wire::RelayError::BadRequest,
            },
            other => panic!("unknown kind {other}"),
        };
        assert_eq!(answer.code(), expected, "{}", v["name"]);
        seen += 1;
    }
    assert!(seen >= 8);
}

#[test]
fn push_vector_requests_pass_the_route_checks() {
    let doc = load_vectors("push-envelope.json");
    let mut seen = 0;
    for v in doc["vectors"].as_array().unwrap() {
        let Some(body) = v["push_request"].as_str() else {
            continue;
        };
        let req: PushRequest = serde_json::from_str(body).unwrap();
        let push = validate_push(&req).unwrap_or_else(|e| panic!("{}: {e}", v["name"]));
        let parsed: Value = serde_json::from_str(body).unwrap();
        assert_eq!(push.kind, Kind::Alert);
        assert_eq!(
            Some(push.reason),
            Reason::parse(parsed["reason"].as_str().unwrap())
        );
        assert_eq!(push.env_b64, parsed["env_b64"].as_str());
        assert_eq!(push.collapse_key, parsed["collapse_key"].as_str());
        assert_eq!(i64::from(push.ttl_s), parsed["ttl_s"].as_i64().unwrap());
        assert_eq!(push.env_b64, v["env_b64"].as_str());
        seen += 1;
    }
    assert!(seen >= 3);
}
