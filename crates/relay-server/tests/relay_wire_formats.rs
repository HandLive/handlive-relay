//! Relay wire formats and pure rules without services: the `to`/`from`
//! wrapper, the `HR` frame, control messages, the instance bus encoding,
//! rendezvous filtering, the bandwidth bucket and push-token validation.

mod common;

use std::time::{Duration, Instant};

use common::load_vectors;
use relay_server::error::ApiError;
use relay_server::relay::bandwidth::TokenBucket;
use relay_server::relay::bus::{BusMessage, channel_device, device_channel};
use relay_server::relay::rendezvous::{canonical_rv_id, rendezvous_allows};
use relay_server::relay::wire::{self, RelayError};
use relay_server::routes::devices::{PushTokenRequest, validate_push_token};
use serde_json::value::RawValue;
use serde_json::{Value, json};
use uuid::Uuid;

const A: &str = "5b1f8c2e-9a4d-8e6f-a1b2-c3d4e5f60718";
const B: &str = "8c7d6e5f-4a3b-8c2d-9e1f-0a1b2c3d4e5f";

fn uuid(s: &str) -> Uuid {
    Uuid::parse_str(s).unwrap()
}

#[test]
fn wrapper_is_rewritten_with_env_bytes_unchanged() {
    // Key order, spacing and escapes of the envelope must survive.
    let env = r#"{ "v":1,"type":"sms","id":"0192f4b2-5c6d-7e8f-9a0b-1c2d3e4f5a6b","ts":1727151200000,"payload":"QUJD+=" , "x":[1, 2] }"#;
    let text = format!(r#"{{"to":"{B}","env":{env}}}"#);
    let inbound = wire::parse_inbound(&text).unwrap();
    assert_eq!(inbound.to, Some(uuid(B)));
    assert!(inbound.op.is_none());
    let raw = inbound.env.unwrap();
    assert!(wire::is_object(raw));
    let out = wire::forwarded_text(&uuid(A), raw);
    assert_eq!(out, format!(r#"{{"from":"{A}","env":{env}}}"#));
    let parsed: Value = serde_json::from_str(&out).unwrap();
    assert_eq!(parsed["from"], A);
    assert_eq!(parsed["env"]["payload"], "QUJD+=");
}

#[test]
fn malformed_wrappers_are_detected() {
    assert!(wire::parse_inbound("not json").is_none());
    assert!(wire::parse_inbound(r#"{"to":"not-a-uuid","env":{}}"#).is_none());
    let arr =
        wire::parse_inbound(r#"{"to":"5b1f8c2e-9a4d-8e6f-a1b2-c3d4e5f60718","env":[1]}"#).unwrap();
    assert!(!wire::is_object(arr.env.unwrap()));
    let control =
        wire::parse_inbound(r#"{"op":"rv_join","rv_id":"Eh8kKS4zOD1CR0xRVltgZQ"}"#).unwrap();
    assert_eq!(control.op.as_deref(), Some("rv_join"));
    assert_eq!(control.rv_id.as_deref(), Some("Eh8kKS4zOD1CR0xRVltgZQ"));
}

#[test]
fn hr_frame_destination_becomes_source() {
    let hl = [0x48, 0x4C, 0x01, 0, 0, 0, 7, 0, 0, 0, 9, 0xAA, 0xBB];
    let mut frame = vec![0x48, 0x52, 0x01, 0x01];
    frame.extend_from_slice(uuid(B).as_bytes());
    frame.extend_from_slice(&hl);
    assert_eq!(wire::parse_hr(&frame), Some(uuid(B)));
    let out = wire::rewrite_hr(&frame, &uuid(A));
    assert_eq!(&out[..4], &frame[..4]);
    assert_eq!(&out[4..20], uuid(A).as_bytes());
    assert_eq!(&out[20..], &hl);

    for bad in [
        &frame[..20],                                               // no HL frame
        &[0x48, 0x4C, 0x01, 0x01][..],                              // HL magic, not HR
        &[&[0x48, 0x52, 0x02, 0x01][..], &frame[4..]].concat()[..], // version 2
        &[&[0x48, 0x52, 0x01, 0x02][..], &frame[4..]].concat()[..], // unknown op
    ] {
        assert_eq!(wire::parse_hr(bad), None);
    }
}

#[test]
fn control_messages_follow_the_catalog() {
    let p = uuid("3f2b1c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d");
    let presence: Value =
        serde_json::from_str(&wire::presence_message(&p, &uuid(B), true)).unwrap();
    assert_eq!(
        presence,
        json!({"op":"presence","pair_id":p.to_string(),"peer_device_id":B,"online":true})
    );
    let revoked: Value = serde_json::from_str(&wire::pair_revoked_message(&p, &uuid(A))).unwrap();
    assert_eq!(
        revoked,
        json!({"op":"pair_revoked","pair_id":p.to_string(),"by":A})
    );
    let joined: Value =
        serde_json::from_str(&wire::rv_joined_message("Eh8kKS4zOD1CR0xRVltgZQ", false)).unwrap();
    assert_eq!(
        joined,
        json!({"op":"rv_joined","rv_id":"Eh8kKS4zOD1CR0xRVltgZQ","peer_present":false})
    );
    let err: Value =
        serde_json::from_str(&wire::error_message(RelayError::NotPaired, Some(&uuid(B)))).unwrap();
    assert_eq!(err["op"], "error");
    assert_eq!(err["code"], "NOT_PAIRED");
    assert_eq!(err["to"], B);
    assert!(err["message"].is_string());
    let err: Value =
        serde_json::from_str(&wire::error_message(RelayError::BadRequest, None)).unwrap();
    assert!(err.get("to").is_none());
    for (e, code) in [
        (RelayError::NotConnected, "NOT_CONNECTED"),
        (RelayError::PayloadTooLarge, "PAYLOAD_TOO_LARGE"),
        (RelayError::Internal, "INTERNAL"),
    ] {
        assert_eq!(e.code(), code);
    }
    let env = RawValue::from_string(r#"{"v":1,"type":"pair"}"#.to_owned()).unwrap();
    assert_eq!(
        wire::rv_msg_message("Eh8kKS4zOD1CR0xRVltgZQ", &env),
        r#"{"op":"rv_msg","rv_id":"Eh8kKS4zOD1CR0xRVltgZQ","env":{"v":1,"type":"pair"}}"#
    );
}

#[test]
fn bus_messages_round_trip() {
    let msgs = [
        BusMessage::ForwardText {
            from: uuid(A),
            text: r#"{"from":"x","env":{}}"#.to_owned(),
        },
        BusMessage::ForwardBinary {
            from: uuid(A),
            frame: vec![0x48, 0x52, 1, 1, 0, 255],
        },
        BusMessage::Control {
            text: "{}".to_owned(),
        },
        BusMessage::PairRevoked {
            pair_id: uuid(B),
            by: uuid(A),
        },
        BusMessage::PairsChanged,
        BusMessage::Replace { conn_id: uuid(B) },
        BusMessage::Close { code: 1000 },
    ];
    for msg in msgs {
        assert_eq!(BusMessage::decode(&msg.encode()), Some(msg));
    }
    assert_eq!(BusMessage::decode(&[]), None);
    assert_eq!(BusMessage::decode(&[99]), None);
    assert_eq!(BusMessage::decode(&[7, 1]), None);
    assert_eq!(device_channel(&uuid(A)), format!("dev:{A}"));
    assert_eq!(channel_device(format!("dev:{A}").as_bytes()), Some(uuid(A)));
    assert_eq!(channel_device(b"presence:x"), None);
}

#[test]
fn rendezvous_only_carries_qr_pair_envelopes() {
    let doc = load_vectors("pair-handshake.json");
    let mut qr = 0;
    let mut pin = 0;
    for v in doc["vectors"].as_array().unwrap() {
        let env = RawValue::from_string(v["hello_envelope"].as_str().unwrap().to_owned()).unwrap();
        // PIN pairing is LAN-only: the relay blocks a PIN-mode pair/hello.
        let allowed = v["mode"] == "qr";
        assert_eq!(rendezvous_allows(&env), allowed, "{}", v["name"]);
        if allowed {
            qr += 1
        } else {
            pin += 1
        }
        let offer =
            RawValue::from_string(v["offer_envelope"].as_str().unwrap().to_owned()).unwrap();
        assert!(rendezvous_allows(&offer));
    }
    assert!(qr >= 1 && pin >= 1);
    let sms = RawValue::from_string(
        r#"{"v":1,"type":"sms","id":"x","ts":1,"payload":"AA=="}"#.to_owned(),
    )
    .unwrap();
    assert!(!rendezvous_allows(&sms));
    let not_env = RawValue::from_string("[1]".to_owned()).unwrap();
    assert!(!rendezvous_allows(&not_env));

    assert_eq!(
        canonical_rv_id("Eh8kKS4zOD1CR0xRVltgZQ").as_deref(),
        Some("Eh8kKS4zOD1CR0xRVltgZQ")
    );
    assert_eq!(canonical_rv_id("Eh8kKS4zOD1CR0xRVltgZR"), None); // non-zero padding bits
    assert_eq!(canonical_rv_id("Eh8kKS4zOD1CR0xRVltg"), None); // 15 bytes
    assert_eq!(canonical_rv_id("Eh8kKS4zOD1CR0xRVltgZQ=="), None); // padded
}

#[test]
fn bucket_delays_instead_of_dropping() {
    let t0 = Instant::now();
    let mut bucket = TokenBucket::new(1000, t0);
    assert_eq!(bucket.take(600, t0), Duration::ZERO);
    assert_eq!(bucket.take(400, t0), Duration::ZERO);
    // 500 bytes over the budget at 1,000 B/s: wait half a second.
    let wait = bucket.take(500, t0);
    assert!((wait.as_secs_f64() - 0.5).abs() < 1e-6, "{wait:?}");
    // After the wait the debt is paid and refilling resumes.
    let later = t0 + Duration::from_millis(1500);
    assert_eq!(bucket.take(1000, later), Duration::ZERO);
    // Refill never exceeds one second of budget.
    let much_later = later + Duration::from_secs(60);
    assert_eq!(bucket.take(1000, much_later), Duration::ZERO);
    assert!(bucket.take(1, much_later) > Duration::ZERO);
}

fn push(provider: &str, token: &str, topic: Option<&str>) -> PushTokenRequest {
    PushTokenRequest {
        provider: provider.to_owned(),
        token: token.to_owned(),
        topic: topic.map(str::to_owned),
    }
}

#[test]
fn push_token_provider_must_fit_the_platform() {
    let hex = "4f1c2e00a9";
    let ok = [
        ("android", push("fcm", "dQw4w9WgXcQ:APA91bH-x_y", None)),
        ("android", push("fcm", "token", Some("ignored"))),
        ("ios", push("apns", hex, Some("app.handlive.ios"))),
        (
            "ipados",
            push("apns_sandbox", hex, Some("app.handlive.ios")),
        ),
    ];
    for (platform, req) in &ok {
        assert!(
            validate_push_token(platform, req).is_ok(),
            "{platform} {}",
            req.provider
        );
    }
    let (_, _, topic) = validate_push_token("android", &ok[1].1).unwrap();
    assert_eq!(topic, None);
    let bad = [
        ("android", push("apns", hex, Some("app.handlive.ios"))),
        ("ios", push("fcm", "token", None)),
        ("macos", push("apns", hex, Some("app.handlive.ios"))),
        ("ios", push("apns", hex, None)),
        ("ios", push("apns", "not-hex", Some("app.handlive.ios"))),
        ("ios", push("apns", hex, Some("bad topic"))),
        ("ios", push("apns", hex, Some(""))),
        ("android", push("fcm", "", None)),
        ("android", push("fcm", "has space", None)),
        ("android", push("gcm", "token", None)),
        ("android", push("fcm", &"x".repeat(4097), None)),
        ("ios", push("apns", hex, Some(&"a".repeat(256)))),
    ];
    for (platform, req) in &bad {
        assert!(
            matches!(
                validate_push_token(platform, req),
                Err(ApiError::BadRequest)
            ),
            "{platform} {} {} {:?}",
            req.provider,
            req.token.len(),
            req.topic
        );
    }
    assert!(validate_push_token("android", &push("fcm", &"x".repeat(4096), None)).is_ok());
}
