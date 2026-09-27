//! The APNs requests the relay sends for the `POST /v1/push` bodies of
//! `shared/test-vectors/push-envelope.json` (SMS pushes, a call, and the SMS
//! text-cut cases): headers, expiration and payload exactly as the vectors
//! give them, including the generic `thread-id` (CONN-04 API 4 logic 3).

mod common;

use common::{TOPIC, TempDir, apns_config, apns_mock, ec_key};
use relay_push::{Alert, Outcome, PushConfig, PushGateway, Reason};
use serde_json::Value;
use uuid::Uuid;

fn now_s() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn vectors() -> Value {
    let path = format!(
        "{}/../../../shared/test-vectors/push-envelope.json",
        env!("CARGO_MANIFEST_DIR")
    );
    serde_json::from_str(&std::fs::read_to_string(&path).expect("read vectors")).unwrap()
}

#[actix_web::test]
async fn apns_requests_match_the_push_vectors() {
    let key = ec_key();
    let apns = apns_mock(&key).await;
    let dir = TempDir::new();
    let config = PushConfig {
        apns: Some(apns_config(&dir, &key, &apns.url, &apns.url)),
        fcm: None,
    };
    let gateway = PushGateway::new(&config).unwrap();
    let doc = vectors();
    let mut sent = 0;
    for v in doc["vectors"].as_array().unwrap() {
        let Some(body) = v["push_request"].as_str() else {
            continue;
        };
        let req: Value = serde_json::from_str(body).unwrap();
        let reason = Reason::parse(req["reason"].as_str().unwrap()).unwrap();
        let token = format!("aa{:04x}", sent);
        let alert = Alert {
            token: &token,
            topic: TOPIC,
            sandbox: false,
            pair_id: Uuid::parse_str(req["pair_id"].as_str().unwrap()).unwrap(),
            reason,
            env_b64: req["env_b64"].as_str().unwrap(),
            collapse_key: req["collapse_key"].as_str(),
            ttl_s: req["ttl_s"].as_u64().unwrap() as u32,
        };
        assert_eq!(gateway.alert(&alert).await, Outcome::Sent, "{}", v["name"]);
        let seen = apns.mock.seen().pop().unwrap();

        let headers = v["apns_headers"].as_object().unwrap();
        assert!(!headers.is_empty());
        for (name, value) in headers {
            assert_eq!(
                Some(&seen.headers[name]),
                value.as_str().map(str::to_owned).as_ref(),
                "{name}"
            );
        }
        let expiration: u64 = seen.headers["apns-expiration"].parse().unwrap();
        let wanted = now_s() + req["ttl_s"].as_u64().unwrap();
        assert!(expiration.abs_diff(wanted) <= 5, "{}", v["name"]);
        let expected: Value = serde_json::from_str(v["apns_payload"].as_str().unwrap()).unwrap();
        assert_eq!(seen.body, expected, "{}", v["name"]);
        sent += 1;
    }
    assert!(sent >= 8, "push requests in the vectors: {sent}");
    apns.stop().await;
}
