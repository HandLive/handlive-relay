//! The push clients against local mock providers (no real credentials):
//! APNs over HTTP/2 with an ES256 provider token, FCM HTTP v1 with a
//! service-account OAuth2 token; headers, bodies, token reuse and renewal,
//! retries and the mapping of provider errors (CONN-04 API 3–4).

mod common;

use std::time::{SystemTime, UNIX_EPOCH};

use actix_web::http::Version;
use common::{
    PROJECT, TOPIC, TempDir, apns_config, apns_mock, ec_key, fcm_config, fcm_mock, rsa_key,
};
use relay_push::{Alert, Outcome, PushConfig, PushGateway, Reason, Wake};
use serde_json::json;
use uuid::Uuid;

fn now_s() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn alert<'a>(
    token: &'a str,
    reason: Reason,
    collapse: Option<&'a str>,
    sandbox: bool,
) -> Alert<'a> {
    Alert {
        token,
        topic: TOPIC,
        sandbox,
        pair_id: Uuid::parse_str("7a6b5c4d-3e2f-4a1b-9c8d-7e6f5a4b3c2d").unwrap(),
        reason,
        env_b64: "ZW5jcnlwdGVkIHdpdGggS19wdXNo",
        collapse_key: collapse,
        ttl_s: reason.default_ttl_s(),
    }
}

#[actix_web::test]
async fn apns_alerts_carry_the_spec_headers_and_payload() {
    let key = ec_key();
    let production = apns_mock(&key).await;
    let sandbox = apns_mock(&key).await;
    let dir = TempDir::new();
    let config = PushConfig {
        apns: Some(apns_config(&dir, &key, &production.url, &sandbox.url)),
        fcm: None,
    };
    let gateway = PushGateway::new(&config).unwrap();
    assert_eq!(gateway.apns_topic(), Some(TOPIC));

    let sms = alert("aa01", Reason::SmsNew, Some("sms:12847"), false);
    assert_eq!(gateway.alert(&sms).await, Outcome::Sent);
    let call = alert("aa02", Reason::CallIncoming, Some("call:0192f4b2"), false);
    assert_eq!(gateway.alert(&call).await, Outcome::Sent);
    let dev = alert("aa03", Reason::CallMissed, None, true);
    assert_eq!(gateway.alert(&dev).await, Outcome::Sent);

    let seen = production.mock.seen();
    assert_eq!(seen.len(), 2);
    let first = &seen[0];
    assert_eq!(first.path, "/3/device/aa01");
    assert_eq!(first.version, Version::HTTP_2);
    assert_eq!(first.headers["apns-push-type"], "alert");
    assert_eq!(first.headers["apns-priority"], "10");
    assert_eq!(first.headers["apns-topic"], TOPIC);
    assert_eq!(first.headers["apns-collapse-id"], "sms:12847");
    let expiration: u64 = first.headers["apns-expiration"].parse().unwrap();
    assert!(expiration.abs_diff(now_s() + 86_400) <= 5, "{expiration}");
    assert_eq!(
        first.body,
        json!({"aps":{"alert":{"loc-key":"push.sms_new"},"mutable-content":1,"sound":"default",
               "thread-id":"sms","interruption-level":"active"},
               "p":"7a6b5c4d-3e2f-4a1b-9c8d-7e6f5a4b3c2d","hl":"ZW5jcnlwdGVkIHdpdGggS19wdXNo"})
    );
    let second = &seen[1];
    assert_eq!(second.body["aps"]["interruption-level"], "time-sensitive");
    assert_eq!(second.body["aps"]["thread-id"], "calls");
    let expiration: u64 = second.headers["apns-expiration"].parse().unwrap();
    assert!(expiration.abs_diff(now_s() + 30) <= 5);
    // The provider token is reused, not signed per push.
    assert_eq!(
        first.headers["authorization"],
        second.headers["authorization"]
    );
    // apns_sandbox tokens go to the sandbox endpoint; no collapse id if none.
    let dev_seen = sandbox.mock.seen();
    assert_eq!(dev_seen.len(), 1);
    assert_eq!(dev_seen[0].path, "/3/device/aa03");
    assert!(!dev_seen[0].headers.contains_key("apns-collapse-id"));
    assert_eq!(*production.mock.rejected_auth.lock().unwrap(), 0);
    production.stop().await;
    sandbox.stop().await;
}

#[actix_web::test]
async fn apns_errors_map_to_outcomes() {
    let key = ec_key();
    let apns = apns_mock(&key).await;
    let dir = TempDir::new();
    let config = PushConfig {
        apns: Some(apns_config(&dir, &key, &apns.url, &apns.url)),
        fcm: None,
    };
    let gateway = PushGateway::new(&config).unwrap();
    let m = &apns.mock;
    m.script(
        "bb01",
        &[(410, json!({"reason": "Unregistered", "timestamp": 1}))],
    );
    m.script("bb02", &[(503, json!({"reason": "ServiceUnavailable"}))]);
    m.script("bb03", &[(403, json!({"reason": "ExpiredProviderToken"}))]);
    m.script("bb04", &[(400, json!({"reason": "BadDeviceToken"}))]);
    m.script("bb05", &[(429, json!({"reason": "TooManyRequests"}))]);
    m.script("bb06", &[(500, json!({})), (500, json!({}))]);

    let send = |token: &'static str| alert(token, Reason::SmsNew, None, false);
    assert_eq!(gateway.alert(&send("bb01")).await, Outcome::TokenInvalid);
    assert_eq!(
        gateway.alert(&send("bb02")).await,
        Outcome::Sent,
        "retried once"
    );
    assert_eq!(
        gateway.alert(&send("bb03")).await,
        Outcome::Sent,
        "new provider token"
    );
    assert_eq!(gateway.alert(&send("bb04")).await, Outcome::Failed);
    assert_eq!(gateway.alert(&send("bb05")).await, Outcome::Failed);
    assert_eq!(
        gateway.alert(&send("bb06")).await,
        Outcome::Failed,
        "one retry only"
    );
    let per_token = |t: &str| m.seen().iter().filter(|s| s.path.ends_with(t)).count();
    let counts: Vec<usize> = ["bb01", "bb02", "bb03", "bb04", "bb05", "bb06"]
        .iter()
        .map(|t| per_token(t))
        .collect();
    assert_eq!(counts, vec![1, 2, 2, 1, 1, 2]);

    // Over 4 KB the push is not sent at all.
    let mut big = send("bb07");
    let huge = "A".repeat(5000);
    big.env_b64 = &huge;
    assert_eq!(gateway.alert(&big).await, Outcome::TooLarge);
    assert_eq!(per_token("bb07"), 0);
    // A wake never goes to APNs.
    assert_eq!(
        gateway
            .alert(&alert("bb08", Reason::UserOpen, None, false))
            .await,
        Outcome::Failed
    );
    apns.stop().await;
}

fn wake(token: &str, reason: Reason) -> Wake<'_> {
    Wake {
        token,
        pair_id: Uuid::parse_str("7a6b5c4d-3e2f-4a1b-9c8d-7e6f5a4b3c2d").unwrap(),
        reason,
        ttl_s: reason.default_ttl_s(),
    }
}

#[actix_web::test]
async fn fcm_wakes_use_one_oauth_token_and_map_errors() {
    let key = rsa_key();
    let fcm = fcm_mock(&key).await;
    let dir = TempDir::new();
    let config = PushConfig {
        apns: None,
        fcm: Some(fcm_config(&dir, &key, &fcm.url)),
    };
    let gateway = PushGateway::new(&config).unwrap();
    assert_eq!(gateway.apns_topic(), None);

    assert_eq!(
        gateway.wake(&wake("phone-1", Reason::SmsSend)).await,
        Outcome::Sent
    );
    assert_eq!(
        gateway.wake(&wake("phone-1", Reason::UserOpen)).await,
        Outcome::Sent
    );
    assert_eq!(
        *fcm.mock.token_requests.lock().unwrap(),
        1,
        "access token reused"
    );
    let seen = fcm.mock.seen();
    assert_eq!(
        seen[0].path,
        format!("/v1/projects/{PROJECT}/messages:send")
    );
    assert_eq!(
        seen[0].body,
        json!({"message":{"token":"phone-1","data":{"t":"wake","p":"7a6b5c4d-3e2f-4a1b-9c8d-7e6f5a4b3c2d","r":"sms_send"},
               "android":{"priority":"HIGH","ttl":"60s","collapse_key":"wake"}}})
    );

    let m = &fcm.mock;
    m.script(
        "phone-gone",
        &[(404, json!({"error": {"code": 404, "status": "NOT_FOUND", "details": [
            {"@type": "type.googleapis.com/google.firebase.fcm.v1.FcmError", "errorCode": "UNREGISTERED"}]}}))],
    );
    m.script(
        "phone-flaky",
        &[(
            503,
            json!({"error": {"code": 503, "status": "UNAVAILABLE"}}),
        )],
    );
    m.script(
        "phone-quota",
        &[(
            429,
            json!({"error": {"code": 429, "status": "RESOURCE_EXHAUSTED",
        "details": [{"errorCode": "QUOTA_EXCEEDED"}]}}),
        )],
    );
    m.script(
        "phone-auth",
        &[(
            401,
            json!({"error": {"code": 401, "status": "UNAUTHENTICATED"}}),
        )],
    );
    assert_eq!(
        gateway.wake(&wake("phone-gone", Reason::CallAction)).await,
        Outcome::TokenInvalid
    );
    assert_eq!(
        gateway.wake(&wake("phone-flaky", Reason::SmsSend)).await,
        Outcome::Sent
    );
    assert_eq!(
        gateway.wake(&wake("phone-quota", Reason::SmsSend)).await,
        Outcome::Failed
    );
    // A 401 renews the access token once.
    assert_eq!(
        gateway.wake(&wake("phone-auth", Reason::SmsSend)).await,
        Outcome::Sent
    );
    assert_eq!(*m.token_requests.lock().unwrap(), 2);
    fcm.stop().await;
}

#[actix_web::test]
async fn unconfigured_or_unreachable_providers_fail_cleanly() {
    let gateway = PushGateway::new(&PushConfig::default()).unwrap();
    assert_eq!(
        gateway.wake(&wake("t", Reason::SmsSend)).await,
        Outcome::Failed
    );
    assert_eq!(
        gateway
            .alert(&alert("aa", Reason::SmsNew, None, false))
            .await,
        Outcome::Failed
    );

    // Nothing listens on the endpoint: one retry, then Failed.
    let key = ec_key();
    let dir = TempDir::new();
    let dead = "http://127.0.0.1:9";
    let config = PushConfig {
        apns: Some(apns_config(&dir, &key, dead, dead)),
        fcm: None,
    };
    let gateway = PushGateway::new(&config).unwrap();
    assert_eq!(
        gateway
            .alert(&alert("aa", Reason::SmsNew, None, false))
            .await,
        Outcome::Failed
    );

    // Unusable key files are refused at startup, without echoing them.
    let bad = PushConfig {
        apns: Some(relay_push::ApnsConfig {
            key_path: dir.write(
                "bad.p8",
                "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n",
            ),
            ..apns_config(&dir, &key, dead, dead)
        }),
        fcm: None,
    };
    let err = PushGateway::new(&bad).err().unwrap();
    assert!(!err.contains("AAAA"), "{err}");
    let missing = PushConfig {
        apns: Some(relay_push::ApnsConfig {
            key_path: dir.0.join("missing.p8"),
            ..apns_config(&dir, &key, dead, dead)
        }),
        fcm: None,
    };
    assert!(PushGateway::new(&missing).is_err());
}
