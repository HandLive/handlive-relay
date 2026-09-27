//! Push bodies of CONN-04 API 3–4 and how provider answers are classified,
//! without any network.

use relay_push::payload::{APNS_MAX_PAYLOAD_BYTES, apns_payload, fcm_message};
use relay_push::{Kind, Reason, apns, fcm};
use serde_json::json;
use uuid::Uuid;

const PAIR: &str = "7a6b5c4d-3e2f-4a1b-9c8d-7e6f5a4b3c2d";

fn pair() -> Uuid {
    Uuid::parse_str(PAIR).unwrap()
}

#[test]
fn apns_payload_matches_conn04_and_carries_no_text() {
    let env = "eyJ2IjoxLCJ0eXBlIjoic21zIiwiaWQiOiIwMTky";
    // The CONN-04 API 4 example (generic thread-id, logic 3).
    assert_eq!(
        apns_payload(Reason::SmsNew, &pair(), env).unwrap(),
        json!({"aps":{"alert":{"loc-key":"push.sms_new"},"mutable-content":1,"sound":"default",
               "thread-id":"sms","interruption-level":"active"},"p":PAIR,"hl":env})
    );
    let call = apns_payload(Reason::CallIncoming, &pair(), env).unwrap();
    assert_eq!(
        call["aps"]["alert"],
        json!({"loc-key": "push.call_incoming"})
    );
    assert_eq!(call["aps"]["interruption-level"], "time-sensitive");
    assert_eq!(call["aps"]["thread-id"], "calls");
    let missed = apns_payload(Reason::CallMissed, &pair(), env).unwrap();
    assert_eq!(
        missed["aps"]["alert"],
        json!({"loc-key": "push.call_missed"})
    );
    assert_eq!(missed["aps"]["interruption-level"], "active");
    assert_eq!(missed["aps"]["thread-id"], "calls");
    for reason in [Reason::UserOpen, Reason::SmsSend, Reason::CallAction] {
        assert!(
            apns_payload(reason, &pair(), env).is_none(),
            "wakes never go to APNs"
        );
    }
    // A 3,000-byte envelope (the API 2 limit) stays within 4 KB.
    let biggest = apns_payload(Reason::CallIncoming, &pair(), &"A".repeat(3000)).unwrap();
    assert!(biggest.to_string().len() <= APNS_MAX_PAYLOAD_BYTES);
}

#[test]
fn fcm_message_matches_conn04() {
    assert_eq!(
        fcm_message("fcm-token", &pair(), Reason::SmsSend, 60),
        json!({"message":{"token":"fcm-token","data":{"t":"wake","p":PAIR,"r":"sms_send"},
               "android":{"priority":"HIGH","ttl":"60s","collapse_key":"wake"}}})
    );
    // TTL never exceeds 60 s (spec 0.4.4).
    let long = fcm_message("t", &pair(), Reason::UserOpen, 86_400);
    assert_eq!(long["message"]["android"]["ttl"], "60s");
    let short = fcm_message("t", &pair(), Reason::CallAction, 20);
    assert_eq!(short["message"]["android"]["ttl"], "20s");
    assert!(long["message"].get("notification").is_none());
}

#[test]
fn reasons_follow_conn04_api2() {
    let table = [
        ("user_open", Kind::Wake, 60),
        ("sms_send", Kind::Wake, 60),
        ("call_action", Kind::Wake, 60),
        ("sms_new", Kind::Alert, 86_400),
        ("call_incoming", Kind::Alert, 30),
        ("call_missed", Kind::Alert, 86_400),
    ];
    for (text, kind, ttl) in table {
        let reason = Reason::parse(text).unwrap();
        assert_eq!(
            (reason.as_str(), reason.kind(), reason.default_ttl_s()),
            (text, kind, ttl)
        );
    }
    assert_eq!(Reason::parse("sms"), None);
    assert_eq!(Reason::parse("SMS_NEW"), None);
}

#[test]
fn apns_answers_are_classified_per_conn04() {
    use apns::Verdict::*;
    for (status, reason, expected) in [
        (200, None, Sent),
        (410, Some("Unregistered"), Unregistered),
        (403, Some("ExpiredProviderToken"), RenewToken),
        (403, Some("InvalidProviderToken"), RenewToken),
        (403, Some("MissingTopic"), Reject),
        (400, Some("BadDeviceToken"), Reject),
        (400, Some("DeviceTokenNotForTopic"), Reject),
        (413, Some("PayloadTooLarge"), Reject),
        (429, Some("TooManyRequests"), Reject),
        (500, Some("InternalServerError"), Retry),
        (503, Some("ServiceUnavailable"), Retry),
    ] {
        assert_eq!(
            apns::verdict(status, reason),
            expected,
            "{status} {reason:?}"
        );
    }
}

#[test]
fn fcm_answers_are_classified_per_conn04() {
    use fcm::Verdict::*;
    for (status, code, expected) in [
        (200, None, Sent),
        (404, Some("UNREGISTERED"), Unregistered),
        (400, Some("UNREGISTERED"), Unregistered),
        (400, Some("INVALID_ARGUMENT"), Reject),
        (401, Some("UNAUTHENTICATED"), RenewToken),
        (403, Some("SENDER_ID_MISMATCH"), Reject),
        (429, Some("QUOTA_EXCEEDED"), Reject),
        (500, Some("INTERNAL"), Retry),
        (503, Some("UNAVAILABLE"), Retry),
    ] {
        assert_eq!(fcm::verdict(status, code), expected, "{status} {code:?}");
    }
}
