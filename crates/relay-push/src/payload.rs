//! Push bodies (spec 0.4.4, 0.12.4, CONN-04 API 3–4). The relay adds no
//! display text: APNs carries only a catalog `loc-key` that the iPhone
//! translates, plus the envelope encrypted with `K_push` for the
//! Notification Service Extension; FCM carries no content at all.

use serde_json::{Value, json};
use uuid::Uuid;

use crate::Reason;

/// APNs payload limit (spec 0.4.4).
pub const APNS_MAX_PAYLOAD_BYTES: usize = 4096;
/// FCM TTL of a wake (spec 0.4.4): a wake older than this is useless.
pub const FCM_WAKE_TTL_S: u32 = 60;

/// `aps.alert.loc-key`, `interruption-level` and `thread-id` per reason
/// (CONN-04 API 4 table). Only alert reasons have one.
pub fn apns_presentation(reason: Reason) -> Option<(&'static str, &'static str, &'static str)> {
    match reason {
        // Generic groups (CONN-04 API 4 logic 3): the conversation is inside
        // the encrypted envelope; I-NSE sets the notification's
        // `threadIdentifier` after decrypting (SMS-02 API 4), and a locked
        // iPhone keeps every SMS push in the `sms` group.
        Reason::SmsNew => Some(("push.sms_new", "active", "sms")),
        Reason::CallIncoming => Some(("push.call_incoming", "time-sensitive", "calls")),
        Reason::CallMissed => Some(("push.call_missed", "active", "calls")),
        Reason::UserOpen | Reason::SmsSend | Reason::CallAction => None,
    }
}

/// `{"aps":{…},"p":<pair_id>,"hl":<env_b64>}` of CONN-04 API 4.
pub fn apns_payload(reason: Reason, pair_id: &Uuid, env_b64: &str) -> Option<Value> {
    let (loc_key, level, thread) = apns_presentation(reason)?;
    Some(json!({
        "aps": {
            "alert": { "loc-key": loc_key },
            "mutable-content": 1,
            "sound": "default",
            "thread-id": thread,
            "interruption-level": level,
        },
        "p": pair_id.hyphenated().to_string(),
        "hl": env_b64,
    }))
}

/// The FCM HTTP v1 request of CONN-04 API 3: a high-priority data message
/// `{t, p, r}` with no notification block and no content.
pub fn fcm_message(token: &str, pair_id: &Uuid, reason: Reason, ttl_s: u32) -> Value {
    json!({
        "message": {
            "token": token,
            "data": {
                "t": "wake",
                "p": pair_id.hyphenated().to_string(),
                "r": reason.as_str(),
            },
            "android": {
                "priority": "HIGH",
                "ttl": format!("{}s", ttl_s.min(FCM_WAKE_TTL_S)),
                "collapse_key": "wake",
            },
        }
    })
}
