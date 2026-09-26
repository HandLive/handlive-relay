//! Relay wire formats (spec 0.4.3, 0.7.3, CONN-03 API 5–6, PAIR-01 API 7).
//!
//! - Text wrapper: `{"to":"<device_id>","env":{…}}` from a device becomes
//!   `{"from":"<device_id>","env":{…}}` for the destination; `env` is copied
//!   byte for byte and never parsed beyond "is a JSON object".
//! - Binary `HR` frame: `0x48 0x52` ‖ ver(1) ‖ op(1, 0x01 = forward) ‖
//!   device_id(16) ‖ the intact HL frame; the relay swaps destination for
//!   source and forwards the rest untouched.
//! - Control messages: text frames `{"op":"<name>", …}`.

use serde::Deserialize;
use serde_json::value::RawValue;
use serde_json::{Value, json};
use uuid::Uuid;

/// Largest frame the relay forwards (envelope limit, spec 0.5.1 rule 4).
pub const MAX_FRAME_BYTES: usize = 256 * 1024;
/// Largest WebSocket message the decoder accepts at all; frames between
/// `MAX_FRAME_BYTES` and this get `error PAYLOAD_TOO_LARGE`, bigger ones
/// close the connection with 4400.
pub const MAX_WS_MESSAGE_BYTES: usize = 1024 * 1024;

pub const HR_MAGIC: [u8; 2] = [0x48, 0x52];
pub const HR_VERSION: u8 = 0x01;
pub const HR_OP_FORWARD: u8 = 0x01;
pub const HR_HEADER_LEN: usize = 20;

/// A text frame from a device: a routing wrapper or a control message.
#[derive(Debug, Deserialize)]
pub struct Inbound<'a> {
    #[serde(default)]
    pub op: Option<String>,
    #[serde(default)]
    pub to: Option<Uuid>,
    #[serde(default, borrow)]
    pub env: Option<&'a RawValue>,
    #[serde(default)]
    pub rv_id: Option<String>,
}

/// Parse a device text frame; `None` when it is not a JSON object of the
/// expected shape.
pub fn parse_inbound(text: &str) -> Option<Inbound<'_>> {
    serde_json::from_str(text).ok()
}

/// A `device_id` is a UUIDv8 (spec 0.2); anything else cannot name a device.
pub fn is_device_id(id: &Uuid) -> bool {
    id.get_version_num() == 8 && id.get_variant() == uuid::Variant::RFC4122
}

/// True when the raw JSON value is an object (an envelope).
pub fn is_object(raw: &RawValue) -> bool {
    raw.get().trim_start().starts_with('{')
}

/// `{"from":"<device_id>","env":<env>}` with `env` copied verbatim.
pub fn forwarded_text(from: &Uuid, env: &RawValue) -> String {
    format!(r#"{{"from":"{}","env":{}}}"#, from.hyphenated(), env.get())
}

/// Destination of an `HR` forward frame, or `None` for a malformed header
/// (wrong magic, version or op, or no HL frame after the header).
pub fn parse_hr(frame: &[u8]) -> Option<Uuid> {
    if frame.len() <= HR_HEADER_LEN
        || frame[0..2] != HR_MAGIC
        || frame[2] != HR_VERSION
        || frame[3] != HR_OP_FORWARD
    {
        return None;
    }
    Uuid::from_slice(&frame[4..HR_HEADER_LEN]).ok()
}

/// The same frame with the destination replaced by the source `device_id`.
pub fn rewrite_hr(frame: &[u8], source: &Uuid) -> Vec<u8> {
    let mut out = frame.to_vec();
    out[4..HR_HEADER_LEN].copy_from_slice(source.as_bytes());
    out
}

/// Error codes of the relay `error` op (CONN-03 API 5), the only ones the
/// relay sends there. A frame the relay cannot pass on because Redis failed
/// is answered `NOT_CONNECTED`: the peer cannot be reached right now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayError {
    NotPaired,
    NotConnected,
    PayloadTooLarge,
    BadRequest,
}

impl RelayError {
    pub fn code(self) -> &'static str {
        match self {
            Self::NotPaired => "NOT_PAIRED",
            Self::NotConnected => "NOT_CONNECTED",
            Self::PayloadTooLarge => "PAYLOAD_TOO_LARGE",
            Self::BadRequest => "BAD_REQUEST",
        }
    }

    fn message(self) -> &'static str {
        match self {
            Self::NotPaired => "Destination is not paired with this device",
            Self::NotConnected => "Destination is not connected",
            Self::PayloadTooLarge => "Frame exceeds 256 KiB",
            Self::BadRequest => "Malformed frame",
        }
    }
}

/// `{"op":"error","code","message","to"?}` — English diagnostics only.
pub fn error_message(err: RelayError, to: Option<&Uuid>) -> String {
    let mut msg = json!({ "op": "error", "code": err.code(), "message": err.message() });
    if let Some(to) = to {
        msg["to"] = Value::String(to.hyphenated().to_string());
    }
    msg.to_string()
}

pub fn presence_message(pair_id: &Uuid, peer_device_id: &Uuid, online: bool) -> String {
    json!({
        "op": "presence",
        "pair_id": pair_id.hyphenated().to_string(),
        "peer_device_id": peer_device_id.hyphenated().to_string(),
        "online": online,
    })
    .to_string()
}

pub fn pair_revoked_message(pair_id: &Uuid, by: &Uuid) -> String {
    json!({
        "op": "pair_revoked",
        "pair_id": pair_id.hyphenated().to_string(),
        "by": by.hyphenated().to_string(),
    })
    .to_string()
}

pub fn rv_joined_message(rv_id: &str, peer_present: bool) -> String {
    json!({ "op": "rv_joined", "rv_id": rv_id, "peer_present": peer_present }).to_string()
}

/// `{"op":"rv_msg","rv_id":…,"env":<env>}` with `env` copied verbatim.
pub fn rv_msg_message(rv_id: &str, env: &RawValue) -> String {
    format!(
        r#"{{"op":"rv_msg","rv_id":{},"env":{}}}"#,
        Value::String(rv_id.to_owned()),
        env.get()
    )
}
