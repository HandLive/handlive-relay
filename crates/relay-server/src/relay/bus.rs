//! Messages between relay instances on the Redis channel `dev:<device_id>`
//! (spec 0.9.4, decision C5). The instance holding a device's connection
//! subscribes to the channel; any instance publishes to it.
//!
//! Encoding: one tag byte, then fixed fields. Forwarded frames are already in
//! their final form, so the receiving instance only checks the pair and
//! writes them out.

use uuid::Uuid;

const TAG_TEXT: u8 = 1;
const TAG_BINARY: u8 = 2;
const TAG_CONTROL: u8 = 3;
const TAG_PAIR_REVOKED: u8 = 4;
const TAG_PAIRS_CHANGED: u8 = 5;
const TAG_REPLACE: u8 = 6;
const TAG_CLOSE: u8 = 7;

/// `dev:<device_id>`.
pub fn device_channel(device_id: &Uuid) -> String {
    format!("dev:{}", device_id.hyphenated())
}

/// The device a `dev:` channel belongs to.
pub fn channel_device(channel: &[u8]) -> Option<Uuid> {
    let rest = channel.strip_prefix(b"dev:")?;
    Uuid::try_parse_ascii(rest).ok()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BusMessage {
    /// Wrapper text frame already rewritten to `{"from","env"}`.
    ForwardText { from: Uuid, text: String },
    /// `HR` frame already carrying the source `device_id`.
    ForwardBinary { from: Uuid, frame: Vec<u8> },
    /// Relay control message written out as-is (`presence`, `rv_joined`,
    /// `rv_msg`).
    Control { text: String },
    /// `by` revoked `pair_id`: send `pair_revoked`, then reload the peers.
    PairRevoked { pair_id: Uuid, by: Uuid },
    /// The device's pairs changed: reload them (no message to the device
    /// except `presence` for pairs that appeared).
    PairsChanged,
    /// A newer connection `conn_id` of the device opened somewhere.
    Replace { conn_id: Uuid },
    /// Close the device's connection with `code` (the device removed itself).
    Close { code: u16 },
}

impl BusMessage {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        match self {
            Self::ForwardText { from, text } => {
                out.push(TAG_TEXT);
                out.extend_from_slice(from.as_bytes());
                out.extend_from_slice(text.as_bytes());
            }
            Self::ForwardBinary { from, frame } => {
                out.push(TAG_BINARY);
                out.extend_from_slice(from.as_bytes());
                out.extend_from_slice(frame);
            }
            Self::Control { text } => {
                out.push(TAG_CONTROL);
                out.extend_from_slice(text.as_bytes());
            }
            Self::PairRevoked { pair_id, by } => {
                out.push(TAG_PAIR_REVOKED);
                out.extend_from_slice(pair_id.as_bytes());
                out.extend_from_slice(by.as_bytes());
            }
            Self::PairsChanged => out.push(TAG_PAIRS_CHANGED),
            Self::Replace { conn_id } => {
                out.push(TAG_REPLACE);
                out.extend_from_slice(conn_id.as_bytes());
            }
            Self::Close { code } => {
                out.push(TAG_CLOSE);
                out.extend_from_slice(&code.to_be_bytes());
            }
        }
        out
    }

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let (&tag, rest) = bytes.split_first()?;
        let uuid_at = |at: usize| Uuid::from_slice(rest.get(at..at + 16)?).ok();
        Some(match tag {
            TAG_TEXT => Self::ForwardText {
                from: uuid_at(0)?,
                text: String::from_utf8(rest.get(16..)?.to_vec()).ok()?,
            },
            TAG_BINARY => Self::ForwardBinary {
                from: uuid_at(0)?,
                frame: rest.get(16..)?.to_vec(),
            },
            TAG_CONTROL => Self::Control {
                text: String::from_utf8(rest.to_vec()).ok()?,
            },
            TAG_PAIR_REVOKED if rest.len() == 32 => Self::PairRevoked {
                pair_id: uuid_at(0)?,
                by: uuid_at(16)?,
            },
            TAG_PAIRS_CHANGED if rest.is_empty() => Self::PairsChanged,
            TAG_REPLACE if rest.len() == 16 => Self::Replace {
                conn_id: uuid_at(0)?,
            },
            TAG_CLOSE if rest.len() == 2 => Self::Close {
                code: u16::from_be_bytes([rest[0], rest[1]]),
            },
            _ => return None,
        })
    }

    /// Bytes this message holds in a receiver's queue.
    pub fn queued_len(&self) -> usize {
        match self {
            Self::ForwardText { text, .. } | Self::Control { text } => text.len(),
            Self::ForwardBinary { frame, .. } => frame.len(),
            _ => 0,
        }
    }
}
