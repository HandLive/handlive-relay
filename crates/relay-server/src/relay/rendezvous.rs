//! Pairing rendezvous over the relay (PAIR-01 API 7): `rv:<rv_id>` is a
//! Redis set of at most two `device_id`s that lives 180 s from its creation.
//! The relay forwards `pair` envelopes between the two members unchanged.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use redis::RedisResult;
use redis::aio::ConnectionManager;
use serde::Deserialize;
use serde_json::value::RawValue;
use uuid::Uuid;

use crate::b64u;

pub const RV_TTL_SECS: u64 = 180;

/// Add the member unless the set is full; set the TTL only on creation.
/// Returns the members after joining, or an empty list when refused.
const JOIN_SCRIPT: &str = r"
local added = redis.call('SADD', KEYS[1], ARGV[1])
if redis.call('SCARD', KEYS[1]) > 2 then
  if added == 1 then redis.call('SREM', KEYS[1], ARGV[1]) end
  return {}
end
if redis.call('TTL', KEYS[1]) < 0 then redis.call('EXPIRE', KEYS[1], ARGV[2]) end
local members = redis.call('SMEMBERS', KEYS[1])
table.insert(members, 1, tostring(added))
return members";

/// Canonical `rv_id` (b64u of exactly 16 bytes), or `None`.
pub fn canonical_rv_id(rv_id: &str) -> Option<String> {
    let bytes: [u8; 16] = b64u::decode_fixed(rv_id)?;
    Some(b64u::encode(&bytes))
}

pub fn rv_key(rv_id: &str) -> String {
    format!("rv:{rv_id}")
}

/// Outcome of `rv_join`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Join {
    /// Refused: the rendezvous already has two other members.
    Full,
    /// Joined; `newly` is false when the device was already a member.
    Joined { newly: bool, members: Vec<Uuid> },
}

pub async fn join(redis: &ConnectionManager, rv_id: &str, device_id: &Uuid) -> RedisResult<Join> {
    let mut conn = redis.clone();
    let reply: Vec<String> = redis::cmd("EVAL")
        .arg(JOIN_SCRIPT)
        .arg(1)
        .arg(rv_key(rv_id))
        .arg(device_id.hyphenated().to_string())
        .arg(RV_TTL_SECS)
        .query_async(&mut conn)
        .await?;
    let Some((added, members)) = reply.split_first() else {
        return Ok(Join::Full);
    };
    Ok(Join::Joined {
        newly: added == "1",
        members: members
            .iter()
            .filter_map(|m| Uuid::parse_str(m).ok())
            .collect(),
    })
}

pub async fn members(redis: &ConnectionManager, rv_id: &str) -> RedisResult<Vec<Uuid>> {
    let mut conn = redis.clone();
    let members: Vec<String> = redis::cmd("SMEMBERS")
        .arg(rv_key(rv_id))
        .query_async(&mut conn)
        .await?;
    Ok(members
        .iter()
        .filter_map(|m| Uuid::parse_str(m).ok())
        .collect())
}

#[derive(Deserialize)]
struct EnvHead {
    #[serde(rename = "type")]
    kind: String,
    #[serde(default)]
    payload: Option<String>,
}

#[derive(Deserialize)]
struct PairPayloadHead {
    op: String,
    #[serde(default)]
    data: Option<PairDataHead>,
}

#[derive(Deserialize)]
struct PairDataHead {
    #[serde(default)]
    mode: Option<String>,
}

/// Whether the relay forwards this envelope through a rendezvous: only
/// `type = "pair"`, and never a PIN-mode `pair/hello` (the PIN is LAN-only;
/// handshake payloads are unencrypted JSON, spec 0.5.1).
pub fn rendezvous_allows(env: &RawValue) -> bool {
    let Ok(head) = serde_json::from_str::<EnvHead>(env.get()) else {
        return false;
    };
    if head.kind != "pair" {
        return false;
    }
    !head
        .payload
        .and_then(|p| STANDARD.decode(p).ok())
        .and_then(|plain| serde_json::from_slice::<PairPayloadHead>(&plain).ok())
        .is_some_and(|p| p.op == "hello" && p.data.and_then(|d| d.mode).as_deref() == Some("pin"))
}
