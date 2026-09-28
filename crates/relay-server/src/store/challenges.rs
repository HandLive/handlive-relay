//! Redis keys for auth (spec 0.9.4): `chal:<device_id>:<challenge>` (TTL
//! 60 s, one key per pending challenge) and `rl:…:<minute>` counters (TTL
//! 120 s).

use redis::AsyncCommands;
use redis::aio::ConnectionManager;
use uuid::Uuid;

use crate::b64u;
use crate::challenge::CHALLENGE_TTL_SECS;

const RATE_LIMIT_TTL_SECS: i64 = 120;

/// `chal:<device_id>:<challenge b64u>`.
pub fn challenge_key(device_id: &Uuid, challenge: &[u8; 32]) -> String {
    format!(
        "chal:{}:{}",
        device_id.hyphenated(),
        b64u::encode(challenge)
    )
}

pub fn rate_limit_key(device_id: &Uuid, group: &str, minute: i64) -> String {
    format!("rl:{}:{group}:{minute}", device_id.hyphenated())
}

/// Store one pending challenge (its b64u text as the value) with TTL 60 s.
/// Other pending challenges of the device stay valid.
pub async fn put(
    conn: &mut ConnectionManager,
    device_id: &Uuid,
    challenge: &[u8; 32],
) -> redis::RedisResult<()> {
    let key = challenge_key(device_id, challenge);
    conn.set_ex(key, b64u::encode(challenge), CHALLENGE_TTL_SECS)
        .await
}

/// Atomically read and delete one pending challenge (GETDEL).
pub async fn take(
    conn: &mut ConnectionManager,
    device_id: &Uuid,
    challenge: &[u8; 32],
) -> redis::RedisResult<Option<String>> {
    conn.get_del(challenge_key(device_id, challenge)).await
}

/// Increment a fixed-window counter and return its new value.
pub async fn incr_window(conn: &mut ConnectionManager, key: &str) -> redis::RedisResult<u64> {
    let (count, _): (u64, bool) = redis::pipe()
        .atomic()
        .incr(key, 1)
        .expire(key, RATE_LIMIT_TTL_SECS)
        .query_async(conn)
        .await?;
    Ok(count)
}
