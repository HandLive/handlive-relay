//! Presence and revocation notices in Redis (spec 0.9.4, CONN-03 API 4,
//! SET-02 API 2).
//!
//! `presence:<device_id>` holds the id of the instance with the device's
//! connection (TTL 60 s, renewed every 20 s). Renewal and removal are
//! compare-and-set scripts, so an instance never overwrites or deletes the
//! presence of a newer connection held by another instance.

use redis::aio::ConnectionManager;
use redis::{AsyncCommands, RedisResult};
use uuid::Uuid;

pub const PRESENCE_TTL_SECS: u64 = 60;
/// `revoked_notice:<device_id>` lives 30 days.
pub const REVOKED_NOTICE_TTL_SECS: i64 = 30 * 24 * 3600;

/// Set the key when it is missing or already ours; 1 = held by us.
const REFRESH_SCRIPT: &str = r"
local v = redis.call('GET', KEYS[1])
if v == false or v == ARGV[1] then
  redis.call('SET', KEYS[1], ARGV[1], 'EX', ARGV[2])
  return 1
end
return 0";

/// Delete the key only when it is ours; 1 = deleted.
const RELEASE_SCRIPT: &str = r"
if redis.call('GET', KEYS[1]) == ARGV[1] then
  return redis.call('DEL', KEYS[1])
end
return 0";

pub fn presence_key(device_id: &Uuid) -> String {
    format!("presence:{}", device_id.hyphenated())
}

pub fn revoked_notice_key(device_id: &Uuid) -> String {
    format!("revoked_notice:{}", device_id.hyphenated())
}

/// Record that `device_id` is connected here (a new connection always wins).
pub async fn claim(redis: &ConnectionManager, device_id: &Uuid, instance: &str) -> RedisResult<()> {
    let mut conn = redis.clone();
    conn.set_ex(presence_key(device_id), instance, PRESENCE_TTL_SECS)
        .await
}

/// Renew our presence; `false` when another instance holds the device now.
pub async fn refresh(
    redis: &ConnectionManager,
    device_id: &Uuid,
    instance: &str,
) -> RedisResult<bool> {
    let mut conn = redis.clone();
    let held: i64 = redis::cmd("EVAL")
        .arg(REFRESH_SCRIPT)
        .arg(1)
        .arg(presence_key(device_id))
        .arg(instance)
        .arg(PRESENCE_TTL_SECS)
        .query_async(&mut conn)
        .await?;
    Ok(held == 1)
}

/// Remove our presence; `true` when it was ours (the device went offline).
pub async fn release(
    redis: &ConnectionManager,
    device_id: &Uuid,
    instance: &str,
) -> RedisResult<bool> {
    let mut conn = redis.clone();
    let deleted: i64 = redis::cmd("EVAL")
        .arg(RELEASE_SCRIPT)
        .arg(1)
        .arg(presence_key(device_id))
        .arg(instance)
        .query_async(&mut conn)
        .await?;
    Ok(deleted == 1)
}

/// Online state of each device, in order (`MGET presence:…`).
pub async fn online(redis: &ConnectionManager, devices: &[Uuid]) -> RedisResult<Vec<bool>> {
    if devices.is_empty() {
        return Ok(Vec::new());
    }
    let keys: Vec<String> = devices.iter().map(presence_key).collect();
    let mut conn = redis.clone();
    let values: Vec<Option<String>> = redis::cmd("MGET").arg(&keys).query_async(&mut conn).await?;
    Ok(values.into_iter().map(|v| v.is_some()).collect())
}

/// Queue a `pair_revoked` for `peer` (SET-02 API 2 logic 3).
pub async fn add_revoked_notice(
    redis: &ConnectionManager,
    peer: &Uuid,
    pair_id: &Uuid,
    by: &Uuid,
) -> RedisResult<()> {
    let key = revoked_notice_key(peer);
    let member = format!("{}|{}", pair_id.hyphenated(), by.hyphenated());
    let mut conn = redis.clone();
    redis::pipe()
        .atomic()
        .sadd(&key, member)
        .ignore()
        .expire(&key, REVOKED_NOTICE_TTL_SECS)
        .ignore()
        .query_async(&mut conn)
        .await
}

/// Read and delete the queued notices of `device_id`: `(pair_id, by)`.
/// Malformed members are skipped.
pub async fn take_revoked_notices(
    redis: &ConnectionManager,
    device_id: &Uuid,
) -> RedisResult<Vec<(Uuid, Uuid)>> {
    let key = revoked_notice_key(device_id);
    let mut conn = redis.clone();
    let (members,): (Vec<String>,) = redis::pipe()
        .atomic()
        .smembers(&key)
        .del(&key)
        .ignore()
        .query_async(&mut conn)
        .await?;
    Ok(members
        .iter()
        .filter_map(|m| {
            let (pair, by) = m.split_once('|')?;
            Some((Uuid::parse_str(pair).ok()?, Uuid::parse_str(by).ok()?))
        })
        .collect())
}
