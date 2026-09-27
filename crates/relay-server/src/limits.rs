//! Fixed-window rate limits in Redis (spec 0.9.4 `rl:` keys, 0.10
//! `RELAY_RATE_LIMIT`) and the client IP used by the registration limit.

use std::net::IpAddr;

use redis::aio::ConnectionManager;
use uuid::Uuid;

use crate::challenge::{minute_window, rate_limit_decision};
use crate::clock::now_ms;
use crate::error::ApiError;
use crate::store::challenges::{incr_window, rate_limit_key};

/// REST calls per device per minute (`RELAY_RATE_LIMIT`).
pub const REST_PER_MINUTE: u64 = 60;
/// `POST /v1/push` calls per sending device per minute (`RELAY_RATE_LIMIT`).
pub const PUSH_PER_MINUTE: u64 = 30;
/// Rate-limit group names inside `rl:<device_id>:<group>:<minute>`.
pub const GROUP_REST: &str = "rest";
pub const GROUP_PUSH: &str = "push";

const HOUR_MS: i64 = 3_600_000;
const IP_WINDOW_TTL_SECS: i64 = 3_600;

/// Count one call of `device_id` in `group`; 429 with `Retry-After` when the
/// minute's quota is used up.
pub async fn check_device(
    redis: &ConnectionManager,
    device_id: &Uuid,
    group: &str,
    limit: u64,
) -> Result<(), ApiError> {
    let now = now_ms();
    let key = rate_limit_key(device_id, group, minute_window(now));
    let mut conn = redis.clone();
    let count = incr_window(&mut conn, &key)
        .await
        .map_err(|e| ApiError::internal("rate limit", e))?;
    rate_limit_decision(count, limit, now)
}

/// `rl:ip:<ip>:reg:<hour>` (TTL 3,600 s).
pub fn registration_key(ip: &IpAddr, hour: i64) -> String {
    format!("rl:ip:{ip}:reg:{hour}")
}

/// Count one new registration from `ip`; 429 once more than `limit` new
/// devices registered from it in the current hour.
pub async fn check_registration(
    redis: &ConnectionManager,
    ip: &IpAddr,
    limit: u64,
) -> Result<(), ApiError> {
    let now = now_ms();
    let key = registration_key(ip, now.div_euclid(HOUR_MS));
    let mut conn = redis.clone();
    let (count, _): (u64, bool) = redis::pipe()
        .atomic()
        .incr(&key, 1)
        .expire(&key, IP_WINDOW_TTL_SECS)
        .query_async(&mut conn)
        .await
        .map_err(|e| ApiError::internal("registration limit", e))?;
    if count <= limit {
        return Ok(());
    }
    let into_hour_ms = now.rem_euclid(HOUR_MS) as u64;
    let retry_after_secs = (HOUR_MS as u64 - into_hour_ms).div_ceil(1000).max(1);
    Err(ApiError::RateLimited { retry_after_secs })
}

/// The address of the client behind the connection.
///
/// `X-Forwarded-For` is only believed when the TCP peer is a trusted proxy:
/// the header is read from the right, skipping trusted proxies, and the first
/// untrusted hop is the client. A malformed entry stops the walk at the last
/// trusted hop, so a forged header can never pick an arbitrary address.
pub fn client_ip(
    peer: Option<IpAddr>,
    forwarded_for: Option<&str>,
    trusted: &[IpAddr],
) -> Option<IpAddr> {
    let peer = peer?;
    if !trusted.contains(&peer) {
        return Some(peer);
    }
    let Some(header) = forwarded_for else {
        return Some(peer);
    };
    let mut last = peer;
    for hop in header.rsplit(',') {
        let Ok(ip) = hop.trim().parse::<IpAddr>() else {
            return Some(last);
        };
        if !trusted.contains(&ip) {
            return Some(ip);
        }
        last = ip;
    }
    Some(last)
}
