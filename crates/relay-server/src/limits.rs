//! Fixed-window rate limits in Redis (spec 0.9.4 `rl:` keys, 0.10
//! `RELAY_RATE_LIMIT`, `RELAY_AUTH_LIMIT`, `RELAY_REG_IP_LIMIT`) and the
//! client IP the per-IP limits count.

use std::net::IpAddr;

use actix_web::HttpRequest;
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
/// `/v1/auth/challenge` + `/v1/auth/token` calls per client IP per minute
/// (`RELAY_AUTH_LIMIT`).
pub const AUTH_PER_IP_PER_MINUTE: u64 = 30;
/// Challenges per (`device_id`, client IP) per minute (`RELAY_AUTH_LIMIT`).
pub const CHALLENGES_PER_DEVICE_IP_PER_MINUTE: u64 = 10;
/// Rate-limit group names inside `rl:<device_id>:<group>:<minute>`.
pub const GROUP_REST: &str = "rest";
pub const GROUP_PUSH: &str = "push";

const HOUR_MS: i64 = 3_600_000;
const HOUR_WINDOW_TTL_SECS: i64 = 3_600;

/// Count one call of `device_id` in `group`; 429 with `Retry-After` when the
/// minute's quota is used up.
pub async fn check_device(
    redis: &ConnectionManager,
    device_id: &Uuid,
    group: &str,
    limit: u64,
) -> Result<(), ApiError> {
    let key = rate_limit_key(device_id, group, minute_window(now_ms()));
    count_minute(redis, &key, limit).await
}

/// What a per-IP limit counts: the IPv4 address, or the /64 prefix of an
/// IPv6 address (one subscriber usually holds a whole /64). An IPv4-mapped
/// IPv6 address counts as its IPv4 address.
pub fn ip_bucket(ip: &IpAddr) -> String {
    match ip.to_canonical() {
        IpAddr::V4(v4) => v4.to_string(),
        IpAddr::V6(v6) => {
            let mut octets = v6.octets();
            octets[8..].fill(0);
            format!("{}/64", std::net::Ipv6Addr::from(octets))
        }
    }
}

/// `rl:ip:<ip>:reg:<hour>` (TTL 3,600 s).
pub fn registration_key(ip: &IpAddr, hour: i64) -> String {
    format!("rl:ip:{}:reg:{hour}", ip_bucket(ip))
}

/// `rl:reg:<hour>` (TTL 3,600 s): new registrations of the whole relay.
pub fn global_registration_key(hour: i64) -> String {
    format!("rl:reg:{hour}")
}

/// `rl:ip:<ip>:auth:<minute>` (TTL 120 s).
pub fn auth_ip_key(ip: &IpAddr, minute: i64) -> String {
    format!("rl:ip:{}:auth:{minute}", ip_bucket(ip))
}

/// `rl:<device_id>:<ip>:chal:<minute>` (TTL 120 s). Without a known client
/// address (only in-process tests) the IP part is `unknown`.
pub fn challenge_quota_key(device_id: &Uuid, ip: Option<&IpAddr>, minute: i64) -> String {
    let bucket = ip.map_or_else(|| "unknown".to_owned(), ip_bucket);
    format!("rl:{}:{bucket}:chal:{minute}", device_id.hyphenated())
}

/// Count one call to `/v1/auth/challenge` or `/v1/auth/token` from `ip`;
/// 429 once the minute's 30 are used. Runs before any database lookup.
pub async fn check_auth_ip(redis: &ConnectionManager, ip: Option<&IpAddr>) -> Result<(), ApiError> {
    let Some(ip) = ip else {
        return Ok(());
    };
    count_minute(
        redis,
        &auth_ip_key(ip, minute_window(now_ms())),
        AUTH_PER_IP_PER_MINUTE,
    )
    .await
}

/// Count one challenge for (`device_id`, client IP); 429 over 10 a minute.
pub async fn check_challenge_quota(
    redis: &ConnectionManager,
    device_id: &Uuid,
    ip: Option<&IpAddr>,
) -> Result<(), ApiError> {
    let key = challenge_quota_key(device_id, ip, minute_window(now_ms()));
    count_minute(redis, &key, CHALLENGES_PER_DEVICE_IP_PER_MINUTE).await
}

async fn count_minute(redis: &ConnectionManager, key: &str, limit: u64) -> Result<(), ApiError> {
    let now = now_ms();
    let mut conn = redis.clone();
    let count = incr_window(&mut conn, key)
        .await
        .map_err(|e| ApiError::internal("rate limit", e))?;
    rate_limit_decision(count, limit, now)
}

/// The client address of a request (see [`client_ip`]).
pub fn request_ip(http: &HttpRequest, trusted: &[IpAddr]) -> Option<IpAddr> {
    let forwarded = http
        .headers()
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok());
    client_ip(http.peer_addr().map(|a| a.ip()), forwarded, trusted)
}

/// Count one new registration: first against `ip`'s hourly limit (when the
/// client address is known), then against the relay-wide hourly cap. 429
/// with `Retry-After` until the hour ends once either is used up.
pub async fn check_registration(
    redis: &ConnectionManager,
    ip: Option<&IpAddr>,
    per_ip_limit: u64,
    global_limit: u64,
) -> Result<(), ApiError> {
    let now = now_ms();
    let hour = now.div_euclid(HOUR_MS);
    if let Some(ip) = ip {
        count_hour(redis, &registration_key(ip, hour), per_ip_limit, now).await?;
    }
    count_hour(redis, &global_registration_key(hour), global_limit, now).await
}

async fn count_hour(
    redis: &ConnectionManager,
    key: &str,
    limit: u64,
    now: i64,
) -> Result<(), ApiError> {
    let mut conn = redis.clone();
    let (count, _): (u64, bool) = redis::pipe()
        .atomic()
        .incr(key, 1)
        .expire(key, HOUR_WINDOW_TTL_SECS)
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
