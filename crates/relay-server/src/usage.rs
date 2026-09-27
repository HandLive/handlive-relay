//! Minimal statistics (spec 0.6.5, 0.9.4): envelopes, bytes and pushes are
//! tallied in memory per device and written to `usage_daily` every minute
//! under `device_hash` = SHA-256(device_id ‖ monthly salt), never under the
//! `device_id` itself.
//!
//! The monthly salt is 32 random bytes kept only in Redis
//! (`usage_salt:<YYYY-MM>`, 40 days): once it expires nobody, the operator
//! included, can link a `device_hash` back to a device.

use std::collections::HashMap;
use std::sync::Mutex;

use redis::aio::ConnectionManager;
use ring::digest::{SHA256, digest};
use ring::rand::{SecureRandom, SystemRandom};
use sqlx::PgPool;
use uuid::Uuid;

use crate::clock::now_ms;
use crate::store::usage::{UsageRow, add_batch};

const SALT_TTL_SECS: u64 = 40 * 24 * 3600;

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Tally {
    pub envelopes: i64,
    pub bytes: i64,
    pub pushes: i32,
}

/// In-memory counters of one relay instance.
#[derive(Default)]
pub struct Usage {
    tallies: Mutex<HashMap<Uuid, Tally>>,
}

impl Usage {
    pub fn add_envelope(&self, device_id: Uuid, bytes: usize) {
        self.update(device_id, |t| {
            t.envelopes += 1;
            t.bytes += bytes as i64;
        });
    }

    pub fn add_push(&self, device_id: Uuid) {
        self.update(device_id, |t| t.pushes += 1);
    }

    /// Take every counter, leaving the tally empty.
    pub fn take(&self) -> HashMap<Uuid, Tally> {
        std::mem::take(&mut *self.lock())
    }

    /// Put back counters that could not be written.
    pub fn restore(&self, tallies: HashMap<Uuid, Tally>) {
        let mut map = self.lock();
        for (device_id, t) in tallies {
            let e = map.entry(device_id).or_default();
            e.envelopes += t.envelopes;
            e.bytes += t.bytes;
            e.pushes += t.pushes;
        }
    }

    fn update(&self, device_id: Uuid, f: impl FnOnce(&mut Tally)) {
        f(self.lock().entry(device_id).or_default());
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<Uuid, Tally>> {
        self.tallies.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// SHA-256(device_id (16 bytes) ‖ salt).
pub fn device_hash(device_id: &Uuid, salt: &[u8]) -> Vec<u8> {
    let mut input = Vec::with_capacity(16 + salt.len());
    input.extend_from_slice(device_id.as_bytes());
    input.extend_from_slice(salt);
    digest(&SHA256, &input).as_ref().to_vec()
}

/// UTC calendar year and month of a Unix time in milliseconds.
pub fn year_month(now_ms: i64) -> (i64, u32) {
    // Civil-from-days (H. Hinnant), proleptic Gregorian calendar.
    let z = now_ms.div_euclid(86_400_000) + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    (year, month as u32)
}

pub fn salt_key(now_ms: i64) -> String {
    let (year, month) = year_month(now_ms);
    format!("usage_salt:{year:04}-{month:02}")
}

/// The salt of the current month, created on first use by any instance.
pub async fn monthly_salt(
    redis: &ConnectionManager,
    rng: &SystemRandom,
) -> Result<Vec<u8>, String> {
    let key = salt_key(now_ms());
    let mut fresh = [0u8; 32];
    rng.fill(&mut fresh)
        .map_err(|_| "salt rng failed".to_owned())?;
    let mut conn = redis.clone();
    let (salt,): (Option<Vec<u8>>,) = redis::pipe()
        .cmd("SET")
        .arg(&key)
        .arg(&fresh[..])
        .arg("NX")
        .arg("EX")
        .arg(SALT_TTL_SECS)
        .ignore()
        .cmd("GET")
        .arg(&key)
        .query_async(&mut conn)
        .await
        .map_err(|e| format!("salt: {e}"))?;
    salt.ok_or_else(|| "salt missing".to_owned())
}

/// Write the tallied counters to `usage_daily`; on failure they are kept for
/// the next attempt. Returns the number of devices written.
pub async fn flush(
    usage: &Usage,
    db: &PgPool,
    redis: &ConnectionManager,
    rng: &SystemRandom,
) -> Result<usize, String> {
    let tallies = usage.take();
    if tallies.is_empty() {
        return Ok(0);
    }
    let salt = match monthly_salt(redis, rng).await {
        Ok(salt) => salt,
        Err(e) => {
            usage.restore(tallies);
            return Err(e);
        }
    };
    let rows: Vec<UsageRow> = tallies
        .iter()
        .map(|(id, t)| (device_hash(id, &salt), t.envelopes, t.bytes, t.pushes))
        .collect();
    if let Err(e) = add_batch(db, &rows).await {
        usage.restore(tallies);
        return Err(format!("usage_daily: {e}"));
    }
    Ok(rows.len())
}
