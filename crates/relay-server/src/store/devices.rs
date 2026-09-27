//! `devices` table access (spec 0.9.4; queries from CONN-03, CONN-04 and
//! SET-02 "Query").

use sqlx::{PgPool, Row};
use uuid::Uuid;

/// Row data needed to authenticate a device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceKey {
    pub ik_sig_pub: Vec<u8>,
    pub revoked: bool,
}

/// Result of a registration upsert.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpsertOutcome {
    Created {
        created_at_ms: i64,
    },
    Updated {
        created_at_ms: i64,
    },
    /// Row exists but is revoked (or holds another key): nothing changed.
    Rejected,
}

pub struct NewDevice<'a> {
    pub device_id: Uuid,
    pub ik_sig_pub: &'a [u8; 32],
    pub platform: &'a str,
    pub app_version: &'a str,
}

/// Register or refresh a device. `ik_sig_pub` of a `device_id` never changes.
pub async fn upsert(pool: &PgPool, device: &NewDevice<'_>) -> Result<UpsertOutcome, sqlx::Error> {
    let row = sqlx::query(
        "INSERT INTO devices (device_id, ik_sig_pub, platform, app_version)
         VALUES ($1, $2, $3, $4)
         ON CONFLICT (device_id) DO UPDATE
         SET app_version = EXCLUDED.app_version, last_seen_at = now()
         WHERE devices.revoked_at IS NULL AND devices.ik_sig_pub = EXCLUDED.ik_sig_pub
         RETURNING (extract(epoch FROM created_at) * 1000)::bigint AS created_at_ms,
                   (xmax = 0) AS inserted",
    )
    .bind(device.device_id)
    .bind(&device.ik_sig_pub[..])
    .bind(device.platform)
    .bind(device.app_version)
    .fetch_optional(pool)
    .await?;

    Ok(match row {
        None => UpsertOutcome::Rejected,
        Some(row) => {
            let created_at_ms: i64 = row.try_get("created_at_ms")?;
            if row.try_get::<bool, _>("inserted")? {
                UpsertOutcome::Created { created_at_ms }
            } else {
                UpsertOutcome::Updated { created_at_ms }
            }
        }
    })
}

/// Public key and revocation state, or `None` if the device is not registered.
pub async fn find_key(pool: &PgPool, device_id: Uuid) -> Result<Option<DeviceKey>, sqlx::Error> {
    let row = sqlx::query(
        "SELECT ik_sig_pub, revoked_at IS NOT NULL AS revoked FROM devices WHERE device_id = $1",
    )
    .bind(device_id)
    .fetch_optional(pool)
    .await?;
    row.map(|r| {
        Ok(DeviceKey {
            ik_sig_pub: r.try_get("ik_sig_pub")?,
            revoked: r.try_get("revoked")?,
        })
    })
    .transpose()
}

pub async fn touch_last_seen(pool: &PgPool, device_id: Uuid) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE devices SET last_seen_at = now() WHERE device_id = $1")
        .bind(device_id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Platform and revocation state, or `None` if the device is not registered.
pub async fn find_platform(
    pool: &PgPool,
    device_id: Uuid,
) -> Result<Option<(String, bool)>, sqlx::Error> {
    let row = sqlx::query(
        "SELECT platform, revoked_at IS NOT NULL AS revoked FROM devices WHERE device_id = $1",
    )
    .bind(device_id)
    .fetch_optional(pool)
    .await?;
    row.map(|r| Ok((r.try_get("platform")?, r.try_get("revoked")?)))
        .transpose()
}

/// Store the push token (CONN-04 API 1); the old token is overwritten.
pub async fn set_push_token(
    pool: &PgPool,
    device_id: Uuid,
    provider: &str,
    token: &str,
    topic: Option<&str>,
) -> Result<bool, sqlx::Error> {
    let done = sqlx::query(
        "UPDATE devices
         SET push_provider = $2, push_token = $3, push_topic = $4, last_seen_at = now()
         WHERE device_id = $1 AND revoked_at IS NULL",
    )
    .bind(device_id)
    .bind(provider)
    .bind(token)
    .bind(topic)
    .execute(pool)
    .await?;
    Ok(done.rows_affected() == 1)
}

/// Drop a token the push provider reported as no longer valid (CONN-04 E3).
pub async fn clear_push_token(pool: &PgPool, device_id: Uuid) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE devices SET push_token = NULL, push_provider = NULL WHERE device_id = $1")
        .bind(device_id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Delete the device (SET-02 API 2, one transaction). Its `pairs` rows go by
/// `ON DELETE CASCADE`; the peers of its unrevoked pairs are returned as
/// `(pair_id, peer_device_id)` so they can be told afterwards.
pub async fn delete_with_peers(
    pool: &PgPool,
    device_id: Uuid,
) -> Result<Vec<(Uuid, Uuid)>, sqlx::Error> {
    let mut tx = pool.begin().await?;
    let rows = sqlx::query(
        "SELECT pair_id,
                CASE WHEN device_a = $1 THEN device_b ELSE device_a END AS peer_device_id
         FROM pairs
         WHERE (device_a = $1 OR device_b = $1) AND revoked_at IS NULL
         FOR UPDATE",
    )
    .bind(device_id)
    .fetch_all(&mut *tx)
    .await?;
    sqlx::query("DELETE FROM devices WHERE device_id = $1")
        .bind(device_id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    rows.into_iter()
        .map(|r| Ok((r.try_get("pair_id")?, r.try_get("peer_device_id")?)))
        .collect()
}

/// Push registration of the other member of a valid pair.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PushTarget {
    pub platform: String,
    pub provider: Option<String>,
    pub token: Option<String>,
    pub topic: Option<String>,
}

/// `to`'s push registration when `from` and `to` are the two members of the
/// non-revoked pair `pair_id` and `to` is not locked out (CONN-04 API 2).
pub async fn push_target(
    pool: &PgPool,
    pair_id: Uuid,
    from: Uuid,
    to: Uuid,
) -> Result<Option<PushTarget>, sqlx::Error> {
    let row = sqlx::query(
        "SELECT d.platform, d.push_provider, d.push_token, d.push_topic
         FROM pairs p
         JOIN devices d ON d.device_id = $3
         WHERE p.pair_id = $1
           AND p.revoked_at IS NULL
           AND ((p.device_a = $2 AND p.device_b = $3) OR (p.device_b = $2 AND p.device_a = $3))
           AND d.revoked_at IS NULL",
    )
    .bind(pair_id)
    .bind(from)
    .bind(to)
    .fetch_optional(pool)
    .await?;
    row.map(|r| {
        Ok(PushTarget {
            platform: r.try_get("platform")?,
            provider: r.try_get("push_provider")?,
            token: r.try_get("push_token")?,
            topic: r.try_get("push_topic")?,
        })
    })
    .transpose()
}
