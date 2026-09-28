//! `pairs` table access (spec 0.9.4; queries from PAIR-01 API 8, PAIR-02
//! API 1, PAIR-03 API 3–4 and CONN-03 API 4). Times cross the API as
//! milliseconds since the Unix epoch.

use std::collections::HashMap;

use sqlx::{PgPool, Row};
use uuid::Uuid;

use crate::revocation::RevokeStatement;

/// Key and platform of a registered, non-revoked device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemberDevice {
    pub ik_sig_pub: Vec<u8>,
    pub platform: String,
}

/// Keys and platforms of `a` and `b` (absent or revoked devices are left out).
pub async fn member_devices(
    pool: &PgPool,
    a: Uuid,
    b: Uuid,
) -> Result<HashMap<Uuid, MemberDevice>, sqlx::Error> {
    let rows = sqlx::query(
        "SELECT device_id, ik_sig_pub, platform FROM devices
         WHERE device_id IN ($1, $2) AND revoked_at IS NULL",
    )
    .bind(a)
    .bind(b)
    .fetch_all(pool)
    .await?;
    rows.into_iter()
        .map(|r| {
            Ok((
                r.try_get("device_id")?,
                MemberDevice {
                    ik_sig_pub: r.try_get("ik_sig_pub")?,
                    platform: r.try_get("platform")?,
                },
            ))
        })
        .collect()
}

pub struct NewPair<'a> {
    pub pair_id: Uuid,
    pub device_a: Uuid,
    pub device_b: Uuid,
    pub attestation: &'a [u8],
    pub sig_a: &'a [u8],
    pub sig_b: &'a [u8],
    pub created_at_ms: i64,
}

/// A pair row as stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredPair {
    pub device_a: Uuid,
    pub device_b: Uuid,
    pub attestation: Vec<u8>,
    pub created_at_ms: i64,
}

pub enum InsertOutcome {
    Created,
    /// `pair_id` exists already; the caller compares it with the request.
    Existing(StoredPair),
}

/// Idempotent pair write: insert if absent, otherwise return the stored row.
pub async fn insert(pool: &PgPool, pair: &NewPair<'_>) -> Result<InsertOutcome, sqlx::Error> {
    let inserted = sqlx::query(
        "INSERT INTO pairs (pair_id, device_a, device_b, attestation, sig_a, sig_b, created_at)
         VALUES ($1, $2, $3, $4, $5, $6, TIMESTAMPTZ 'epoch' + $7 * INTERVAL '1 millisecond')
         ON CONFLICT (pair_id) DO NOTHING
         RETURNING pair_id",
    )
    .bind(pair.pair_id)
    .bind(pair.device_a)
    .bind(pair.device_b)
    .bind(pair.attestation)
    .bind(pair.sig_a)
    .bind(pair.sig_b)
    .bind(pair.created_at_ms)
    .fetch_optional(pool)
    .await?;
    if inserted.is_some() {
        return Ok(InsertOutcome::Created);
    }
    let row = sqlx::query(
        "SELECT device_a, device_b, attestation,
                (extract(epoch FROM created_at) * 1000)::bigint AS created_at_ms
         FROM pairs WHERE pair_id = $1",
    )
    .bind(pair.pair_id)
    .fetch_one(pool)
    .await?;
    Ok(InsertOutcome::Existing(StoredPair {
        device_a: row.try_get("device_a")?,
        device_b: row.try_get("device_b")?,
        attestation: row.try_get("attestation")?,
        created_at_ms: row.try_get("created_at_ms")?,
    }))
}

/// One entry of `GET /v1/pairs`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairListing {
    pub pair_id: Uuid,
    pub peer_device_id: Uuid,
    pub peer_platform: String,
    pub created_at_ms: i64,
    pub revoked_at_ms: Option<i64>,
    /// Signer of the revocation statement.
    pub revoked_by: Option<Uuid>,
    /// `HLREVOKE1` signature; `None` on rows revoked before signed revocation.
    pub revoke_sig: Option<Vec<u8>>,
}

/// The pairs `device_id` belongs to, newest first (PAIR-02 API 1).
pub async fn list(
    pool: &PgPool,
    device_id: Uuid,
    include_revoked: bool,
) -> Result<Vec<PairListing>, sqlx::Error> {
    let rows = sqlx::query(
        "SELECT p.pair_id,
                CASE WHEN p.device_a = $1 THEN p.device_b ELSE p.device_a END AS peer_device_id,
                d.platform AS peer_platform,
                (extract(epoch FROM p.created_at) * 1000)::bigint AS created_at_ms,
                (extract(epoch FROM p.revoked_at) * 1000)::bigint AS revoked_at_ms,
                p.revoked_by, p.revoke_sig
         FROM pairs p
         JOIN devices d ON d.device_id = CASE WHEN p.device_a = $1 THEN p.device_b ELSE p.device_a END
         WHERE (p.device_a = $1 OR p.device_b = $1)
           AND ($2::boolean OR p.revoked_at IS NULL)
         ORDER BY p.created_at DESC",
    )
    .bind(device_id)
    .bind(include_revoked)
    .fetch_all(pool)
    .await?;
    rows.into_iter()
        .map(|r| {
            Ok(PairListing {
                pair_id: r.try_get("pair_id")?,
                peer_device_id: r.try_get("peer_device_id")?,
                peer_platform: r.try_get("peer_platform")?,
                created_at_ms: r.try_get("created_at_ms")?,
                revoked_at_ms: r.try_get("revoked_at_ms")?,
                revoked_by: r.try_get("revoked_by")?,
                revoke_sig: r.try_get("revoke_sig")?,
            })
        })
        .collect()
}

/// Store a verified statement if its signer is a member and the pair is
/// still valid (the first statement stays). Returns the peer to notify, or
/// `None` when nothing changed.
pub async fn revoke(
    pool: &PgPool,
    statement: &RevokeStatement,
) -> Result<Option<Uuid>, sqlx::Error> {
    let row = sqlx::query(
        "UPDATE pairs
         SET revoked_at = TIMESTAMPTZ 'epoch' + $3 * INTERVAL '1 millisecond',
             revoked_by = $2, revoke_sig = $4
         WHERE pair_id = $1 AND (device_a = $2 OR device_b = $2) AND revoked_at IS NULL
         RETURNING CASE WHEN device_a = $2 THEN device_b ELSE device_a END AS peer_device_id",
    )
    .bind(statement.pair_id)
    .bind(statement.by)
    .bind(statement.revoked_at)
    .bind(&statement.sig[..])
    .fetch_optional(pool)
    .await?;
    row.map(|r| r.try_get("peer_device_id")).transpose()
}

/// Members of a pair, whatever its state: `(device_a, device_b)`.
pub async fn members(pool: &PgPool, pair_id: Uuid) -> Result<Option<(Uuid, Uuid)>, sqlx::Error> {
    let row = sqlx::query("SELECT device_a, device_b FROM pairs WHERE pair_id = $1")
        .bind(pair_id)
        .fetch_optional(pool)
        .await?;
    row.map(|r| Ok((r.try_get("device_a")?, r.try_get("device_b")?)))
        .transpose()
}

/// Valid pairs of `device_id` whose peer is registered and not revoked:
/// `(pair_id, peer_device_id)` — the peers a relay connection may reach.
pub async fn active_peers(
    pool: &PgPool,
    device_id: Uuid,
) -> Result<Vec<(Uuid, Uuid)>, sqlx::Error> {
    let rows = sqlx::query(
        "SELECT p.pair_id,
                CASE WHEN p.device_a = $1 THEN p.device_b ELSE p.device_a END AS peer_device_id
         FROM pairs p
         JOIN devices d ON d.device_id = CASE WHEN p.device_a = $1 THEN p.device_b ELSE p.device_a END
         WHERE (p.device_a = $1 OR p.device_b = $1)
           AND p.revoked_at IS NULL AND d.revoked_at IS NULL",
    )
    .bind(device_id)
    .fetch_all(pool)
    .await?;
    rows.into_iter()
        .map(|r| Ok((r.try_get("pair_id")?, r.try_get("peer_device_id")?)))
        .collect()
}

/// Signed statements of the pairs of `device_id` revoked within the last 30
/// days (PAIR-03 API 4 logic 2). Rows revoked before signed revocation have
/// no statement and are left out: a device would ignore them anyway.
pub async fn recently_revoked(
    pool: &PgPool,
    device_id: Uuid,
) -> Result<Vec<RevokeStatement>, sqlx::Error> {
    let rows = sqlx::query(
        "SELECT pair_id, revoked_by, revoke_sig,
                (extract(epoch FROM revoked_at) * 1000)::bigint AS revoked_at_ms
         FROM pairs
         WHERE (device_a = $1 OR device_b = $1)
           AND revoked_at > now() - INTERVAL '30 days'
           AND revoked_by IS NOT NULL AND revoke_sig IS NOT NULL",
    )
    .bind(device_id)
    .fetch_all(pool)
    .await?;
    rows.into_iter()
        .map(|r| {
            let sig: Vec<u8> = r.try_get("revoke_sig")?;
            Ok(RevokeStatement {
                pair_id: r.try_get("pair_id")?,
                by: r.try_get("revoked_by")?,
                revoked_at: r.try_get("revoked_at_ms")?,
                sig: sig
                    .try_into()
                    .map_err(|_| sqlx::Error::Decode("revoke_sig is not 64 bytes".into()))?,
            })
        })
        .collect()
}
