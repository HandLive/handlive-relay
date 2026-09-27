//! `usage_daily` statistics (spec 0.9.4): counters per salted `device_hash`,
//! never per `device_id`, deleted after 30 days.

use sqlx::PgPool;

/// One batch row: `(device_hash, envelopes, bytes, pushes)`.
pub type UsageRow = (Vec<u8>, i64, i64, i32);

/// Add a batch of counters to today's rows (CONN-03 API 6, CONN-04 API 2).
pub async fn add_batch(pool: &PgPool, rows: &[UsageRow]) -> Result<(), sqlx::Error> {
    if rows.is_empty() {
        return Ok(());
    }
    let hashes: Vec<&[u8]> = rows.iter().map(|r| r.0.as_slice()).collect();
    let envelopes: Vec<i64> = rows.iter().map(|r| r.1).collect();
    let bytes: Vec<i64> = rows.iter().map(|r| r.2).collect();
    let pushes: Vec<i32> = rows.iter().map(|r| r.3).collect();
    sqlx::query(
        "INSERT INTO usage_daily (day, device_hash, envelopes, bytes, pushes)
         SELECT current_date, h, e, b, p
         FROM UNNEST($1::bytea[], $2::bigint[], $3::bigint[], $4::integer[]) AS t(h, e, b, p)
         ON CONFLICT (day, device_hash) DO UPDATE
         SET envelopes = usage_daily.envelopes + EXCLUDED.envelopes,
             bytes     = usage_daily.bytes + EXCLUDED.bytes,
             pushes    = usage_daily.pushes + EXCLUDED.pushes",
    )
    .bind(&hashes)
    .bind(&envelopes)
    .bind(&bytes)
    .bind(&pushes)
    .execute(pool)
    .await?;
    Ok(())
}

/// Daily cleanup (spec 0.9.4): statistics older than 30 days, then devices
/// inactive for 180 days (their pairs go by CASCADE). Returns both counts.
pub async fn delete_expired(pool: &PgPool) -> Result<(u64, u64), sqlx::Error> {
    let usage =
        sqlx::query("DELETE FROM usage_daily WHERE day < current_date - INTERVAL '30 days'")
            .execute(pool)
            .await?
            .rows_affected();
    let devices =
        sqlx::query("DELETE FROM devices WHERE last_seen_at < now() - INTERVAL '180 days'")
            .execute(pool)
            .await?
            .rows_affected();
    Ok((usage, devices))
}
