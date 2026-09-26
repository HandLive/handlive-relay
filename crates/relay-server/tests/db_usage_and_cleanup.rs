//! Statistics and data cleanup against real PostgreSQL 16 + Redis 7
//! (spec 0.6.5, 0.9.4): usage is stored per salted device hash only, and
//! the daily job deletes statistics after 30 days and devices inactive for
//! 180 days together with their pairs.
//!
//! Ignored by default; needs PostgreSQL + Redis (see relay/README.md).

mod common;

use common::http_harness::{app, state};
use common::relay_harness::{call, enroll, pair_body};
use redis::AsyncCommands;
use relay_server::clock::now_ms;
use relay_server::maintenance::run_cleanup;
use relay_server::usage::{device_hash, flush, salt_key};
use uuid::Uuid;

async fn usage_row(db: &sqlx::PgPool, hash: &[u8]) -> Option<(i64, i64, i32)> {
    sqlx::query_as(
        "SELECT envelopes, bytes, pushes FROM usage_daily WHERE day = current_date AND device_hash = $1",
    )
    .bind(hash)
    .fetch_optional(db)
    .await
    .unwrap()
}

#[actix_web::test]
#[ignore = "needs PostgreSQL + Redis (docker compose)"]
async fn usage_is_written_under_the_monthly_device_hash() {
    let state = state().await;
    let device = Uuid::new_v4();
    state.usage.add_envelope(device, 1_000);
    state.usage.add_envelope(device, 24);
    state.usage.add_push(device);
    let written = flush(&state.usage, &state.db, &state.redis, &state.rng)
        .await
        .unwrap();
    assert!(written >= 1);

    let mut redis = state.redis.clone();
    let salt: Vec<u8> = redis.get(salt_key(now_ms())).await.unwrap();
    assert_eq!(salt.len(), 32);
    let ttl: i64 = redis.ttl(salt_key(now_ms())).await.unwrap();
    assert!(ttl > 39 * 24 * 3600, "{ttl}");
    let hash = device_hash(&device, &salt);
    assert_eq!(usage_row(&state.db, &hash).await, Some((2, 1_024, 1)));

    // Later flushes add up in the same row.
    state.usage.add_envelope(device, 6);
    flush(&state.usage, &state.db, &state.redis, &state.rng)
        .await
        .unwrap();
    assert_eq!(usage_row(&state.db, &hash).await, Some((3, 1_030, 1)));
    // Nothing identifies the device itself.
    let (raw,): (i64,) = sqlx::query_as(
        "SELECT count(*) FROM usage_daily WHERE position($1::bytea in device_hash) > 0",
    )
    .bind(&device.as_bytes()[..])
    .fetch_one(&state.db)
    .await
    .unwrap();
    assert_eq!(raw, 0);
}

#[actix_web::test]
#[ignore = "needs PostgreSQL + Redis (docker compose)"]
async fn daily_cleanup_deletes_old_statistics_and_inactive_devices() {
    let state = state().await;
    let app = app!(state);
    let old_hash = Uuid::new_v4().as_bytes().to_vec();
    let recent_hash = Uuid::new_v4().as_bytes().to_vec();
    for (hash, age) in [(&old_hash, 31), (&recent_hash, 29)] {
        sqlx::query(
            "INSERT INTO usage_daily (day, device_hash, envelopes) VALUES (current_date - $2::int, $1, 1)",
        )
        .bind(hash)
        .bind(age)
        .execute(&state.db)
        .await
        .unwrap();
    }
    let android = enroll(&app, "android").await;
    let stale_mac = enroll(&app, "macos").await;
    let active_mac = enroll(&app, "macos").await;
    let stale_pair = Uuid::new_v4();
    for (id, client) in [(stale_pair, &stale_mac), (Uuid::new_v4(), &active_mac)] {
        let body = pair_body(id, &android.device, &client.device, now_ms());
        call(&app, "POST", "/v1/pairs", &client.token, Some(&body)).await;
    }
    for (member, days) in [(&stale_mac, 181), (&active_mac, 179)] {
        sqlx::query("UPDATE devices SET last_seen_at = now() - $2::int * INTERVAL '1 day' WHERE device_id = $1")
            .bind(member.id())
            .bind(days)
            .execute(&state.db)
            .await
            .unwrap();
    }

    let (usage_rows, devices) = run_cleanup(&state).await.unwrap();
    assert!(usage_rows >= 1 && devices >= 1);
    let exists = |sql: &'static str, id: Vec<u8>| {
        let db = state.db.clone();
        async move {
            let (n,): (i64,) = sqlx::query_as(sql).bind(id).fetch_one(&db).await.unwrap();
            n
        }
    };
    let usage_sql = "SELECT count(*) FROM usage_daily WHERE device_hash = $1";
    assert_eq!(exists(usage_sql, old_hash).await, 0);
    assert_eq!(exists(usage_sql, recent_hash).await, 1);
    let device_sql = "SELECT count(*) FROM devices WHERE device_id::text = encode($1, 'escape')";
    assert_eq!(
        exists(device_sql, stale_mac.id().to_string().into_bytes()).await,
        0
    );
    assert_eq!(
        exists(device_sql, active_mac.id().to_string().into_bytes()).await,
        1
    );
    let (pairs,): (i64,) = sqlx::query_as("SELECT count(*) FROM pairs WHERE pair_id = $1")
        .bind(stale_pair)
        .fetch_one(&state.db)
        .await
        .unwrap();
    assert_eq!(pairs, 0, "pairs of a deleted device go by cascade");
}
