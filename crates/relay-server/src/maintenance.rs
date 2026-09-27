//! Background jobs of a relay instance: writing usage counters every minute
//! and the daily data cleanup of spec 0.9.4 (statistics after 30 days,
//! devices inactive for 180 days).

use std::time::Duration;

use actix_web::web;
use redis::AsyncCommands;

use crate::clock::now_ms;
use crate::state::AppState;
use crate::store::usage::delete_expired;
use crate::usage;

/// How often an instance checks whether today's cleanup still has to run.
const CLEANUP_CHECK: Duration = Duration::from_secs(3600);
/// The cleanup lock outlives its day so only one instance runs it daily.
const CLEANUP_LOCK_TTL_SECS: u64 = 25 * 3600;

/// `maintenance:<day>` — taken with SET NX by the instance that runs the
/// cleanup of that UTC day.
pub fn cleanup_lock_key(now_ms: i64) -> String {
    format!("maintenance:{}", now_ms.div_euclid(86_400_000))
}

/// Run the cleanup once. Logs only the row counts.
pub async fn run_cleanup(state: &AppState) -> Result<(u64, u64), sqlx::Error> {
    let (usage_rows, devices) = delete_expired(&state.db).await?;
    log::info!("cleanup: deleted {usage_rows} usage rows and {devices} inactive devices");
    Ok((usage_rows, devices))
}

/// Start the usage flush and the daily cleanup on the current runtime.
pub fn spawn(state: web::Data<AppState>) {
    let flusher = state.clone();
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(flusher.settings.usage_flush_interval);
        tick.tick().await;
        loop {
            tick.tick().await;
            if let Err(e) =
                usage::flush(&flusher.usage, &flusher.db, &flusher.redis, &flusher.rng).await
            {
                log::warn!("usage flush failed: {e}");
            }
        }
    });
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(CLEANUP_CHECK);
        loop {
            tick.tick().await;
            let mut redis = state.redis.clone();
            let lock: redis::RedisResult<bool> = redis
                .set_options(
                    cleanup_lock_key(now_ms()),
                    &state.settings.instance_id,
                    redis::SetOptions::default()
                        .conditional_set(redis::ExistenceCheck::NX)
                        .with_expiration(redis::SetExpiry::EX(CLEANUP_LOCK_TTL_SECS)),
                )
                .await;
            match lock {
                Ok(true) => {
                    if let Err(e) = run_cleanup(&state).await {
                        log::warn!("cleanup failed: {e}");
                    }
                }
                Ok(false) => {}
                Err(e) => log::warn!("cleanup lock failed: {e}"),
            }
        }
    });
}
