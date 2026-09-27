//! HandLive cloud relay: device registration and challenge/JWT
//! authentication, attested pairs, the `/v1/relay` WebSocket channel with
//! routing across instances through Redis, and minimal usage statistics.
//! Zero-knowledge: never decrypts or logs payloads (spec 0.4.3, 0.6.5).

pub mod attestation;
pub mod auth_extractor;
pub mod b64u;
pub mod challenge;
pub mod clock;
pub mod config;
pub mod device_identity;
pub mod error;
pub mod jwt;
pub mod limits;
pub mod maintenance;
pub mod relay;
pub mod routes;
pub mod signatures;
pub mod state;
pub mod store;
pub mod usage;

use actix_web::middleware::Logger;
use actix_web::web;

/// Largest JSON body accepted on the auth/registration endpoints.
pub const MAX_JSON_BODY_BYTES: usize = 4 * 1024;

/// Embedded migrations from `relay/migrations`.
pub static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("../../migrations");

/// Register JSON/query/path error mapping and all routes on an app.
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.app_data(routes::json_config(MAX_JSON_BODY_BYTES))
        .app_data(
            web::QueryConfig::default().error_handler(|_, _| error::ApiError::BadRequest.into()),
        )
        .app_data(
            web::PathConfig::default().error_handler(|_, _| error::ApiError::BadRequest.into()),
        )
        .configure(routes::configure);
}

/// Access log: path, status, response size and latency only — no query
/// string, no body, no header (spec 0.5.1 rule 5, 0.6.5).
pub fn access_log() -> Logger {
    Logger::new("%U %s %b %Dms")
}
