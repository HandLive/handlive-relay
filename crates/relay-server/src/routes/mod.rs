//! HTTP routes (spec 0.7.4).

pub mod auth;
pub mod devices;
pub mod pairs;
pub mod relay_ws;

use actix_web::web;

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/v1")
            .route("/devices", web::post().to(devices::register))
            .route("/auth/challenge", web::post().to(auth::challenge))
            .route("/auth/token", web::post().to(auth::token))
            .route("/pairs", web::post().to(pairs::register))
            .route("/pairs", web::get().to(pairs::list))
            .route("/pairs/{pair_id}/revoke", web::post().to(pairs::revoke))
            .route("/relay", web::get().to(relay_ws::connect)),
    );
}

/// JSON limits and error mapping: oversize → 413, anything else → 400.
pub fn json_config(limit: usize) -> web::JsonConfig {
    web::JsonConfig::default()
        .limit(limit)
        .error_handler(crate::error::json_error_handler)
}
