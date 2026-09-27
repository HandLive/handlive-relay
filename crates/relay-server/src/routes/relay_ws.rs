//! `GET /v1/relay` — WebSocket upgrade of the relay channel (CONN-03 API 4).
//! A bad JWT gets 401, a removed device 404 (spec 0.6.4), before any upgrade.

use actix_web::{HttpRequest, HttpResponse, web};

use crate::auth_extractor::AuthenticatedDevice;
use crate::error::ApiError;
use crate::limits::{self, GROUP_REST, REST_PER_MINUTE};
use crate::relay::connection;
use crate::relay::wire::MAX_WS_MESSAGE_BYTES;
use crate::state::AppState;

pub async fn connect(
    state: web::Data<AppState>,
    device: AuthenticatedDevice,
    req: HttpRequest,
    body: web::Payload,
) -> Result<HttpResponse, ApiError> {
    limits::check_device(&state.redis, &device.device_id, GROUP_REST, REST_PER_MINUTE).await?;
    let (response, session, stream) =
        actix_ws::handle(&req, body).map_err(|_| ApiError::BadRequest)?;
    let stream = stream
        .max_frame_size(MAX_WS_MESSAGE_BYTES)
        .aggregate_continuations()
        .max_continuation_size(MAX_WS_MESSAGE_BYTES);
    actix_web::rt::spawn(connection::run(state, device.device_id, session, stream));
    Ok(response)
}
