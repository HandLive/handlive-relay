//! `POST /v1/auth/challenge` and `POST /v1/auth/token`
//! (spec 0.6.4, CONN-03 API 2–3).

use actix_web::{HttpRequest, HttpResponse, web};
use serde::Deserialize;
use serde_json::json;
use uuid::Uuid;

use crate::b64u;
use crate::challenge::{self, CHALLENGE_TTL_SECS};
use crate::clock::now_ms;
use crate::error::ApiError;
use crate::limits;
use crate::signatures::{auth_message, verify_device_signature};
use crate::state::AppState;
use crate::store::challenges;
use crate::store::devices::{self, DeviceKey};

#[derive(Debug, Deserialize)]
pub struct ChallengeRequest {
    pub device_id: Uuid,
}

#[derive(Debug, Deserialize)]
pub struct TokenRequest {
    pub device_id: Uuid,
    pub challenge: String,
    pub sig: String,
}

/// Map a `devices` lookup to the device public key or the spec error.
pub fn usable_key(found: Option<DeviceKey>) -> Result<[u8; 32], ApiError> {
    let key = found.ok_or(ApiError::DeviceNotFound)?;
    if key.revoked {
        return Err(ApiError::DeviceRevoked);
    }
    key.ik_sig_pub
        .try_into()
        .map_err(|_| ApiError::internal("devices row", "ik_sig_pub not 32 bytes"))
}

/// Token proof check, in spec order: consumed challenge must match, then the
/// device must be registered, then the `HLAUTH1` signature must verify.
pub fn check_token_proof(
    stored_challenge: Option<&str>,
    req: &TokenRequest,
    sig: &[u8; 64],
    found: Option<DeviceKey>,
) -> Result<(), ApiError> {
    let challenge = challenge::accept_presented(stored_challenge, &req.challenge)?;
    let ik_sig_pub = usable_key(found)?;
    let msg = auth_message(&challenge, &req.device_id);
    verify_device_signature(&req.device_id, &ik_sig_pub, &msg, sig)
}

/// `POST /v1/auth/challenge`: the per-IP limit first (no database work for a
/// flooding client), then the (`device_id`, IP) quota, then the device. Each
/// challenge gets its own key, so asking for more never locks a device out.
pub async fn challenge(
    state: web::Data<AppState>,
    http: HttpRequest,
    body: web::Json<ChallengeRequest>,
) -> Result<HttpResponse, ApiError> {
    let ip = limits::request_ip(&http, &state.settings.trusted_proxies);
    limits::check_auth_ip(&state.redis, ip.as_ref()).await?;
    let device_id = body.device_id;
    limits::check_challenge_quota(&state.redis, &device_id, ip.as_ref()).await?;
    let found = devices::find_key(&state.db, device_id)
        .await
        .map_err(|e| ApiError::internal("devices lookup", e))?;
    usable_key(found)?;

    let now = now_ms();
    let challenge = challenge::generate(&state.rng)?;
    let mut redis = state.redis.clone();
    challenges::put(&mut redis, &device_id, &challenge)
        .await
        .map_err(|e| ApiError::internal("challenge store", e))?;
    Ok(HttpResponse::Ok().json(json!({
        "challenge": b64u::encode(&challenge),
        "expires_at": now + (CHALLENGE_TTL_SECS as i64) * 1000,
    })))
}

/// `POST /v1/auth/token`: the per-IP limit of the challenge endpoint first,
/// then the echoed challenge is consumed (GETDEL of its own key).
pub async fn token(
    state: web::Data<AppState>,
    http: HttpRequest,
    body: web::Json<TokenRequest>,
) -> Result<HttpResponse, ApiError> {
    let ip = limits::request_ip(&http, &state.settings.trusted_proxies);
    limits::check_auth_ip(&state.redis, ip.as_ref()).await?;
    let req = body.into_inner();
    let sig: [u8; 64] = b64u::decode_field(&req.sig)?;
    // A malformed challenge was never issued.
    let presented: [u8; 32] =
        b64u::decode_fixed(&req.challenge).ok_or(ApiError::ChallengeExpired)?;
    let mut redis = state.redis.clone();
    let stored = challenges::take(&mut redis, &req.device_id, &presented)
        .await
        .map_err(|e| ApiError::internal("challenge take", e))?;
    // Missing challenge short-circuits before touching the database.
    if stored.is_none() {
        return Err(ApiError::ChallengeExpired);
    }
    let found = devices::find_key(&state.db, req.device_id)
        .await
        .map_err(|e| ApiError::internal("devices lookup", e))?;
    check_token_proof(stored.as_deref(), &req, &sig, found)?;

    devices::touch_last_seen(&state.db, req.device_id)
        .await
        .map_err(|e| ApiError::internal("devices touch", e))?;
    let (access_token, expires_in) = state.jwt.issue(&req.device_id, now_ms() / 1000)?;
    Ok(HttpResponse::Ok().json(json!({
        "access_token": access_token,
        "expires_in": expires_in,
    })))
}
