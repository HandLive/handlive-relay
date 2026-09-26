//! Device endpoints:
//! - `POST /v1/devices` — register or refresh (CONN-03 API 1); no JWT, the
//!   body is self-authenticated by an `HLREG1` signature;
//! - `PUT /v1/devices/me/push-token` (CONN-04 API 1);
//! - `DELETE /v1/devices/me?revoke_pairs=` (SET-02 API 2, decision C16).

use actix_web::http::header::AUTHORIZATION;
use actix_web::{HttpRequest, HttpResponse, web};
use serde::Deserialize;
use serde_json::json;
use uuid::Uuid;

use crate::auth_extractor::{AuthenticatedDevice, bearer_token};
use crate::b64u;
use crate::clock::now_ms;
use crate::error::ApiError;
use crate::limits::{self, GROUP_REST, REST_PER_MINUTE};
use crate::relay::bus::BusMessage;
use crate::relay::connection::CLOSE_NORMAL;
use crate::relay::presence;
use crate::routes::pairs::notify;
use crate::signatures::{registration_message, verify_device_signature};
use crate::state::AppState;
use crate::store::challenges::challenge_key;
use crate::store::devices::{self, NewDevice, UpsertOutcome};

/// Maximum clock skew between the device `ts` and the relay (5 minutes).
pub const MAX_TS_SKEW_MS: i64 = 5 * 60 * 1000;
pub const PLATFORMS: [&str; 4] = ["android", "macos", "ios", "ipados"];
/// `app_version` is `string(32)`: at most 32 code points.
pub const APP_VERSION_MAX_CHARS: usize = 32;

#[derive(Debug, Deserialize)]
pub struct RegisterRequest {
    pub device_id: Uuid,
    pub platform: String,
    pub app_version: String,
    pub ik_sig_pub: String,
    pub ts: i64,
    pub sig: String,
}

/// Validate shape, timestamp and signature of a registration.
/// Returns the decoded public key on success.
pub fn verify_registration(req: &RegisterRequest, now_ms: i64) -> Result<[u8; 32], ApiError> {
    let chars = req.app_version.chars().count();
    if !PLATFORMS.contains(&req.platform.as_str()) || chars == 0 || chars > APP_VERSION_MAX_CHARS {
        return Err(ApiError::BadRequest);
    }
    let ik_sig_pub: [u8; 32] = b64u::decode_field(&req.ik_sig_pub)?;
    let sig: [u8; 64] = b64u::decode_field(&req.sig)?;
    if (now_ms - req.ts).abs() > MAX_TS_SKEW_MS {
        return Err(ApiError::SignatureInvalid);
    }
    let msg = registration_message(&req.device_id, &ik_sig_pub, &req.platform, req.ts);
    verify_device_signature(&req.device_id, &ik_sig_pub, &msg, &sig)?;
    Ok(ik_sig_pub)
}

pub async fn register(
    state: web::Data<AppState>,
    http: HttpRequest,
    body: web::Json<RegisterRequest>,
) -> Result<HttpResponse, ApiError> {
    let req = body.into_inner();
    let ik_sig_pub = verify_registration(&req, now_ms())?;
    // At most 10 new devices per hour per client IP (CONN-03 API 1 logic 3).
    let known = devices::find_key(&state.db, req.device_id)
        .await
        .map_err(|e| ApiError::internal("devices lookup", e))?;
    if known.is_none() {
        let forwarded = http
            .headers()
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok());
        let peer = http.peer_addr().map(|a| a.ip());
        if let Some(ip) = limits::client_ip(peer, forwarded, &state.settings.trusted_proxies) {
            let limit = state.settings.registrations_per_ip_per_hour;
            limits::check_registration(&state.redis, &ip, limit).await?;
        }
    }
    let new = NewDevice {
        device_id: req.device_id,
        ik_sig_pub: &ik_sig_pub,
        platform: &req.platform,
        app_version: &req.app_version,
    };
    let outcome = devices::upsert(&state.db, &new)
        .await
        .map_err(|e| ApiError::internal("devices upsert", e))?;
    let (mut response, created_at_ms) = match outcome {
        UpsertOutcome::Created { created_at_ms } => (HttpResponse::Created(), created_at_ms),
        UpsertOutcome::Updated { created_at_ms } => (HttpResponse::Ok(), created_at_ms),
        UpsertOutcome::Rejected => return Err(rejection_reason(&state, req.device_id).await),
    };
    Ok(response.json(json!({
        "device_id": req.device_id.hyphenated().to_string(),
        "created_at": created_at_ms,
    })))
}

/// The upsert changed nothing: the row is revoked (410). A different key for
/// the same `device_id` cannot pass `verify_registration`, so that case only
/// signals a key mismatch (401).
async fn rejection_reason(state: &AppState, device_id: Uuid) -> ApiError {
    match devices::find_key(&state.db, device_id).await {
        Ok(Some(key)) if key.revoked => ApiError::DeviceRevoked,
        Ok(_) => ApiError::SignatureInvalid,
        Err(e) => ApiError::internal("devices lookup", e),
    }
}

pub const PUSH_PROVIDERS: [&str; 3] = ["fcm", "apns", "apns_sandbox"];
/// `token` is `string(4096)`, `topic` is `string(255)` (CONN-04 API 1).
pub const PUSH_TOKEN_MAX_CHARS: usize = 4096;
pub const PUSH_TOPIC_MAX_CHARS: usize = 255;

#[derive(Debug, Deserialize)]
pub struct PushTokenRequest {
    pub provider: String,
    pub token: String,
    #[serde(default)]
    pub topic: Option<String>,
}

/// Validated push registration: `(provider, token, topic)`.
///
/// The provider must fit the platform (android ↔ fcm, ios/ipados ↔ apns or
/// apns_sandbox; a Mac never registers for push). APNs tokens are hex and go
/// into the request path, so they are checked strictly; APNs needs a topic.
pub fn validate_push_token<'a>(
    platform: &str,
    req: &'a PushTokenRequest,
) -> Result<(&'a str, &'a str, Option<&'a str>), ApiError> {
    let provider = req.provider.as_str();
    let fits = match platform {
        "android" => provider == "fcm",
        "ios" | "ipados" => provider == "apns" || provider == "apns_sandbox",
        _ => false,
    };
    let token = req.token.as_str();
    if !PUSH_PROVIDERS.contains(&provider)
        || !fits
        || token.is_empty()
        || token.chars().count() > PUSH_TOKEN_MAX_CHARS
    {
        return Err(ApiError::BadRequest);
    }
    if provider == "fcm" {
        if !token.bytes().all(|b| b.is_ascii_graphic()) {
            return Err(ApiError::BadRequest);
        }
        return Ok((provider, token, None));
    }
    let topic = req.topic.as_deref().ok_or(ApiError::BadRequest)?;
    let topic_ok = !topic.is_empty()
        && topic.chars().count() <= PUSH_TOPIC_MAX_CHARS
        && topic
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-' || b == b'_');
    if !token.bytes().all(|b| b.is_ascii_hexdigit()) || !topic_ok {
        return Err(ApiError::BadRequest);
    }
    Ok((provider, token, Some(topic)))
}

pub async fn put_push_token(
    state: web::Data<AppState>,
    device: AuthenticatedDevice,
    body: web::Json<PushTokenRequest>,
) -> Result<HttpResponse, ApiError> {
    limits::check_device(&state.redis, &device.device_id, GROUP_REST, REST_PER_MINUTE).await?;
    let found = devices::find_platform(&state.db, device.device_id)
        .await
        .map_err(|e| ApiError::internal("devices lookup", e))?;
    let (platform, _) = found.ok_or(ApiError::DeviceNotFound)?;
    let req = body.into_inner();
    let (provider, token, topic) = validate_push_token(&platform, &req)?;
    // With APNs configured, a token must be for this relay's app.
    if let (Some(topic), Some(expected)) = (topic, state.push.apns_topic())
        && topic != expected
    {
        return Err(ApiError::BadRequest);
    }
    let token = if provider == "fcm" {
        token.to_owned()
    } else {
        token.to_ascii_lowercase()
    };
    let stored = devices::set_push_token(&state.db, device.device_id, provider, &token, topic)
        .await
        .map_err(|e| ApiError::internal("push token update", e))?;
    if !stored {
        return Err(ApiError::DeviceNotFound);
    }
    Ok(HttpResponse::NoContent().finish())
}

#[derive(Debug, Deserialize)]
pub struct DeleteQuery {
    pub revoke_pairs: bool,
}

/// Remove the calling device from the relay. `revoke_pairs=false` deregisters
/// silently (the pairs keep working on the LAN); `true` revokes every pair and
/// tells the peers now or when they next connect.
pub async fn delete_me(
    state: web::Data<AppState>,
    http: HttpRequest,
    query: web::Query<DeleteQuery>,
) -> Result<HttpResponse, ApiError> {
    // Not the usual extractor: a device already gone gets 204 (repeat call).
    let device_id = state
        .jwt
        .verify(bearer_token(http.headers().get(AUTHORIZATION))?)?;
    let found = devices::find_key(&state.db, device_id)
        .await
        .map_err(|e| ApiError::internal("devices lookup", e))?;
    match found {
        None => return Ok(HttpResponse::NoContent().finish()),
        Some(key) if key.revoked => return Err(ApiError::DeviceRevoked),
        Some(_) => {}
    }
    limits::check_device(&state.redis, &device_id, GROUP_REST, REST_PER_MINUTE).await?;
    let peers = devices::delete_with_peers(&state.db, device_id)
        .await
        .map_err(|e| ApiError::internal("devices delete", e))?;
    for (pair_id, peer) in &peers {
        if query.revoke_pairs {
            if let Err(e) =
                presence::add_revoked_notice(&state.redis, peer, pair_id, &device_id).await
            {
                log::warn!("revoked notice failed: {e}");
            }
            let msg = BusMessage::PairRevoked {
                pair_id: *pair_id,
                by: device_id,
            };
            notify(&state, peer, &msg).await;
        } else {
            // Silent: the peer's connection just stops routing the pair.
            notify(&state, peer, &BusMessage::PairsChanged).await;
        }
    }
    // Presence goes first, so the closing connection finds nothing of its own
    // to release and announces no "offline" to the peers.
    let mut redis = state.redis.clone();
    let cleared: redis::RedisResult<()> = redis::cmd("DEL")
        .arg(presence::presence_key(&device_id))
        .arg(challenge_key(&device_id))
        .query_async(&mut redis)
        .await;
    if let Err(e) = cleared {
        log::warn!("presence cleanup failed: {e}");
    }
    notify(
        &state,
        &device_id,
        &BusMessage::Close { code: CLOSE_NORMAL },
    )
    .await;
    Ok(HttpResponse::NoContent().finish())
}
