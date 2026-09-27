//! `POST /v1/push` — push to the other device of a pair (CONN-04 API 2):
//! a `wake` through FCM to the Android phone, an `alert` through APNs to an
//! iPhone/iPad. The relay checks the pair, the platform, the token and the
//! quota, never reads `env_b64` and does not keep it after sending.

use actix_web::{HttpResponse, web};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use redis::AsyncCommands;
use relay_push::{Alert, Kind, Outcome, Reason, Wake};
use serde::Deserialize;
use serde_json::json;
use uuid::Uuid;

use crate::auth_extractor::AuthenticatedDevice;
use crate::error::ApiError;
use crate::limits::{self, GROUP_PUSH, PUSH_PER_MINUTE};
use crate::state::AppState;
use crate::store::devices;

/// `env_b64` limit (CONN-04 API 2).
pub const ENV_B64_MAX_BYTES: usize = 3000;
/// `collapse_key` is `string(64)`; it becomes the `apns-collapse-id` header.
pub const COLLAPSE_KEY_MAX_CHARS: usize = 64;
/// Longest `ttl_s` accepted (the largest default, SMS and missed calls).
pub const TTL_MAX_S: i64 = 86_400;
/// A wake with the same reason for the same device within 5 minutes is
/// accepted but not sent again (CONN-04 API 2 logic 3).
pub const WAKE_COALESCE_SECS: u64 = 300;

#[derive(Debug, Deserialize)]
pub struct PushRequest {
    pub pair_id: Uuid,
    pub to: Uuid,
    pub kind: String,
    pub reason: String,
    #[serde(default)]
    pub env_b64: Option<String>,
    #[serde(default)]
    pub collapse_key: Option<String>,
    #[serde(default)]
    pub ttl_s: Option<i64>,
}

/// A request that passed the shape checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidPush<'a> {
    pub kind: Kind,
    pub reason: Reason,
    pub env_b64: Option<&'a str>,
    pub collapse_key: Option<&'a str>,
    pub ttl_s: u32,
}

/// Shape checks that need no database: kind and reason agree, `env_b64`
/// only with alerts (≤ 3,000 bytes of b64 → 413 beyond), `collapse_key`
/// printable ASCII up to 64 characters, `ttl_s` between 0 and 86,400.
pub fn validate_push(req: &PushRequest) -> Result<ValidPush<'_>, ApiError> {
    let kind = match req.kind.as_str() {
        "wake" => Kind::Wake,
        "alert" => Kind::Alert,
        _ => return Err(ApiError::BadRequest),
    };
    let reason = Reason::parse(&req.reason)
        .filter(|r| r.kind() == kind)
        .ok_or(ApiError::BadRequest)?;
    let collapse_key = match req.collapse_key.as_deref() {
        None => None,
        Some(c)
            if !c.is_empty()
                && c.len() <= COLLAPSE_KEY_MAX_CHARS
                && c.bytes().all(|b| b.is_ascii_graphic()) =>
        {
            Some(c)
        }
        Some(_) => return Err(ApiError::BadRequest),
    };
    let ttl_s = match req.ttl_s {
        None => reason.default_ttl_s(),
        Some(t) if (0..=TTL_MAX_S).contains(&t) => t as u32,
        Some(_) => return Err(ApiError::BadRequest),
    };
    let env_b64 = match (kind, req.env_b64.as_deref()) {
        (Kind::Wake, None) => None,
        (Kind::Wake, Some(_)) | (Kind::Alert, None) => return Err(ApiError::BadRequest),
        (Kind::Alert, Some(env)) if env.len() > ENV_B64_MAX_BYTES => {
            return Err(ApiError::PayloadTooLarge);
        }
        (Kind::Alert, Some(env)) => {
            if env.is_empty() || STANDARD.decode(env).is_err() {
                return Err(ApiError::BadRequest);
            }
            Some(env)
        }
    };
    Ok(ValidPush {
        kind,
        reason,
        env_b64,
        collapse_key,
        ttl_s,
    })
}

/// `wake:<device_id>:<reason>` — set while a wake is coalesced.
pub fn wake_key(to: &Uuid, reason: Reason) -> String {
    format!("wake:{}:{}", to.hyphenated(), reason.as_str())
}

pub async fn send(
    state: web::Data<AppState>,
    device: AuthenticatedDevice,
    body: web::Json<PushRequest>,
) -> Result<HttpResponse, ApiError> {
    limits::check_device(&state.redis, &device.device_id, GROUP_PUSH, PUSH_PER_MINUTE).await?;
    let req = body.into_inner();
    let push = validate_push(&req)?;
    let target = devices::push_target(&state.db, req.pair_id, device.device_id, req.to)
        .await
        .map_err(|e| ApiError::internal("push target", e))?
        .ok_or(ApiError::NotPaired)?;
    let platform_fits = match push.kind {
        Kind::Wake => target.platform == "android",
        Kind::Alert => target.platform == "ios" || target.platform == "ipados",
    };
    if !platform_fits {
        return Err(ApiError::BadRequest);
    }
    let provider_fits = |p: &str| match push.kind {
        Kind::Wake => p == "fcm",
        Kind::Alert => p == "apns" || p == "apns_sandbox",
    };
    let (Some(provider), Some(token)) = (target.provider.as_deref(), target.token.as_deref())
    else {
        return Err(ApiError::PushTokenMissing);
    };
    if !provider_fits(provider) {
        return Err(ApiError::PushTokenMissing);
    }

    let mut redis = state.redis.clone();
    let coalesce = (push.kind == Kind::Wake).then(|| wake_key(&req.to, push.reason));
    if let Some(key) = &coalesce {
        let first: bool = redis
            .set_options(
                key,
                1,
                redis::SetOptions::default()
                    .conditional_set(redis::ExistenceCheck::NX)
                    .with_expiration(redis::SetExpiry::EX(WAKE_COALESCE_SECS)),
            )
            .await
            .map_err(|e| ApiError::internal("wake coalescing", e))?;
        if !first {
            return Ok(accepted());
        }
    }

    let outcome = match push.kind {
        Kind::Wake => {
            let wake = Wake {
                token,
                pair_id: req.pair_id,
                reason: push.reason,
                ttl_s: push.ttl_s,
            };
            state.push.wake(&wake).await
        }
        Kind::Alert => {
            let alert = Alert {
                token,
                topic: target.topic.as_deref().unwrap_or_default(),
                sandbox: provider == "apns_sandbox",
                pair_id: req.pair_id,
                reason: push.reason,
                env_b64: push.env_b64.unwrap_or_default(),
                collapse_key: push.collapse_key,
                ttl_s: push.ttl_s,
            };
            state.push.alert(&alert).await
        }
    };
    if outcome != Outcome::Sent
        && let Some(key) = &coalesce
    {
        let _: redis::RedisResult<()> = redis.del(key).await;
    }
    match outcome {
        Outcome::Sent => {
            state.usage.add_push(device.device_id);
            Ok(accepted())
        }
        // CONN-04 E3: forget the dead token; the device registers again.
        Outcome::TokenInvalid => {
            devices::clear_push_token(&state.db, req.to)
                .await
                .map_err(|e| ApiError::internal("push token clear", e))?;
            Err(ApiError::PushTokenMissing)
        }
        Outcome::TooLarge => Err(ApiError::PayloadTooLarge),
        Outcome::Failed => Err(ApiError::PushProviderError),
    }
}

fn accepted() -> HttpResponse {
    HttpResponse::Accepted().json(json!({ "accepted": true }))
}
