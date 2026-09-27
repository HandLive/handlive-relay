//! `POST /v1/pairs` (PAIR-01 API 8), `GET /v1/pairs` (PAIR-02 API 1) and
//! `POST /v1/pairs/{pair_id}/revoke` (PAIR-03 API 3).

use actix_web::{HttpResponse, web};
use serde::Deserialize;
use serde_json::json;
use uuid::Uuid;

use crate::attestation::{ATTESTATION_LEN, PairClaim, verify_pair_claim};
use crate::auth_extractor::AuthenticatedDevice;
use crate::b64u;
use crate::error::ApiError;
use crate::limits::{self, GROUP_REST, REST_PER_MINUTE};
use crate::relay::bus::BusMessage;
use crate::relay::presence;
use crate::state::AppState;
use crate::store::pairs::{self, InsertOutcome, NewPair};

pub const REVOKE_REASONS: [&str; 3] = ["user", "reinstall", "lost_device"];

#[derive(Debug, Deserialize)]
pub struct PairRequest {
    pub pair_id: Uuid,
    pub device_a: Uuid,
    pub device_b: Uuid,
    pub created_at: i64,
    pub attestation: String,
    pub sig_a: String,
    pub sig_b: String,
}

#[derive(Debug, Deserialize)]
pub struct ListQuery {
    pub include_revoked: Option<bool>,
}

#[derive(Debug, Deserialize)]
pub struct RevokeRequest {
    pub reason: String,
}

/// Decoded binary fields of a pair registration.
pub struct PairFields {
    pub attestation: Vec<u8>,
    pub sig_a: [u8; 64],
    pub sig_b: [u8; 64],
}

/// Shape checks of `POST /v1/pairs` that need no database.
pub fn decode_pair_request(req: &PairRequest) -> Result<PairFields, ApiError> {
    if req.device_a == req.device_b {
        return Err(ApiError::BadRequest);
    }
    let attestation = b64u::decode(&req.attestation)
        .filter(|a| a.len() == ATTESTATION_LEN)
        .ok_or(ApiError::BadRequest)?;
    Ok(PairFields {
        attestation,
        sig_a: b64u::decode_field(&req.sig_a)?,
        sig_b: b64u::decode_field(&req.sig_b)?,
    })
}

pub async fn register(
    state: web::Data<AppState>,
    device: AuthenticatedDevice,
    body: web::Json<PairRequest>,
) -> Result<HttpResponse, ApiError> {
    limits::check_device(&state.redis, &device.device_id, GROUP_REST, REST_PER_MINUTE).await?;
    let req = body.into_inner();
    let fields = decode_pair_request(&req)?;
    if device.device_id != req.device_a && device.device_id != req.device_b {
        return Err(ApiError::NotPaired);
    }
    let members = pairs::member_devices(&state.db, req.device_a, req.device_b)
        .await
        .map_err(|e| ApiError::internal("pair members", e))?;
    let (Some(a), Some(b)) = (members.get(&req.device_a), members.get(&req.device_b)) else {
        return Err(ApiError::DeviceNotFound);
    };
    // device_a is the Android phone, device_b the Mac/iPhone/iPad (0.9.4).
    if a.platform != "android" || b.platform == "android" {
        return Err(ApiError::BadRequest);
    }
    let key = |k: &Vec<u8>| -> Result<[u8; 32], ApiError> {
        k.as_slice()
            .try_into()
            .map_err(|_| ApiError::internal("devices row", "ik_sig_pub not 32 bytes"))
    };
    let claim = PairClaim {
        pair_id: req.pair_id,
        device_a: req.device_a,
        device_b: req.device_b,
        created_at_ms: req.created_at,
        attestation: &fields.attestation,
        sig_a: &fields.sig_a,
        sig_b: &fields.sig_b,
    };
    verify_pair_claim(&claim, &key(&a.ik_sig_pub)?, &key(&b.ik_sig_pub)?)?;
    let new = NewPair {
        pair_id: req.pair_id,
        device_a: req.device_a,
        device_b: req.device_b,
        attestation: &fields.attestation,
        sig_a: &fields.sig_a,
        sig_b: &fields.sig_b,
        created_at_ms: req.created_at,
    };
    let outcome = pairs::insert(&state.db, &new)
        .await
        .map_err(|e| ApiError::internal("pairs insert", e))?;
    let body = |created_at: i64| json!({ "pair_id": req.pair_id.hyphenated().to_string(), "created_at": created_at });
    match outcome {
        InsertOutcome::Created => {
            // Both relay connections start routing for the new pair.
            for member in [req.device_a, req.device_b] {
                notify(&state, &member, &BusMessage::PairsChanged).await;
            }
            Ok(HttpResponse::Created().json(body(req.created_at)))
        }
        InsertOutcome::Existing(stored)
            if stored.device_a == req.device_a
                && stored.device_b == req.device_b
                && stored.attestation == fields.attestation =>
        {
            Ok(HttpResponse::Ok().json(body(stored.created_at_ms)))
        }
        InsertOutcome::Existing(_) => Err(ApiError::PairExists),
    }
}

pub async fn list(
    state: web::Data<AppState>,
    device: AuthenticatedDevice,
    query: web::Query<ListQuery>,
) -> Result<HttpResponse, ApiError> {
    limits::check_device(&state.redis, &device.device_id, GROUP_REST, REST_PER_MINUTE).await?;
    let include_revoked = query.include_revoked.unwrap_or(true);
    let rows = pairs::list(&state.db, device.device_id, include_revoked)
        .await
        .map_err(|e| ApiError::internal("pairs list", e))?;
    let peers: Vec<Uuid> = rows.iter().map(|r| r.peer_device_id).collect();
    let online = presence::online(&state.redis, &peers)
        .await
        .map_err(|e| ApiError::internal("presence lookup", e))?;
    let pairs: Vec<_> = rows
        .iter()
        .zip(online)
        .map(|(r, online)| {
            json!({
                "pair_id": r.pair_id.hyphenated().to_string(),
                "peer_device_id": r.peer_device_id.hyphenated().to_string(),
                "peer_platform": r.peer_platform,
                "created_at": r.created_at_ms,
                "revoked_at": r.revoked_at_ms,
                "peer_online": online,
            })
        })
        .collect();
    Ok(HttpResponse::Ok().json(json!({ "pairs": pairs })))
}

pub async fn revoke(
    state: web::Data<AppState>,
    device: AuthenticatedDevice,
    path: web::Path<String>,
    body: web::Json<RevokeRequest>,
) -> Result<HttpResponse, ApiError> {
    limits::check_device(&state.redis, &device.device_id, GROUP_REST, REST_PER_MINUTE).await?;
    let pair_id = Uuid::try_parse(&path).map_err(|_| ApiError::BadRequest)?;
    if !REVOKE_REASONS.contains(&body.reason.as_str()) {
        return Err(ApiError::BadRequest);
    }
    let me = device.device_id;
    let revoked = pairs::revoke(&state.db, pair_id, me)
        .await
        .map_err(|e| ApiError::internal("pairs revoke", e))?;
    if let Some(peer) = revoked {
        notify(&state, &peer, &BusMessage::PairRevoked { pair_id, by: me }).await;
        notify(&state, &me, &BusMessage::PairsChanged).await;
        return Ok(HttpResponse::NoContent().finish());
    }
    match pairs::members(&state.db, pair_id)
        .await
        .map_err(|e| ApiError::internal("pairs lookup", e))?
    {
        None => Err(ApiError::DeviceNotFound),
        Some((a, b)) if a != me && b != me => Err(ApiError::NotPaired),
        // Already revoked earlier: idempotent (PAIR-03 E4).
        Some(_) => Ok(HttpResponse::NoContent().finish()),
    }
}

/// Publish to a device's relay connection, wherever it is; a failure only
/// delays the change until the device reconnects (its pairs are reloaded).
pub async fn notify(state: &AppState, device_id: &Uuid, msg: &BusMessage) {
    if let Err(e) = state.hub.publish(device_id, msg).await {
        log::warn!("relay notify failed: {e}");
    }
}
