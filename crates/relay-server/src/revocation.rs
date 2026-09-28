//! Signed revocation statements (`HLREVOKE1`, spec 0.6.2): the bodies of
//! `POST /v1/pairs/{pair_id}/revoke` (PAIR-03 API 3) and
//! `DELETE /v1/devices/me?revoke_pairs=true` (SET-02 API 2), and the checks
//! the relay makes before it stores and forwards a statement.
//!
//! The relay cannot forge a revocation: peers act on `pair_revoked` only when
//! the signature is the peer's (PAIR-03 API 4). The relay still refuses a
//! statement it could not forward in good faith, so a client learns at once
//! that its request was malformed.

use std::collections::HashMap;

use serde::Deserialize;
use uuid::Uuid;

use crate::b64u;
use crate::error::ApiError;
use crate::signatures::{revoke_message, verify_device_signature};

/// `REVOKE_CLOCK_SKEW` (spec 0.10): `revoked_at` within ±10 minutes of the
/// relay clock.
pub const REVOKE_CLOCK_SKEW_MS: i64 = 10 * 60 * 1000;

/// A verified statement: `by` revoked `pair_id` at `revoked_at` (ms).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevokeStatement {
    pub pair_id: Uuid,
    pub by: Uuid,
    pub revoked_at: i64,
    pub sig: [u8; 64],
}

/// Body of `POST /v1/pairs/{pair_id}/revoke`. Every field is optional here so
/// that a missing one is `BAD_REQUEST` from [`verify_statement`]; `reason` is
/// informational, neither signed nor stored.
#[derive(Debug, Default, Deserialize)]
pub struct RevokeRequest {
    pub revoked_at: Option<i64>,
    pub sig: Option<String>,
    pub reason: Option<String>,
}

/// One item of `revocations[]` in `DELETE /v1/devices/me?revoke_pairs=true`.
#[derive(Debug, Clone, Deserialize)]
pub struct Revocation {
    pub pair_id: Uuid,
    pub revoked_at: Option<i64>,
    pub sig: Option<String>,
}

/// Body of `DELETE /v1/devices/me?revoke_pairs=true`.
#[derive(Debug, Default, Deserialize)]
pub struct DeleteRequest {
    #[serde(default)]
    pub revocations: Vec<Revocation>,
}

/// Check a statement made by the caller: `by` is the caller (the JWT
/// subject), `revoked_at` is within [`REVOKE_CLOCK_SKEW_MS`] of `now_ms`, and
/// `sig` verifies strictly with the caller's stored key. Anything missing or
/// wrong is `BAD_REQUEST`.
pub fn verify_statement(
    pair_id: &Uuid,
    caller: &Uuid,
    caller_ik_sig_pub: &[u8; 32],
    revoked_at: Option<i64>,
    sig: Option<&str>,
    now_ms: i64,
) -> Result<RevokeStatement, ApiError> {
    let revoked_at = revoked_at.ok_or(ApiError::BadRequest)?;
    let sig: [u8; 64] = b64u::decode_field(sig.ok_or(ApiError::BadRequest)?)?;
    let unsigned = u64::try_from(revoked_at).map_err(|_| ApiError::BadRequest)?;
    if revoked_at.abs_diff(now_ms) > REVOKE_CLOCK_SKEW_MS.unsigned_abs() {
        return Err(ApiError::BadRequest);
    }
    let msg = revoke_message(pair_id, caller, unsigned);
    verify_device_signature(caller, caller_ik_sig_pub, &msg, &sig)
        .map_err(|_| ApiError::BadRequest)?;
    Ok(RevokeStatement {
        pair_id: *pair_id,
        by: *caller,
        revoked_at,
        sig,
    })
}

/// Match the statements of a "delete all data" call to the unrevoked pairs
/// the relay holds for the caller, `held` = `(pair_id, peer_device_id)`.
/// Every held pair needs exactly one valid statement; statements for pairs
/// the relay does not hold are ignored. Returns the statements with their
/// peer, in the order of `held`.
pub fn verify_revocations(
    held: &[(Uuid, Uuid)],
    items: &[Revocation],
    caller: &Uuid,
    caller_ik_sig_pub: &[u8; 32],
    now_ms: i64,
) -> Result<Vec<(RevokeStatement, Uuid)>, ApiError> {
    let mut by_pair: HashMap<Uuid, &Revocation> = HashMap::with_capacity(items.len());
    for item in items {
        if by_pair.insert(item.pair_id, item).is_some() {
            return Err(ApiError::BadRequest);
        }
    }
    held.iter()
        .map(|(pair_id, peer)| {
            let item = by_pair.get(pair_id).ok_or(ApiError::BadRequest)?;
            let statement = verify_statement(
                pair_id,
                caller,
                caller_ik_sig_pub,
                item.revoked_at,
                item.sig.as_deref(),
                now_ms,
            )?;
            Ok((statement, *peer))
        })
        .collect()
}
