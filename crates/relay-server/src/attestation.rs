//! Pair attestation (spec 0.6.2) and the checks of `POST /v1/pairs`
//! (PAIR-01 API 8).
//!
//! `attestation` = `"HLPAIR1"` ‖ pair_id(16) ‖ device_id Android(16) ‖
//! device_id client(16) ‖ ik_sig_pub Android(32) ‖ ik_sig_pub client(32) ‖
//! created_at(int64 BE). Both devices sign exactly these bytes with Ed25519;
//! the relay verifies both signatures with the keys it holds in `devices`.

use uuid::Uuid;

use crate::error::ApiError;
use crate::signatures::verify_device_signature;

pub const ATTESTATION_LABEL: &[u8] = b"HLPAIR1";
/// 7 + 16 + 16 + 16 + 32 + 32 + 8 bytes.
pub const ATTESTATION_LEN: usize = 127;

/// The fields carried inside an attestation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attestation {
    pub pair_id: Uuid,
    pub device_a: Uuid,
    pub device_b: Uuid,
    pub ik_sig_pub_a: [u8; 32],
    pub ik_sig_pub_b: [u8; 32],
    pub created_at_ms: i64,
}

impl Attestation {
    /// Canonical byte form (the signed message).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(ATTESTATION_LEN);
        out.extend_from_slice(ATTESTATION_LABEL);
        out.extend_from_slice(self.pair_id.as_bytes());
        out.extend_from_slice(self.device_a.as_bytes());
        out.extend_from_slice(self.device_b.as_bytes());
        out.extend_from_slice(&self.ik_sig_pub_a);
        out.extend_from_slice(&self.ik_sig_pub_b);
        out.extend_from_slice(&self.created_at_ms.to_be_bytes());
        out
    }

    /// Parse the canonical form; `None` for a wrong label or length.
    pub fn parse(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != ATTESTATION_LEN || !bytes.starts_with(ATTESTATION_LABEL) {
            return None;
        }
        let rest = &bytes[ATTESTATION_LABEL.len()..];
        let uuid_at = |at: usize| Uuid::from_slice(&rest[at..at + 16]).ok();
        let key_at = |at: usize| -> Option<[u8; 32]> { rest[at..at + 32].try_into().ok() };
        Some(Self {
            pair_id: uuid_at(0)?,
            device_a: uuid_at(16)?,
            device_b: uuid_at(32)?,
            ik_sig_pub_a: key_at(48)?,
            ik_sig_pub_b: key_at(80)?,
            created_at_ms: i64::from_be_bytes(rest[112..120].try_into().ok()?),
        })
    }
}

/// What the request body claims, next to the attestation bytes.
pub struct PairClaim<'a> {
    pub pair_id: Uuid,
    pub device_a: Uuid,
    pub device_b: Uuid,
    pub created_at_ms: i64,
    pub attestation: &'a [u8],
    pub sig_a: &'a [u8; 64],
    pub sig_b: &'a [u8; 64],
}

/// Verify a pair registration against the keys stored for both devices.
///
/// - The attestation must parse and repeat the body's `pair_id`, `device_a`,
///   `device_b` and `created_at` → otherwise `BAD_REQUEST`.
/// - Its keys must be the registered keys → otherwise `SIGNATURE_INVALID`
///   (the signatures cannot be verified with the keys the relay trusts).
/// - `sig_a` (Android) and `sig_b` (client) must verify strictly.
pub fn verify_pair_claim(
    claim: &PairClaim<'_>,
    stored_key_a: &[u8; 32],
    stored_key_b: &[u8; 32],
) -> Result<(), ApiError> {
    let parsed = Attestation::parse(claim.attestation).ok_or(ApiError::BadRequest)?;
    if parsed.pair_id != claim.pair_id
        || parsed.device_a != claim.device_a
        || parsed.device_b != claim.device_b
        || parsed.created_at_ms != claim.created_at_ms
    {
        return Err(ApiError::BadRequest);
    }
    if parsed.ik_sig_pub_a != *stored_key_a || parsed.ik_sig_pub_b != *stored_key_b {
        return Err(ApiError::SignatureInvalid);
    }
    verify_device_signature(
        &claim.device_a,
        stored_key_a,
        claim.attestation,
        claim.sig_a,
    )?;
    verify_device_signature(
        &claim.device_b,
        stored_key_b,
        claim.attestation,
        claim.sig_b,
    )
}
