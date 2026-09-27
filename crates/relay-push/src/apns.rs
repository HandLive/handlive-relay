//! APNs over HTTP/2 with a provider token (CONN-04 API 4).
//!
//! The provider token is an ES256 JWT (`kid` = key id, `iss` = team id,
//! `iat`) signed with the `.p8` key; Apple accepts a token for 60 minutes
//! and rejects refreshes more often than every 20, so it is reused and
//! renewed every 50 minutes, or at once when APNs reports it expired.

use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde::{Deserialize, Serialize};

use crate::config::ApnsConfig;
use crate::payload::{APNS_MAX_PAYLOAD_BYTES, apns_payload};
use crate::{Alert, Outcome, http};

pub const PROVIDER_TOKEN_REFRESH: Duration = Duration::from_secs(50 * 60);
const RETRY_DELAY: Duration = Duration::from_millis(500);

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProviderClaims {
    pub iss: String,
    pub iat: u64,
}

/// The cached provider token and the key that signs it.
pub struct ProviderToken {
    key: EncodingKey,
    key_id: String,
    team_id: String,
    cached: Mutex<Option<(String, Instant)>>,
}

impl ProviderToken {
    /// `pem` is the content of the `.p8` file (PKCS#8 EC private key).
    pub fn new(pem: &[u8], key_id: &str, team_id: &str) -> Result<Self, String> {
        let key = EncodingKey::from_ec_pem(pem).map_err(|_| "APNs key is not a PKCS#8 EC key")?;
        let token = Self {
            key,
            key_id: key_id.to_owned(),
            team_id: team_id.to_owned(),
            cached: Mutex::new(None),
        };
        token.sign()?;
        Ok(token)
    }

    fn sign(&self) -> Result<String, String> {
        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some(self.key_id.clone());
        header.typ = None;
        let iat = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let claims = ProviderClaims {
            iss: self.team_id.clone(),
            iat,
        };
        jsonwebtoken::encode(&header, &claims, &self.key)
            .map_err(|e| format!("APNs provider token: {e}"))
    }

    /// The current token; a new one after 50 minutes or when `renew`.
    pub fn get(&self, renew: bool) -> Result<String, String> {
        let mut cached = self.cached.lock().unwrap_or_else(|e| e.into_inner());
        if let Some((token, at)) = cached.as_ref()
            && !renew
            && at.elapsed() < PROVIDER_TOKEN_REFRESH
        {
            return Ok(token.clone());
        }
        let token = self.sign()?;
        *cached = Some((token.clone(), Instant::now()));
        Ok(token)
    }
}

/// What to do with an APNs answer (CONN-04 API 4 "Response").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Sent,
    /// 410 `Unregistered`: the token is dead, drop it (E3).
    Unregistered,
    /// 403 with an expired or invalid provider token: sign a new one once.
    RenewToken,
    /// 500 / 503: try once more.
    Retry,
    /// Configuration or request error (400, other 403, 404, 413, 429 …).
    Reject,
}

pub fn verdict(status: u16, reason: Option<&str>) -> Verdict {
    match (status, reason) {
        (200, _) => Verdict::Sent,
        (410, _) => Verdict::Unregistered,
        (403, Some("ExpiredProviderToken" | "InvalidProviderToken")) => Verdict::RenewToken,
        (500 | 503, _) => Verdict::Retry,
        _ => Verdict::Reject,
    }
}

#[derive(Deserialize)]
struct ApnsError {
    reason: String,
}

pub struct ApnsClient {
    http: reqwest::Client,
    production_url: String,
    sandbox_url: String,
    topic: String,
    token: ProviderToken,
}

impl ApnsClient {
    pub fn new(config: &ApnsConfig) -> Result<Self, String> {
        let pem = std::fs::read(&config.key_path)
            .map_err(|e| format!("APNs key {}: {e}", config.key_path.display()))?;
        Ok(Self {
            http: http::apns_client()?,
            production_url: config.production_url.clone(),
            sandbox_url: config.sandbox_url.clone(),
            topic: config.topic.clone(),
            token: ProviderToken::new(&pem, &config.key_id, &config.team_id)?,
        })
    }

    pub fn topic(&self) -> &str {
        &self.topic
    }

    pub async fn send(&self, alert: &Alert<'_>) -> Outcome {
        let Some(payload) = apns_payload(alert.reason, &alert.pair_id, alert.env_b64) else {
            return Outcome::Failed;
        };
        let body = payload.to_string();
        if body.len() > APNS_MAX_PAYLOAD_BYTES {
            return Outcome::TooLarge;
        }
        let base = if alert.sandbox {
            &self.sandbox_url
        } else {
            &self.production_url
        };
        let url = format!("{base}/3/device/{}", alert.token);
        let expiration = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
            + u64::from(alert.ttl_s);
        let (mut renewed, mut retried) = (false, false);
        loop {
            let jwt = match self.token.get(renewed) {
                Ok(jwt) => jwt,
                Err(e) => {
                    log::error!("{e}");
                    return Outcome::Failed;
                }
            };
            let mut request = self
                .http
                .post(&url)
                .header("authorization", format!("bearer {jwt}"))
                .header("apns-push-type", "alert")
                .header("apns-topic", alert.topic)
                .header("apns-priority", "10")
                .header("apns-expiration", expiration.to_string())
                .header("content-type", "application/json")
                .body(body.clone());
            if let Some(collapse) = alert.collapse_key {
                request = request.header("apns-collapse-id", collapse);
            }
            let (status, reason) = match request.send().await {
                Ok(resp) => {
                    let status = resp.status().as_u16();
                    let reason = if status == 200 {
                        None
                    } else {
                        resp.json::<ApnsError>().await.ok().map(|e| e.reason)
                    };
                    (status, reason)
                }
                Err(e) => {
                    // Without the URL: it holds the device token.
                    log::warn!("apns request failed: {}", e.without_url());
                    if retried {
                        return Outcome::Failed;
                    }
                    retried = true;
                    tokio::time::sleep(RETRY_DELAY).await;
                    continue;
                }
            };
            match verdict(status, reason.as_deref()) {
                Verdict::Sent => return Outcome::Sent,
                Verdict::Unregistered => return Outcome::TokenInvalid,
                Verdict::RenewToken if !renewed => renewed = true,
                Verdict::Retry if !retried => {
                    retried = true;
                    tokio::time::sleep(RETRY_DELAY).await;
                }
                _ => {
                    log::warn!(
                        "apns rejected a push: status {status}, reason {}",
                        reason.as_deref().unwrap_or("-")
                    );
                    return Outcome::Failed;
                }
            }
        }
    }
}
