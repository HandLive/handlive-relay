//! FCM HTTP v1 (CONN-04 API 3) with a service-account OAuth2 token.
//!
//! The relay signs an RS256 assertion with the service account's key,
//! trades it at `token_uri` for an access token, and reuses that token
//! until five minutes before it expires (or at once after a 401).

use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use crate::config::FcmConfig;
use crate::payload::fcm_message;
use crate::{Outcome, Wake, http};

pub const FCM_SCOPE: &str = "https://www.googleapis.com/auth/firebase.messaging";
pub const GOOGLE_TOKEN_URI: &str = "https://oauth2.googleapis.com/token";
pub const JWT_BEARER_GRANT: &str = "urn:ietf:params:oauth:grant-type:jwt-bearer";
/// Lifetime of the signed assertion (Google's maximum).
const ASSERTION_TTL_S: u64 = 3600;
/// Renew the access token this long before it expires.
const RENEW_MARGIN_S: u64 = 300;
const RETRY_DELAY: Duration = Duration::from_millis(500);

#[derive(Deserialize)]
struct ServiceAccount {
    client_email: String,
    private_key: String,
    #[serde(default)]
    token_uri: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AssertionClaims {
    pub iss: String,
    pub scope: String,
    pub aud: String,
    pub iat: u64,
    pub exp: u64,
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    expires_in: u64,
}

#[derive(Deserialize)]
struct FcmErrorBody {
    error: FcmError,
}

#[derive(Deserialize)]
struct FcmError {
    #[serde(default)]
    status: Option<String>,
    #[serde(default)]
    details: Vec<FcmErrorDetail>,
}

#[derive(Deserialize)]
struct FcmErrorDetail {
    #[serde(default, rename = "errorCode")]
    error_code: Option<String>,
}

/// What to do with an FCM answer (CONN-04 API 3 "Response").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Sent,
    /// `UNREGISTERED`: the token is dead, drop it (E3).
    Unregistered,
    /// 401: fetch a new access token once.
    RenewToken,
    /// 500 / 503: try once more.
    Retry,
    /// Configuration or request error (400, 403, 404, 429 …).
    Reject,
}

pub fn verdict(status: u16, error_code: Option<&str>) -> Verdict {
    match (status, error_code) {
        (200, _) => Verdict::Sent,
        (_, Some("UNREGISTERED")) => Verdict::Unregistered,
        (401, _) => Verdict::RenewToken,
        (500 | 503, _) => Verdict::Retry,
        _ => Verdict::Reject,
    }
}

fn now_s() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub struct FcmClient {
    http: reqwest::Client,
    send_url: String,
    token_uri: String,
    client_email: String,
    key: EncodingKey,
    access: Mutex<Option<(String, Instant)>>,
}

impl FcmClient {
    pub fn new(config: &FcmConfig) -> Result<Self, String> {
        let path = config.service_account_path.display();
        let text = std::fs::read(&config.service_account_path)
            .map_err(|e| format!("FCM service account {path}: {e}"))?;
        let account: ServiceAccount = serde_json::from_slice(&text)
            .map_err(|_| format!("FCM service account {path}: not a service-account JSON"))?;
        let key = EncodingKey::from_rsa_pem(account.private_key.as_bytes())
            .map_err(|_| format!("FCM service account {path}: private_key is not an RSA key"))?;
        Ok(Self {
            http: http::fcm_client()?,
            send_url: format!(
                "{}/v1/projects/{}/messages:send",
                config.url, config.project_id
            ),
            token_uri: account
                .token_uri
                .unwrap_or_else(|| GOOGLE_TOKEN_URI.to_owned()),
            client_email: account.client_email,
            key,
            access: Mutex::new(None),
        })
    }

    fn assertion(&self) -> Result<String, String> {
        let iat = now_s();
        let claims = AssertionClaims {
            iss: self.client_email.clone(),
            scope: FCM_SCOPE.to_owned(),
            aud: self.token_uri.clone(),
            iat,
            exp: iat + ASSERTION_TTL_S,
        };
        jsonwebtoken::encode(&Header::new(Algorithm::RS256), &claims, &self.key)
            .map_err(|e| format!("FCM assertion: {e}"))
    }

    /// The cached access token, or a new one when missing, near expiry or
    /// `renew`.
    async fn access_token(&self, renew: bool) -> Result<String, String> {
        let mut access = self.access.lock().await;
        if let Some((token, refresh_at)) = access.as_ref()
            && !renew
            && Instant::now() < *refresh_at
        {
            return Ok(token.clone());
        }
        let assertion = self.assertion()?;
        let form = [
            ("grant_type", JWT_BEARER_GRANT),
            ("assertion", assertion.as_str()),
        ];
        let resp = self
            .http
            .post(&self.token_uri)
            .form(&form)
            .send()
            .await
            .map_err(|e| format!("FCM token request failed: {}", e.without_url()))?;
        if !resp.status().is_success() {
            return Err(format!(
                "FCM token request refused: status {}",
                resp.status().as_u16()
            ));
        }
        let token: TokenResponse = resp
            .json()
            .await
            .map_err(|_| "FCM token response unreadable".to_owned())?;
        let valid = Duration::from_secs(token.expires_in.saturating_sub(RENEW_MARGIN_S).max(60));
        *access = Some((token.access_token.clone(), Instant::now() + valid));
        Ok(token.access_token)
    }

    pub async fn send(&self, wake: &Wake<'_>) -> Outcome {
        let body = fcm_message(wake.token, &wake.pair_id, wake.reason, wake.ttl_s);
        let (mut renewed, mut retried) = (false, false);
        loop {
            let access = match self.access_token(renewed).await {
                Ok(access) => access,
                Err(e) => {
                    log::warn!("{e}");
                    return Outcome::Failed;
                }
            };
            let (status, code) = match self
                .http
                .post(&self.send_url)
                .bearer_auth(access)
                .json(&body)
                .send()
                .await
            {
                Ok(resp) => {
                    let status = resp.status().as_u16();
                    let code = if status == 200 {
                        None
                    } else {
                        resp.json::<FcmErrorBody>().await.ok().and_then(|b| {
                            b.error
                                .details
                                .into_iter()
                                .find_map(|d| d.error_code)
                                .or(b.error.status)
                        })
                    };
                    (status, code)
                }
                Err(e) => {
                    log::warn!("fcm request failed: {}", e.without_url());
                    if retried {
                        return Outcome::Failed;
                    }
                    retried = true;
                    tokio::time::sleep(RETRY_DELAY).await;
                    continue;
                }
            };
            match verdict(status, code.as_deref()) {
                Verdict::Sent => return Outcome::Sent,
                Verdict::Unregistered => return Outcome::TokenInvalid,
                Verdict::RenewToken if !renewed => renewed = true,
                Verdict::Retry if !retried => {
                    retried = true;
                    tokio::time::sleep(RETRY_DELAY).await;
                }
                _ => {
                    log::warn!(
                        "fcm rejected a push: status {status}, code {}",
                        code.as_deref().unwrap_or("-")
                    );
                    return Outcome::Failed;
                }
            }
        }
    }
}
