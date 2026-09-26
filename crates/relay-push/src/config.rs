//! Push provider configuration, from environment variables and key files at
//! run time only (CONN-04 API 3–4). Keys never live in the repository; this
//! struct holds paths and public identifiers, never key material.

use std::env;
use std::path::PathBuf;

pub const APNS_PRODUCTION_URL: &str = "https://api.push.apple.com";
pub const APNS_SANDBOX_URL: &str = "https://api.sandbox.push.apple.com";
pub const FCM_URL: &str = "https://fcm.googleapis.com";

/// Which providers this relay can reach; `None` = not configured.
#[derive(Debug, Clone, Default)]
pub struct PushConfig {
    pub apns: Option<ApnsConfig>,
    pub fcm: Option<FcmConfig>,
}

#[derive(Debug, Clone)]
pub struct ApnsConfig {
    /// The `.p8` provider key (PKCS#8 PEM of an ES256 key).
    pub key_path: PathBuf,
    pub key_id: String,
    pub team_id: String,
    /// Bundle id of the iOS app (`apns-topic`); push tokens must name it.
    pub topic: String,
    pub production_url: String,
    pub sandbox_url: String,
}

#[derive(Debug, Clone)]
pub struct FcmConfig {
    pub project_id: String,
    /// Google service-account JSON (`client_email`, `private_key`, `token_uri`).
    pub service_account_path: PathBuf,
    pub url: String,
}

impl PushConfig {
    /// Read `RELAY_APNS_*` and `RELAY_FCM_*`. A provider is enabled only
    /// when all of its required variables are set; a partial set is an error.
    pub fn from_env() -> Result<Self, String> {
        let apns = group(&[
            "RELAY_APNS_KEY_PATH",
            "RELAY_APNS_KEY_ID",
            "RELAY_APNS_TEAM_ID",
            "RELAY_APNS_TOPIC",
        ])?
        .map(|v| ApnsConfig {
            key_path: PathBuf::from(&v[0]),
            key_id: v[1].clone(),
            team_id: v[2].clone(),
            topic: v[3].clone(),
            production_url: optional("RELAY_APNS_URL", APNS_PRODUCTION_URL),
            sandbox_url: optional("RELAY_APNS_SANDBOX_URL", APNS_SANDBOX_URL),
        });
        let fcm = group(&["RELAY_FCM_PROJECT_ID", "RELAY_FCM_SERVICE_ACCOUNT_PATH"])?.map(|v| {
            FcmConfig {
                project_id: v[0].clone(),
                service_account_path: PathBuf::from(&v[1]),
                url: optional("RELAY_FCM_URL", FCM_URL),
            }
        });
        Ok(Self { apns, fcm })
    }
}

/// All of `names` set (non-empty) → their values; none set → `None`.
fn group(names: &[&str]) -> Result<Option<Vec<String>>, String> {
    let values: Vec<Option<String>> = names
        .iter()
        .map(|n| env::var(n).ok().filter(|v| !v.trim().is_empty()))
        .collect();
    if values.iter().all(Option::is_none) {
        return Ok(None);
    }
    if values.iter().any(Option::is_none) {
        return Err(format!("set all of {} or none", names.join(", ")));
    }
    Ok(Some(values.into_iter().flatten().collect()))
}

fn optional(name: &str, default: &str) -> String {
    env::var(name)
        .ok()
        .filter(|v| !v.trim().is_empty())
        .unwrap_or_else(|| default.to_owned())
        .trim_end_matches('/')
        .to_owned()
}
