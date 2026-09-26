//! Runtime configuration from environment variables (see `relay/.env.example`
//! and `relay/README.md`). Secrets are never read from files in the repository.

use std::env;
use std::net::IpAddr;
use std::time::Duration;

use relay_push::PushConfig;

pub struct Config {
    pub database_url: String,
    pub redis_url: String,
    pub jwt_secret: Vec<u8>,
    pub bind: String,
    pub settings: RelaySettings,
    /// APNs and FCM (`RELAY_APNS_*`, `RELAY_FCM_*`); unset providers stay off.
    pub push: PushConfig,
}

impl Config {
    pub fn from_env() -> Result<Self, String> {
        let mut settings = RelaySettings::default();
        if let Ok(id) = env::var("RELAY_INSTANCE_ID") {
            if id.trim().is_empty() {
                return Err("RELAY_INSTANCE_ID is empty".to_owned());
            }
            settings.instance_id = id.trim().to_owned();
        }
        if let Ok(list) = env::var("RELAY_TRUSTED_PROXIES") {
            settings.trusted_proxies = parse_ip_list(&list)?;
        }
        Ok(Self {
            database_url: required("DATABASE_URL")?,
            redis_url: required("REDIS_URL")?,
            jwt_secret: required("RELAY_JWT_SECRET")?.into_bytes(),
            bind: env::var("RELAY_BIND").unwrap_or_else(|_| "127.0.0.1:8080".to_owned()),
            settings,
            push: PushConfig::from_env()?,
        })
    }
}

/// Relay behaviour knobs. Defaults are the spec values (0.9.4, 0.10, CONN-03);
/// tests shorten the timers.
#[derive(Debug, Clone)]
pub struct RelaySettings {
    /// Value written to `presence:<device_id>`; unique per running instance.
    pub instance_id: String,
    /// Reverse proxies whose `X-Forwarded-For` is believed (0.9.4 `rl:ip:`).
    pub trusted_proxies: Vec<IpAddr>,
    /// New registrations per client IP per hour (CONN-03 API 1).
    pub registrations_per_ip_per_hour: u64,
    /// Renewal period of `presence:<device_id>` (TTL 60 s, renewed every 20 s).
    pub presence_refresh: Duration,
    /// WebSocket ping period of the relay (`WS_PING_INTERVAL`).
    pub ping_interval: Duration,
    /// A relay connection that sent nothing for this long is closed (4411).
    pub idle_timeout: Duration,
    /// `RELAY_RATE_LIMIT`: bytes per second a device may send to one pair.
    pub pair_bandwidth_bytes_per_sec: u64,
    /// How often usage counters are written to `usage_daily`.
    pub usage_flush_interval: Duration,
    /// Bytes waiting for a slow receiver before its connection is dropped.
    pub max_queued_bytes: usize,
    /// A write to a device stuck this long drops the connection (4500).
    pub write_timeout: Duration,
}

impl Default for RelaySettings {
    fn default() -> Self {
        Self {
            instance_id: uuid::Uuid::new_v4().hyphenated().to_string(),
            trusted_proxies: Vec::new(),
            registrations_per_ip_per_hour: 10,
            presence_refresh: Duration::from_secs(20),
            ping_interval: Duration::from_secs(15),
            idle_timeout: Duration::from_secs(45),
            pair_bandwidth_bytes_per_sec: 2 * 1024 * 1024,
            usage_flush_interval: Duration::from_secs(60),
            max_queued_bytes: 32 * 1024 * 1024,
            write_timeout: Duration::from_secs(10),
        }
    }
}

/// Parse a comma-separated list of IP addresses (`RELAY_TRUSTED_PROXIES`).
pub fn parse_ip_list(list: &str) -> Result<Vec<IpAddr>, String> {
    list.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| {
            s.parse::<IpAddr>()
                .map_err(|_| format!("RELAY_TRUSTED_PROXIES: not an IP address: {s}"))
        })
        .collect()
}

fn required(name: &str) -> Result<String, String> {
    env::var(name).map_err(|_| format!("missing environment variable {name}"))
}
