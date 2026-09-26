//! Push proxy of the HandLive relay (spec 0.4.4, CONN-04): wakes an Android
//! phone through FCM and alerts an iPhone/iPad through APNs.
//!
//! Zero-knowledge: FCM gets no content; APNs gets a catalog `loc-key` and the
//! envelope the phone encrypted with `K_push`, which the relay cannot read and
//! does not keep. Tokens and payloads are never logged.

pub mod apns;
pub mod config;
pub mod fcm;
mod http;
pub mod payload;

use uuid::Uuid;

pub use config::{ApnsConfig, FcmConfig, PushConfig};

/// `kind` of `POST /v1/push`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// FCM data message that wakes the Android phone.
    Wake,
    /// APNs alert for a suspended iPhone/iPad.
    Alert,
}

/// `reason` of `POST /v1/push` (CONN-04 API 2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    UserOpen,
    SmsSend,
    CallAction,
    SmsNew,
    CallIncoming,
    CallMissed,
}

impl Reason {
    pub const ALL: [Reason; 6] = [
        Reason::UserOpen,
        Reason::SmsSend,
        Reason::CallAction,
        Reason::SmsNew,
        Reason::CallIncoming,
        Reason::CallMissed,
    ];

    pub fn parse(text: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|r| r.as_str() == text)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::UserOpen => "user_open",
            Self::SmsSend => "sms_send",
            Self::CallAction => "call_action",
            Self::SmsNew => "sms_new",
            Self::CallIncoming => "call_incoming",
            Self::CallMissed => "call_missed",
        }
    }

    /// Wakes go to the phone, alerts to an iPhone/iPad.
    pub fn kind(self) -> Kind {
        match self {
            Self::UserOpen | Self::SmsSend | Self::CallAction => Kind::Wake,
            Self::SmsNew | Self::CallIncoming | Self::CallMissed => Kind::Alert,
        }
    }

    /// `ttl_s` when the request has none (CONN-04 API 2): 60 s for wakes,
    /// 30 s for an incoming call (the value CALL-01 API 4 sends), 86,400 s
    /// for new SMS and missed calls.
    pub fn default_ttl_s(self) -> u32 {
        match self {
            Self::SmsNew | Self::CallMissed => 86_400,
            Self::CallIncoming => 30,
            Self::UserOpen | Self::SmsSend | Self::CallAction => 60,
        }
    }
}

/// Result of one push attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Sent,
    /// The provider says the token is gone (FCM `UNREGISTERED`, APNs 410).
    TokenInvalid,
    /// The APNs payload would exceed 4 KB.
    TooLarge,
    /// Provider error, configuration error or provider not configured.
    Failed,
}

/// A wake for an Android phone.
pub struct Wake<'a> {
    pub token: &'a str,
    pub pair_id: Uuid,
    pub reason: Reason,
    pub ttl_s: u32,
}

/// An alert for an iPhone/iPad.
pub struct Alert<'a> {
    pub token: &'a str,
    pub topic: &'a str,
    /// `apns_sandbox` tokens go to the sandbox endpoint.
    pub sandbox: bool,
    pub pair_id: Uuid,
    pub reason: Reason,
    pub env_b64: &'a str,
    pub collapse_key: Option<&'a str>,
    pub ttl_s: u32,
}

/// The configured providers.
pub struct PushGateway {
    apns: Option<apns::ApnsClient>,
    fcm: Option<fcm::FcmClient>,
}

impl PushGateway {
    /// Load the keys named by the configuration; fails on unreadable keys.
    pub fn new(config: &PushConfig) -> Result<Self, String> {
        Ok(Self {
            apns: config
                .apns
                .as_ref()
                .map(apns::ApnsClient::new)
                .transpose()?,
            fcm: config.fcm.as_ref().map(fcm::FcmClient::new).transpose()?,
        })
    }

    /// The APNs topic push tokens must name, when APNs is configured.
    pub fn apns_topic(&self) -> Option<&str> {
        self.apns.as_ref().map(apns::ApnsClient::topic)
    }

    pub async fn wake(&self, push: &Wake<'_>) -> Outcome {
        match &self.fcm {
            Some(fcm) => fcm.send(push).await,
            None => {
                log::warn!("wake push dropped: FCM is not configured");
                Outcome::Failed
            }
        }
    }

    pub async fn alert(&self, push: &Alert<'_>) -> Outcome {
        match &self.apns {
            Some(apns) => apns.send(push).await,
            None => {
                log::warn!("alert push dropped: APNs is not configured");
                Outcome::Failed
            }
        }
    }
}
