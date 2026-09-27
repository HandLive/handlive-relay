//! `PushConfig::from_env` (one test: environment variables are process-wide).

use relay_push::PushConfig;
use relay_push::config::{APNS_PRODUCTION_URL, APNS_SANDBOX_URL, FCM_URL};

const VARS: [&str; 9] = [
    "RELAY_APNS_KEY_PATH",
    "RELAY_APNS_KEY_ID",
    "RELAY_APNS_TEAM_ID",
    "RELAY_APNS_TOPIC",
    "RELAY_APNS_URL",
    "RELAY_APNS_SANDBOX_URL",
    "RELAY_FCM_PROJECT_ID",
    "RELAY_FCM_SERVICE_ACCOUNT_PATH",
    "RELAY_FCM_URL",
];

fn set(name: &str, value: &str) {
    // SAFETY: this binary has a single test; nothing reads the environment
    // concurrently.
    unsafe { std::env::set_var(name, value) };
}

fn clear() {
    for name in VARS {
        // SAFETY: as above.
        unsafe { std::env::remove_var(name) };
    }
}

#[test]
fn providers_are_enabled_by_complete_variable_sets() {
    clear();
    let none = PushConfig::from_env().unwrap();
    assert!(none.apns.is_none() && none.fcm.is_none());

    set("RELAY_APNS_KEY_PATH", "/run/secrets/AuthKey.p8");
    set("RELAY_APNS_KEY_ID", "ABC123DEFG");
    let err = PushConfig::from_env().unwrap_err();
    assert!(err.contains("RELAY_APNS_TEAM_ID"), "{err}");
    set("RELAY_APNS_TEAM_ID", "DEF123GHIJ");
    set("RELAY_APNS_TOPIC", "app.handlive.ios");
    let apns = PushConfig::from_env().unwrap().apns.unwrap();
    assert_eq!(apns.key_path.to_str(), Some("/run/secrets/AuthKey.p8"));
    assert_eq!(
        (apns.key_id.as_str(), apns.team_id.as_str()),
        ("ABC123DEFG", "DEF123GHIJ")
    );
    assert_eq!(apns.topic, "app.handlive.ios");
    assert_eq!(
        (apns.production_url.as_str(), apns.sandbox_url.as_str()),
        (APNS_PRODUCTION_URL, APNS_SANDBOX_URL)
    );
    set("RELAY_APNS_URL", "http://127.0.0.1:9000/");
    let apns = PushConfig::from_env().unwrap().apns.unwrap();
    assert_eq!(apns.production_url, "http://127.0.0.1:9000");

    set("RELAY_FCM_PROJECT_ID", "handlive-prod");
    assert!(
        PushConfig::from_env().is_err(),
        "service account path missing"
    );
    set("RELAY_FCM_SERVICE_ACCOUNT_PATH", "/run/secrets/fcm.json");
    let fcm = PushConfig::from_env().unwrap().fcm.unwrap();
    assert_eq!(fcm.project_id, "handlive-prod");
    assert_eq!(
        fcm.service_account_path.to_str(),
        Some("/run/secrets/fcm.json")
    );
    assert_eq!(fcm.url, FCM_URL);
    // An empty value counts as unset.
    set("RELAY_APNS_TOPIC", " ");
    assert!(PushConfig::from_env().is_err());
    clear();
}
