//! Per-pair bandwidth limit (`RELAY_RATE_LIMIT`, CONN-03 API 6 logic 2):
//! over the limit the relay delays reading the sender instead of dropping
//! frames, and the sender still receives while it is held back.
//!
//! Ignored by default; needs PostgreSQL + Redis (see relay/README.md).

mod common;

use std::time::{Duration, Instant};

use common::relay_harness::{
    Relay, connect, enroll, envelope, pair, presence, rest, test_settings,
};
use serde_json::json;

#[actix_web::test]
#[ignore = "needs PostgreSQL + Redis (docker compose)"]
async fn frames_over_the_limit_are_delayed_not_dropped() {
    const RATE: u64 = 50_000;
    let mut settings = test_settings();
    settings.pair_bandwidth_bytes_per_sec = RATE;
    let relay = Relay::start(settings).await;
    let app = rest!(relay);
    let android = enroll(&app, "android").await;
    let mac = enroll(&app, "macos").await;
    let pair_id = pair(&app, &android, &mac).await;
    let mut android_ws = connect(&relay, &android).await;
    assert_eq!(
        android_ws.recv_json().await,
        presence(pair_id, mac.id(), false)
    );
    let mut mac_ws = connect(&relay, &mac).await;
    assert_eq!(
        mac_ws.recv_json().await,
        presence(pair_id, android.id(), true)
    );
    assert_eq!(
        android_ws.recv_json().await,
        presence(pair_id, mac.id(), true)
    );

    // 15 frames of ~10 kB (small enough to sit in socket buffers, so the
    // sender is never blocked by TCP): one second of burst, then about two
    // seconds of wait.
    let body = "B".repeat(10_000);
    let start = Instant::now();
    let mut sent = 0usize;
    for i in 0..15 {
        let text =
            json!({"to": android.id(), "env": envelope("clipboard", &format!("{i}:{body}"))})
                .to_string();
        sent += text.len();
        mac_ws.send_text(text).await;
    }
    // While the Mac's upload is held back, it still receives at once.
    let urgent = envelope("sms", "dXJnZW50");
    android_ws
        .send_json(&json!({"to": mac.id(), "env": urgent}))
        .await;
    let quick = Instant::now();
    assert_eq!(
        mac_ws.recv_json().await,
        json!({"from": android.id(), "env": urgent})
    );
    assert!(
        quick.elapsed() < Duration::from_millis(500),
        "{:?}",
        quick.elapsed()
    );

    for i in 0..15 {
        let got = android_ws.recv_json().await;
        let payload = got["env"]["payload"].as_str().unwrap();
        assert!(
            payload.starts_with(&format!("{i}:")),
            "frame {i} out of order"
        );
    }
    let elapsed = start.elapsed().as_secs_f64();
    let expected = (sent as f64 - RATE as f64) / RATE as f64;
    assert!(
        elapsed >= expected * 0.9,
        "{sent} bytes in {elapsed:.2} s, limit {RATE} B/s"
    );
    relay.stop().await;
}
