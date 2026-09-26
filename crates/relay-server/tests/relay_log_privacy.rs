//! Zero-knowledge logging (spec 0.5.1 rule 5, 0.6.5, CONN-03 API 6 logic 4):
//! every log record written while the relay registers, pairs, forwards
//! both frame kinds, runs a rendezvous, refuses frames and removes a device
//! is captured, and none may carry envelope content, identifiers, tokens or
//! query strings. Access-log lines must still be there (path and status).
//!
//! One test in its own binary: it installs the process-wide logger.
//! Ignored by default; needs PostgreSQL + Redis (see relay/README.md).

mod common;

use std::sync::Mutex;

use actix_web::App;
use actix_web::http::StatusCode;
use actix_web::middleware::Compat;
use common::relay_harness::{Relay, call, connect, enroll, pair, presence, test_settings};
use log::{LevelFilter, Log, Metadata, Record};
use relay_server::{access_log, configure};
use serde_json::json;
use uuid::Uuid;

struct Capture(Mutex<Vec<String>>);

impl Log for Capture {
    fn enabled(&self, _: &Metadata) -> bool {
        true
    }

    fn log(&self, record: &Record) {
        // The test's own WebSocket client is not the relay.
        let target = record.target();
        if target.starts_with("tungstenite") || target.starts_with("tokio_tungstenite") {
            return;
        }
        let line = format!("{} {} {}", record.level(), target, record.args());
        self.0.lock().unwrap().push(line);
    }

    fn flush(&self) {}
}

static CAPTURE: Capture = Capture(Mutex::new(Vec::new()));

#[actix_web::test]
#[ignore = "needs PostgreSQL + Redis (docker compose)"]
async fn relay_logs_carry_no_content_or_identifiers() {
    log::set_logger(&CAPTURE).unwrap();
    log::set_max_level(LevelFilter::Trace);

    let relay = Relay::start(test_settings()).await;
    let app = actix_web::test::init_service(
        App::new()
            .app_data(relay.state.clone())
            .wrap(Compat::new(access_log()))
            .configure(configure),
    )
    .await;
    let android = enroll(&app, "android").await;
    let mac = enroll(&app, "macos").await;
    let iphone = enroll(&app, "ios").await;
    let stranger = enroll(&app, "android").await;
    let pair_id = pair(&app, &android, &mac).await;
    pair(&app, &android, &iphone).await;
    let marker = format!("MARKER{}", Uuid::new_v4().simple());
    let hex_marker = format!("feedface{}", Uuid::new_v4().simple());

    let push = json!({"provider": "apns", "token": hex_marker, "topic": "app.handlive.ios"});
    let (status, _) = call(
        &app,
        "PUT",
        "/v1/devices/me/push-token",
        &iphone.token,
        Some(&push),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let mut android_ws = connect(&relay, &android).await;
    android_ws.recv_json().await;
    android_ws.recv_json().await;
    let mut mac_ws = connect(&relay, &mac).await;
    assert_eq!(
        mac_ws.recv_json().await,
        presence(pair_id, android.id(), true)
    );
    android_ws.recv_json().await;

    let env = json!({"v":1,"type":"sms","id":Uuid::new_v4(),"ts":1,"payload":marker,"note":marker});
    mac_ws
        .send_json(&json!({"to": android.id(), "env": env}))
        .await;
    android_ws.recv_json().await;
    let mut frame = vec![0x48, 0x52, 0x01, 0x01];
    frame.extend_from_slice(android.id().as_bytes());
    frame.extend_from_slice(marker.as_bytes());
    mac_ws.send_binary(frame).await;
    android_ws.recv_binary().await;
    // Refused frames are not logged either.
    mac_ws
        .send_json(&json!({"to": stranger.id(), "env": env}))
        .await;
    mac_ws.recv_json().await;
    mac_ws.send_text(format!("{{broken {marker}")).await;
    mac_ws.recv_json().await;
    // Rendezvous traffic.
    let rv_id = relay_server::b64u::encode(Uuid::new_v4().as_bytes());
    let pair_env = json!({"v":1,"type":"pair","id":Uuid::new_v4(),"ts":1,"payload":marker});
    mac_ws
        .send_json(&json!({"op":"rv_join","rv_id":rv_id}))
        .await;
    mac_ws.recv_json().await;
    android_ws
        .send_json(&json!({"op":"rv_join","rv_id":rv_id}))
        .await;
    android_ws.recv_json().await;
    mac_ws.recv_json().await;
    mac_ws
        .send_json(&json!({"op":"rv_msg","rv_id":rv_id,"env":pair_env}))
        .await;
    android_ws.recv_json().await;
    // Removal with a query string.
    let (status, _) = call(
        &app,
        "DELETE",
        "/v1/devices/me?revoke_pairs=true",
        &mac.token,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    mac_ws.expect_close().await;
    android_ws.recv_json().await;
    relay.stop().await;
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    let lines = CAPTURE.0.lock().unwrap().clone();
    let forbidden: Vec<String> = [
        marker.clone(),
        hex_marker.clone(),
        rv_id.clone(),
        "revoke_pairs".to_owned(),
        android.token.clone(),
        mac.token.clone(),
        iphone.token.clone(),
    ]
    .into_iter()
    .chain(
        [&android, &mac, &iphone, &stranger]
            .iter()
            .flat_map(|m| [m.id().to_string(), m.id().simple().to_string()]),
    )
    .collect();
    for line in &lines {
        for bad in &forbidden {
            assert!(!line.contains(bad.as_str()), "log line leaks data: {line}");
        }
    }
    let access = |path: &str| lines.iter().any(|l| l.contains(path));
    assert!(
        access("/v1/relay 101"),
        "no access log for the relay upgrade: {lines:#?}"
    );
    assert!(
        access("/v1/pairs 201"),
        "no access log for pair registration"
    );
    assert!(
        access("/v1/devices/me 204"),
        "no access log for the removal"
    );
}
