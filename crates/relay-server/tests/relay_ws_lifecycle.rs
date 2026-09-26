//! Lifecycle of `/v1/relay` connections: upgrade refusals, replacement
//! (4409), idle close (4411), pairs registered or revoked while connected,
//! `pair_revoked` replay on reconnect and `DELETE /v1/devices/me` (C16).
//!
//! Ignored by default; needs PostgreSQL + Redis (see relay/README.md).

mod common;

use std::time::Duration;

use actix_web::http::StatusCode;
use common::http_harness::TEST_JWT_SECRET;
use common::relay_harness::{
    Relay, call, connect, enroll, envelope, pair, presence, rest, test_settings, try_connect,
};
use redis::AsyncCommands;
use relay_server::clock::now_ms;
use relay_server::jwt::JwtKeys;
use relay_server::relay::presence::{presence_key, revoked_notice_key};
use serde_json::json;

#[actix_web::test]
#[ignore = "needs PostgreSQL + Redis (docker compose)"]
async fn upgrade_is_refused_without_a_valid_token() {
    let relay = Relay::start(test_settings()).await;
    let app = rest!(relay);
    let mac = enroll(&app, "macos").await;

    let (status, body) = try_connect(&relay, "not-a-jwt").await.err().unwrap();
    assert_eq!(
        (status, body["error"]["code"].as_str()),
        (401, Some("SIGNATURE_INVALID"))
    );
    let keys = JwtKeys::from_secret(TEST_JWT_SECRET.as_bytes()).unwrap();
    let (expired, _) = keys.issue(&mac.id(), now_ms() / 1000 - 901).unwrap();
    let (status, body) = try_connect(&relay, &expired).await.err().unwrap();
    assert_eq!(
        (status, body["error"]["code"].as_str()),
        (401, Some("TOKEN_EXPIRED"))
    );
    // The device removed itself: its still-valid JWT no longer opens the relay.
    let (status, _) = call(
        &app,
        "DELETE",
        "/v1/devices/me?revoke_pairs=false",
        &mac.token,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, body) = try_connect(&relay, &mac.token).await.err().unwrap();
    assert_eq!(
        (status, body["error"]["code"].as_str()),
        (404, Some("DEVICE_NOT_FOUND"))
    );
    relay.stop().await;
}

#[actix_web::test]
#[ignore = "needs PostgreSQL + Redis (docker compose)"]
async fn a_new_connection_replaces_the_old_one() {
    let relay = Relay::start(test_settings()).await;
    let app = rest!(relay);
    let android = enroll(&app, "android").await;
    let mac = enroll(&app, "macos").await;
    let pair_id = pair(&app, &android, &mac).await;
    let mut android_ws = connect(&relay, &android).await;
    assert_eq!(
        android_ws.recv_json().await,
        presence(pair_id, mac.id(), false)
    );

    let mut first = connect(&relay, &mac).await;
    assert_eq!(
        first.recv_json().await,
        presence(pair_id, android.id(), true)
    );
    assert_eq!(
        android_ws.recv_json().await,
        presence(pair_id, mac.id(), true)
    );
    let mut second = connect(&relay, &mac).await;
    assert_eq!(
        second.recv_json().await,
        presence(pair_id, android.id(), true)
    );
    assert_eq!(first.expect_close().await, Some(4409));
    // The phone sees the Mac online again, never offline.
    assert_eq!(
        android_ws.recv_json().await,
        presence(pair_id, mac.id(), true)
    );
    android_ws.expect_quiet(Duration::from_millis(300)).await;

    let env = envelope("sms", "dG8gc2Vjb25k");
    android_ws
        .send_json(&json!({"to": mac.id(), "env": env}))
        .await;
    assert_eq!(
        second.recv_json().await,
        json!({"from": android.id(), "env": env})
    );
    let mut redis = relay.state.redis.clone();
    let holder: Option<String> = redis.get(presence_key(&mac.id())).await.unwrap();
    assert_eq!(
        holder.as_deref(),
        Some(relay.state.settings.instance_id.as_str())
    );
    relay.stop().await;
}

#[actix_web::test]
#[ignore = "needs PostgreSQL + Redis (docker compose)"]
async fn a_silent_connection_is_closed_as_idle() {
    let mut settings = test_settings();
    settings.ping_interval = Duration::from_millis(100);
    settings.idle_timeout = Duration::from_millis(400);
    let relay = Relay::start(settings).await;
    let app = rest!(relay);
    let mac = enroll(&app, "macos").await;
    let mut ws = connect(&relay, &mac).await;
    // Not reading means not answering the relay's pings.
    tokio::time::sleep(Duration::from_millis(900)).await;
    assert_eq!(ws.expect_close().await, Some(4411));
    // Presence is released with the connection.
    let mut redis = relay.state.redis.clone();
    for _ in 0..50 {
        let present: bool = redis.exists(presence_key(&mac.id())).await.unwrap();
        if !present {
            relay.stop().await;
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("presence still set after the idle close");
}

#[actix_web::test]
#[ignore = "needs PostgreSQL + Redis (docker compose)"]
async fn pairs_registered_and_revoked_while_connected() {
    let relay = Relay::start(test_settings()).await;
    let app = rest!(relay);
    let android = enroll(&app, "android").await;
    let mac = enroll(&app, "macos").await;
    let mut android_ws = connect(&relay, &android).await;
    let mut mac_ws = connect(&relay, &mac).await;
    mac_ws
        .send_json(&json!({"to": android.id(), "env": envelope("sms", "eA==")}))
        .await;
    assert_eq!(mac_ws.recv_json().await["code"], "NOT_PAIRED");

    // Registered while both are connected: presence arrives, routing starts.
    let pair_id = pair(&app, &android, &mac).await;
    assert_eq!(
        android_ws.recv_json().await,
        presence(pair_id, mac.id(), true)
    );
    assert_eq!(
        mac_ws.recv_json().await,
        presence(pair_id, android.id(), true)
    );
    let env = envelope("session", "aGVsbG8=");
    mac_ws
        .send_json(&json!({"to": android.id(), "env": env}))
        .await;
    assert_eq!(
        android_ws.recv_json().await,
        json!({"from": mac.id(), "env": env})
    );

    // Revoked by the phone: the Mac is told at once, routing stops both ways.
    let path = format!("/v1/pairs/{pair_id}/revoke");
    let (status, _) = call(
        &app,
        "POST",
        &path,
        &android.token,
        Some(&json!({"reason": "user"})),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert_eq!(
        mac_ws.recv_json().await,
        json!({"op": "pair_revoked", "pair_id": pair_id, "by": android.id()})
    );
    android_ws.expect_quiet(Duration::from_millis(300)).await;
    mac_ws
        .send_json(&json!({"to": android.id(), "env": envelope("sms", "eA==")}))
        .await;
    assert_eq!(mac_ws.recv_json().await["code"], "NOT_PAIRED");
    android_ws
        .send_json(&json!({"to": mac.id(), "env": envelope("sms", "eA==")}))
        .await;
    assert_eq!(android_ws.recv_json().await["code"], "NOT_PAIRED");

    // A reconnect replays the revocation (30 days) and no presence for it.
    mac_ws.close().await;
    let mut again = connect(&relay, &mac).await;
    assert_eq!(
        again.recv_json().await,
        json!({"op": "pair_revoked", "pair_id": pair_id, "by": android.id()})
    );
    again.expect_quiet(Duration::from_millis(300)).await;
    relay.stop().await;
}

#[actix_web::test]
#[ignore = "needs PostgreSQL + Redis (docker compose)"]
async fn removing_a_device_silently_keeps_peers_uninformed() {
    let relay = Relay::start(test_settings()).await;
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

    let (status, _) = call(
        &app,
        "DELETE",
        "/v1/devices/me?revoke_pairs=false",
        &mac.token,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert_eq!(mac_ws.expect_close().await, Some(1000));
    // No pair_revoked and no notice for the phone (C16); the pair is gone.
    android_ws.expect_quiet(Duration::from_millis(300)).await;
    android_ws
        .send_json(&json!({"to": mac.id(), "env": envelope("sms", "eA==")}))
        .await;
    assert_eq!(android_ws.recv_json().await["code"], "NOT_PAIRED");
    let mut redis = relay.state.redis.clone();
    let notices: bool = redis
        .exists(revoked_notice_key(&android.id()))
        .await
        .unwrap();
    assert!(!notices);
    let (status, body) = call(&app, "GET", "/v1/pairs", &android.token, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["pairs"], json!([]));
    relay.stop().await;
}

#[actix_web::test]
#[ignore = "needs PostgreSQL + Redis (docker compose)"]
async fn deleting_all_data_revokes_pairs_now_and_on_reconnect() {
    let relay = Relay::start(test_settings()).await;
    let app = rest!(relay);
    let android = enroll(&app, "android").await;
    let mac = enroll(&app, "macos").await;
    let iphone = enroll(&app, "ios").await;
    let pair_mac = pair(&app, &android, &mac).await;
    let pair_iphone = pair(&app, &android, &iphone).await;
    let mut mac_ws = connect(&relay, &mac).await;
    assert_eq!(
        mac_ws.recv_json().await,
        presence(pair_mac, android.id(), false)
    );
    let mut android_ws = connect(&relay, &android).await;
    android_ws.recv_json().await;
    android_ws.recv_json().await;
    assert_eq!(
        mac_ws.recv_json().await,
        presence(pair_mac, android.id(), true)
    );

    let (status, _) = call(
        &app,
        "DELETE",
        "/v1/devices/me?revoke_pairs=true",
        &android.token,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert_eq!(android_ws.expect_close().await, Some(1000));
    // Online peer: told right away.
    assert_eq!(
        mac_ws.recv_json().await,
        json!({"op": "pair_revoked", "pair_id": pair_mac, "by": android.id()})
    );
    // Offline peer: told when it connects, then the notice is gone.
    let mut iphone_ws = connect(&relay, &iphone).await;
    assert_eq!(
        iphone_ws.recv_json().await,
        json!({"op": "pair_revoked", "pair_id": pair_iphone, "by": android.id()})
    );
    iphone_ws.expect_quiet(Duration::from_millis(200)).await;
    iphone_ws.close().await;
    let mut iphone_ws = connect(&relay, &iphone).await;
    iphone_ws.expect_quiet(Duration::from_millis(300)).await;

    // Repeating the call with the old token is still 204.
    let (status, _) = call(
        &app,
        "DELETE",
        "/v1/devices/me?revoke_pairs=true",
        &android.token,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    relay.stop().await;
}
