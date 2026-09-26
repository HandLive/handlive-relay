//! Two relay instances sharing PostgreSQL and Redis (decision C5): devices
//! on different instances reach each other through `dev:<device_id>`
//! pub/sub, see each other's presence, get revocations made on the other
//! instance, and a reconnect to the other instance replaces the old
//! connection.
//!
//! Ignored by default; needs PostgreSQL + Redis (see relay/README.md).

mod common;

use std::time::Duration;

use actix_web::http::StatusCode;
use common::relay_harness::{
    Relay, call, connect, enroll, envelope, pair, presence, rest, test_settings,
};
use redis::AsyncCommands;
use relay_server::relay::presence::presence_key;
use serde_json::json;

fn hr_frame(to: &uuid::Uuid, hl: &[u8]) -> Vec<u8> {
    let mut frame = vec![0x48, 0x52, 0x01, 0x01];
    frame.extend_from_slice(to.as_bytes());
    frame.extend_from_slice(hl);
    frame
}

#[actix_web::test]
#[ignore = "needs PostgreSQL + Redis (docker compose)"]
async fn devices_on_two_instances_reach_each_other() {
    let one = Relay::start(test_settings()).await;
    let two = Relay::start(test_settings()).await;
    assert_ne!(
        one.state.settings.instance_id,
        two.state.settings.instance_id
    );
    let app_one = rest!(one);
    let app_two = rest!(two);
    let android = enroll(&app_one, "android").await;
    let mac = enroll(&app_two, "macos").await;
    let pair_id = pair(&app_one, &android, &mac).await;

    let mut mac_ws = connect(&two, &mac).await;
    assert_eq!(
        mac_ws.recv_json().await,
        presence(pair_id, android.id(), false)
    );
    let mut android_ws = connect(&one, &android).await;
    assert_eq!(
        android_ws.recv_json().await,
        presence(pair_id, mac.id(), true)
    );
    assert_eq!(
        mac_ws.recv_json().await,
        presence(pair_id, android.id(), true)
    );
    let mut redis = one.state.redis.clone();
    let holder: Option<String> = redis.get(presence_key(&mac.id())).await.unwrap();
    assert_eq!(
        holder.as_deref(),
        Some(two.state.settings.instance_id.as_str())
    );

    let env = envelope("sms", "YWNyb3NzIGluc3RhbmNlcw==");
    mac_ws
        .send_json(&json!({"to": android.id(), "env": env}))
        .await;
    assert_eq!(
        android_ws.recv_json().await,
        json!({"from": mac.id(), "env": env})
    );
    let back = envelope("ack", "b2s=");
    android_ws
        .send_json(&json!({"to": mac.id(), "env": back}))
        .await;
    assert_eq!(
        mac_ws.recv_json().await,
        json!({"from": android.id(), "env": back})
    );
    let hl = [0x48, 0x4C, 0x01, 0, 0, 0, 0, 0, 0, 0, 5, 1, 2, 3];
    android_ws.send_binary(hr_frame(&mac.id(), &hl)).await;
    assert_eq!(mac_ws.recv_binary().await, hr_frame(&android.id(), &hl));

    // The pair list served by either instance sees the peer online.
    let (status, body) = call(&app_two, "GET", "/v1/pairs", &mac.token, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["pairs"][0]["peer_online"], true);

    // Revoked through instance one, the Mac on instance two is told.
    let path = format!("/v1/pairs/{pair_id}/revoke");
    let (status, _) = call(
        &app_one,
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
    mac_ws
        .send_json(&json!({"to": android.id(), "env": envelope("sms", "eA==")}))
        .await;
    assert_eq!(mac_ws.recv_json().await["code"], "NOT_PAIRED");
    one.stop().await;
    two.stop().await;
}

#[actix_web::test]
#[ignore = "needs PostgreSQL + Redis (docker compose)"]
async fn reconnecting_to_another_instance_replaces_the_old_connection() {
    let one = Relay::start(test_settings()).await;
    let two = Relay::start(test_settings()).await;
    let app = rest!(one);
    let android = enroll(&app, "android").await;
    let mac = enroll(&app, "macos").await;
    let pair_id = pair(&app, &android, &mac).await;
    let mut android_ws = connect(&one, &android).await;
    assert_eq!(
        android_ws.recv_json().await,
        presence(pair_id, mac.id(), false)
    );

    let mut old = connect(&one, &mac).await;
    assert_eq!(old.recv_json().await, presence(pair_id, android.id(), true));
    assert_eq!(
        android_ws.recv_json().await,
        presence(pair_id, mac.id(), true)
    );
    let mut new = connect(&two, &mac).await;
    assert_eq!(new.recv_json().await, presence(pair_id, android.id(), true));
    assert_eq!(old.expect_close().await, Some(4409));
    // Only "online" again, never "offline", and the presence belongs to two.
    assert_eq!(
        android_ws.recv_json().await,
        presence(pair_id, mac.id(), true)
    );
    android_ws.expect_quiet(Duration::from_millis(300)).await;
    let mut redis = one.state.redis.clone();
    let holder: Option<String> = redis.get(presence_key(&mac.id())).await.unwrap();
    assert_eq!(
        holder.as_deref(),
        Some(two.state.settings.instance_id.as_str())
    );

    let env = envelope("clipboard", "bmV3IGluc3RhbmNl");
    android_ws
        .send_json(&json!({"to": mac.id(), "env": env}))
        .await;
    assert_eq!(
        new.recv_json().await,
        json!({"from": android.id(), "env": env})
    );

    // Leaving from instance two is announced once.
    new.close().await;
    assert_eq!(
        android_ws.recv_json().await,
        presence(pair_id, mac.id(), false)
    );
    android_ws
        .send_json(&json!({"to": mac.id(), "env": envelope("sms", "eA==")}))
        .await;
    assert_eq!(android_ws.recv_json().await["code"], "NOT_CONNECTED");
    one.stop().await;
    two.stop().await;
}
