//! Redis restart while devices are connected (phase 2 "Testing": relay
//! restart with Redis presence lost; CONN-02 E). A restart is simulated by
//! wiping the data (`FLUSHALL`) and dropping every client connection
//! (`CLIENT KILL`), which is what the relay observes when Redis restarts.
//! The relay must re-subscribe, restore presence and forward again without
//! the devices reconnecting.
//!
//! One test in its own binary: it flushes the Redis database, so it must
//! not share a run with other tests (cargo runs test binaries one by one).
//! Ignored by default; needs PostgreSQL + Redis (see relay/README.md).

mod common;

use std::time::Duration;

use common::relay_harness::{
    Relay, connect, enroll, envelope, pair, presence, rest, test_settings,
};
use redis::AsyncCommands;
use relay_server::relay::bus::device_channel;
use relay_server::relay::presence::presence_key;
use serde_json::{Value, json};
use tokio_tungstenite::tungstenite::Message;

#[actix_web::test]
#[ignore = "needs PostgreSQL + Redis (docker compose)"]
async fn relay_recovers_when_redis_loses_presence_and_connections() {
    let mut settings = test_settings();
    settings.presence_refresh = Duration::from_millis(300);
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

    let client = redis::Client::open(std::env::var("REDIS_URL").unwrap()).unwrap();
    let mut admin = client.get_multiplexed_async_connection().await.unwrap();
    let _: () = redis::cmd("FLUSHALL")
        .query_async(&mut admin)
        .await
        .unwrap();
    let killed: i64 = redis::cmd("CLIENT")
        .arg(&["KILL", "TYPE", "pubsub"])
        .query_async(&mut admin)
        .await
        .unwrap();
    assert!(killed >= 1, "no pub/sub connection to drop");
    let _: i64 = redis::cmd("CLIENT")
        .arg(&["KILL", "TYPE", "normal", "SKIPME", "yes"])
        .query_async(&mut admin)
        .await
        .unwrap();

    // Presence comes back without the devices doing anything.
    for id in [android.id(), mac.id()] {
        let mut restored = false;
        for _ in 0..100 {
            if admin.exists(presence_key(&id)).await.unwrap() {
                restored = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(restored, "presence not restored");
    }

    // The bus subscribed again on a new connection.
    for id in [android.id(), mac.id()] {
        let mut subscribed = false;
        for _ in 0..100 {
            let (_, count): (String, i64) = redis::cmd("PUBSUB")
                .arg("NUMSUB")
                .arg(device_channel(&id))
                .query_async(&mut admin)
                .await
                .unwrap();
            if count == 1 {
                subscribed = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(subscribed, "dev: channel not subscribed again");
    }

    // Forwarding resumes: frames sent while the bus reconnects may be
    // refused (NOT_CONNECTED, never silently lost), then they flow.
    let mut delivered = false;
    for attempt in 0..50 {
        let env = envelope("sms", &format!("attempt-{attempt}"));
        mac_ws
            .send_json(&json!({"to": android.id(), "env": env}))
            .await;
        if let Some(Message::Text(t)) = android_ws.next(Duration::from_millis(200)).await {
            let v: Value = serde_json::from_str(&t).unwrap();
            assert_eq!(v, json!({"from": mac.id(), "env": env}));
            delivered = true;
            break;
        }
        let refused = mac_ws.recv_json().await;
        assert!(refused["code"] == "NOT_CONNECTED", "{refused}");
    }
    assert!(delivered, "forwarding did not resume");
    for i in 0..20 {
        let env = envelope("sms", &format!("after-{i}"));
        android_ws
            .send_json(&json!({"to": mac.id(), "env": env}))
            .await;
        assert_eq!(
            mac_ws.recv_json().await,
            json!({"from": android.id(), "env": env})
        );
    }
    relay.stop().await;
}
