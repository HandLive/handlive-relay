//! Pairing rendezvous over the relay (PAIR-01 API 7): `rv_join`,
//! `rv_joined`, `rv_msg` between two devices that are not paired yet, with
//! the real pairing envelopes of `shared/test-vectors/pair-handshake.json`.
//!
//! Ignored by default; needs PostgreSQL + Redis (see relay/README.md).

mod common;

use std::time::Duration;

use common::load_vectors;
use common::relay_harness::{Relay, connect, enroll, rest, test_settings};
use redis::AsyncCommands;
use relay_server::b64u;
use relay_server::relay::rendezvous::rv_key;
use serde_json::{Value, json};

fn vector_envelopes() -> (Value, Value, Value) {
    let doc = load_vectors("pair-handshake.json");
    let vectors = doc["vectors"].as_array().unwrap();
    let qr = vectors.iter().find(|v| v["mode"] == "qr").unwrap();
    let pin = vectors.iter().find(|v| v["mode"] == "pin").unwrap();
    let parse = |s: &Value| serde_json::from_str::<Value>(s.as_str().unwrap()).unwrap();
    (
        parse(&qr["hello_envelope"]),
        parse(&qr["offer_envelope"]),
        parse(&pin["hello_envelope"]),
    )
}

fn fresh_rv_id() -> String {
    b64u::encode(uuid::Uuid::new_v4().as_bytes())
}

#[actix_web::test]
#[ignore = "needs PostgreSQL + Redis (docker compose)"]
async fn two_unpaired_devices_exchange_pair_envelopes() {
    let relay = Relay::start(test_settings()).await;
    let app = rest!(relay);
    let mac = enroll(&app, "macos").await;
    let android = enroll(&app, "android").await;
    let mut mac_ws = connect(&relay, &mac).await;
    let mut android_ws = connect(&relay, &android).await;
    let rv_id = fresh_rv_id();
    let (hello, offer, _) = vector_envelopes();

    // The Mac shows the QR code and waits; the phone scans and joins.
    mac_ws
        .send_json(&json!({"op": "rv_join", "rv_id": rv_id}))
        .await;
    assert_eq!(
        mac_ws.recv_json().await,
        json!({"op": "rv_joined", "rv_id": rv_id, "peer_present": false})
    );
    let mut redis = relay.state.redis.clone();
    let ttl: i64 = redis.ttl(rv_key(&rv_id)).await.unwrap();
    assert!((170..=180).contains(&ttl), "{ttl}");
    android_ws
        .send_json(&json!({"op": "rv_join", "rv_id": rv_id}))
        .await;
    let joined = json!({"op": "rv_joined", "rv_id": rv_id, "peer_present": true});
    assert_eq!(android_ws.recv_json().await, joined);
    assert_eq!(mac_ws.recv_json().await, joined);
    // The second join does not extend the rendezvous.
    let ttl_after: i64 = redis.ttl(rv_key(&rv_id)).await.unwrap();
    assert!(ttl_after <= ttl);

    mac_ws
        .send_json(&json!({"op": "rv_msg", "rv_id": rv_id, "env": hello}))
        .await;
    assert_eq!(
        android_ws.recv_json().await,
        json!({"op": "rv_msg", "rv_id": rv_id, "env": hello})
    );
    android_ws
        .send_json(&json!({"op": "rv_msg", "rv_id": rv_id, "env": offer}))
        .await;
    assert_eq!(
        mac_ws.recv_json().await,
        json!({"op": "rv_msg", "rv_id": rv_id, "env": offer})
    );

    // Joining again (e.g. after a reconnect) tells only the joiner.
    mac_ws
        .send_json(&json!({"op": "rv_join", "rv_id": rv_id}))
        .await;
    assert_eq!(mac_ws.recv_json().await, joined);
    android_ws.expect_quiet(Duration::from_millis(300)).await;
    relay.stop().await;
}

#[actix_web::test]
#[ignore = "needs PostgreSQL + Redis (docker compose)"]
async fn rendezvous_refuses_what_pairing_does_not_allow() {
    let relay = Relay::start(test_settings()).await;
    let app = rest!(relay);
    let mac = enroll(&app, "macos").await;
    let android = enroll(&app, "android").await;
    let intruder = enroll(&app, "android").await;
    let mut mac_ws = connect(&relay, &mac).await;
    let mut android_ws = connect(&relay, &android).await;
    let mut intruder_ws = connect(&relay, &intruder).await;
    let rv_id = fresh_rv_id();
    let (hello, _, pin_hello) = vector_envelopes();
    let code = |v: Value| v["code"].as_str().unwrap().to_owned();

    // Before the peer joins there is nobody to forward to.
    mac_ws
        .send_json(&json!({"op": "rv_join", "rv_id": rv_id}))
        .await;
    mac_ws.recv_json().await;
    mac_ws
        .send_json(&json!({"op": "rv_msg", "rv_id": rv_id, "env": hello}))
        .await;
    assert_eq!(code(mac_ws.recv_json().await), "NOT_CONNECTED");

    android_ws
        .send_json(&json!({"op": "rv_join", "rv_id": rv_id}))
        .await;
    android_ws.recv_json().await;
    mac_ws.recv_json().await;
    // A third member is refused and learns nothing.
    intruder_ws
        .send_json(&json!({"op": "rv_join", "rv_id": rv_id}))
        .await;
    assert_eq!(code(intruder_ws.recv_json().await), "BAD_REQUEST");
    intruder_ws
        .send_json(&json!({"op": "rv_msg", "rv_id": rv_id, "env": hello}))
        .await;
    assert_eq!(code(intruder_ws.recv_json().await), "BAD_REQUEST");

    // PIN pairing is LAN-only; only `pair` envelopes pass.
    mac_ws
        .send_json(&json!({"op": "rv_msg", "rv_id": rv_id, "env": pin_hello}))
        .await;
    assert_eq!(code(mac_ws.recv_json().await), "BAD_REQUEST");
    let mut sms = hello.clone();
    sms["type"] = json!("sms");
    mac_ws
        .send_json(&json!({"op": "rv_msg", "rv_id": rv_id, "env": sms}))
        .await;
    assert_eq!(code(mac_ws.recv_json().await), "BAD_REQUEST");
    for bad in [
        json!({"op": "rv_join", "rv_id": "short"}),
        json!({"op": "rv_join"}),
        json!({"op": "rv_msg", "rv_id": rv_id}),
        json!({"op": "rv_msg", "rv_id": rv_id, "env": "text"}),
    ] {
        mac_ws.send_json(&bad).await;
        assert_eq!(code(mac_ws.recv_json().await), "BAD_REQUEST", "{bad}");
    }
    android_ws.expect_quiet(Duration::from_millis(300)).await;

    // An expired rendezvous behaves like an unknown one.
    let mut redis = relay.state.redis.clone();
    let _: () = redis.del(rv_key(&rv_id)).await.unwrap();
    mac_ws
        .send_json(&json!({"op": "rv_msg", "rv_id": rv_id, "env": hello}))
        .await;
    assert_eq!(code(mac_ws.recv_json().await), "BAD_REQUEST");
    relay.stop().await;
}
