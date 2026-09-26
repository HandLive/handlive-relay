//! `/v1/relay` forwarding with real WebSocket clients (CONN-03 API 4–6):
//! both frame kinds, presence, the error ops and a phone with two clients.
//!
//! Ignored by default; needs PostgreSQL + Redis (see relay/README.md).

mod common;

use std::collections::HashSet;
use std::time::Duration;

use common::relay_harness::{
    Ending, Relay, connect, enroll, envelope, pair, presence, rest, test_settings,
};
use serde_json::{Value, json};
use tokio_tungstenite::tungstenite::Message;
use uuid::Uuid;

fn hr_frame(to: &Uuid, hl: &[u8]) -> Vec<u8> {
    let mut frame = vec![0x48, 0x52, 0x01, 0x01];
    frame.extend_from_slice(to.as_bytes());
    frame.extend_from_slice(hl);
    frame
}

#[actix_web::test]
#[ignore = "needs PostgreSQL + Redis (docker compose)"]
async fn text_and_binary_frames_reach_the_paired_peer() {
    let relay = Relay::start(test_settings()).await;
    let app = rest!(relay);
    let android = enroll(&app, "android").await;
    let mac = enroll(&app, "macos").await;
    let pair_id = pair(&app, &android, &mac).await;

    let mut mac_ws = connect(&relay, &mac).await;
    assert_eq!(
        mac_ws.recv_json().await,
        presence(pair_id, android.id(), false)
    );
    let mut android_ws = connect(&relay, &android).await;
    assert_eq!(
        android_ws.recv_json().await,
        presence(pair_id, mac.id(), true)
    );
    assert_eq!(
        mac_ws.recv_json().await,
        presence(pair_id, android.id(), true)
    );

    // The envelope arrives byte for byte, wrapped in `from`.
    let env = r#"{"v":1, "type":"sms","id":"0192f4b2-5c6d-7e8f-9a0b-1c2d3e4f5a6b","ts":1727151200000,"payload":"c2VjcmV0+"}"#;
    mac_ws
        .send_text(format!(r#"{{"to":"{}","env":{env}}}"#, android.id()))
        .await;
    assert_eq!(
        android_ws.recv_text().await,
        format!(r#"{{"from":"{}","env":{env}}}"#, mac.id())
    );
    let reply = envelope("ack", "cmVwbHk=");
    android_ws
        .send_json(&json!({"to": mac.id(), "env": reply}))
        .await;
    assert_eq!(
        mac_ws.recv_json().await,
        json!({"from": android.id(), "env": reply})
    );

    // HR frame: destination swapped for the source, the HL frame untouched.
    let hl: Vec<u8> = [
        &[0x48, 0x4C, 0x01, 0, 0, 0, 1, 0, 0, 0, 20][..],
        &[7u8; 60][..],
    ]
    .concat();
    mac_ws.send_binary(hr_frame(&android.id(), &hl)).await;
    assert_eq!(android_ws.recv_binary().await, hr_frame(&mac.id(), &hl));
    android_ws.send_binary(hr_frame(&mac.id(), &hl)).await;
    assert_eq!(mac_ws.recv_binary().await, hr_frame(&android.id(), &hl));

    // The peer leaving is announced.
    android_ws.close().await;
    assert_eq!(
        mac_ws.recv_json().await,
        presence(pair_id, android.id(), false)
    );
    relay.stop().await;
}

fn error(code: &str, to: Option<&Uuid>) -> Value {
    let mut v = json!({"op": "error", "code": code});
    if let Some(to) = to {
        v["to"] = json!(to);
    }
    v
}

/// Compare an `error` op without its free-text `message`.
fn without_message(mut v: Value) -> Value {
    assert!(v["message"].is_string(), "{v}");
    v.as_object_mut().unwrap().remove("message");
    v
}

#[actix_web::test]
#[ignore = "needs PostgreSQL + Redis (docker compose)"]
async fn unpaired_offline_and_malformed_frames_get_errors() {
    let relay = Relay::start(test_settings()).await;
    let app = rest!(relay);
    let android = enroll(&app, "android").await;
    let mac = enroll(&app, "macos").await;
    let stranger = enroll(&app, "android").await;
    let pair_id = pair(&app, &android, &mac).await;
    let mut mac_ws = connect(&relay, &mac).await;
    assert_eq!(
        mac_ws.recv_json().await,
        presence(pair_id, android.id(), false)
    );
    let a = android.id();
    let s = stranger.id();

    mac_ws
        .send_json(&json!({"to": s, "env": envelope("sms", "eA==")}))
        .await;
    assert_eq!(
        without_message(mac_ws.recv_json().await),
        error("NOT_PAIRED", Some(&s))
    );
    mac_ws
        .send_json(&json!({"to": a, "env": envelope("sms", "eA==")}))
        .await;
    assert_eq!(
        without_message(mac_ws.recv_json().await),
        error("NOT_CONNECTED", Some(&a))
    );
    mac_ws.send_text("{not json".to_owned()).await;
    assert_eq!(
        without_message(mac_ws.recv_json().await),
        error("BAD_REQUEST", None)
    );
    mac_ws.send_json(&json!({"to": a, "env": [1, 2]})).await;
    assert_eq!(
        without_message(mac_ws.recv_json().await),
        error("BAD_REQUEST", Some(&a))
    );
    mac_ws.send_json(&json!({"to": a})).await;
    assert_eq!(
        without_message(mac_ws.recv_json().await),
        error("BAD_REQUEST", Some(&a))
    );
    mac_ws.send_json(&json!({"op": "subscribe"})).await;
    assert_eq!(
        without_message(mac_ws.recv_json().await),
        error("BAD_REQUEST", None)
    );

    // Over 256 KiB: refused, the connection stays usable.
    let big = "A".repeat(256 * 1024);
    mac_ws
        .send_json(&json!({"to": a, "env": envelope("clipboard", &big)}))
        .await;
    assert_eq!(
        without_message(mac_ws.recv_json().await),
        error("PAYLOAD_TOO_LARGE", Some(&a))
    );
    mac_ws.send_binary(hr_frame(&a, &vec![0; 256 * 1024])).await;
    assert_eq!(
        without_message(mac_ws.recv_json().await),
        error("PAYLOAD_TOO_LARGE", Some(&a))
    );
    mac_ws.send_binary(vec![0x48, 0x4C, 1, 1, 0, 0]).await;
    assert_eq!(
        without_message(mac_ws.recv_json().await),
        error("BAD_REQUEST", None)
    );
    // Just under the limit is fine (peer offline → NOT_CONNECTED, not a size error).
    let fits = "A".repeat(200 * 1024);
    mac_ws
        .send_json(&json!({"to": a, "env": envelope("clipboard", &fits)}))
        .await;
    assert_eq!(
        without_message(mac_ws.recv_json().await),
        error("NOT_CONNECTED", Some(&a))
    );

    // Beyond the decoder limit (1 MiB) the relay closes with 4400. It stops
    // reading the oversized frame, so the close frame can be lost to a TCP
    // reset while the client is still sending; the connection must end.
    mac_ws
        .send_binary(hr_frame(&a, &vec![0; 1024 * 1024 + 1]))
        .await;
    let ending = mac_ws.expect_end().await;
    assert!(
        matches!(ending, Ending::Code(4400) | Ending::Dropped),
        "{ending:?}"
    );
    relay.stop().await;
}

#[actix_web::test]
#[ignore = "needs PostgreSQL + Redis (docker compose)"]
async fn phone_routes_to_each_of_its_clients_only() {
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
    let mut iphone_ws = connect(&relay, &iphone).await;
    assert_eq!(
        iphone_ws.recv_json().await,
        presence(pair_iphone, android.id(), false)
    );
    let mut android_ws = connect(&relay, &android).await;
    let opening: HashSet<String> = [android_ws.recv_json().await, android_ws.recv_json().await]
        .iter()
        .map(Value::to_string)
        .collect();
    let expected: HashSet<String> = [
        presence(pair_mac, mac.id(), true),
        presence(pair_iphone, iphone.id(), true),
    ]
    .iter()
    .map(Value::to_string)
    .collect();
    assert_eq!(opening, expected);
    assert_eq!(
        mac_ws.recv_json().await,
        presence(pair_mac, android.id(), true)
    );
    assert_eq!(
        iphone_ws.recv_json().await,
        presence(pair_iphone, android.id(), true)
    );

    for (ws, from) in [(&mut mac_ws, mac.id()), (&mut iphone_ws, iphone.id())] {
        let env = envelope("clipboard", &from.to_string());
        ws.send_json(&json!({"to": android.id(), "env": env})).await;
        assert_eq!(
            android_ws.recv_json().await,
            json!({"from": from, "env": env})
        );
    }
    let to_mac = envelope("sms", "bWFj");
    android_ws
        .send_json(&json!({"to": mac.id(), "env": to_mac}))
        .await;
    let to_iphone = envelope("sms", "aXBob25l");
    android_ws
        .send_json(&json!({"to": iphone.id(), "env": to_iphone}))
        .await;
    assert_eq!(
        mac_ws.recv_json().await,
        json!({"from": android.id(), "env": to_mac})
    );
    assert_eq!(
        iphone_ws.recv_json().await,
        json!({"from": android.id(), "env": to_iphone})
    );

    // Two clients of the same phone are not paired with each other.
    mac_ws
        .send_json(&json!({"to": iphone.id(), "env": envelope("sms", "eA==")}))
        .await;
    let err = mac_ws.recv_json().await;
    assert_eq!(
        (err["code"].as_str(), err["to"].as_str()),
        (Some("NOT_PAIRED"), Some(iphone.id().to_string().as_str()))
    );
    iphone_ws.expect_quiet(Duration::from_millis(300)).await;
    relay.stop().await;
}

#[actix_web::test]
#[ignore = "needs PostgreSQL + Redis (docker compose)"]
async fn frames_keep_their_order() {
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

    for i in 0..200 {
        if i % 2 == 0 {
            mac_ws
                .send_json(
                    &json!({"to": android.id(), "env": envelope("clipboard", &i.to_string())}),
                )
                .await;
        } else {
            mac_ws
                .send_binary(hr_frame(&android.id(), &(i as u32).to_be_bytes()))
                .await;
        }
    }
    for i in 0..200u32 {
        match android_ws.next(common::relay_harness::WAIT).await {
            Some(Message::Text(t)) => {
                let v: Value = serde_json::from_str(&t).unwrap();
                assert_eq!(v["env"]["payload"], i.to_string());
            }
            Some(Message::Binary(b)) => assert_eq!(&b[20..], &i.to_be_bytes()),
            other => panic!("frame {i}: {other:?}"),
        }
    }
    relay.stop().await;
}
