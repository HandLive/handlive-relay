//! Every REST body, relay control message and push body the relay emits in a
//! typical session, validated against the shared JSON Schemas
//! (`shared/schemas`: `relay-rest`, `relay-*`, `relay-wrapper`, `push`),
//! the APNs payloads of SMS and call pushes included.
//! The requests the tests send as devices are validated too, so the tests
//! speak the contract they check.
//!
//! Ignored by default; needs PostgreSQL + Redis (see relay/README.md).

mod common;

use actix_web::http::StatusCode;
use actix_web::{App, test, web};
use common::http_harness::{TEST_JWT_SECRET, post};
use common::push_mocks::{self, TOPIC};
use common::relay_harness::{Relay, call, connect, pair_body};
use common::schemas::Schemas;
use common::{TestDevice, load_vectors};
use relay_server::clock::now_ms;
use relay_server::config::{Config, RelaySettings};
use relay_server::state::AppState;
use relay_server::{MIGRATOR, b64u, configure};
use serde_json::{Value, json};
use uuid::Uuid;

/// A valid `sms` envelope and a `pair` envelope from the shared vectors.
fn vector_envelopes() -> (Value, Value) {
    let frames = load_vectors("relay-frame.json");
    let sms = frames["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["kind"] == "text_rewrite")
        .map(|v| serde_json::from_str(v["env"].as_str().unwrap()).unwrap())
        .unwrap();
    let pairing = load_vectors("pair-handshake.json");
    let hello =
        serde_json::from_str(pairing["vectors"][0]["hello_envelope"].as_str().unwrap()).unwrap();
    (sms, hello)
}

#[actix_web::test]
#[ignore = "needs PostgreSQL + Redis (docker compose)"]
async fn relay_output_matches_the_shared_schemas() {
    let schemas = Schemas::load();
    let providers = push_mocks::start().await;
    let config = Config {
        database_url: std::env::var("DATABASE_URL").unwrap(),
        redis_url: std::env::var("REDIS_URL").unwrap(),
        jwt_secret: TEST_JWT_SECRET.as_bytes().to_vec(),
        bind: String::new(),
        settings: RelaySettings {
            registrations_per_ip_per_hour: u64::MAX,
            ..RelaySettings::default()
        },
        push: providers.config.clone(),
    };
    let state = web::Data::new(AppState::connect(&config).await.unwrap());
    MIGRATOR.run(&state.db).await.unwrap();
    let app = test::init_service(App::new().app_data(state.clone()).configure(configure)).await;
    let mut errors: Vec<Value> = Vec::new();

    // Registration and authentication (CONN-03 API 1–3).
    let mut enroll = async |platform: &str| {
        let device = TestDevice::random();
        let body = device.registration_body(platform, now_ms());
        schemas.check("relay-rest#devices-request", &body);
        let (status, resp) = post(&app, "/v1/devices", &body).await;
        assert_eq!(status, StatusCode::CREATED);
        schemas.check("relay-rest#devices-response", &resp);
        let id = json!({"device_id": device.device_id});
        schemas.check("relay-rest#auth-challenge-request", &id);
        let (_, chal) = post(&app, "/v1/auth/challenge", &id).await;
        schemas.check("relay-rest#auth-challenge-response", &chal);
        let token_req = device.token_body(chal["challenge"].as_str().unwrap());
        schemas.check("relay-rest#auth-token-request", &token_req);
        let (_, tok) = post(&app, "/v1/auth/token", &token_req).await;
        schemas.check("relay-rest#auth-token-response", &tok);
        let (_, err) = post(&app, "/v1/auth/token", &token_req).await;
        errors.push(err);
        common::relay_harness::Member {
            device,
            token: tok["access_token"].as_str().unwrap().to_owned(),
        }
    };
    let android = enroll("android").await;
    let iphone = enroll("ios").await;
    let mac = enroll("macos").await;

    // Pairs (PAIR-01 API 8, PAIR-02 API 1, PAIR-03 API 3).
    let pair_iphone = Uuid::new_v4();
    let body = pair_body(pair_iphone, &android.device, &iphone.device, now_ms());
    schemas.check("relay-rest#pairs-request", &body);
    let (status, resp) = call(&app, "POST", "/v1/pairs", &iphone.token, Some(&body)).await;
    assert_eq!(status, StatusCode::CREATED);
    schemas.check("relay-rest#pairs-response", &resp);
    let (_, resp) = call(&app, "POST", "/v1/pairs", &android.token, Some(&body)).await;
    schemas.check("relay-rest#pairs-response", &resp);
    let pair_mac = Uuid::new_v4();
    let body = pair_body(pair_mac, &android.device, &mac.device, now_ms());
    call(&app, "POST", "/v1/pairs", &mac.token, Some(&body)).await;
    let changed = pair_body(pair_mac, &android.device, &mac.device, now_ms() + 1);
    errors.push(
        call(&app, "POST", "/v1/pairs", &mac.token, Some(&changed))
            .await
            .1,
    );

    // Push tokens and pushes (CONN-04 API 1–4).
    let apns = json!({"provider": "apns", "token": "abcdef0123", "topic": TOPIC});
    schemas.check("relay-rest#push-token-request", &apns);
    call(
        &app,
        "PUT",
        "/v1/devices/me/push-token",
        &iphone.token,
        Some(&apns),
    )
    .await;
    let fcm = json!({"provider": "fcm", "token": "fcm-token-1"});
    schemas.check("relay-rest#push-token-request", &fcm);
    call(
        &app,
        "PUT",
        "/v1/devices/me/push-token",
        &android.token,
        Some(&fcm),
    )
    .await;
    let push_vectors = load_vectors("push-envelope.json");
    let env_b64 = push_vectors["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .find_map(|v| v["env_b64"].as_str())
        .unwrap();
    let pushes = [
        json!({"pair_id": pair_iphone, "to": iphone.id(), "kind": "alert", "reason": "call_incoming",
               "env_b64": env_b64, "collapse_key": "call:0192f3f0-6a1b-7c2d-8e3f-4a5b6c7d8e90", "ttl_s": 30}),
        json!({"pair_id": pair_iphone, "to": iphone.id(), "kind": "alert", "reason": "sms_new",
               "env_b64": env_b64, "collapse_key": "sms:12847", "ttl_s": 86400}),
        json!({"pair_id": pair_iphone, "to": android.id(), "kind": "wake", "reason": "user_open"}),
    ];
    let senders = [&android, &android, &iphone];
    for (push, sender) in pushes.iter().zip(senders) {
        schemas.check("relay-rest#push-request", push);
        let (status, resp) = call(&app, "POST", "/v1/push", &sender.token, Some(push)).await;
        assert_eq!(status, StatusCode::ACCEPTED, "{resp}");
        schemas.check("relay-rest#push-response", &resp);
        if push["kind"] == "alert" {
            let (_, _, payload) = providers.apns.last();
            schemas.check("push#apns-payload", &payload);
        }
    }
    let (_, _, fcm_body) = providers.fcm.last();
    schemas.check("push#fcm-request", &fcm_body);
    errors.push(
        call(&app, "POST", "/v1/push", &mac.token, Some(&pushes[0]))
            .await
            .1,
    );

    // The relay channel (CONN-03 API 4–6, PAIR-01 API 7, PAIR-03 API 4).
    let relay = Relay::start(common::relay_harness::test_settings()).await;
    let (sms_env, pair_env) = vector_envelopes();
    let mut android_ws = connect(&relay, &android).await;
    let mut control: Vec<Value> = vec![android_ws.recv_json().await, android_ws.recv_json().await];
    let mut mac_ws = connect(&relay, &mac).await;
    control.push(mac_ws.recv_json().await);
    control.push(android_ws.recv_json().await);
    let outbound = json!({"to": android.id(), "env": sms_env});
    schemas.check("relay-wrapper", &outbound);
    schemas.check("relay-wrapper#outbound", &outbound);
    mac_ws.send_json(&outbound).await;
    let inbound = android_ws.recv_json().await;
    schemas.check("relay-wrapper", &inbound);
    schemas.check("relay-wrapper#inbound", &inbound);
    for bad in [
        json!({"to": iphone.id(), "env": sms_env}),
        json!({"to": Uuid::new_v4(), "env": sms_env}),
        json!({"op": "nope"}),
        json!({"to": android.id(), "env": {"v": 1, "type": "clipboard", "id": "0192f3e2-4b5d-7e6f-8a70-9b0c1d2e3f40",
               "ts": 1, "payload": "A".repeat(300 * 1024)}}),
    ] {
        mac_ws.send_json(&bad).await;
        control.push(mac_ws.recv_json().await);
    }
    let mut iphone_ws = connect(&relay, &iphone).await;
    control.push(iphone_ws.recv_json().await);
    control.push(android_ws.recv_json().await);
    iphone_ws.close().await;
    control.push(android_ws.recv_json().await);
    let rv_id = b64u::encode(Uuid::new_v4().as_bytes());
    let join = json!({"op": "rv_join", "rv_id": rv_id});
    schemas.check("relay-rv_join", &join);
    mac_ws.send_json(&join).await;
    control.push(mac_ws.recv_json().await);
    android_ws.send_json(&join).await;
    control.push(android_ws.recv_json().await);
    control.push(mac_ws.recv_json().await);
    let rv_msg = json!({"op": "rv_msg", "rv_id": rv_id, "env": pair_env});
    schemas.check("relay-rv_msg", &rv_msg);
    mac_ws.send_json(&rv_msg).await;
    control.push(android_ws.recv_json().await);
    let path = format!("/v1/pairs/{pair_mac}/revoke");
    let revoke = json!({"reason": "user"});
    schemas.check("relay-rest#pair-revoke-request", &revoke);
    call(&app, "POST", &path, &android.token, Some(&revoke)).await;
    control.push(mac_ws.recv_json().await);

    let mut ops = std::collections::BTreeSet::new();
    for msg in &control {
        let op = msg["op"]
            .as_str()
            .unwrap_or_else(|| panic!("not a control op: {msg}"));
        schemas.check(&format!("relay-{op}"), msg);
        ops.insert(op.to_owned());
    }
    let expected: std::collections::BTreeSet<String> =
        ["presence", "error", "rv_joined", "rv_msg", "pair_revoked"]
            .map(String::from)
            .into();
    assert_eq!(ops, expected);

    // Error bodies (0.8.2) and the pair list, last.
    let (_, list) = call(&app, "GET", "/v1/pairs", &android.token, None).await;
    schemas.check("relay-rest#pairs-list-response", &list);
    errors.push(
        call(
            &app,
            "GET",
            "/v1/pairs?include_revoked=x",
            &android.token,
            None,
        )
        .await
        .1,
    );
    errors.push(call(&app, "GET", "/v1/pairs", "garbage", None).await.1);
    errors.push(
        post(
            &app,
            "/v1/auth/challenge",
            &json!({"device_id": Uuid::new_v4()}),
        )
        .await
        .1,
    );
    assert!(errors.len() >= 6);
    for err in &errors {
        schemas.check("relay-rest#error-response", err);
    }
    relay.stop().await;
    providers.stop().await;
}
