//! `POST /v1/push` (CONN-04 API 2) against real PostgreSQL 16 + Redis 7 and
//! mock APNs/FCM endpoints: pair and platform checks, missing and dead
//! tokens, wake coalescing, provider errors, limits and statistics; and the
//! APNs topic check of `PUT /v1/devices/me/push-token`.
//!
//! Ignored by default; needs PostgreSQL + Redis (see relay/README.md).

mod common;

use actix_web::http::StatusCode;
use actix_web::{App, test, web};
use common::http_harness::{TEST_JWT_SECRET, TestService, code};
use common::push_mocks::{self, TOPIC};
use common::relay_harness::{Member, call, enroll, pair_body};
use redis::AsyncCommands;
use relay_push::PushConfig;
use relay_server::challenge::minute_window;
use relay_server::clock::now_ms;
use relay_server::config::{Config, RelaySettings};
use relay_server::state::AppState;
use relay_server::store::challenges::rate_limit_key;
use relay_server::{MIGRATOR, configure};
use serde_json::{Value, json};
use uuid::Uuid;

async fn state_with(push: PushConfig) -> web::Data<AppState> {
    let config = Config {
        database_url: std::env::var("DATABASE_URL").unwrap(),
        redis_url: std::env::var("REDIS_URL").unwrap(),
        jwt_secret: TEST_JWT_SECRET.as_bytes().to_vec(),
        bind: String::new(),
        settings: RelaySettings::default(),
        push,
    };
    let state = AppState::connect(&config).await.unwrap();
    MIGRATOR.run(&state.db).await.unwrap();
    web::Data::new(state)
}

async fn set_token(app: &impl TestService, member: &Member, body: Value) {
    let (status, err) = call(
        app,
        "PUT",
        "/v1/devices/me/push-token",
        &member.token,
        Some(&body),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{err}");
}

async fn paired(app: &impl TestService, android: &Member, client: &Member) -> Uuid {
    let pair_id = Uuid::new_v4();
    let body = pair_body(pair_id, &android.device, &client.device, now_ms());
    let (status, _) = call(app, "POST", "/v1/pairs", &client.token, Some(&body)).await;
    assert_eq!(status, StatusCode::CREATED);
    pair_id
}

fn alert(pair_id: Uuid, to: Uuid, env: &str) -> Value {
    json!({"pair_id": pair_id, "to": to, "kind": "alert", "reason": "sms_new",
           "env_b64": env, "collapse_key": "sms:sms:12847", "ttl_s": 86400})
}

fn wake(pair_id: Uuid, to: Uuid, reason: &str) -> Value {
    json!({"pair_id": pair_id, "to": to, "kind": "wake", "reason": reason})
}

#[actix_web::test]
#[ignore = "needs PostgreSQL + Redis (docker compose)"]
async fn alerts_and_wakes_reach_the_providers() {
    let providers = push_mocks::start().await;
    let state = state_with(providers.config.clone()).await;
    let app = test::init_service(App::new().app_data(state.clone()).configure(configure)).await;
    let android = enroll(&app, "android").await;
    let iphone = enroll(&app, "ios").await;
    let pair_id = paired(&app, &android, &iphone).await;
    let apns_token = format!("aa{}", Uuid::new_v4().simple());
    set_token(
        &app,
        &iphone,
        json!({"provider": "apns", "token": apns_token, "topic": TOPIC}),
    )
    .await;
    let fcm_token = format!("fcm-{}", Uuid::new_v4().simple());
    set_token(
        &app,
        &android,
        json!({"provider": "fcm", "token": fcm_token}),
    )
    .await;

    // The phone alerts the suspended iPhone (SMS-02 step 10).
    let env = "ZW52ZWxvcGUgZW5jcnlwdGVkIHdpdGggS19wdXNo";
    let (status, body) = call(
        &app,
        "POST",
        "/v1/push",
        &android.token,
        Some(&alert(pair_id, iphone.id(), env)),
    )
    .await;
    assert_eq!(
        (status, body),
        (StatusCode::ACCEPTED, json!({"accepted": true}))
    );
    let (path, headers, payload) = providers.apns.last();
    assert_eq!(path, format!("/3/device/{apns_token}"));
    assert!(headers.contains(&("apns-collapse-id".to_owned(), "sms:sms:12847".to_owned())));
    assert!(headers.contains(&("apns-topic".to_owned(), TOPIC.to_owned())));
    assert_eq!(payload["aps"]["alert"], json!({"loc-key": "push.sms_new"}));
    assert_eq!(
        (payload["p"].clone(), payload["hl"].clone()),
        (json!(pair_id), json!(env))
    );

    // The iPhone wakes the phone; the same reason again within 5 minutes is
    // accepted but not sent, another reason is sent.
    for _ in 0..2 {
        let (status, _) = call(
            &app,
            "POST",
            "/v1/push",
            &iphone.token,
            Some(&wake(pair_id, android.id(), "sms_send")),
        )
        .await;
        assert_eq!(status, StatusCode::ACCEPTED);
    }
    assert_eq!(providers.fcm.count(), 1);
    let (_, _, message) = providers.fcm.last();
    assert_eq!(
        message,
        json!({"message":{"token":fcm_token,"data":{"t":"wake","p":pair_id,"r":"sms_send"},
               "android":{"priority":"HIGH","ttl":"60s","collapse_key":"wake"}}})
    );
    let (status, _) = call(
        &app,
        "POST",
        "/v1/push",
        &iphone.token,
        Some(&wake(pair_id, android.id(), "user_open")),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED);
    assert_eq!(providers.fcm.count(), 2);

    // Sent pushes count for the sender's statistics.
    let tallies = state.usage.take();
    assert_eq!(tallies[&android.id()].pushes, 1);
    assert_eq!(tallies[&iphone.id()].pushes, 2);
    providers.stop().await;
}

#[actix_web::test]
#[ignore = "needs PostgreSQL + Redis (docker compose)"]
async fn push_requests_are_checked_and_errors_mapped() {
    let providers = push_mocks::start().await;
    let state = state_with(providers.config.clone()).await;
    let app = test::init_service(App::new().app_data(state.clone()).configure(configure)).await;
    let android = enroll(&app, "android").await;
    let iphone = enroll(&app, "ios").await;
    let mac = enroll(&app, "macos").await;
    let stranger = enroll(&app, "ios").await;
    let pair_iphone = paired(&app, &android, &iphone).await;
    let pair_mac = paired(&app, &android, &mac).await;
    let env = "ZW52";
    let post = |who: &Member, body: Value| {
        let token = who.token.clone();
        let app = &app;
        async move { call(app, "POST", "/v1/push", &token, Some(&body)).await }
    };

    // No token yet (E1), then a token APNs reports dead (E3): cleared, 409.
    let (status, err) = post(&android, alert(pair_iphone, iphone.id(), env)).await;
    assert_eq!(
        (status, code(&err)),
        (StatusCode::CONFLICT, "PUSH_TOKEN_MISSING")
    );
    set_token(
        &app,
        &iphone,
        json!({"provider": "apns", "token": "dead01", "topic": TOPIC}),
    )
    .await;
    let (status, err) = post(&android, alert(pair_iphone, iphone.id(), env)).await;
    assert_eq!(
        (status, code(&err)),
        (StatusCode::CONFLICT, "PUSH_TOKEN_MISSING")
    );
    let (token,): (Option<String>,) =
        sqlx::query_as("SELECT push_token FROM devices WHERE device_id = $1")
            .bind(iphone.id())
            .fetch_one(&state.db)
            .await
            .unwrap();
    assert_eq!(token, None);
    // A configuration error at APNs is a provider error (502).
    set_token(
        &app,
        &iphone,
        json!({"provider": "apns", "token": "bad001", "topic": TOPIC}),
    )
    .await;
    let (status, err) = post(&android, alert(pair_iphone, iphone.id(), env)).await;
    assert_eq!(
        (status, code(&err)),
        (StatusCode::BAD_GATEWAY, "PUSH_PROVIDER_ERROR")
    );

    // Not the other member of a valid pair.
    let (status, err) = post(&stranger, alert(pair_iphone, iphone.id(), env)).await;
    assert_eq!((status, code(&err)), (StatusCode::FORBIDDEN, "NOT_PAIRED"));
    let (status, err) = post(&android, alert(pair_mac, iphone.id(), env)).await;
    assert_eq!((status, code(&err)), (StatusCode::FORBIDDEN, "NOT_PAIRED"));
    // Kind and platform must agree; a Mac gets no push at all.
    let (status, _) = post(
        &android,
        json!({"pair_id": pair_mac, "to": mac.id(), "kind": "alert",
        "reason": "sms_new", "env_b64": env}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _) = post(
        &iphone,
        json!({"pair_id": pair_iphone, "to": android.id(), "kind": "alert",
        "reason": "sms_new", "env_b64": env}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    for bad in [
        json!({"pair_id": pair_iphone, "to": iphone.id(), "kind": "alert", "reason": "user_open", "env_b64": env}),
        json!({"pair_id": pair_iphone, "to": iphone.id(), "kind": "alert", "reason": "sms_new"}),
        json!({"pair_id": pair_iphone, "to": iphone.id(), "kind": "alert", "reason": "sms_new", "env_b64": "not base64!"}),
        json!({"pair_id": pair_iphone, "to": iphone.id(), "kind": "alert", "reason": "sms_new", "env_b64": env, "collapse_key": "x".repeat(65)}),
        json!({"pair_id": pair_iphone, "to": iphone.id(), "kind": "alert", "reason": "sms_new", "env_b64": env, "ttl_s": -1}),
        json!({"pair_id": pair_iphone, "to": android.id(), "kind": "wake", "reason": "sms_send", "env_b64": env}),
        json!({"pair_id": pair_iphone, "to": android.id(), "kind": "ping", "reason": "sms_send"}),
    ] {
        let (status, err) = post(&android, bad.clone()).await;
        assert_eq!(
            (status, code(&err)),
            (StatusCode::BAD_REQUEST, "BAD_REQUEST"),
            "{bad}"
        );
    }
    let too_big = "A".repeat(3004);
    let (status, err) = post(&android, alert(pair_iphone, iphone.id(), &too_big)).await;
    assert_eq!(
        (status, code(&err)),
        (StatusCode::PAYLOAD_TOO_LARGE, "PAYLOAD_TOO_LARGE")
    );

    // A failed wake is not coalesced: the next one is tried again.
    set_token(&app, &android, json!({"provider": "fcm", "token": "down"})).await;
    for _ in 0..2 {
        let (status, err) = post(&iphone, wake(pair_iphone, android.id(), "call_action")).await;
        assert_eq!(
            (status, code(&err)),
            (StatusCode::BAD_GATEWAY, "PUSH_PROVIDER_ERROR")
        );
    }
    set_token(&app, &android, json!({"provider": "fcm", "token": "gone"})).await;
    let (status, err) = post(&iphone, wake(pair_iphone, android.id(), "call_action")).await;
    assert_eq!(
        (status, code(&err)),
        (StatusCode::CONFLICT, "PUSH_TOKEN_MISSING")
    );

    // Revoked pair: no more pushes (PAIR-03 API 3 logic 4).
    let path = format!("/v1/pairs/{pair_iphone}/revoke");
    call(
        &app,
        "POST",
        &path,
        &iphone.token,
        Some(&json!({"reason": "user"})),
    )
    .await;
    let (status, err) = post(&android, alert(pair_iphone, iphone.id(), env)).await;
    assert_eq!((status, code(&err)), (StatusCode::FORBIDDEN, "NOT_PAIRED"));

    // 30 pushes per minute per sender.
    let mut redis = state.redis.clone();
    let minute = minute_window(now_ms());
    for m in [minute, minute + 1] {
        let _: () = redis
            .set_ex(rate_limit_key(&android.id(), "push", m), 30, 120)
            .await
            .unwrap();
    }
    let (status, err) = post(&android, alert(pair_iphone, iphone.id(), env)).await;
    assert_eq!(
        (status, code(&err)),
        (StatusCode::TOO_MANY_REQUESTS, "RATE_LIMITED")
    );
    providers.stop().await;
}

#[actix_web::test]
#[ignore = "needs PostgreSQL + Redis (docker compose)"]
async fn apns_tokens_must_name_the_configured_app() {
    let providers = push_mocks::start().await;
    let state = state_with(providers.config.clone()).await;
    let app = test::init_service(App::new().app_data(state.clone()).configure(configure)).await;
    let iphone = enroll(&app, "ios").await;
    let other = json!({"provider": "apns", "token": "abcd", "topic": "com.example.other"});
    let (status, err) = call(
        &app,
        "PUT",
        "/v1/devices/me/push-token",
        &iphone.token,
        Some(&other),
    )
    .await;
    assert_eq!(
        (status, code(&err)),
        (StatusCode::BAD_REQUEST, "BAD_REQUEST")
    );
    set_token(
        &app,
        &iphone,
        json!({"provider": "apns", "token": "abcd", "topic": TOPIC}),
    )
    .await;
    providers.stop().await;

    // Without APNs configured no topic can match: no APNs token is stored,
    // and a push to that device finds none.
    let state = state_with(PushConfig::default()).await;
    let app = test::init_service(App::new().app_data(state.clone()).configure(configure)).await;
    let android = enroll(&app, "android").await;
    let iphone = enroll(&app, "ios").await;
    let pair_id = paired(&app, &android, &iphone).await;
    let token = json!({"provider": "apns", "token": "abcd", "topic": TOPIC});
    let (status, err) = call(
        &app,
        "PUT",
        "/v1/devices/me/push-token",
        &iphone.token,
        Some(&token),
    )
    .await;
    assert_eq!(
        (status, code(&err)),
        (StatusCode::BAD_REQUEST, "BAD_REQUEST")
    );
    let body = alert(pair_id, iphone.id(), "ZW52");
    let (status, err) = call(&app, "POST", "/v1/push", &android.token, Some(&body)).await;
    assert_eq!(
        (status, code(&err)),
        (StatusCode::CONFLICT, "PUSH_TOKEN_MISSING")
    );
}
