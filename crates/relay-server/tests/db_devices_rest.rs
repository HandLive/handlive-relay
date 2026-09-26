//! `PUT /v1/devices/me/push-token` (CONN-04 API 1), `DELETE /v1/devices/me`
//! (SET-02 API 2, C16) and the per-IP registration limit (CONN-03 API 1)
//! against real PostgreSQL 16 + Redis 7.
//!
//! Ignored by default; needs PostgreSQL + Redis (see relay/README.md).

mod common;

use std::net::SocketAddr;

use actix_web::http::StatusCode;
use actix_web::{App, test, web};
use common::TestDevice;
use common::http_harness::{TEST_JWT_SECRET, app, code, read, state};
use common::relay_harness::{call, enroll, pair_body};
use redis::AsyncCommands;
use relay_server::clock::now_ms;
use relay_server::config::{Config, RelaySettings};
use relay_server::relay::presence::revoked_notice_key;
use relay_server::state::AppState;
use relay_server::{MIGRATOR, configure};
use serde_json::{Value, json};
use uuid::Uuid;

async fn push_row(state: &AppState, id: Uuid) -> (Option<String>, Option<String>, Option<String>) {
    sqlx::query_as("SELECT push_provider, push_token, push_topic FROM devices WHERE device_id = $1")
        .bind(id)
        .fetch_one(&state.db)
        .await
        .unwrap()
}

#[actix_web::test]
#[ignore = "needs PostgreSQL + Redis (docker compose)"]
async fn push_tokens_are_stored_per_platform() {
    let state = state().await;
    let app = app!(state);
    let android = enroll(&app, "android").await;
    let iphone = enroll(&app, "ios").await;
    let mac = enroll(&app, "macos").await;
    let put = "/v1/devices/me/push-token";

    // The longest FCM token passes the 8 KiB body limit of this route.
    let fcm = "a".repeat(4096);
    let (status, _) = call(
        &app,
        "PUT",
        put,
        &android.token,
        Some(&json!({"provider": "fcm", "token": fcm})),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert_eq!(
        push_row(&state, android.id()).await,
        (Some("fcm".into()), Some(fcm), None)
    );
    // A new token overwrites the old one; APNs tokens are kept lowercase.
    let apns =
        json!({"provider": "apns_sandbox", "token": "4F1C2E00A9", "topic": "app.handlive.ios"});
    let (status, _) = call(&app, "PUT", put, &iphone.token, Some(&apns)).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let apns = json!({"provider": "apns", "token": "ABCDEF01", "topic": "app.handlive.ios"});
    let (status, _) = call(&app, "PUT", put, &iphone.token, Some(&apns)).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert_eq!(
        push_row(&state, iphone.id()).await,
        (
            Some("apns".into()),
            Some("abcdef01".into()),
            Some("app.handlive.ios".into())
        )
    );

    for (member, body) in [
        (
            &android,
            json!({"provider": "apns", "token": "abcd", "topic": "app.handlive.ios"}),
        ),
        (&iphone, json!({"provider": "fcm", "token": "abcd"})),
        (&iphone, json!({"provider": "apns", "token": "abcd"})),
        (
            &mac,
            json!({"provider": "apns", "token": "abcd", "topic": "app.handlive.ios"}),
        ),
        (&android, json!({"provider": "fcm"})),
    ] {
        let (status, err) = call(&app, "PUT", put, &member.token, Some(&body)).await;
        assert_eq!(
            (status, code(&err)),
            (StatusCode::BAD_REQUEST, "BAD_REQUEST"),
            "{body}"
        );
    }
    let huge = json!({"provider": "fcm", "token": "a".repeat(9000)});
    let (status, err) = call(&app, "PUT", put, &android.token, Some(&huge)).await;
    assert_eq!(
        (status, code(&err)),
        (StatusCode::PAYLOAD_TOO_LARGE, "PAYLOAD_TOO_LARGE")
    );
}

#[actix_web::test]
#[ignore = "needs PostgreSQL + Redis (docker compose)"]
async fn devices_remove_themselves_with_or_without_revoking() {
    let state = state().await;
    let app = app!(state);
    let android = enroll(&app, "android").await;
    let mac = enroll(&app, "macos").await;
    let iphone = enroll(&app, "ios").await;
    let pair_mac = Uuid::new_v4();
    let pair_iphone = Uuid::new_v4();
    for (id, client) in [(pair_mac, &mac), (pair_iphone, &iphone)] {
        let body = pair_body(id, &android.device, &client.device, now_ms());
        let (status, _) = call(&app, "POST", "/v1/pairs", &client.token, Some(&body)).await;
        assert_eq!(status, StatusCode::CREATED);
    }
    let pair_rows = |id: Uuid| {
        let db = state.db.clone();
        async move {
            let (n,): (i64,) = sqlx::query_as("SELECT count(*) FROM pairs WHERE pair_id = $1")
                .bind(id)
                .fetch_one(&db)
                .await
                .unwrap();
            n
        }
    };

    let (status, _) = call(&app, "DELETE", "/v1/devices/me", &mac.token, None).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "revoke_pairs is required");
    // Silent removal: no notice for the phone, the pair row is gone.
    let (status, _) = call(
        &app,
        "DELETE",
        "/v1/devices/me?revoke_pairs=false",
        &mac.token,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert_eq!(pair_rows(pair_mac).await, 0);
    let mut redis = state.redis.clone();
    let notices: Vec<String> = redis
        .smembers(revoked_notice_key(&android.id()))
        .await
        .unwrap();
    assert!(notices.is_empty());
    let (status, err) = call(&app, "GET", "/v1/pairs", &mac.token, None).await;
    assert_eq!(
        (status, code(&err)),
        (StatusCode::NOT_FOUND, "DEVICE_NOT_FOUND")
    );
    let (status, _) = call(
        &app,
        "DELETE",
        "/v1/devices/me?revoke_pairs=false",
        &mac.token,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "repeat call");
    // The same key can register again (a new row).
    let (status, _) = common::http_harness::post(
        &app,
        "/v1/devices",
        &mac.device.registration_body("macos", now_ms()),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);

    // Delete all data: every peer gets a 30-day notice.
    let (status, _) = call(
        &app,
        "DELETE",
        "/v1/devices/me?revoke_pairs=true",
        &android.token,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert_eq!(pair_rows(pair_iphone).await, 0);
    let key = revoked_notice_key(&iphone.id());
    let notices: Vec<String> = redis.smembers(&key).await.unwrap();
    assert_eq!(notices, vec![format!("{pair_iphone}|{}", android.id())]);
    let ttl: i64 = redis.ttl(&key).await.unwrap();
    assert!(ttl > 29 * 24 * 3600 && ttl <= 30 * 24 * 3600, "{ttl}");

    // A device locked out by operations stays locked out.
    sqlx::query("UPDATE devices SET revoked_at = now() WHERE device_id = $1")
        .bind(iphone.id())
        .execute(&state.db)
        .await
        .unwrap();
    let (status, err) = call(
        &app,
        "DELETE",
        "/v1/devices/me?revoke_pairs=true",
        &iphone.token,
        None,
    )
    .await;
    assert_eq!((status, code(&err)), (StatusCode::GONE, "DEVICE_REVOKED"));
}

/// State with the registration limit on and one trusted proxy.
async fn limited_state(proxy: &str) -> web::Data<AppState> {
    let config = Config {
        database_url: std::env::var("DATABASE_URL").unwrap(),
        redis_url: std::env::var("REDIS_URL").unwrap(),
        jwt_secret: TEST_JWT_SECRET.as_bytes().to_vec(),
        bind: String::new(),
        settings: RelaySettings {
            trusted_proxies: vec![proxy.parse().unwrap()],
            ..RelaySettings::default()
        },
    };
    let state = AppState::connect(&config).await.unwrap();
    MIGRATOR.run(&state.db).await.unwrap();
    web::Data::new(state)
}

async fn register_from(
    app: &impl common::http_harness::TestService,
    peer: &str,
    forwarded: Option<&str>,
    body: &Value,
) -> (StatusCode, Option<u64>) {
    let mut req = test::TestRequest::post()
        .uri("/v1/devices")
        .peer_addr(peer.parse::<SocketAddr>().unwrap())
        .set_json(body);
    if let Some(f) = forwarded {
        req = req.insert_header(("X-Forwarded-For", f));
    }
    let resp = test::call_service(app, req.to_request()).await;
    let retry = resp
        .headers()
        .get("Retry-After")
        .map(|v| v.to_str().unwrap().parse().unwrap());
    let (status, _) = read(resp).await;
    (status, retry)
}

#[actix_web::test]
#[ignore = "needs PostgreSQL + Redis (docker compose)"]
async fn new_registrations_are_limited_per_client_ip() {
    let proxy = "10.99.0.1";
    let state = limited_state(proxy).await;
    let app = test::init_service(App::new().app_data(state.clone()).configure(configure)).await;
    // A random documentation address per run keeps runs independent.
    let n = u16::from_be_bytes(Uuid::new_v4().as_bytes()[..2].try_into().unwrap());
    let client = format!("2001:db8::{n:x}");
    let direct = format!("[{client}]:5000");

    let first = TestDevice::random();
    let (status, _) = register_from(
        &app,
        &direct,
        None,
        &first.registration_body("ios", now_ms()),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    for i in 1..10 {
        let body = TestDevice::random().registration_body("ios", now_ms());
        let (status, _) = register_from(&app, &direct, None, &body).await;
        assert_eq!(status, StatusCode::CREATED, "registration {i}");
    }
    let (status, retry) = register_from(
        &app,
        &direct,
        None,
        &TestDevice::random().registration_body("ios", now_ms()),
    )
    .await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert!((1..=3600).contains(&retry.unwrap()));
    // Refreshing an existing device is not a new registration.
    let (status, _) = register_from(
        &app,
        &direct,
        None,
        &first.registration_body("ios", now_ms()),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    // Behind the trusted proxy the forwarded client address counts...
    let via_proxy = format!("{proxy}:443");
    let (status, _) = register_from(
        &app,
        &via_proxy,
        Some(&client),
        &TestDevice::random().registration_body("ios", now_ms()),
    )
    .await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    // ...while an untrusted peer's forwarded header is ignored.
    let other = format!("[2001:db8::1:{n:x}]:5000");
    let (status, _) = register_from(
        &app,
        &other,
        Some(&client),
        &TestDevice::random().registration_body("ios", now_ms()),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
}
