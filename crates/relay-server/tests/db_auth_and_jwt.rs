//! Challenge, token and JWT extractor against real PostgreSQL 16 + Redis 7.
//!
//! Ignored by default. Run with the dev services up (see relay/README.md):
//!   set -a && . ./.env.example && set +a && cargo test -- --ignored

mod common;

use actix_web::http::StatusCode;
use actix_web::test;
use common::TestDevice;
use common::http_harness::{TEST_JWT_SECRET, login, read, register, whoami_with};
use common::http_harness::{app, code, post, state};
use redis::AsyncCommands;
use relay_server::b64u;
use relay_server::challenge::minute_window;
use relay_server::clock::now_ms;
use relay_server::jwt::JwtKeys;
use relay_server::limits::{auth_ip_key, challenge_quota_key};
use relay_server::store::challenges::challenge_key;
use serde_json::{Value, json};
use std::net::{IpAddr, SocketAddr};

/// A random client address: IPv6 in its own /64, so parallel tests never
/// share a per-IP counter.
fn random_ipv6() -> IpAddr {
    let mut bytes = *uuid::Uuid::new_v4().as_bytes();
    bytes[0] = 0x20;
    bytes[1] = 0x01;
    IpAddr::from(bytes)
}

/// The same /64 as `ip`, another interface id.
fn same_64(ip: IpAddr) -> IpAddr {
    let IpAddr::V6(v6) = ip else { panic!("ipv6") };
    let mut bytes = v6.octets();
    bytes[15] ^= 0xff;
    bytes[9] ^= 0x5a;
    IpAddr::from(bytes)
}

async fn post_from(
    app: &impl common::http_harness::TestService,
    ip: IpAddr,
    path: &str,
    body: &Value,
) -> (StatusCode, Value) {
    let req = test::TestRequest::post()
        .uri(path)
        .peer_addr(SocketAddr::new(ip, 40_000))
        .set_json(body)
        .to_request();
    read(test::call_service(app, req).await).await
}

/// Set a fixed-window counter for this minute and the next one.
async fn fill_window(
    state: &relay_server::state::AppState,
    key_for: impl Fn(i64) -> String,
    n: u64,
) {
    let mut redis = state.redis.clone();
    let minute = minute_window(now_ms());
    for m in [minute, minute + 1] {
        let _: () = redis.set_ex(key_for(m), n, 120).await.unwrap();
    }
}

#[actix_web::test]
#[ignore = "needs PostgreSQL + Redis (docker compose)"]
async fn challenge_token_and_jwt_extractor() {
    let state = state().await;
    let app = app!(state);
    let device = TestDevice::random();

    let (status, err) = post(
        &app,
        "/v1/auth/challenge",
        &json!({ "device_id": device.device_id }),
    )
    .await;
    assert_eq!(
        (status, code(&err)),
        (StatusCode::NOT_FOUND, "DEVICE_NOT_FOUND")
    );

    register(&app, &device).await;
    let (status, chal) = post(
        &app,
        "/v1/auth/challenge",
        &json!({ "device_id": device.device_id }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let expires_at = chal["expires_at"].as_i64().unwrap();
    assert!((expires_at - now_ms() - 60_000).abs() < 2_000);
    let body = device.token_body(chal["challenge"].as_str().unwrap());
    let (status, tok) = post(&app, "/v1/auth/token", &body).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(tok["expires_in"], 900);

    // Reusing the consumed challenge.
    let (status, err) = post(&app, "/v1/auth/token", &body).await;
    assert_eq!(
        (status, code(&err)),
        (StatusCode::UNAUTHORIZED, "CHALLENGE_EXPIRED")
    );

    let token = tok["access_token"].as_str().unwrap();
    let (status, me) = whoami_with(&app, Some(token)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(me["device_id"], device.device_id.to_string());
}

#[actix_web::test]
#[ignore = "needs PostgreSQL + Redis (docker compose)"]
async fn expired_challenge_and_wrong_signature() {
    let state = state().await;
    let app = app!(state);
    let device = TestDevice::random();
    register(&app, &device).await;
    let id = json!({ "device_id": device.device_id });

    // Let the Redis TTL lapse instead of waiting 60 s.
    let (_, chal) = post(&app, "/v1/auth/challenge", &id).await;
    let mut redis = state.redis.clone();
    let bytes: [u8; 32] = b64u::decode_fixed(chal["challenge"].as_str().unwrap()).unwrap();
    let _: bool = redis
        .pexpire(challenge_key(&device.device_id, &bytes), 1)
        .await
        .unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let body = device.token_body(chal["challenge"].as_str().unwrap());
    let (status, err) = post(&app, "/v1/auth/token", &body).await;
    assert_eq!(
        (status, code(&err)),
        (StatusCode::UNAUTHORIZED, "CHALLENGE_EXPIRED")
    );

    // Signed by another key: rejected, and the challenge is consumed.
    let (_, chal) = post(&app, "/v1/auth/challenge", &id).await;
    let mut body = TestDevice::random().token_body(chal["challenge"].as_str().unwrap());
    body["device_id"] = device.device_id.to_string().into();
    let (status, err) = post(&app, "/v1/auth/token", &body).await;
    assert_eq!(
        (status, code(&err)),
        (StatusCode::UNAUTHORIZED, "SIGNATURE_INVALID")
    );
    let good = device.token_body(chal["challenge"].as_str().unwrap());
    let (status, err) = post(&app, "/v1/auth/token", &good).await;
    assert_eq!(
        (status, code(&err)),
        (StatusCode::UNAUTHORIZED, "CHALLENGE_EXPIRED")
    );
}

#[actix_web::test]
#[ignore = "needs PostgreSQL + Redis (docker compose)"]
async fn jwt_rejections() {
    let state = state().await;
    let app = app!(state);
    let device = TestDevice::random();
    register(&app, &device).await;

    let (status, err) = whoami_with(&app, None).await;
    assert_eq!(
        (status, code(&err)),
        (StatusCode::UNAUTHORIZED, "SIGNATURE_INVALID")
    );

    let keys = JwtKeys::from_secret(TEST_JWT_SECRET.as_bytes()).unwrap();
    let (expired, _) = keys
        .issue(&device.device_id, now_ms() / 1000 - 901)
        .unwrap();
    let (status, err) = whoami_with(&app, Some(&expired)).await;
    assert_eq!(
        (status, code(&err)),
        (StatusCode::UNAUTHORIZED, "TOKEN_EXPIRED")
    );

    // JWT still valid, but the device left the relay (spec 0.6.4 step 4).
    let token = login(&app, &device).await;
    sqlx::query("UPDATE devices SET revoked_at = now() WHERE device_id = $1")
        .bind(device.device_id)
        .execute(&state.db)
        .await
        .unwrap();
    let (status, err) = whoami_with(&app, Some(&token)).await;
    assert_eq!((status, code(&err)), (StatusCode::GONE, "DEVICE_REVOKED"));
    sqlx::query("DELETE FROM devices WHERE device_id = $1")
        .bind(device.device_id)
        .execute(&state.db)
        .await
        .unwrap();
    let (status, err) = whoami_with(&app, Some(&token)).await;
    assert_eq!(
        (status, code(&err)),
        (StatusCode::NOT_FOUND, "DEVICE_NOT_FOUND")
    );
}

#[actix_web::test]
#[ignore = "needs PostgreSQL + Redis (docker compose)"]
async fn rate_limit_and_body_errors() {
    let state = state().await;
    let app = app!(state);
    let device = TestDevice::random();
    register(&app, &device).await;

    // Fill the current (and next, in case the minute rolls over) window.
    let mut redis = state.redis.clone();
    let minute = minute_window(now_ms());
    for m in [minute, minute + 1] {
        let _: () = redis
            .set_ex(challenge_quota_key(&device.device_id, None, m), 10, 120)
            .await
            .unwrap();
    }
    let req = test::TestRequest::post()
        .uri("/v1/auth/challenge")
        .set_json(json!({ "device_id": device.device_id }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    let retry: u64 = resp
        .headers()
        .get("Retry-After")
        .unwrap()
        .to_str()
        .unwrap()
        .parse()
        .unwrap();
    assert!((1..=60).contains(&retry));

    let req = test::TestRequest::post()
        .uri("/v1/auth/token")
        .insert_header(("Content-Type", "application/json"))
        .set_payload("{not json")
        .to_request();
    let (status, err) = read(test::call_service(&app, req).await).await;
    assert_eq!(
        (status, code(&err)),
        (StatusCode::BAD_REQUEST, "BAD_REQUEST")
    );

    let big = json!({ "device_id": device.device_id, "challenge": "x".repeat(8192), "sig": "" });
    let (status, err) = post(&app, "/v1/auth/token", &big).await;
    assert_eq!(
        (status, code(&err)),
        (StatusCode::PAYLOAD_TOO_LARGE, "PAYLOAD_TOO_LARGE")
    );
}

#[actix_web::test]
#[ignore = "needs PostgreSQL + Redis (docker compose)"]
async fn a_new_challenge_never_replaces_a_pending_one() {
    let state = state().await;
    let app = app!(state);
    let device = TestDevice::random();
    register(&app, &device).await;
    let id = json!({ "device_id": device.device_id });
    let (_, first) = post(&app, "/v1/auth/challenge", &id).await;
    // A stranger asking for challenges for the same device_id.
    let (status, second) = post_from(&app, random_ipv6(), "/v1/auth/challenge", &id).await;
    assert_eq!(status, StatusCode::OK);
    assert_ne!(first["challenge"], second["challenge"]);
    for chal in [&first, &second] {
        let body = device.token_body(chal["challenge"].as_str().unwrap());
        let (status, tok) = post(&app, "/v1/auth/token", &body).await;
        assert_eq!(status, StatusCode::OK, "{tok}");
    }
}

#[actix_web::test]
#[ignore = "needs PostgreSQL + Redis (docker compose)"]
async fn auth_calls_are_limited_per_client_ip_before_the_database() {
    let state = state().await;
    let app = app!(state);
    let ip = random_ipv6();
    // 29 calls used: one more passes, then challenge and token share the cap.
    fill_window(&state, |m| auth_ip_key(&ip, m), 29).await;
    let unknown = json!({ "device_id": uuid::Uuid::new_v4() });
    let (status, err) = post_from(&app, ip, "/v1/auth/challenge", &unknown).await;
    assert_eq!(
        (status, code(&err)),
        (StatusCode::NOT_FOUND, "DEVICE_NOT_FOUND")
    );
    // Same /64, another address: counted together, refused before any lookup.
    let (status, err) = post_from(&app, same_64(ip), "/v1/auth/challenge", &unknown).await;
    assert_eq!(
        (status, code(&err)),
        (StatusCode::TOO_MANY_REQUESTS, "RATE_LIMITED")
    );
    let device = TestDevice::random();
    let token_body = device.token_body(&b64u::encode(&[7u8; 32]));
    let (status, err) = post_from(&app, ip, "/v1/auth/token", &token_body).await;
    assert_eq!(
        (status, code(&err)),
        (StatusCode::TOO_MANY_REQUESTS, "RATE_LIMITED")
    );
    // Another client is not affected.
    let (status, err) = post_from(&app, random_ipv6(), "/v1/auth/challenge", &unknown).await;
    assert_eq!(
        (status, code(&err)),
        (StatusCode::NOT_FOUND, "DEVICE_NOT_FOUND")
    );
}

#[actix_web::test]
#[ignore = "needs PostgreSQL + Redis (docker compose)"]
async fn challenge_quota_is_per_device_and_client_ip() {
    let state = state().await;
    let app = app!(state);
    let device = TestDevice::random();
    register(&app, &device).await;
    let id = json!({ "device_id": device.device_id });
    let stranger = random_ipv6();
    fill_window(
        &state,
        |m| challenge_quota_key(&device.device_id, Some(&stranger), m),
        10,
    )
    .await;
    let (status, err) = post_from(&app, stranger, "/v1/auth/challenge", &id).await;
    assert_eq!(
        (status, code(&err)),
        (StatusCode::TOO_MANY_REQUESTS, "RATE_LIMITED")
    );
    // The device itself, from its own address, still gets in.
    let (status, chal) = post_from(&app, random_ipv6(), "/v1/auth/challenge", &id).await;
    assert_eq!(status, StatusCode::OK);
    let body = device.token_body(chal["challenge"].as_str().unwrap());
    let (status, _) = post(&app, "/v1/auth/token", &body).await;
    assert_eq!(status, StatusCode::OK);
}
