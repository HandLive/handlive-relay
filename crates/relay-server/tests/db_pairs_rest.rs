//! `POST /v1/pairs`, `GET /v1/pairs` and `POST /v1/pairs/{pair_id}/revoke`
//! against real PostgreSQL 16 + Redis 7 (PAIR-01 API 8, PAIR-02 API 1,
//! PAIR-03 API 3) and the REST rate limit (`RELAY_RATE_LIMIT`).
//!
//! Ignored by default; needs PostgreSQL + Redis (see relay/README.md).

mod common;

use actix_web::http::StatusCode;
use actix_web::test;
use common::TestDevice;
use common::http_harness::{app, code, state};
use common::relay_harness::{call, enroll, pair_body};
use redis::AsyncCommands;
use relay_server::challenge::minute_window;
use relay_server::clock::now_ms;
use relay_server::store::challenges::rate_limit_key;
use serde_json::json;
use uuid::Uuid;

#[actix_web::test]
#[ignore = "needs PostgreSQL + Redis (docker compose)"]
async fn pair_registration_is_verified_and_idempotent() {
    let state = state().await;
    let app = app!(state);
    let android = enroll(&app, "android").await;
    let mac = enroll(&app, "macos").await;
    let other = enroll(&app, "ios").await;
    let pair_id = Uuid::new_v4();
    let created_at = 1_727_150_003_210;
    let body = pair_body(pair_id, &android.device, &mac.device, created_at);

    let (status, resp) = call(&app, "POST", "/v1/pairs", &mac.token, Some(&body)).await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(resp, json!({"pair_id": pair_id, "created_at": created_at}));
    // The other member repeating the same registration: 200, same body.
    let (status, again) = call(&app, "POST", "/v1/pairs", &android.token, Some(&body)).await;
    assert_eq!((status, again), (StatusCode::OK, resp));
    // Same pair_id, different data.
    let changed = pair_body(pair_id, &android.device, &mac.device, created_at + 1);
    let (status, err) = call(&app, "POST", "/v1/pairs", &mac.token, Some(&changed)).await;
    assert_eq!((status, code(&err)), (StatusCode::CONFLICT, "PAIR_EXISTS"));

    let fresh = |a: &TestDevice, b: &TestDevice| pair_body(Uuid::new_v4(), a, b, now_ms());
    // Not a member of the pair.
    let (status, err) = call(
        &app,
        "POST",
        "/v1/pairs",
        &other.token,
        Some(&fresh(&android.device, &mac.device)),
    )
    .await;
    assert_eq!((status, code(&err)), (StatusCode::FORBIDDEN, "NOT_PAIRED"));
    // The peer never registered with the relay.
    let unknown = TestDevice::random();
    let (status, err) = call(
        &app,
        "POST",
        "/v1/pairs",
        &mac.token,
        Some(&fresh(&unknown, &mac.device)),
    )
    .await;
    assert_eq!(
        (status, code(&err)),
        (StatusCode::NOT_FOUND, "DEVICE_NOT_FOUND")
    );
    // device_a must be the phone.
    let (status, err) = call(
        &app,
        "POST",
        "/v1/pairs",
        &mac.token,
        Some(&fresh(&mac.device, &other.device)),
    )
    .await;
    assert_eq!(
        (status, code(&err)),
        (StatusCode::BAD_REQUEST, "BAD_REQUEST")
    );
    // A signature by another key.
    let mut forged = fresh(&android.device, &mac.device);
    forged["sig_a"] = forged["sig_b"].clone();
    let (status, err) = call(&app, "POST", "/v1/pairs", &mac.token, Some(&forged)).await;
    assert_eq!(
        (status, code(&err)),
        (StatusCode::UNAUTHORIZED, "SIGNATURE_INVALID")
    );
    // Body and attestation disagree.
    let mut mismatch = fresh(&android.device, &mac.device);
    mismatch["created_at"] = json!(1);
    let (status, err) = call(&app, "POST", "/v1/pairs", &mac.token, Some(&mismatch)).await;
    assert_eq!(
        (status, code(&err)),
        (StatusCode::BAD_REQUEST, "BAD_REQUEST")
    );
    // No token.
    let req = test::TestRequest::post()
        .uri("/v1/pairs")
        .set_json(&body)
        .to_request();
    let (status, err) = common::http_harness::read(test::call_service(&app, req).await).await;
    assert_eq!(
        (status, code(&err)),
        (StatusCode::UNAUTHORIZED, "SIGNATURE_INVALID")
    );
}

#[actix_web::test]
#[ignore = "needs PostgreSQL + Redis (docker compose)"]
async fn listing_and_revoking_pairs() {
    let state = state().await;
    let app = app!(state);
    let android = enroll(&app, "android").await;
    let mac = enroll(&app, "macos").await;
    let iphone = enroll(&app, "ios").await;
    let stranger = enroll(&app, "ios").await;
    let pair_mac = Uuid::new_v4();
    let pair_iphone = Uuid::new_v4();
    for (id, client, at) in [
        (pair_mac, &mac, 1_000_000),
        (pair_iphone, &iphone, 2_000_000),
    ] {
        let body = pair_body(id, &android.device, &client.device, at);
        let (status, _) = call(&app, "POST", "/v1/pairs", &client.token, Some(&body)).await;
        assert_eq!(status, StatusCode::CREATED);
    }

    let (status, list) = call(&app, "GET", "/v1/pairs", &android.token, None).await;
    assert_eq!(status, StatusCode::OK);
    // Newest first, peers seen from the caller's side.
    assert_eq!(
        list,
        json!({"pairs": [
            {"pair_id": pair_iphone, "peer_device_id": iphone.id(), "peer_platform": "ios",
             "created_at": 2_000_000, "revoked_at": null, "peer_online": false},
            {"pair_id": pair_mac, "peer_device_id": mac.id(), "peer_platform": "macos",
             "created_at": 1_000_000, "revoked_at": null, "peer_online": false},
        ]})
    );
    let (_, list) = call(&app, "GET", "/v1/pairs", &mac.token, None).await;
    assert_eq!(list["pairs"][0]["peer_device_id"], json!(android.id()));
    assert_eq!(list["pairs"][0]["peer_platform"], "android");

    let revoke = |id: Uuid| format!("/v1/pairs/{id}/revoke");
    let reason = json!({"reason": "lost_device"});
    let (status, err) = call(
        &app,
        "POST",
        &revoke(pair_mac),
        &stranger.token,
        Some(&reason),
    )
    .await;
    assert_eq!((status, code(&err)), (StatusCode::FORBIDDEN, "NOT_PAIRED"));
    let (status, err) = call(
        &app,
        "POST",
        &revoke(Uuid::new_v4()),
        &mac.token,
        Some(&reason),
    )
    .await;
    assert_eq!(
        (status, code(&err)),
        (StatusCode::NOT_FOUND, "DEVICE_NOT_FOUND")
    );
    let (status, _) = call(
        &app,
        "POST",
        &revoke(pair_mac),
        &mac.token,
        Some(&json!({"reason": "bored"})),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _) = call(
        &app,
        "POST",
        "/v1/pairs/not-a-uuid/revoke",
        &mac.token,
        Some(&reason),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let (status, _) = call(&app, "POST", &revoke(pair_mac), &mac.token, Some(&reason)).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    // Idempotent, also for the other member (PAIR-03 E4).
    let (status, _) = call(
        &app,
        "POST",
        &revoke(pair_mac),
        &android.token,
        Some(&json!({"reason": "user"})),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let (_, list) = call(&app, "GET", "/v1/pairs", &android.token, None).await;
    let revoked = &list["pairs"][1];
    assert_eq!(revoked["pair_id"], json!(pair_mac));
    let at = revoked["revoked_at"].as_i64().expect("revoked_at set");
    assert!((at - now_ms()).abs() < 60_000);
    let (_, active) = call(
        &app,
        "GET",
        "/v1/pairs?include_revoked=false",
        &android.token,
        None,
    )
    .await;
    assert_eq!(active["pairs"].as_array().unwrap().len(), 1);
    assert_eq!(active["pairs"][0]["pair_id"], json!(pair_iphone));
    let (status, _) = call(
        &app,
        "GET",
        "/v1/pairs?include_revoked=maybe",
        &android.token,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let row: (Option<Uuid>,) = sqlx::query_as("SELECT revoked_by FROM pairs WHERE pair_id = $1")
        .bind(pair_mac)
        .fetch_one(&state.db)
        .await
        .unwrap();
    assert_eq!(row.0, Some(mac.id()));
}

#[actix_web::test]
#[ignore = "needs PostgreSQL + Redis (docker compose)"]
async fn rest_calls_are_limited_per_device() {
    let state = state().await;
    let app = app!(state);
    let mac = enroll(&app, "macos").await;
    let (status, _) = call(&app, "GET", "/v1/pairs", &mac.token, None).await;
    assert_eq!(status, StatusCode::OK);

    let mut redis = state.redis.clone();
    let minute = minute_window(now_ms());
    for m in [minute, minute + 1] {
        let _: () = redis
            .set_ex(rate_limit_key(&mac.id(), "rest", m), 60, 120)
            .await
            .unwrap();
    }
    let req = test::TestRequest::get()
        .uri("/v1/pairs")
        .insert_header(("Authorization", format!("Bearer {}", mac.token)))
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
}
