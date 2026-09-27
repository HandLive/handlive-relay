//! Test keys generated at run time (never stored) and local mock servers
//! for APNs (HTTP/2 without TLS) and FCM with its OAuth token endpoint.
#![allow(dead_code)]

use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use actix_web::dev::ServerHandle;
use actix_web::http::Version;
use actix_web::{App, HttpRequest, HttpResponse, HttpServer, web};
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use relay_push::apns::ProviderClaims;
use relay_push::fcm::{AssertionClaims, FCM_SCOPE, JWT_BEARER_GRANT};
use relay_push::{ApnsConfig, FcmConfig};
use ring::rand::SystemRandom;
use ring::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair};
use rsa::pkcs8::{EncodePrivateKey, LineEnding};
use rsa::traits::PublicKeyParts;
use serde_json::{Value, json};

pub const KEY_ID: &str = "ABC123DEFG";
pub const TEAM_ID: &str = "DEF123GHIJ";
pub const TOPIC: &str = "app.handlive.ios";
pub const CLIENT_EMAIL: &str = "relay@handlive-test.iam.gserviceaccount.com";
pub const PROJECT: &str = "handlive-test";

fn pem(label: &str, der: &[u8]) -> String {
    let body = STANDARD.encode(der);
    let lines: Vec<&str> = body
        .as_bytes()
        .chunks(64)
        .map(|c| std::str::from_utf8(c).unwrap())
        .collect();
    format!(
        "-----BEGIN {label}-----\n{}\n-----END {label}-----\n",
        lines.join("\n")
    )
}

/// A fresh P-256 key: PKCS#8 PEM (the `.p8` form) and its public point.
pub struct EcKey {
    pub pem: String,
    pub x: String,
    pub y: String,
}

pub fn ec_key() -> EcKey {
    let rng = SystemRandom::new();
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
    let pair =
        EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng).unwrap();
    let point = pair.public_key().as_ref();
    EcKey {
        pem: pem("PRIVATE KEY", pkcs8.as_ref()),
        x: URL_SAFE_NO_PAD.encode(&point[1..33]),
        y: URL_SAFE_NO_PAD.encode(&point[33..65]),
    }
}

/// A fresh RSA-2048 key: PKCS#8 PEM (as in a service-account JSON) and the
/// public modulus and exponent.
pub struct RsaKey {
    pub pem: String,
    pub n: String,
    pub e: String,
}

pub fn rsa_key() -> RsaKey {
    let key = rsa::RsaPrivateKey::new(&mut rsa::rand_core::OsRng, 2048).unwrap();
    RsaKey {
        pem: key.to_pkcs8_pem(LineEnding::LF).unwrap().to_string(),
        n: URL_SAFE_NO_PAD.encode(key.n().to_bytes_be()),
        e: URL_SAFE_NO_PAD.encode(key.e().to_bytes_be()),
    }
}

/// A private directory for key files, removed on drop.
pub struct TempDir(pub PathBuf);

impl TempDir {
    pub fn new() -> Self {
        let dir = std::env::temp_dir().join(format!("hl-push-{}", uuid::Uuid::new_v4().simple()));
        std::fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }

    pub fn write(&self, name: &str, content: &str) -> PathBuf {
        let path = self.0.join(name);
        std::fs::write(&path, content).unwrap();
        path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// One request as a mock provider saw it.
#[derive(Debug, Clone)]
pub struct Seen {
    pub path: String,
    pub version: Version,
    pub headers: HashMap<String, String>,
    pub body: Value,
}

/// Scripted answers per device token: popped in order, then 200.
#[derive(Default)]
pub struct Mock {
    pub seen: Mutex<Vec<Seen>>,
    pub script: Mutex<HashMap<String, VecDeque<(u16, Value)>>>,
    pub token_requests: Mutex<u32>,
    pub rejected_auth: Mutex<u32>,
}

impl Mock {
    pub fn script(&self, token: &str, answers: &[(u16, Value)]) {
        self.script
            .lock()
            .unwrap()
            .insert(token.to_owned(), answers.iter().cloned().collect());
    }

    fn next_answer(&self, token: &str) -> (u16, Value) {
        self.script
            .lock()
            .unwrap()
            .get_mut(token)
            .and_then(VecDeque::pop_front)
            .unwrap_or((200, json!({})))
    }

    pub fn seen(&self) -> Vec<Seen> {
        self.seen.lock().unwrap().clone()
    }

    fn record(&self, req: &HttpRequest, body: &[u8]) {
        let headers = req
            .headers()
            .iter()
            .map(|(k, v)| (k.as_str().to_owned(), v.to_str().unwrap_or("").to_owned()))
            .collect();
        self.seen.lock().unwrap().push(Seen {
            path: req.path().to_owned(),
            version: req.version(),
            headers,
            body: serde_json::from_slice(body).unwrap_or(Value::Null),
        });
    }
}

pub struct MockServer {
    pub url: String,
    pub mock: Arc<Mock>,
    handle: ServerHandle,
}

impl MockServer {
    pub async fn stop(&self) {
        self.handle.stop(false).await;
    }
}

/// Mock APNs: HTTP/2 over cleartext, checks the provider token.
pub async fn apns_mock(key: &EcKey) -> MockServer {
    let mock = Arc::new(Mock::default());
    let decoding = DecodingKey::from_ec_components(&key.x, &key.y).unwrap();
    let state = (mock.clone(), decoding);
    let server = HttpServer::new(move || {
        let state = state.clone();
        App::new().route(
            "/3/device/{token}",
            web::post().to(move |req: HttpRequest, body: web::Bytes| {
                let (mock, decoding) = state.clone();
                async move {
                    mock.record(&req, &body);
                    let auth = req
                        .headers()
                        .get("authorization")
                        .and_then(|v| v.to_str().ok())
                        .and_then(|v| v.strip_prefix("bearer "))
                        .unwrap_or("");
                    let mut validation = Validation::new(Algorithm::ES256);
                    validation.required_spec_claims.clear();
                    validation.validate_exp = false;
                    let valid = jsonwebtoken::decode_header(auth)
                        .is_ok_and(|h| h.kid.as_deref() == Some(KEY_ID))
                        && jsonwebtoken::decode::<ProviderClaims>(auth, &decoding, &validation)
                            .is_ok_and(|t| t.claims.iss == TEAM_ID);
                    if !valid {
                        *mock.rejected_auth.lock().unwrap() += 1;
                        return HttpResponse::Forbidden()
                            .json(json!({"reason": "InvalidProviderToken"}));
                    }
                    let token = req.match_info().get("token").unwrap_or("").to_owned();
                    let (status, body) = mock.next_answer(&token);
                    let mut resp =
                        HttpResponse::build(actix_web::http::StatusCode::from_u16(status).unwrap());
                    if status == 200 {
                        resp.insert_header(("apns-id", uuid::Uuid::new_v4().to_string()))
                            .finish()
                    } else {
                        resp.json(body)
                    }
                }
            }),
        )
    })
    .workers(1)
    .disable_signals()
    .shutdown_timeout(1)
    .bind_auto_h2c(("127.0.0.1", 0))
    .unwrap();
    let url = format!("http://{}", server.addrs()[0]);
    let server = server.run();
    let handle = server.handle();
    actix_web::rt::spawn(server);
    MockServer { url, mock, handle }
}

/// Mock FCM with its OAuth token endpoint at `<url>/token`.
pub async fn fcm_mock(key: &RsaKey) -> MockServer {
    let mock = Arc::new(Mock::default());
    let decoding = DecodingKey::from_rsa_components(&key.n, &key.e).unwrap();
    let issued: Arc<Mutex<Vec<String>>> = Arc::default();
    let state = (mock.clone(), decoding, issued);
    let server = HttpServer::new(move || {
        let token_state = state.clone();
        let send_state = state.clone();
        App::new()
            .route(
                "/token",
                web::post().to(move |req: HttpRequest, form: web::Form<HashMap<String, String>>| {
                    let (mock, decoding, issued) = token_state.clone();
                    async move {
                        *mock.token_requests.lock().unwrap() += 1;
                        let url = format!("http://{}/token", req.connection_info().host());
                        let mut validation = Validation::new(Algorithm::RS256);
                        validation.set_audience(&[url]);
                        let assertion = form.get("assertion").cloned().unwrap_or_default();
                        let ok = form.get("grant_type").map(String::as_str) == Some(JWT_BEARER_GRANT)
                            && jsonwebtoken::decode::<AssertionClaims>(&assertion, &decoding, &validation)
                                .is_ok_and(|t| {
                                    t.claims.iss == CLIENT_EMAIL
                                        && t.claims.scope == FCM_SCOPE
                                        && t.claims.exp == t.claims.iat + 3600
                                });
                        if !ok {
                            return HttpResponse::BadRequest().json(json!({"error": "invalid_grant"}));
                        }
                        let access = format!("access-{}", uuid::Uuid::new_v4().simple());
                        issued.lock().unwrap().push(access.clone());
                        HttpResponse::Ok().json(json!({"access_token": access, "expires_in": 3599, "token_type": "Bearer"}))
                    }
                }),
            )
            .route(
                "/v1/projects/{project}/messages:send",
                web::post().to(move |req: HttpRequest, body: web::Bytes| {
                    let (mock, _, issued) = send_state.clone();
                    async move {
                        mock.record(&req, &body);
                        let bearer = req
                            .headers()
                            .get("authorization")
                            .and_then(|v| v.to_str().ok())
                            .and_then(|v| v.strip_prefix("Bearer "))
                            .unwrap_or("")
                            .to_owned();
                        let current = issued.lock().unwrap().last().cloned();
                        if req.match_info().get("project") != Some(PROJECT)
                            || current.as_deref() != Some(bearer.as_str())
                        {
                            *mock.rejected_auth.lock().unwrap() += 1;
                            return HttpResponse::Unauthorized()
                                .json(json!({"error": {"code": 401, "status": "UNAUTHENTICATED"}}));
                        }
                        let value: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
                        let token = value["message"]["token"].as_str().unwrap_or("").to_owned();
                        let (status, answer) = mock.next_answer(&token);
                        if status == 200 {
                            return HttpResponse::Ok().json(json!({"name": format!("projects/{PROJECT}/messages/1")}));
                        }
                        HttpResponse::build(actix_web::http::StatusCode::from_u16(status).unwrap())
                            .json(answer)
                    }
                }),
            )
    })
    .workers(1)
    .disable_signals()
    .shutdown_timeout(1)
    .bind(("127.0.0.1", 0))
    .unwrap();
    let url = format!("http://{}", server.addrs()[0]);
    let server = server.run();
    let handle = server.handle();
    actix_web::rt::spawn(server);
    MockServer { url, mock, handle }
}

/// APNs configuration pointing both endpoints at mocks.
pub fn apns_config(dir: &TempDir, key: &EcKey, production: &str, sandbox: &str) -> ApnsConfig {
    ApnsConfig {
        key_path: dir.write("AuthKey_ABC123DEFG.p8", &key.pem),
        key_id: KEY_ID.to_owned(),
        team_id: TEAM_ID.to_owned(),
        topic: TOPIC.to_owned(),
        production_url: production.to_owned(),
        sandbox_url: sandbox.to_owned(),
    }
}

/// FCM configuration with a service-account file whose `token_uri` is the mock.
pub fn fcm_config(dir: &TempDir, key: &RsaKey, url: &str) -> FcmConfig {
    let account = json!({
        "type": "service_account",
        "project_id": PROJECT,
        "private_key_id": "test",
        "private_key": key.pem,
        "client_email": CLIENT_EMAIL,
        "token_uri": format!("{url}/token"),
    });
    FcmConfig {
        project_id: PROJECT.to_owned(),
        service_account_path: dir.write("service-account.json", &account.to_string()),
        url: url.to_owned(),
    }
}
