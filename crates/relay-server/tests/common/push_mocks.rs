//! Mock push providers for the `POST /v1/push` tests: an APNs endpoint over
//! HTTP/2 without TLS and an FCM endpoint with its OAuth token URI, keyed on
//! the device token. Keys are generated per run and written to a temporary
//! directory; nothing is stored in the repository. The provider protocol
//! details are tested in `relay-push`.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use actix_web::dev::ServerHandle;
use actix_web::{App, HttpRequest, HttpResponse, HttpServer, web};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use relay_push::{ApnsConfig, FcmConfig, PushConfig};
use ring::rand::SystemRandom;
use ring::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair};
use rsa::pkcs8::{EncodePrivateKey, LineEnding};
use serde_json::{Value, json};

pub const TOPIC: &str = "app.handlive.ios";

/// One request a mock received: `(path, headers, body)`.
pub type Request = (String, Vec<(String, String)>, Value);

#[derive(Default)]
pub struct Seen(pub Mutex<Vec<Request>>);

impl Seen {
    fn record(&self, req: &HttpRequest, body: &[u8]) {
        let headers = req
            .headers()
            .iter()
            .map(|(k, v)| (k.as_str().to_owned(), v.to_str().unwrap_or("").to_owned()))
            .collect();
        let body = serde_json::from_slice(body).unwrap_or(Value::Null);
        self.0
            .lock()
            .unwrap()
            .push((req.path().to_owned(), headers, body));
    }

    pub fn count(&self) -> usize {
        self.0.lock().unwrap().len()
    }

    pub fn last(&self) -> Request {
        self.0.lock().unwrap().last().cloned().expect("a request")
    }
}

pub struct Providers {
    pub apns: Arc<Seen>,
    pub fcm: Arc<Seen>,
    pub config: PushConfig,
    handles: Vec<ServerHandle>,
    dir: PathBuf,
}

impl Providers {
    pub async fn stop(&self) {
        for h in &self.handles {
            h.stop(false).await;
        }
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

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

/// APNs answers: token `dead…` → 410, `bad0…` → 400, anything else → 200.
/// FCM answers: token `gone` → 404 UNREGISTERED, `down` → 503, else 200.
pub async fn start() -> Providers {
    let apns = Arc::new(Seen::default());
    let fcm = Arc::new(Seen::default());

    let seen = apns.clone();
    let apns_server = HttpServer::new(move || {
        let seen = seen.clone();
        App::new().route(
            "/3/device/{token}",
            web::post().to(move |req: HttpRequest, body: web::Bytes| {
                let seen = seen.clone();
                async move {
                    seen.record(&req, &body);
                    let token = req.match_info().get("token").unwrap_or("");
                    if token.starts_with("dead") {
                        HttpResponse::Gone().json(json!({"reason": "Unregistered"}))
                    } else if token.starts_with("bad0") {
                        HttpResponse::BadRequest().json(json!({"reason": "BadDeviceToken"}))
                    } else {
                        HttpResponse::Ok().insert_header(("apns-id", "1")).finish()
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
    let apns_url = format!("http://{}", apns_server.addrs()[0]);

    let seen = fcm.clone();
    let fcm_server = HttpServer::new(move || {
        let seen = seen.clone();
        App::new()
            .route(
                "/token",
                web::post().to(|| async {
                    HttpResponse::Ok().json(json!({"access_token": "mock", "expires_in": 3600}))
                }),
            )
            .route(
                "/v1/projects/{project}/messages:send",
                web::post().to(move |req: HttpRequest, body: web::Bytes| {
                    let seen = seen.clone();
                    async move {
                        seen.record(&req, &body);
                        let v: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
                        match v["message"]["token"].as_str() {
                            Some("gone") => HttpResponse::NotFound().json(json!({"error": {
                                "status": "NOT_FOUND", "details": [{"errorCode": "UNREGISTERED"}]}})),
                            Some("down") => HttpResponse::ServiceUnavailable()
                                .json(json!({"error": {"status": "UNAVAILABLE"}})),
                            _ => HttpResponse::Ok().json(json!({"name": "projects/p/messages/1"})),
                        }
                    }
                }),
            )
    })
    .workers(1)
    .disable_signals()
    .shutdown_timeout(1)
    .bind(("127.0.0.1", 0))
    .unwrap();
    let fcm_url = format!("http://{}", fcm_server.addrs()[0]);

    let mut handles = Vec::new();
    for server in [apns_server.run(), fcm_server.run()] {
        handles.push(server.handle());
        actix_web::rt::spawn(server);
    }

    let dir = std::env::temp_dir().join(format!("hl-push-{}", uuid::Uuid::new_v4().simple()));
    std::fs::create_dir_all(&dir).unwrap();
    let rng = SystemRandom::new();
    let ec = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
    let key_path = dir.join("AuthKey.p8");
    std::fs::write(&key_path, pem("PRIVATE KEY", ec.as_ref())).unwrap();
    let rsa_key = rsa::RsaPrivateKey::new(&mut rsa::rand_core::OsRng, 2048).unwrap();
    let account = json!({
        "client_email": "relay@test.iam.gserviceaccount.com",
        "private_key": rsa_key.to_pkcs8_pem(LineEnding::LF).unwrap().to_string(),
        "token_uri": format!("{fcm_url}/token"),
    });
    let account_path = dir.join("service-account.json");
    std::fs::write(&account_path, account.to_string()).unwrap();

    let config = PushConfig {
        apns: Some(ApnsConfig {
            key_path,
            key_id: "ABC123DEFG".to_owned(),
            team_id: "DEF123GHIJ".to_owned(),
            topic: TOPIC.to_owned(),
            production_url: apns_url.clone(),
            sandbox_url: apns_url,
        }),
        fcm: Some(FcmConfig {
            project_id: "handlive-test".to_owned(),
            service_account_path: account_path,
            url: fcm_url,
        }),
    };
    Providers {
        apns,
        fcm,
        config,
        handles,
        dir,
    }
}
