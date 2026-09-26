//! Harness for relay channel tests: real relay instances listening on
//! 127.0.0.1 (PostgreSQL + Redis from the environment) and real WebSocket
//! clients. REST calls go through an in-process service sharing the
//! instance's state, so the registration IP limit does not interfere.

use std::net::SocketAddr;
use std::time::Duration;

use actix_web::dev::ServerHandle;
use actix_web::http::StatusCode;
use actix_web::{App, HttpServer, test, web};
use futures_util::{SinkExt, StreamExt};
use redis::AsyncCommands;
use relay_server::attestation::Attestation;
use relay_server::clock::now_ms;
use relay_server::config::{Config, RelaySettings};
use relay_server::relay::presence::presence_key;
use relay_server::state::AppState;
use relay_server::{MIGRATOR, access_log, b64u, configure};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};
use uuid::Uuid;

use super::TestDevice;
use super::http_harness::{TEST_JWT_SECRET, TestService, code, post};

/// How long a test waits for an expected frame.
pub const WAIT: Duration = Duration::from_secs(5);

/// Spec defaults, without the per-IP registration limit.
pub fn test_settings() -> RelaySettings {
    RelaySettings {
        registrations_per_ip_per_hour: u64::MAX,
        ..RelaySettings::default()
    }
}

pub struct Relay {
    pub addr: SocketAddr,
    pub state: web::Data<AppState>,
    pub server: ServerHandle,
}

impl Relay {
    pub async fn start(settings: RelaySettings) -> Relay {
        let config = Config {
            database_url: std::env::var("DATABASE_URL").expect("DATABASE_URL"),
            redis_url: std::env::var("REDIS_URL").expect("REDIS_URL"),
            jwt_secret: TEST_JWT_SECRET.as_bytes().to_vec(),
            bind: String::new(),
            settings,
            push: Default::default(),
        };
        let state = web::Data::new(AppState::connect(&config).await.expect("connect"));
        MIGRATOR.run(&state.db).await.expect("migrate");
        let app_state = state.clone();
        let server = HttpServer::new(move || {
            App::new()
                .app_data(app_state.clone())
                .wrap(access_log())
                .configure(configure)
        })
        .workers(1)
        .disable_signals()
        .bind(("127.0.0.1", 0))
        .expect("bind")
        .shutdown_timeout(1);
        let addr = server.addrs()[0];
        let server = server.run();
        let handle = server.handle();
        actix_web::rt::spawn(server);
        Relay {
            addr,
            state,
            server: handle,
        }
    }

    pub async fn stop(&self) {
        self.server.stop(false).await;
    }

    /// Wait until the device's connection is set up (its presence is set).
    pub async fn wait_present(&self, device_id: &Uuid) {
        let mut redis = self.state.redis.clone();
        for _ in 0..100 {
            let present: bool = redis.exists(presence_key(device_id)).await.unwrap();
            if present {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!("device never became present");
    }
}

/// In-process REST service over the relay's state.
macro_rules! rest {
    ($relay:expr) => {
        ::actix_web::test::init_service(
            ::actix_web::App::new()
                .app_data($relay.state.clone())
                .configure(::relay_server::configure),
        )
        .await
    };
}
pub(crate) use rest;

/// A registered device with a fresh access token.
pub struct Member {
    pub device: TestDevice,
    pub token: String,
}

impl Member {
    pub fn id(&self) -> Uuid {
        self.device.device_id
    }
}

pub async fn enroll(app: &impl TestService, platform: &str) -> Member {
    let device = TestDevice::random();
    let (status, body) = post(
        app,
        "/v1/devices",
        &device.registration_body(platform, now_ms()),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let token = super::http_harness::login(app, &device).await;
    Member { device, token }
}

/// Body of `POST /v1/pairs` signed by both devices.
pub fn pair_body(
    pair_id: Uuid,
    android: &TestDevice,
    client: &TestDevice,
    created_at: i64,
) -> Value {
    let attestation = Attestation {
        pair_id,
        device_a: android.device_id,
        device_b: client.device_id,
        ik_sig_pub_a: android.public,
        ik_sig_pub_b: client.public,
        created_at_ms: created_at,
    }
    .to_bytes();
    json!({
        "pair_id": pair_id,
        "device_a": android.device_id,
        "device_b": client.device_id,
        "created_at": created_at,
        "attestation": b64u::encode(&attestation),
        "sig_a": b64u::encode(&android.sign(&attestation)),
        "sig_b": b64u::encode(&client.sign(&attestation)),
    })
}

pub async fn call(
    app: &impl TestService,
    method: &str,
    path: &str,
    token: &str,
    body: Option<&Value>,
) -> (StatusCode, Value) {
    let req = match method {
        "GET" => test::TestRequest::get(),
        "POST" => test::TestRequest::post(),
        "PUT" => test::TestRequest::put(),
        "DELETE" => test::TestRequest::delete(),
        other => panic!("method {other}"),
    }
    .uri(path)
    .insert_header(("Authorization", format!("Bearer {token}")));
    let req = match body {
        Some(b) => req.set_json(b),
        None => req,
    };
    super::http_harness::read(test::call_service(app, req.to_request()).await).await
}

/// Register a pair (the client calls `POST /v1/pairs`); returns `pair_id`.
pub async fn pair(app: &impl TestService, android: &Member, client: &Member) -> Uuid {
    let pair_id = Uuid::new_v4();
    let body = pair_body(pair_id, &android.device, &client.device, now_ms());
    let (status, resp) = call(app, "POST", "/v1/pairs", &client.token, Some(&body)).await;
    assert_eq!(status, StatusCode::CREATED, "{resp} {}", code(&resp));
    pair_id
}

pub type Socket = WebSocketStream<MaybeTlsStream<TcpStream>>;

/// What reading the socket produced.
#[derive(Debug)]
pub enum Event {
    Frame(Message),
    /// The socket ended or failed.
    Dropped,
    Timeout,
}

/// How the relay ended a connection.
#[derive(Debug, PartialEq, Eq)]
pub enum Ending {
    Code(u16),
    NoCode,
    /// Gone without a readable close frame (e.g. reset while data was in flight).
    Dropped,
}

/// A device's relay connection.
pub struct WsClient {
    pub ws: Socket,
}

/// Open `/v1/relay`; on refusal returns the HTTP status and error body.
pub async fn try_connect(relay: &Relay, token: &str) -> Result<WsClient, (u16, Value)> {
    let mut req = format!("ws://{}/v1/relay", relay.addr)
        .into_client_request()
        .unwrap();
    req.headers_mut()
        .insert("Authorization", format!("Bearer {token}").parse().unwrap());
    match tokio_tungstenite::connect_async(req).await {
        Ok((ws, _)) => Ok(WsClient { ws }),
        Err(tokio_tungstenite::tungstenite::Error::Http(resp)) => {
            let status = resp.status().as_u16();
            let body = resp
                .body()
                .as_ref()
                .and_then(|b| serde_json::from_slice(b).ok())
                .unwrap_or(Value::Null);
            Err((status, body))
        }
        Err(e) => panic!("connect: {e}"),
    }
}

pub async fn connect(relay: &Relay, member: &Member) -> WsClient {
    let client = try_connect(relay, &member.token)
        .await
        .unwrap_or_else(|(s, b)| panic!("connect refused: {s} {b}"));
    relay.wait_present(&member.id()).await;
    client
}

impl WsClient {
    pub async fn send_json(&mut self, value: &Value) {
        self.send_text(value.to_string()).await;
    }

    pub async fn send_text(&mut self, text: String) {
        self.ws.send(Message::text(text)).await.expect("send");
    }

    pub async fn send_binary(&mut self, bytes: Vec<u8>) {
        self.ws.send(Message::binary(bytes)).await.expect("send");
    }

    /// Next data or close frame within `wait` (pings are answered and skipped).
    pub async fn next(&mut self, wait: Duration) -> Option<Message> {
        match self.event(wait).await {
            Event::Frame(m) => Some(m),
            Event::Dropped | Event::Timeout => None,
        }
    }

    /// Next data or close frame, the socket ending, or nothing within `wait`.
    pub async fn event(&mut self, wait: Duration) -> Event {
        let deadline = tokio::time::Instant::now() + wait;
        loop {
            match tokio::time::timeout_at(deadline, self.ws.next()).await {
                Err(_) => return Event::Timeout,
                Ok(None) | Ok(Some(Err(_))) => return Event::Dropped,
                Ok(Some(Ok(Message::Ping(_) | Message::Pong(_)))) => continue,
                Ok(Some(Ok(m))) => return Event::Frame(m),
            }
        }
    }

    pub async fn recv_text(&mut self) -> String {
        match self.next(WAIT).await {
            Some(Message::Text(t)) => t.to_string(),
            other => panic!("expected a text frame, got {other:?}"),
        }
    }

    pub async fn recv_json(&mut self) -> Value {
        serde_json::from_str(&self.recv_text().await).expect("json frame")
    }

    pub async fn recv_binary(&mut self) -> Vec<u8> {
        match self.next(WAIT).await {
            Some(Message::Binary(b)) => b.to_vec(),
            other => panic!("expected a binary frame, got {other:?}"),
        }
    }

    /// Nothing but pings within `wait`.
    pub async fn expect_quiet(&mut self, wait: Duration) {
        if let Some(m) = self.next(wait).await {
            panic!("unexpected frame {m:?}");
        }
    }

    /// The close code the relay sent (`None` when the socket just ended).
    /// The relay's close code; panics when no close frame arrives.
    pub async fn expect_close(&mut self) -> Option<u16> {
        match self.expect_end().await {
            Ending::Code(code) => Some(code),
            Ending::NoCode => None,
            Ending::Dropped => panic!("socket dropped without a close frame"),
        }
    }

    /// How the connection ended; panics on a data frame or a timeout.
    pub async fn expect_end(&mut self) -> Ending {
        match self.event(WAIT).await {
            Event::Frame(Message::Close(Some(frame))) => Ending::Code(u16::from(frame.code)),
            Event::Frame(Message::Close(None)) => Ending::NoCode,
            Event::Dropped => Ending::Dropped,
            Event::Timeout => panic!("the connection did not end"),
            Event::Frame(other) => panic!("expected close, got {other:?}"),
        }
    }

    pub async fn close(mut self) {
        let _ = self.ws.close(None).await;
    }
}

/// A `presence` message for `pair_id` as the relay sends it.
pub fn presence(pair_id: Uuid, peer: Uuid, online: bool) -> Value {
    json!({"op":"presence","pair_id":pair_id,"peer_device_id":peer,"online":online})
}

/// An envelope with a recognisable payload.
pub fn envelope(kind: &str, marker: &str) -> Value {
    json!({"v":1,"type":kind,"id":Uuid::new_v4(),"ts":now_ms(),"payload":marker})
}

/// A client that completes the WebSocket upgrade and then never writes a
/// byte — not even pongs — like a peer whose network died.
pub async fn silent_connect(relay: &Relay, token: &str) -> TcpStream {
    let mut stream = TcpStream::connect(relay.addr).await.unwrap();
    let request = format!(
        "GET /v1/relay HTTP/1.1\r\nHost: {}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
         Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\
         Authorization: Bearer {token}\r\n\r\n",
        relay.addr
    );
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        stream.read_exact(&mut byte).await.unwrap();
        head.push(byte[0]);
    }
    assert!(
        head.starts_with(b"HTTP/1.1 101"),
        "{}",
        String::from_utf8_lossy(&head)
    );
    stream
}

/// Read server frames (without answering them) until the close frame;
/// returns its code, or `None` when the stream ends first.
pub async fn silent_close_code(stream: &mut TcpStream) -> Option<u16> {
    let read = async {
        loop {
            let mut head = [0u8; 2];
            stream.read_exact(&mut head).await.ok()?;
            let mut len = u64::from(head[1] & 0x7f);
            if len == 126 {
                let mut ext = [0u8; 2];
                stream.read_exact(&mut ext).await.ok()?;
                len = u64::from(u16::from_be_bytes(ext));
            } else if len == 127 {
                let mut ext = [0u8; 8];
                stream.read_exact(&mut ext).await.ok()?;
                len = u64::from_be_bytes(ext);
            }
            let mut payload = vec![0u8; len as usize];
            stream.read_exact(&mut payload).await.ok()?;
            if head[0] & 0x0f == 0x8 {
                return payload.get(..2).map(|c| u16::from_be_bytes([c[0], c[1]]));
            }
        }
    };
    tokio::time::timeout(WAIT, read)
        .await
        .expect("no close frame in time")
}
