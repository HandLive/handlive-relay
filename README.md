English | [Tiếng Việt](README.vi.md)

# handlive-relay

The HandLive cloud relay carries traffic between devices that are not on the same local network. The relay never reads content. It only forwards end-to-end encrypted data, never decrypts it and never logs content. Logs carry only path, status, size and error code.

Rust, actix-web 4 + actix-ws, sqlx/PostgreSQL 16, Redis 7. The relay has no user interface and sends no user-facing text: errors are codes, and devices localize them (detailed design 0.12).

This repository is one part of the HandLive workspace: the hub repository
`handlive` (docs, plans) is the parent directory and `../shared` is the
`handlive-shared` repository (tests read `../shared/test-vectors`). Clone the
set from the hub with `tools/workspace.sh clone <group-url>`; see `CLAUDE.md`.

## Endpoints

Specification: `../docs/detailed-design/00-common-specs.md` (0.4.3, 0.6.4, 0.7.3, 0.7.4, 0.8.2, 0.8.3, 0.9.4) and the leaf functions named below.

| Method | Path | Auth | Spec |
|--------|------|------|------|
| POST | `/v1/devices` | `HLREG1` signature | CONN-03 API 1; at most 10 new devices per client IP per hour |
| POST | `/v1/auth/challenge` | — | 0.6.4, CONN-03 API 2 |
| POST | `/v1/auth/token` | — | 0.6.4, CONN-03 API 3 (JWT HS256, 900 s) |
| PUT | `/v1/devices/me/push-token` | JWT | CONN-04 API 1 |
| DELETE | `/v1/devices/me?revoke_pairs=<bool>` | JWT | SET-02 API 2, decision C16 |
| POST | `/v1/pairs` | JWT | PAIR-01 API 8 (attestation + two signatures) |
| GET | `/v1/pairs[?include_revoked=<bool>]` | JWT | PAIR-02 API 1 |
| POST | `/v1/pairs/{pair_id}/revoke` | JWT | PAIR-03 API 3 |
| POST | `/v1/push` | JWT | CONN-04 API 2–4 (FCM wake, APNs alert) |
| GET (WebSocket) | `/v1/relay` | JWT | CONN-03 API 4–6, PAIR-01 API 7, PAIR-03 API 4 |

Every JWT endpoint checks that the device still exists (404 `DEVICE_NOT_FOUND`, 410 `DEVICE_REVOKED`) and counts against 60 calls per minute per device (429 with `Retry-After`); `POST /v1/push` has its own limit of 30 per minute per sender.

### Push (`crates/relay-push`)

- `wake` → FCM HTTP v1 to the Android phone: a high-priority data message `{t: "wake", p: <pair_id>, r: <reason>}`, TTL at most 60 s, no content. OAuth2 access token from the service-account key, reused until five minutes before it expires.
- `alert` → APNs over HTTP/2 to the iPhone/iPad: `apns-push-type: alert`, `apns-priority: 10`, `apns-expiration`, `apns-collapse-id`, `apns-topic`; the payload has only `aps.alert.loc-key` (`push.sms_new`, `push.call_incoming`, `push.call_missed`), `mutable-content`, `sound`, `thread-id` (`sms` or `calls`), `interruption-level`, plus `p` (pair_id) and `hl` (the envelope encrypted with `K_push`, not kept). The relay sends no display text. The ES256 provider token is renewed every 50 minutes.
- The target must be the other member of a valid pair (403), have a token (409 `PUSH_TOKEN_MISSING`); a wake with the same reason within 5 minutes answers 202 without a second send; a token the provider reports dead is deleted (409); provider errors answer 502 `PUSH_PROVIDER_ERROR` after one retry of 500/503 or network errors. Queuing and retrying failed pushes until their deadline is the phone's `push_outbox` (spec 0.9.1).

### The relay channel `/v1/relay`

- Text frames `{"to","env"}` become `{"from","env"}` with `env` copied byte for byte; binary `HR` frames (`0x48 0x52` ‖ ver ‖ op ‖ device_id ‖ HL frame) get the source `device_id` in place of the destination. Only the two devices of a valid pair reach each other (`error NOT_PAIRED`); an unreachable peer gets `error NOT_CONNECTED`; frames over 256 KiB get `error PAYLOAD_TOO_LARGE`; over 2 MiB/s per pair the relay delays reading instead of dropping.
- Control ops: `presence` (every pair on connect, then on each change), `pair_revoked` (at once, on reconnect for 30 days, and from `revoked_notice`), `rv_join` / `rv_joined` / `rv_msg` (pairing rendezvous: two members, 180 s, `pair` envelopes only, no PIN hello), `error`.
- Several instances share the work (decision C5): `presence:<device_id>` names the instance holding a device, and instances forward to each other through the Redis channel `dev:<device_id>`. After a Redis restart an instance subscribes again and restores presence without dropping the devices.
- Close codes: 1000 (the device removed itself), 4400 (malformed stream), 4409 (replaced by a newer connection), 4411 (silent for 45 s; the relay pings every 15 s), 4500 (internal).
- Statistics: envelopes, bytes and pushes per `device_hash` = SHA-256(device_id ‖ monthly salt), the salt living 40 days in Redis only; a daily job deletes statistics after 30 days and devices inactive for 180 days.

## Layout

```
relay/
  Cargo.toml              workspace (pins the relay stack)
  docker-compose.yml      dev PostgreSQL 16 + Redis 7
  .env.example            dev placeholders; copy to .env (gitignored)
  migrations/             sqlx migrations, applied at server start
  crates/relay-server/    the server (lib + bin); tests/ holds all tests
  crates/relay-push/      push proxy: APNs (HTTP/2, .p8 token) and FCM (HTTP v1, OAuth2)
    src/routes/           REST handlers and the /v1/relay upgrade
    src/relay/            relay channel: wire formats, Redis bus and hub,
                          presence, rendezvous, bandwidth, connection task
    src/store/            PostgreSQL queries (devices, pairs, usage_daily)
```

## Development

Rust toolchain on PATH (e.g. `export PATH=/opt/homebrew/opt/rustup/bin:$PATH`).

```bash
cd relay
cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test
```

`cargo test` needs no services: tests that need PostgreSQL and Redis are `#[ignore]`d.

### With PostgreSQL + Redis

Host ports are shifted to avoid clashing with a local PostgreSQL/Redis:
PostgreSQL `127.0.0.1:55432`, Redis `127.0.0.1:56379`.

```bash
cd relay
docker compose up -d --wait
set -a && . ./.env.example && set +a      # or your own .env
cargo test -- --ignored                   # integration tests (real WebSockets, two instances)
cargo run -p relay-server                 # applies migrations, listens on RELAY_BIND
docker compose down -v                    # stop and drop the dev volume
```

`tests/relay_redis_restart.rs` flushes the Redis database; run the integration tests against a dev Redis only, one test binary at a time (the default of `cargo test`). The push tests use local mock APNs/FCM servers and keys generated per run; no real credentials are needed.

Load test from one machine (`../shared/tools/bench/relay_load.py`): start the relay with `RELAY_TRUSTED_PROXIES=127.0.0.1`; the script sends one `X-Forwarded-For` address per simulated device, so the limit of 10 new registrations per hour applies per simulated address instead of to 127.0.0.1.

## Configuration

| Variable | Meaning |
|----------|---------|
| `DATABASE_URL` | PostgreSQL URL |
| `REDIS_URL` | Redis URL |
| `RELAY_JWT_SECRET` | HS256 key for device JWTs, ≥ 32 bytes (`openssl rand -base64 48`). Never commit it |
| `RELAY_BIND` | Listen address, default `127.0.0.1:8080` |
| `RELAY_INSTANCE_ID` | Optional name of this instance in `presence:<device_id>`; default a random UUID per start |
| `RELAY_TRUSTED_PROXIES` | Optional comma-separated IPs of reverse proxies whose `X-Forwarded-For` is believed for the per-IP registration limit; without it the TCP peer address counts |
| `RELAY_APNS_KEY_PATH` | Path of the APNs `.p8` provider key (outside the repository). APNs is enabled when this and the next three are set |
| `RELAY_APNS_KEY_ID` | Key id of the `.p8` key (JWT `kid`) |
| `RELAY_APNS_TEAM_ID` | Apple team id (JWT `iss`) |
| `RELAY_APNS_TOPIC` | Bundle id of the iOS app (`app.handlive.ios`); push tokens must name it |
| `RELAY_APNS_URL`, `RELAY_APNS_SANDBOX_URL` | Optional APNs endpoints, default `https://api.push.apple.com` and `https://api.sandbox.push.apple.com` (`apns_sandbox` tokens) |
| `RELAY_FCM_PROJECT_ID` | Firebase project id. FCM is enabled when this and the next are set |
| `RELAY_FCM_SERVICE_ACCOUNT_PATH` | Path of the Google service-account JSON (`client_email`, `private_key`, `token_uri`), outside the repository |
| `RELAY_FCM_URL` | Optional FCM endpoint, default `https://fcm.googleapis.com` |
| `RUST_LOG` | Log filter, default `info` |

Keys are read from files at start-up; a partial APNs or FCM set, or an unreadable key, stops the relay. Without a provider, pushes of that kind answer 502. Never commit keys, service-account files or `.env`.

## License

Apache License 2.0 — see [LICENSE](LICENSE). Contributions follow the org [CONTRIBUTING](https://github.com/HandLive/.github/blob/main/CONTRIBUTING.md) (small commits under a real name, DCO sign-off with `git commit -s`); report vulnerabilities privately per [SECURITY](https://github.com/HandLive/.github/blob/main/SECURITY.md).
