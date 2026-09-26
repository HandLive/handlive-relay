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
| GET (WebSocket) | `/v1/relay` | JWT | CONN-03 API 4–6, PAIR-01 API 7, PAIR-03 API 4 |

Every JWT endpoint checks that the device still exists (404 `DEVICE_NOT_FOUND`, 410 `DEVICE_REVOKED`) and counts against 60 calls per minute per device (429 with `Retry-After`).

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

`tests/relay_redis_restart.rs` flushes the Redis database; run the integration tests against a dev Redis only, one test binary at a time (the default of `cargo test`).

## Configuration

| Variable | Meaning |
|----------|---------|
| `DATABASE_URL` | PostgreSQL URL |
| `REDIS_URL` | Redis URL |
| `RELAY_JWT_SECRET` | HS256 key for device JWTs, ≥ 32 bytes (`openssl rand -base64 48`). Never commit it |
| `RELAY_BIND` | Listen address, default `127.0.0.1:8080` |
| `RELAY_INSTANCE_ID` | Optional name of this instance in `presence:<device_id>`; default a random UUID per start |
| `RELAY_TRUSTED_PROXIES` | Optional comma-separated IPs of reverse proxies whose `X-Forwarded-For` is believed for the per-IP registration limit; without it the TCP peer address counts |
| `RUST_LOG` | Log filter, default `info` |

## License

Apache License 2.0 — see [LICENSE](LICENSE). Contributions follow the org [CONTRIBUTING](https://github.com/HandLive/.github/blob/main/CONTRIBUTING.md) (small commits under a real name, DCO sign-off with `git commit -s`); report vulnerabilities privately per [SECURITY](https://github.com/HandLive/.github/blob/main/SECURITY.md).
