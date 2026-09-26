[English](README.md) | Tiếng Việt

# handlive-relay

Máy chủ chuyển tiếp khi các thiết bị không cùng mạng. Relay không đọc nội dung. Relay chỉ chuyển tiếp dữ liệu đã mã hóa đầu-cuối, không giải mã và không ghi nội dung vào log. Log chỉ có đường dẫn, mã trạng thái, kích thước và mã lỗi.

Rust, actix-web 4 + actix-ws, sqlx/PostgreSQL 16, Redis 7. Relay không có giao diện và không gửi câu chữ hiển thị. Lỗi là mã. Thiết bị tự dịch mã theo ngôn ngữ đang dùng (thiết kế chi tiết 0.12).

Kho này là một phần của workspace HandLive: kho hub `handlive` (tài liệu, kế hoạch) là thư mục cha, `../shared` là kho `handlive-shared` (test đọc `../shared/test-vectors`). Clone cả bộ từ hub bằng `tools/workspace.sh clone <group-url>`; xem `CLAUDE.md`.

## Endpoint

Đặc tả: `../docs/detailed-design/00-common-specs.md` (0.4.3, 0.6.4, 0.7.3, 0.7.4, 0.8.2, 0.8.3, 0.9.4) và các chức năng lá ghi trong bảng.

| Method | Đường dẫn | Xác thực | Đặc tả |
|--------|-----------|----------|--------|
| POST | `/v1/devices` | Chữ ký `HLREG1` | CONN-03 API 1; tối đa 10 thiết bị mới mỗi giờ cho một IP |
| POST | `/v1/auth/challenge` | — | 0.6.4, CONN-03 API 2 |
| POST | `/v1/auth/token` | — | 0.6.4, CONN-03 API 3 (JWT HS256, 900 s) |
| PUT | `/v1/devices/me/push-token` | JWT | CONN-04 API 1 |
| DELETE | `/v1/devices/me?revoke_pairs=<bool>` | JWT | SET-02 API 2, quyết định C16 |
| POST | `/v1/pairs` | JWT | PAIR-01 API 8 (attestation + hai chữ ký) |
| GET | `/v1/pairs[?include_revoked=<bool>]` | JWT | PAIR-02 API 1 |
| POST | `/v1/pairs/{pair_id}/revoke` | JWT | PAIR-03 API 3 |
| GET (WebSocket) | `/v1/relay` | JWT | CONN-03 API 4–6, PAIR-01 API 7, PAIR-03 API 4 |

Mọi endpoint dùng JWT đều kiểm thiết bị còn tồn tại (404 `DEVICE_NOT_FOUND`, 410 `DEVICE_REVOKED`) và tính vào giới hạn 60 lời gọi mỗi phút cho mỗi thiết bị (429 kèm `Retry-After`).

### Kênh relay `/v1/relay`

- Khung text `{"to","env"}` thành `{"from","env"}`, `env` được chép nguyên từng byte; khung nhị phân `HR` (`0x48 0x52` ‖ ver ‖ op ‖ device_id ‖ khung HL) được thay `device_id` đích bằng `device_id` nguồn. Chỉ hai thiết bị của một cặp hợp lệ gửi được cho nhau (`error NOT_PAIRED`); thiết bị đích không kết nối nhận `error NOT_CONNECTED`; khung quá 256 KiB nhận `error PAYLOAD_TOO_LARGE`; quá 2 MiB/s mỗi cặp thì relay đọc chậm lại chứ không bỏ khung.
- Thông điệp điều khiển: `presence` (mọi cặp khi vừa kết nối, rồi mỗi lần thay đổi), `pair_revoked` (ngay lập tức, khi kết nối lại trong 30 ngày, và từ `revoked_notice`), `rv_join` / `rv_joined` / `rv_msg` (điểm hẹn ghép nối: hai thành viên, 180 s, chỉ envelope `pair`, chặn hello bằng PIN), `error`.
- Nhiều instance cùng chạy (quyết định C5): `presence:<device_id>` ghi instance đang giữ kết nối của thiết bị, các instance chuyển tiếp cho nhau qua kênh Redis `dev:<device_id>`. Sau khi Redis khởi động lại, instance đăng ký kênh lại và khôi phục presence mà không ngắt thiết bị.
- Mã đóng: 1000 (thiết bị tự gỡ khỏi relay), 4400 (luồng sai định dạng), 4409 (bị kết nối mới thay thế), 4411 (im lặng 45 s; relay ping mỗi 15 s), 4500 (lỗi nội bộ).
- Thống kê: số envelope, số byte và số push theo `device_hash` = SHA-256(device_id ‖ muối theo tháng), muối chỉ nằm trong Redis 40 ngày; tác vụ hằng ngày xóa thống kê quá 30 ngày và thiết bị không hoạt động 180 ngày.

## Bố cục

```
relay/
  Cargo.toml              workspace (ghim phiên bản bộ thư viện relay)
  docker-compose.yml      PostgreSQL 16 + Redis 7 cho dev
  .env.example            giá trị giữ chỗ cho dev; chép thành .env (gitignore)
  migrations/             migration sqlx, chạy khi server khởi động
  crates/relay-server/    server (lib + bin); tests/ chứa mọi test
    src/routes/           handler REST và phần nâng cấp /v1/relay
    src/relay/            kênh relay: định dạng khung, bus và hub Redis,
                          presence, điểm hẹn, băng thông, tác vụ kết nối
    src/store/            truy vấn PostgreSQL (devices, pairs, usage_daily)
```

## Phát triển

Cần Rust toolchain trên PATH (ví dụ `export PATH=/opt/homebrew/opt/rustup/bin:$PATH`).

```bash
cd relay
cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test
```

`cargo test` không cần dịch vụ nào: test cần PostgreSQL và Redis được đánh dấu `#[ignore]`.

### Với PostgreSQL + Redis

Cổng host đã dời để không đụng PostgreSQL/Redis cục bộ: PostgreSQL `127.0.0.1:55432`, Redis `127.0.0.1:56379`.

```bash
cd relay
docker compose up -d --wait
set -a && . ./.env.example && set +a      # hoặc .env của bạn
cargo test -- --ignored                   # test tích hợp (WebSocket thật, hai instance)
cargo run -p relay-server                 # chạy migration, lắng nghe ở RELAY_BIND
docker compose down -v                    # dừng và xóa volume dev
```

`tests/relay_redis_restart.rs` xóa sạch cơ sở dữ liệu Redis; chỉ chạy test tích hợp với Redis dev, mỗi lần một file test (mặc định của `cargo test`).

## Cấu hình

| Biến | Ý nghĩa |
|------|---------|
| `DATABASE_URL` | URL PostgreSQL |
| `REDIS_URL` | URL Redis |
| `RELAY_JWT_SECRET` | Khóa HS256 cho JWT của thiết bị, ≥ 32 byte (`openssl rand -base64 48`). Không bao giờ commit |
| `RELAY_BIND` | Địa chỉ lắng nghe, mặc định `127.0.0.1:8080` |
| `RELAY_INSTANCE_ID` | Tùy chọn: tên instance ghi vào `presence:<device_id>`; mặc định một UUID ngẫu nhiên mỗi lần khởi động |
| `RELAY_TRUSTED_PROXIES` | Tùy chọn: danh sách IP (phân tách bằng dấu phẩy) của reverse proxy được tin `X-Forwarded-For` cho giới hạn đăng ký theo IP; không đặt thì dùng địa chỉ TCP của bên kết nối |
| `RUST_LOG` | Bộ lọc log, mặc định `info` |

## Giấy phép

Apache License 2.0 — xem [LICENSE](LICENSE). Đóng góp theo [CONTRIBUTING](https://github.com/HandLive/.github/blob/main/CONTRIBUTING.vi.md) (commit nhỏ, đứng tên người thật, ký DCO bằng `git commit -s`); báo lỗ hổng bảo mật kín theo [SECURITY](https://github.com/HandLive/.github/blob/main/SECURITY.vi.md).
