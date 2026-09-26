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
| POST | `/v1/push` | JWT | CONN-04 API 2–4 (đánh thức qua FCM, cảnh báo qua APNs) |
| GET (WebSocket) | `/v1/relay` | JWT | CONN-03 API 4–6, PAIR-01 API 7, PAIR-03 API 4 |

Mọi endpoint dùng JWT đều kiểm thiết bị còn tồn tại (404 `DEVICE_NOT_FOUND`, 410 `DEVICE_REVOKED`) và tính vào giới hạn 60 lời gọi mỗi phút cho mỗi thiết bị (429 kèm `Retry-After`); `POST /v1/push` có giới hạn riêng 30 lần mỗi phút cho mỗi thiết bị gửi.

### Push (`crates/relay-push`)

- `wake` → FCM HTTP v1 tới điện thoại Android: tin dữ liệu ưu tiên cao `{t: "wake", p: <pair_id>, r: <reason>}`, TTL tối đa 60 s, không có nội dung. Token truy cập OAuth2 lấy bằng khóa service account, dùng lại tới năm phút trước khi hết hạn.
- `alert` → APNs qua HTTP/2 tới iPhone/iPad: `apns-push-type: alert`, `apns-priority: 10`, `apns-expiration`, `apns-collapse-id`, `apns-topic`; payload chỉ có `aps.alert.loc-key` (`push.sms_new`, `push.call_incoming`, `push.call_missed`), `mutable-content`, `sound`, `thread-id` (`sms` hoặc `calls`), `interruption-level`, cùng `p` (pair_id) và `hl` (envelope mã hóa bằng `K_push`, không lưu lại). Relay không gửi câu chữ hiển thị. Token nhà cung cấp ES256 được làm mới mỗi 50 phút.
- Thiết bị đích phải là thành viên còn lại của một cặp hợp lệ (403) và có token (409 `PUSH_TOKEN_MISSING`); `wake` cùng lý do trong 5 phút trả 202 mà không gửi lần nữa; token bị nhà cung cấp báo hỏng thì bị xóa (409); lỗi nhà cung cấp trả 502 `PUSH_PROVIDER_ERROR` sau một lần thử lại khi gặp 500/503 hoặc lỗi mạng. Việc xếp hàng và thử lại push lỗi tới hạn chót là việc của `push_outbox` trên điện thoại (đặc tả 0.9.1).

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
  crates/relay-push/      proxy push: APNs (HTTP/2, token .p8) và FCM (HTTP v1, OAuth2)
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

`tests/relay_redis_restart.rs` xóa sạch cơ sở dữ liệu Redis; chỉ chạy test tích hợp với Redis dev, mỗi lần một file test (mặc định của `cargo test`). Test push dùng máy chủ APNs/FCM giả chạy cục bộ và khóa sinh ra mỗi lần chạy; không cần thông tin xác thực thật.

Kiểm thử tải trên một máy (`../shared/tools/bench/relay_load.py`): chạy relay với `RELAY_TRUSTED_PROXIES=127.0.0.1`; script gửi mỗi thiết bị giả một địa chỉ `X-Forwarded-For`, nên giới hạn 10 đăng ký mới mỗi giờ áp cho từng địa chỉ giả thay vì cho 127.0.0.1.

## Cấu hình

| Biến | Ý nghĩa |
|------|---------|
| `DATABASE_URL` | URL PostgreSQL |
| `REDIS_URL` | URL Redis |
| `RELAY_JWT_SECRET` | Khóa HS256 cho JWT của thiết bị, ≥ 32 byte (`openssl rand -base64 48`). Không bao giờ commit |
| `RELAY_BIND` | Địa chỉ lắng nghe, mặc định `127.0.0.1:8080` |
| `RELAY_INSTANCE_ID` | Tùy chọn: tên instance ghi vào `presence:<device_id>`; mặc định một UUID ngẫu nhiên mỗi lần khởi động |
| `RELAY_TRUSTED_PROXIES` | Tùy chọn: danh sách IP (phân tách bằng dấu phẩy) của reverse proxy được tin `X-Forwarded-For` cho giới hạn đăng ký theo IP; không đặt thì dùng địa chỉ TCP của bên kết nối |
| `RELAY_APNS_KEY_PATH` | Đường dẫn khóa nhà cung cấp APNs `.p8` (nằm ngoài kho). APNs bật khi biến này và ba biến sau đều được đặt |
| `RELAY_APNS_KEY_ID` | Mã khóa của khóa `.p8` (`kid` của JWT) |
| `RELAY_APNS_TEAM_ID` | Mã nhóm Apple (`iss` của JWT) |
| `RELAY_APNS_TOPIC` | Bundle id của ứng dụng iOS (`app.handlive.ios`); token push phải ghi đúng giá trị này |
| `RELAY_APNS_URL`, `RELAY_APNS_SANDBOX_URL` | Tùy chọn: endpoint APNs, mặc định `https://api.push.apple.com` và `https://api.sandbox.push.apple.com` (token `apns_sandbox`) |
| `RELAY_FCM_PROJECT_ID` | Mã dự án Firebase. FCM bật khi biến này và biến sau đều được đặt |
| `RELAY_FCM_SERVICE_ACCOUNT_PATH` | Đường dẫn file JSON service account của Google (`client_email`, `private_key`, `token_uri`), nằm ngoài kho |
| `RELAY_FCM_URL` | Tùy chọn: endpoint FCM, mặc định `https://fcm.googleapis.com` |
| `RUST_LOG` | Bộ lọc log, mặc định `info` |

Khóa được đọc từ file khi khởi động; bộ biến APNs hoặc FCM thiếu một phần, hoặc khóa không đọc được, sẽ khiến relay dừng. Không có nhà cung cấp nào thì push loại đó trả 502. Không bao giờ commit khóa, file service account hay `.env`.

## Giấy phép

Apache License 2.0 — xem [LICENSE](LICENSE). Đóng góp theo [CONTRIBUTING](https://github.com/HandLive/.github/blob/main/CONTRIBUTING.vi.md) (commit nhỏ, đứng tên người thật, ký DCO bằng `git commit -s`); báo lỗ hổng bảo mật kín theo [SECURITY](https://github.com/HandLive/.github/blob/main/SECURITY.vi.md).
