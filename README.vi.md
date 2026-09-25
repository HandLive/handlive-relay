[English](README.md) | Tiếng Việt

# handlive-relay

Máy chủ trung gian của HandLive khi các thiết bị không cùng mạng nội bộ. Relay không đọc nội dung: chỉ chuyển tiếp dữ liệu đã mã hóa đầu-cuối, không giải mã và không ghi nội dung vào log — log chỉ có đường dẫn, mã trạng thái, kích thước và mã lỗi.

Rust, actix-web 4, sqlx/PostgreSQL 16, Redis 7. Relay không có giao diện và không gửi câu chữ hiển thị: lỗi là mã, thiết bị tự dịch theo ngôn ngữ của mình (thiết kế chi tiết 0.12).

Kho này là một phần của workspace HandLive: kho hub `handlive` (tài liệu, kế hoạch) là thư mục cha, `../shared` là kho `handlive-shared` (test đọc `../shared/test-vectors`). Clone cả bộ từ hub bằng `tools/workspace.sh clone <group-url>`; xem `CLAUDE.md`.

Phạm vi Phase 0: Cargo workspace, migration lược đồ (đặc tả `../docs/detailed-design/00-common-specs.md` 0.9.4), đăng ký và xác thực thiết bị:

| Method | Đường dẫn | Đặc tả |
|--------|-----------|--------|
| POST | `/v1/devices` | CONN-03 API 1 (tự ký `HLREG1`) |
| POST | `/v1/auth/challenge` | 0.6.4, CONN-03 API 2 |
| POST | `/v1/auth/token` | 0.6.4, CONN-03 API 3 (JWT HS256, 900 s) |

`AuthenticatedDevice` (`src/auth_extractor.rs`) là extractor JWT cho các endpoint dùng JWT về sau (kiểm `sub` còn trong `devices`).

## Bố cục

```
relay/
  Cargo.toml              workspace (ghim phiên bản bộ thư viện relay)
  docker-compose.yml      PostgreSQL 16 + Redis 7 cho dev
  .env.example            giá trị giữ chỗ cho dev; chép thành .env (gitignore)
  migrations/             migration sqlx, chạy khi server khởi động
  crates/relay-server/    server (lib + bin); tests/ chứa mọi test
```

## Phát triển

Cần Rust toolchain trên PATH (ví dụ `export PATH=/opt/homebrew/opt/rustup/bin:$PATH`).

```bash
cd relay
cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test
```

`cargo test` không cần Docker: test dùng cơ sở dữ liệu được đánh dấu `#[ignore]`.

### Với PostgreSQL + Redis

Cổng host đã dời để không đụng PostgreSQL/Redis cục bộ: PostgreSQL `127.0.0.1:55432`, Redis `127.0.0.1:56379`.

```bash
cd relay
docker compose up -d --wait
set -a && . ./.env.example && set +a      # hoặc .env của bạn
cargo test -- --ignored                   # test tích hợp dùng cơ sở dữ liệu
cargo run -p relay-server                 # chạy migration, lắng nghe ở RELAY_BIND
docker compose down -v                    # dừng và xóa volume dev
```

## Cấu hình

| Biến | Ý nghĩa |
|------|---------|
| `DATABASE_URL` | URL PostgreSQL |
| `REDIS_URL` | URL Redis |
| `RELAY_JWT_SECRET` | Khóa HS256 cho JWT của thiết bị, ≥ 32 byte (`openssl rand -base64 48`). Không bao giờ commit |
| `RELAY_BIND` | Địa chỉ lắng nghe, mặc định `127.0.0.1:8080` |
| `RUST_LOG` | Bộ lọc log, mặc định `info` |

## Giấy phép

Apache License 2.0 — xem [LICENSE](LICENSE). Đóng góp theo [CONTRIBUTING](https://github.com/HandLive/.github/blob/main/CONTRIBUTING.vi.md) (commit nhỏ, đứng tên người thật, ký DCO bằng `git commit -s`); báo lỗ hổng bảo mật kín theo [SECURITY](https://github.com/HandLive/.github/blob/main/SECURITY.vi.md).
