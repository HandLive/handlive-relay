# CLAUDE.md — handlive-relay

Cloud relay of HandLive (Rust, actix-web 4, actix-ws, sqlx/PostgreSQL 16, Redis 7) for devices that are not on the same network. It never reads content: it only forwards end-to-end encrypted data (zero-knowledge). One part of the HandLive **workspace**: the hub repository `handlive` is this directory's parent, holds the specification that all code implements, and its `CLAUDE.md` applies here in full.

## Workspace layout (mandatory)

```
<workspace>/        hub repo "handlive": CLAUDE.md (read first), docs/, plans/, tools/docs/, tools/workspace.sh
  relay/            this repo (handlive-relay)
  shared/           repo "handlive-shared": test-vectors/, schemas/, design-tokens/, tools/
```

Tests read `../shared/test-vectors` (`crates/relay-server/tests/common/mod.rs`). From the hub, `tools/workspace.sh clone <group-url>` checks the parts out.

## Working here

- Read in this order: `../CLAUDE.md` → `../docs/detailed-design/README.md` → `../docs/detailed-design/00-common-specs.md` (0.6.4 auth, 0.8.2 HTTP codes, 0.9.4 schema and Redis keys) → the phase file in `../plans/20260925-implementation/` → `03-connectivity.md` CONN-03/CONN-04 → `../docs/code-standards.md`.
- The relay never decrypts, stores or logs a `payload`; logs carry only path, status, size and error code. Contracts change in the hub docs first; test vectors and schemas change only in `../shared` (repo handlive-shared) as their own commits — say so in the report so the Android and Apple agents re-run their tests.
- Build and test: `cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test`; integration: `docker compose up -d --wait`, load `.env.example`, `cargo test -- --ignored`. Migrations live in `migrations/` and run at server start.
- Branches: `feat/phase-0N-<slug>` per phase. Commit early and small — one commit per logical step (scaffold, module, tests, docs), conventional commits (`feat(relay): …`, `test(relay): …`), no AI references. A commit never spans repositories. Commit before writing the report and list the hashes with the repository name in `../plans/20260925-implementation/reports/`.
- CI (`.github/workflows/ci-relay.yml`) reproduces the layout: this repo into `relay/`, handlive-shared into `shared/`. It does not run when only shared changes — start it by hand (workflow_dispatch).
