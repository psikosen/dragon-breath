# Drogon + SurrealDB + Redis Starter (Dashboard CMD Backend)

A production-grade starter backend using **[Drogon](https://github.com/drogonframework/drogon)** (C++20) with:
- **SurrealDB** as the database (HTTP API).
- **Redis** for caching + token blacklist.
- **JWT (HS256)** auth with a lightweight header-only implementation (OpenSSL HMAC).
- Clean Controller / Filter / DB client layers.
- Docker & docker-compose for one-command local run.
- SurrealQL migrations + seed script.

> Targets a dashboard/CLI-style app: simple, fast, secure.

## Quick start

```bash
# 1) Start DBs
docker compose up -d surrealdb redis

# 2) Apply schema
./scripts/run_migrations.sh

# 3) Build & run the API
docker compose up --build api
# API at http://localhost:8080
```

### Native build

```bash
# deps on Ubuntu (example)
sudo apt-get update && sudo apt-get install -y build-essential cmake libssl-dev libjsoncpp-dev libhiredis-dev
# Drogon (if not installed): https://github.com/drogonframework/drogon
mkdir -p build && cd build && cmake .. && cmake --build . -j
./drgn_surreal --config=./config/config.json
```

## API

- `POST /api/auth/register` `{ "email": "...", "password": "..." }` → `{ token, user }`
- `POST /api/auth/login` `{ "email": "...", "password": "..." }` → `{ token, user }`
- `POST /api/auth/logout` (Auth) → `204` (adds JWT jti to Redis blacklist until expiry)
- `GET /api/me` (Auth) → `{ user }`
- `GET /api/users` (Auth: admin) → list users

**Auth header:** `Authorization: Bearer <token>`

### Curl smoke test

```bash
curl -X POST http://localhost:8080/api/auth/register \
  -H 'Content-Type: application/json' \
  -d '{"email":"admin@example.com","password":"secret"}'
```


## gRPC API

- Service: `dragonbreath.grpc.UserService` listening on port `50051` by default.
- `GetUser(GetUserRequest)` → returns a sanitized user profile (`id`, `email`, `role`, timestamps).

Example using [grpcurl](https://github.com/fullstorydev/grpcurl):

```bash
grpcurl -plaintext -d '{"id":"user:01H..."}' localhost:50051 dragonbreath.grpc.UserService/GetUser
```

Configure the listener with `GRPC_LISTEN_ADDR` (defaults to `0.0.0.0:50051`).

## Config

See `config/config.json`. Override via env vars for Surreal, Redis, JWT secret.

## SurrealDB schema

See `db/migrations/001_init.surql` for **namespace/db**, tables, fields, perms.

## Redis

- Cache: `cache:user:<id>` (5 min TTL)
- Blacklist: `blacklist:jti:<jti>` (TTL = token expiry)

## Notes

- Passwords use PBKDF2-HMAC-SHA256 with random salt.
- JWT uses HS256. Rotate `JWT_SECRET` between environments.
- The Surreal client uses HTTP `/sql` with `Surreal-NS` / `Surreal-DB` headers and Basic auth.

## Next steps

See **TICKETS.md** for a prioritized, senior-dev friendly backlog.
