# Backlog / Tickets (Senior Dev)

## Epic A: Auth hardening
1. **Switch to Argon2id** for password hashing (libsodium) + timing-safe compare.
2. **Rotate JWT secret** with key IDs (kid) + JWKS endpoint; add rolling key migration.
3. **Refresh tokens**: short-lived access, long-lived refresh; store refresh in Redis (rotating).
4. **Role/permission system**: role table & policy filter; add per-route permission matrix.

## Epic B: Observability & Ops
5. **Structured logging** (JSON) with request IDs and user IDs; sample rate controls.
6. **Metrics** via Prometheus exporter (latency buckets, Redis/Surreal timings).
7. **Health & readiness** endpoints; dependency pings (Redis, Surreal).

## Epic C: Data & schema
8. **Migrations runner** in C++ (idempotent) replacing bash; track applied versions.
9. **Unique composite indexes** where needed; email normalization (lowercase + trim).
10. **Soft-delete** fields + policies; created_at/updated_at triggers.

## Epic D: Caching & perf
11. **Typed cache layer** with generics and stampede protection (single-flight).
12. **Fine-grained invalidation** on user update; use Redis SCAN test in CI.
13. **Rate limiting** per-IP & per-account (token bucket in Redis).

## Epic E: Security
14. **CSRF** for cookie mode (if switching from Bearer).
15. **Brute-force guard**: exponential backoff counters in Redis.
16. **Audit log** table + admin viewer; sign logs with HMAC for tamper detection.

## Epic F: Developer experience
17. **OpenAPI** doc generator + single file swagger UI route.
18. **Dev seeds** (admin + sample users) with repeatable IDs.
19. **e2e tests** (ctest + curl) that bring up docker-compose on CI.
20. **Examples**: add a `projects` resource (CRUD) with ownership policies.
