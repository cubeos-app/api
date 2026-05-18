# Requirements — Middleware stack (spec/005 — RETROSPECTIVE)

Source: Article C-IV + `cmd/cubeos-api/main.go` + `internal/middleware/`.

> Retrospective. ID convention: 500-block.

REQ-500: The system shall register middleware in exactly this order: Logger, Recovery, RealIP, RequestID, CORS, Timeout(60s), MaxBodySize(10MB), SetupRequired, JWTAuth.
REQ-501: While the SetupRequired middleware is active and `/cubeos/data/.setup_complete` is absent, the system shall block all routes except `/api/v1/setup/*`.
REQ-502: The system shall expose `/health` + `/api/v1/auth/login` as public routes (skip JWTAuth).
REQ-503: The system shall use chi v5 for routing (Article C-V).
REQ-504: When a request's body exceeds 10 MB, the MaxBodySize middleware shall return HTTP 413.
REQ-505: When a request exceeds 60 seconds, the Timeout middleware shall return HTTP 504.
REQ-506: When a handler panics, the Recovery middleware shall catch + return HTTP 500 + log via Logger.
REQ-507: While CORS evaluates, the system shall allow origins matching cubeos.cube and the configured dashboard origin.
REQ-508: The system shall attach a per-request UUID via RequestID middleware so every log line includes the correlation ID.
REQ-509: The system shall extract real client IP from `X-Forwarded-For` via RealIP middleware (CubeOS runs behind NPM).
REQ-510: When JWT is missing OR invalid, the JWTAuth middleware shall return HTTP 401 + record failed attempt via fail2ban filter.
REQ-511: The system shall sign JWTs with HS256 + `JWT_SECRET` env var.
REQ-512: The system shall set token TTL to 24h, refresh-token TTL to 7d, and include sub + iat + exp + profile claims.
REQ-513: The system shall colocate middleware tests at `internal/middleware/*_test.go`.
REQ-514: The system shall enforce the middleware order via test in `internal/middleware/chain_test.go` (asserts via reflection OR documented sequence).
