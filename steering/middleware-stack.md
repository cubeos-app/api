# Steering — Middleware stack

Fixed order per Article C-III. Defined in `internal/middleware/chain.go`.

## The chain

```
1. Logger             — structured request log via zerolog
2. Recovery           — panic → 500 + log; without this, panics kill the process
3. RealIP             — set X-Real-IP from X-Forwarded-For (behind NPM reverse proxy)
4. RequestID          — UUID per request, attached to logger ctx
5. CORS               — allow cubeos.cube + dashboard origin
6. Timeout(60s)       — request context deadline; downstream queries cancel
7. MaxBodySize(10MB)  — defense against huge POSTs; returns 413
8. SetupRequired      — blocks all routes except /api/v1/setup/* until first-boot wizard completes
9. JWTAuth            — verifies Authorization: Bearer <jwt> per request; public routes excluded
```

## Why this order

- **Logger first** — captures everything including panics + auth failures.
- **Recovery second** — wraps everything below; without it a downstream panic kills the request handler and lets the process crash.
- **RealIP before logging downstream** — logger needs the real client IP for audit value.
- **RequestID before downstream handlers** — every log line gets the request ID for correlation.
- **CORS early** — before auth so OPTIONS preflight succeeds.
- **Timeout before body parse** — slow-loris protection.
- **MaxBodySize before handler** — handler shouldn't have to defend against huge bodies itself.
- **SetupRequired before JWTAuth** — first-boot wizard endpoints are reachable without auth.
- **JWTAuth last** — by this point, the request is well-formed and the auth check is the gate.

## The order is asserted by test

`internal/middleware/chain_test.go` checks the registered middleware order against the spec list. A reorder breaks the test before it ships.

## Public routes (skip JWTAuth)

- `GET /health`
- `POST /api/v1/auth/login`
- `GET /api/v1/setup/*` (first-boot wizard only; blocked once `.setup_complete` exists)
- `GET /api/v1/security/ca-cert` (per docs/spec/007 REQ-710 — operator needs this BEFORE trust)
- `GET /metrics` (when prometheus_exporter flag enabled per docs/spec/010 REQ-1016)

All other routes require valid JWT.

## JWT settings

- Algorithm: HS256
- Secret: `JWT_SECRET` env var (CHANGE on every deploy; auto-generated at first boot, persisted to `/cubeos/config/secrets.env`)
- Token TTL: 24h
- Refresh-token TTL: 7d
- Claims: `sub` (user id), `iat`, `exp`, `profile` (active access profile)

## Failure responses

| Middleware       | Failure | Response                                       |
|------------------|---------|------------------------------------------------|
| Logger           | n/a     | n/a                                            |
| Recovery         | panic   | HTTP 500 + Logger captures stack               |
| RealIP           | n/a     | n/a                                            |
| RequestID        | n/a     | n/a                                            |
| CORS             | bad origin | HTTP 403                                    |
| Timeout(60s)     | exceeded | HTTP 504 with retry-after                     |
| MaxBodySize(10MB)| over    | HTTP 413                                       |
| SetupRequired    | not setup | HTTP 503 redirect to /api/v1/setup           |
| JWTAuth          | bad/missing | HTTP 401                                    |
