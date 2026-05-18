# Steering — Middleware stack

Fixed order per Article C-IV. CGC-verified in `cmd/cubeos-api/main.go` + `internal/middleware/`.

## The chain

```
1. Logger             — structured request log via zerolog
2. Recovery           — panic → 500 + log
3. RealIP             — set X-Real-IP from X-Forwarded-For (behind NPM)
4. RequestID          — UUID per request, attached to logger ctx
5. CORS               — allow cubeos.cube + dashboard origin
6. Timeout(60s)       — request context deadline
7. MaxBodySize(10MB)  — defense against huge POSTs
8. SetupRequired      — blocks all routes except /api/v1/setup/* until first-boot wizard completes
9. JWTAuth            — verifies Authorization: Bearer <jwt> per request
```

## Why this order

- **Logger first** — captures everything including panics + auth failures.
- **Recovery second** — wraps everything below.
- **RealIP before logging downstream** — logger needs the real IP.
- **RequestID before downstream** — every log line gets the ID for correlation.
- **CORS early** — OPTIONS preflight succeeds without auth.
- **Timeout before body parse** — slow-loris protection.
- **MaxBodySize before handler** — handler doesn't defend against huge bodies.
- **SetupRequired before JWTAuth** — first-boot wizard endpoints reachable without auth.
- **JWTAuth last** — by this point, request is well-formed and auth check is the gate.

## Public routes (skip JWTAuth)

- `GET /health`
- `POST /api/v1/auth/login`
- `GET /api/v1/setup/*` (first-boot wizard only; blocked once .setup_complete exists)

## JWT settings

- Algorithm: HS256
- Secret: `JWT_SECRET` env var (auto-generated at first boot, persisted to `/cubeos/config/secrets.env`)
- Token TTL: 24h, refresh: 7d
- Claims: sub, iat, exp, profile (active access profile)

## Failure responses per middleware

| Middleware | Failure → response |
|---|---|
| Recovery | panic → 500, Logger captures stack |
| CORS | bad origin → 403 |
| Timeout | exceeded → 504 with retry-after |
| MaxBodySize | over → 413 |
| SetupRequired | not setup → 503 redirect to /api/v1/setup |
| JWTAuth | bad/missing → 401 |
