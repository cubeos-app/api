# Design — Middleware stack (spec/005 — RETROSPECTIVE)

CGC-grounded. See `steering/middleware-stack.md` for full detail. This spec captures the spec-form REQs.

## Layout

```
cmd/cubeos-api/main.go         ← registers middleware chain in order
internal/middleware/
  chain.go                     ← (likely) chain composition
  jwt_auth.go                  ← JWTAuth middleware
  setup_required.go            ← SetupRequired middleware
  *_test.go                    ← colocated tests
```

## The chain (real order)

```
1. Logger             — zerolog request logger
2. Recovery           — panic → 500 + log
3. RealIP             — X-Forwarded-For
4. RequestID          — UUID per request
5. CORS               — cubeos.cube + dashboard origin
6. Timeout(60s)       — request ctx deadline
7. MaxBodySize(10MB)  — body cap
8. SetupRequired      — gate on .setup_complete
9. JWTAuth            — bearer token
```

## JWT

- HS256, JWT_SECRET from `/cubeos/config/secrets.env`
- TTL 24h, refresh 7d
- Claims: sub, iat, exp, profile

## Failure responses

| Middleware | Failure → response |
|---|---|
| Recovery | panic → 500 |
| CORS | bad origin → 403 |
| Timeout | exceeded → 504 |
| MaxBodySize | over → 413 |
| SetupRequired | not setup → 503 |
| JWTAuth | bad/missing → 401 |
