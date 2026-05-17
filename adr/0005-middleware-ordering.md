# 5. Fixed middleware order

Date: 2026-05-17 (codifying decision originally made 2026-01)

## Status

Accepted

## Context

Middleware order matters for security + observability + correctness. Examples:
- Recovery BEFORE Logger means panics are not logged.
- JWTAuth BEFORE Timeout means slow auth attacks block other request handling.
- CORS AFTER JWTAuth means OPTIONS preflight fails for auth'd routes.

A casual `r.Use(...)` chain can reorder accidentally on a refactor → silent security regression.

## Decision

Fix the middleware order in `internal/middleware/chain.go` as: Logger → Recovery → RealIP → RequestID → CORS → Timeout(60s) → MaxBodySize(10MB) → SetupRequired → JWTAuth. Assert the order via test in `internal/middleware/chain_test.go`.

## Consequences

**Positive:**
- Reorder-by-mistake is caught by CI.
- Documented + greppable.
- Failure modes per layer are explicit (see `steering/middleware-stack.md`).

**Negative:**
- Adding a new middleware requires updating the test assertion (which is the desired friction).

**Enforced by:** Component Article C-III.
