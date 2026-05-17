# 2. chi v5 as the HTTP router

Date: 2026-05-17 (codifying decision originally made 2026-01)

## Status

Accepted

## Context

Need an HTTP router for the api. Candidates: stdlib `net/http` + manual mux, gorilla/mux (now maintenance-only), gin, echo, chi v5.

## Decision

`github.com/go-chi/chi/v5`. Mount path `/api/v1/`. Public routes `/health` + `/api/v1/auth/login`.

## Consequences

**Positive:**
- 100% stdlib-compatible `http.Handler` interface — middleware composes cleanly with stdlib middleware.
- No reflection-based magic (unlike gin); fast + debuggable.
- Active maintenance (gorilla deprecated; gin's velocity has slowed).
- Idiomatic Go with no surprising defaults.

**Negative:**
- Slightly more verbose than gin for simple cases (acceptable trade for readability).
- Fewer built-in middleware (we have to write our own for SetupRequired, JWTAuth — fine, we want full control of those anyway).

**Enforced by:** Component Article C-V.
