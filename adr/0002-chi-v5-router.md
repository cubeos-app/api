# 2. chi v5 as the HTTP router

Date: 2026-05-18 (codifying decision originally made 2026-01)

## Status
Accepted

## Context
CGC-verified: `github.com/go-chi/chi/v5` imported in `cmd/cubeos-api/main.go` + `internal/handlers/profiles.go` + many other handlers. Candidates considered: stdlib mux, gorilla/mux (now maintenance-only), gin, echo, chi v5.

## Decision
chi v5. Mount path `/api/v1/`. Public routes: `/health` + `/api/v1/auth/login`.

## Consequences
**Positive:** 100% stdlib-compatible http.Handler; no reflection magic; active maintenance; idiomatic.
**Negative:** Slightly more verbose than gin (acceptable trade for readability).
**Enforced by:** Article C-V.
