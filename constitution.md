# Constitution — CubeOS API (component of CubeOS)

Component-scoped invariants. Inherits **the full CubeOS project-level constitution** at `/home/claude-runner/gitlab/products/cubeos/docs/constitution.md` — Articles I-XIX — which apply unchanged. This file adds api-specific articles.

> Articles below are numbered C-I, C-II, ... ("Component Article I, II, ...") to distinguish from the project-level Articles I-XIX which inherit unchanged.

## Article C-I — Orchestrator is the sole lifecycle entry point

The system shall route every container lifecycle operation (install / uninstall / start / stop / restart) through one Orchestrator (`internal/managers/orchestrator.go`). Other handlers MUST delegate to Orchestrator; no handler may call SwarmManager directly. The Orchestrator's saga-run mutex serializes lifecycle requests per stack.

## Article C-II — FlowEngine saga semantics

The system shall implement multi-step lifecycle operations as FlowEngine sagas in `internal/flowengine/`. Each saga step has an explicit compensating action. If any step fails, the system shall execute the compensating actions in reverse order from the failure point. The five canonical sagas are: `appstore_install` (9 steps), `appstore_remove` (6 steps), `network_mode_switch` (5 steps), `first_boot_setup` (9 steps), `access_profile_switch` (8 steps with full compensation).

## Article C-III — Middleware order is fixed

The router middleware stack shall apply in exactly this order:

```
Logger → Recovery → RealIP → RequestID → CORS → Timeout(60s) → MaxBodySize(10MB) → SetupRequired → JWTAuth
```

Reordering changes failure-mode semantics (Recovery before Logger means panics are not logged; JWTAuth before Timeout means slow auth attacks block request handling). The order is asserted by middleware-ordering test.

## Article C-IV — Profile-aware activities

Activities `add_dns`, `remove_dns`, `create_proxy`, `remove_proxy` shall check the active access profile and skip themselves when profile=`standard`. The orchestrator wraps these activities with the profile-check; sagas do not duplicate the check. (Sourced from `api/CLAUDE.md` §FlowEngine.)

## Article C-V — chi v5 router

The system shall use `github.com/go-chi/chi/v5` for routing. No other router. Mount path `/api/v1/`. Public routes: `/health` + `/api/v1/auth/login`.

## Article C-VI — modernc.org/sqlite (pure Go)

The system shall use `modernc.org/sqlite` as the SQLite driver. Never `mattn/go-sqlite3` (CGO-bound, violates Article XI of project constitution). All queries use `?` parameterised binds — never string concatenation.

## Article C-VII — Boot DHCP reconciliation

The system shall run a DHCP reconciliation step at startup: read persisted network_modes + access_profiles, then HAL POST /pihole/dhcp/enabled per the resolved state. This protects against post-mortem-restart drift when the operator changed config offline (e.g. SD-card mount on a workstation).

## Article C-VIII — Schema version tracking

The system shall track the current schema version in `internal/database/schema.go` as a `CurrentSchemaVersion` constant. On startup, `internal/database/migrations.go` walks from the persisted version up to `CurrentSchemaVersion` and applies each migration. The migrations array is **append-only** per project Article XIII — existing entries are NEVER edited.

## Article C-IX — `make verify-routes` invariant

The system shall expose every registered route via the Swagger documentation. The `make verify-routes` target diffs the chi router's `Walk()` output against the Swagger spec; non-zero exit = constitutional violation. Run as a pre-commit gate AND in CI on every push.

## Article C-X — Test categories

The system shall maintain three test categories: (a) unit tests in `*_test.go` colocated with implementation, (b) handler integration tests in `internal/handlers/*_test.go` exercising the full middleware stack with an in-memory SQLite, (c) end-to-end tests under `tests/e2e/` running against a real Pi (Make target `make e2e-pi`). `make test` runs (a) + (b); `make e2e-pi` runs (c).

## Article C-XI — Environment-var configuration (no hardcoded defaults)

The system shall read configuration via `os.Getenv` with sensible defaults in `internal/config/config.go`. The 7 canonical env vars are: `CUBEOS_PORT`, `CUBEOS_DB_PATH`, `CUBEOS_DATA_DIR`, `JWT_SECRET`, `HAL_URL`, `CUBEOS_TIER`, `CUBEOS_ACCESS_PROFILE`. Adding a new env var requires updating both `internal/config/config.go` and `api/CLAUDE.md` Environment Variables table.

## Article C-XII — Pi-hole v6 REST contract

The system shall talk to Pi-hole via the v6 REST API at `http://127.0.0.1:6001/api/*` per the contract in `api/CLAUDE.md` §"Pi-hole v6 REST API". Auth via session ID in `X-FTL-SID` header. Changes auto-apply (no restart needed). NEVER call the legacy Pi-hole v5 PHP admin endpoints.
