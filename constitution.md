# Constitution — CubeOS API

Component-scoped invariants. Inherits the full CubeOS project-level constitution at `/home/claude-runner/gitlab/products/cubeos/docs/constitution.md`. This file adds api-specific Articles (C-I through C-XI). All facts CGC-verified 2026-05-18.

## Article C-I — Orchestrator delegates; never calls Docker directly

The system shall route every container lifecycle operation through `internal/managers/orchestrator.go:27` Orchestrator type. Orchestrator either calls `SwarmManager` (for Swarm-managed stacks) or `DockerManager` (for direct container ops). Direct `client, _ := client.NewClientWithOpts(...)` in handlers is forbidden.

## Article C-II — WorkflowEngine is the saga runtime; one workflow at a time

The system shall use the `WorkflowEngine` at `internal/flowengine/engine.go:61` as the canonical saga runtime. The engine is **single-threaded by design** (one workflow processed at a time per node) to avoid SQLite contention on the Pi's SD card — see CGC docstring on engine.go.

The engine has:
- Adaptive polling (ActivePollInterval when active workflows exist; IdlePollInterval otherwise)
- Reaper goroutine releasing expired worker locks
- Recovery on startup (incomplete workflows in pending/running/compensating states resume)
- Per-type completion hooks (async, panic-recovered)
- Multi-node coordination via WorkflowStore.LockWorkflow(id, nodeID, lockDuration) (architecture supports; v1.0 single-node)

## Article C-III — Workflow + activity 2-level composition

The system shall compose multi-step operations as: a `WorkflowDefinition` (at `internal/flowengine/workflows/<name>.go`) that names ordered steps; each step references an `Activity` (at `internal/flowengine/activities/<domain>.go`). The 12 canonical workflows + 14 activities are the shipped set as of 2026-05-18.

Adding a new operation = (a) one new workflow file, OR (b) reuse an existing workflow with different params. Adding a new activity (a domain-level primitive) requires a new file under `activities/` and code review.

## Article C-IV — Middleware order is fixed

The router middleware shall apply in this order (CGC-verified `cmd/cubeos-api/main.go`):

```
Logger → Recovery → RealIP → RequestID → CORS → Timeout(60s) → MaxBodySize(10MB) → SetupRequired → JWTAuth
```

Reorder breaks failure-mode semantics (Recovery-before-Logger means panics aren't logged; JWTAuth-before-Timeout means slow auth attacks block other handling).

## Article C-V — chi v5 router

The system shall use `github.com/go-chi/chi/v5` for routing (CGC-verified in cmd/cubeos-api/main.go imports). Mount path `/api/v1/`. Public routes: `/health` + `/api/v1/auth/login`.

## Article C-VI — modernc.org/sqlite (pure Go)

The system shall use `modernc.org/sqlite` (CGC-verified import in `internal/database/database.go`). Never `mattn/go-sqlite3` (violates Article XI of parent constitution).

## Article C-VII — Docker circuit breaker

The system shall route all Docker daemon calls through `internal/circuitbreaker/` to prevent cascading failures when Docker is unresponsive (slow systemctl + service restarts on Pi). SwarmManager + DockerManager both take a `*CircuitBreaker` in their constructors.

## Article C-VIII — Schema version tracked as `CurrentSchemaVersion` constant

The system shall track the current schema version in `internal/database/schema.go:13` as `const CurrentSchemaVersion = N`. On startup, `internal/database/migrations.go` walks from the persisted version up to `CurrentSchemaVersion`. Current value: 27.

## Article C-IX — `make verify-routes` invariant

The system shall expose every registered route via the Swagger docs. The `make verify-routes` target diffs the chi router's `Walk()` output against the Swagger spec. Non-zero exit = constitutional violation. CGC-verified `api/scripts/verify-routes.sh` exists.

## Article C-X — Activity-level compose transformation (not managers/compose.go)

The system shall perform CasaOS → Swarm compose transformation INSIDE `internal/flowengine/activities/appstore.go` + `app_install.go`. There shall NOT be a `internal/managers/compose.go` file (CGC-verified does not exist).

## Article C-XI — Pi-hole v6 REST + NPM v2 REST contracts

The system shall talk to Pi-hole exclusively via the v6 REST API at `http://127.0.0.1:6001/api/*` and NPM exclusively via the NPM v2 REST API. NEVER call Pi-hole v5 PHP admin endpoints or write directly to `/etc/dnsmasq.d/`. Real client files: `internal/clients/pihole_external.go` + `npm_external.go`. The reconciliation logic is in `managers/pihole_sync.go` + `npm_sync.go`.
