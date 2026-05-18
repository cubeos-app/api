# Project Charter — CubeOS API

> Component-scoped charter. Parent: `/home/claude-runner/gitlab/products/cubeos/docs/PROJECT.md`. CGC-grounded 2026-05-18 (audit: `claude-gateway/docs/sdd-audits/api-cgc-2026-05-18.md`).

## Role in the CubeOS family

`api/` (GitLab project 13) is the **Go backend** — the central REST API + Orchestrator + WorkflowEngine + per-domain handlers + 37 business-logic managers.

- **Talks to:** SQLite (modernc.org/sqlite — `internal/database/`), HAL (`http://10.42.24.1:6005` via `HAL_URL` — `internal/hal/`), Pi-hole v6 REST (`http://127.0.0.1:6001`), NPM v2 REST, Docker Swarm (via SDK in `internal/docker/`).
- **Listens on:** `6010` (`CUBEOS_PORT`).
- **Consumed by:** `dashboard/`, `cubeos-cli`, user-installed apps via FlowEngine APIs.
- **Entry point:** `cmd/cubeos-api/main.go` (CGC-verified).

## What this repo owns (CGC-verified, 2026-05-18)

The current shipped surface: **150 files / 4007 functions / 670 classes / 14 internal packages**:

1. **REST API surface** at `/api/v1/*` — 30 handler files in `internal/handlers/`.
2. **Orchestrator** at `internal/managers/orchestrator.go:27` — coordinator that delegates lifecycle work to FlowEngine workflows.
3. **WorkflowEngine** at `internal/flowengine/engine.go:61` — adaptive-polling saga runner with reaper + recovery + single-threaded SQLite-safe processing + completion hooks.
4. **12 Workflows** + **14 Activities** — the canonical lifecycle operations (compose+orchestrate architecture).
5. **PortManager** at `internal/managers/ports_new.go:91` — triple-source validation (DB + Swarm + HAL) for the 6100-6999 user-app range.
6. **Middleware stack** in `internal/middleware/` — Logger → Recovery → RealIP → RequestID → CORS → Timeout(60s) → MaxBodySize(10MB) → SetupRequired → JWTAuth.
7. **SQLite schema** at version 27 (CGC-verified at `internal/database/schema.go:13`).
8. **Docker circuit breaker** (`internal/circuitbreaker/`) — prevents cascading failures when Docker daemon hangs.
9. **NPM + Pi-hole sync** (`managers/npm_sync.go` + `pihole_sync.go`) — reconciliation loops keep external state aligned with CubeOS desired state.
10. **Backup subsystem** (`managers/backup*.go`) — backup_crypto + backup_destinations + backup_scheduler + backup engine.

## What this repo does NOT own

- **Host services** — `hal/` owns (Article I).
- **UI** — `dashboard/` owns.
- **Coreapp compose definitions** — `coreapps/` owns.
- **Image build / installer** — `releases/` owns.

## Constitutional inheritance

Inherits the full CubeOS project-level constitution. Most load-bearing for api/:

- Article I (HAL boundary — every host call via `internal/hal/Client`)
- Article IV (Swarm is truth — `internal/managers/swarm.go`)
- Article V (port discipline 6010 + 6100-6999)
- Article XI (`CGO_ENABLED=0` + modernc.org/sqlite)
- Article XII (Swagger annotations + `make verify-routes`)
- Article XIII (append-only migrations — currently v27)
- Article XVII (Claude Code files gitignored)

## Build (CGC-verified)

```bash
cd api
make build          # → build/cubeos
make build-arm64    # cross-compile for Pi
make build-x86_64   # cross-compile for x86/amd64
make run            # → go run ./cmd/cubeos-api
make test           # all packages
make test-handlers  # internal/handlers/...
make verify-routes  # routes-vs-Swagger parity (Article XII)
make fmt            # gofmt
make lint           # golangci-lint
make tidy           # go mod tidy
```

## Source trace

- `api/CLAUDE.md` (local-only)
- `cmd/cubeos-api/main.go` — wiring
- `internal/flowengine/engine.go:61` — WorkflowEngine type
- `internal/managers/orchestrator.go:27` — Orchestrator type
- `internal/database/schema.go:13` — CurrentSchemaVersion = 27
- Parent: `/home/claude-runner/gitlab/products/cubeos/docs/architecture/02_ARCHITECTURE.md` §2.1
- Parent: `/home/claude-runner/gitlab/products/cubeos/docs/architecture/03_DATABASE_SCHEMA.md`
- Parent: `/home/claude-runner/gitlab/products/cubeos/docs/architecture/07_API_CONTRACTS.md`
- Parent: `/home/claude-runner/gitlab/products/cubeos/docs/spec/009-swarm-orchestrator/`
- CGC audit: `claude-gateway/docs/sdd-audits/api-cgc-2026-05-18.md`
