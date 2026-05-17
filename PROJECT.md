# Project Charter — CubeOS API (component of CubeOS)

> Component-scoped charter. Parent project charter: `/home/claude-runner/gitlab/products/cubeos/docs/PROJECT.md`. Parent constitution: `docs/constitution.md`. This file describes what `api/` (project 13) owns within CubeOS.

## Role in the CubeOS family

`api/` is the **Go backend** — the central API + Orchestrator + FlowEngine + per-domain handlers + per-business-domain managers. It is the *unified API* called out in `docs/spec/009-swarm-orchestrator/` as the fix for the Three-Headed Hydra problem.

- **Talks to:** SQLite (modernc.org/sqlite), HAL (`http://10.42.24.1:6005` via `HAL_URL`), Pi-hole v6 REST (`http://127.0.0.1:6001`), NPM v2 REST, Docker Swarm (via SDK).
- **Listens on:** `6010` (per `CUBEOS_PORT`).
- **Consumed by:** `dashboard/` (the Vue 3 frontend), `cubeos-cli`, user-installed apps via the FlowEngine APIs.

## What this repo owns

1. **REST API surface** at `/api/v1/*` — every operator action against the system enters here.
2. **Orchestrator** — the single coordinator for app lifecycle. All `docker stack deploy / rm` calls go through Orchestrator → SwarmManager.
3. **FlowEngine** — saga runtime with explicit compensating actions. Currently runs 5 workflows.
4. **PortManager** — allocator for the `6100-6999` user-app port range per CubeOS Article V.
5. **Compose transformer** — CasaOS-format compose → Swarm-compatible compose at install time.
6. **SQLite schema** — currently v27, append-only migrations per CubeOS Article XIII.
7. **Middleware stack** — Logger → Recovery → RealIP → RequestID → CORS → Timeout(60s) → MaxBodySize(10MB) → SetupRequired → JWTAuth.

## What this repo does NOT own

- **Host services** (firewall, hostapd, wpa_supplicant, DHCP wiring) — `hal/` owns these (CubeOS Article I).
- **UI** — `dashboard/` owns Vue components.
- **Coreapp compose definitions** — `coreapps/` owns each coreapp's docker-compose.yml.
- **Image build / installer** — `releases/` owns Packer + Pi Imager manifest.

## Constitutional inheritance

This component repo inherits the full CubeOS project-level constitution. Of the 19 articles in `docs/constitution.md`, these are most directly load-bearing for api/:

- **Article I** — HAL boundary (never touch host services directly; always via `HAL_URL`)
- **Article IV** — Docker Swarm is truth; never `docker run`
- **Article V** — port discipline (6010 for api, 6100-6999 for user apps)
- **Article XI** — `CGO_ENABLED=0` (use `modernc.org/sqlite`)
- **Article XII** — Swagger annotations mandatory; `make verify-routes` invariant
- **Article XIII** — append-only migrations
- **Article XVII** — Claude Code files gitignored

This repo's own `constitution.md` adds api-specific articles (FlowEngine saga semantics, middleware ordering, etc.) without contradicting any project-level Article.

## Build

```bash
cd api
make build          # → build/cubeos
make build-arm64    # → cross-compile for Pi
make build-x86_64   # → cross-compile for x86/amd64
make run            # → go run ./cmd/cubeos
make test           # → go test -v ./...
make verify-routes  # → routes-vs-Swagger parity check
make fmt            # → gofmt (per CubeOS rule 7)
make lint           # → golangci-lint
```

## Source trace

Component-specific source material:
- `api/CLAUDE.md` (this repo's local-only operator notes)
- `/home/claude-runner/gitlab/products/cubeos/docs/architecture/02_ARCHITECTURE.md` §2.1 (Component structure)
- `/home/claude-runner/gitlab/products/cubeos/docs/architecture/03_DATABASE_SCHEMA.md`
- `/home/claude-runner/gitlab/products/cubeos/docs/architecture/07_API_CONTRACTS.md`
- `/home/claude-runner/gitlab/products/cubeos/docs/spec/009-swarm-orchestrator/` (the project-level retrospective; this repo's spec/001-005 break out the implementation per concern)

Cross-cutting rules: `/home/claude-runner/gitlab/products/cubeos/CLAUDE.md` and `docs/constitution.md`.
