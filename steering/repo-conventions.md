# Steering — Repo conventions

## Build

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

## Env vars (CGC-verified)

| Env | Default | Purpose |
|---|---|---|
| CUBEOS_PORT | 6010 | Listen port |
| CUBEOS_DB_PATH | /cubeos/data/cubeos.db | SQLite path |
| CUBEOS_DATA_DIR | /cubeos/data | Data root |
| JWT_SECRET | (dev default) | JWT signing key |
| HAL_URL | http://10.42.24.1:6005 | HAL service endpoint |
| CUBEOS_TIER | (auto-detected) | full or container |
| CUBEOS_ACCESS_PROFILE | standard | Active access profile |

## Branches + commits + identity

Same as CubeOS family — per parent CLAUDE.md + Article XIX. `git -c user.name="Kyriakos Papadopoulos" -c user.email="ncpjfuzl@mxmx.email" commit ...`

## File layout (CGC-verified)

```
/
  cmd/cubeos-api/main.go            ← entry point
  internal/                          ← 14 packages
  Makefile                           ← see above for targets
  go.mod / go.sum                    ← Go 1.24
  README.md
  CLAUDE.md                          ← LOCAL-ONLY, gitignored
  PROJECT.json + PROJECT.md          ← spec-kit charter
  constitution.md                    ← hard rules
  steering/                          ← this dir
  adr/
  spec/
  .agentic/slot-config.entry.json
  .gitignore
```

## Release

Per parent Article XV: push to `main` → CI auto-deploys to every registered Pi. For parallel-dev waves: per ADR-0006.
