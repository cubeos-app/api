# Steering — Coding standards

CGC-grounded 2026-05-18 against the real 150-file / 4007-function api/ repo.

## Package layout

```
cmd/cubeos-api/main.go              ← entry point (CGC-verified, NOT cmd/cubeos/)
internal/
  circuitbreaker/                   ← Docker circuit breaker
  clients/                          ← npm_external, pihole_external
  config/                           ← env-var loading
  database/                         ← database.go, schema.go (CurrentSchemaVersion=27), migrations.go
  docker/                           ← Docker SDK helpers
  docs/                             ← Swagger UI asset embedding
  flowengine/                       ← engine.go (WorkflowEngine), saga.go, store.go, step.go, registry.go, definition.go, progress.go, errors.go
    workflows/                      ← 12 workflow definitions
    activities/                     ← 14 activity implementations
  hal/                              ← HAL client (api → hal)
  handlers/                         ← 30 .go files, one per /api/v1/<domain>/
  managers/                         ← 37 .go files; Orchestrator at orchestrator.go:27; PortManager at ports_new.go:91
  middleware/                       ← chi middleware chain
  models/                           ← API + DB models
  system/                           ← system helpers
```

## Type naming

- Manager types: `<Domain>Manager` (Orchestrator is the exception — coordinator, not a per-domain manager).
- Handler structs: `<Domain>Handler` with `New<Domain>Handler(orchestrator *managers.Orchestrator, ...)` constructor.
- WorkflowEngine integration: `WorkflowEngine`, `WorkflowDefinition`, `WorkflowStore`, `ActivityRegistry`, `SagaOrchestrator`, `StepExecutor`.

## File-per-domain in handlers/

| Domain | File |
|---|---|
| apps | apps.go (+ apps_test.go) |
| appstore | appstore.go (+ appstore_test.go) |
| backups | backups.go |
| casaos | casaos.go |
| chat | chat.go |
| communication | communication.go |
| docs | docs.go |
| extended | extended.go |
| firewall | firewall.go |
| fqdns | fqdns.go (+ test) |
| handlers | handlers.go (top-level handler struct) |
| handlers_test | handlers_test.go |
| hardware | hardware.go |
| logs | logs.go |
| media | media.go |
| metrics | metrics.go |
| mounts | mounts.go |
| network | network.go (+ test) |
| npm | npm.go |
| ports | ports.go |
| profiles | profiles.go (access profiles + profile-switching) |
| registry | registry.go |
| setup | setup.go (first-boot wizard) |
| smb | smb.go |
| storage | storage.go |
| swagger_types | swagger_types.go |
| updates | updates.go |
| vpn | vpn.go |
| websocket | websocket.go |
| workflows | workflows.go (FlowEngine introspection) |

## Forbidden patterns

- Calling `docker.NewClient()` outside `managers/` (Article C-I).
- `managers/compose.go` (Article C-X — compose transform lives in activities).
- Direct Pi-hole `/etc/dnsmasq.d/` writes (Article C-XI).
- Schema migrations edited in place (parent Article XIII).
- Logger / Recovery / RealIP / RequestID / CORS / Timeout / MaxBodySize / SetupRequired / JWTAuth chain reordered (Article C-IV).
