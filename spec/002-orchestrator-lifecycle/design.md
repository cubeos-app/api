# Design — Orchestrator lifecycle (spec/002 — RETROSPECTIVE)

CGC-grounded. Real Orchestrator at `internal/managers/orchestrator.go:27` (~1700 lines).

## Real method set

```go
NewOrchestrator(cfg OrchestratorConfig) (*Orchestrator, error)
(*Orchestrator) Close() error
(*Orchestrator) SetFlowEngine(e *flowengine.WorkflowEngine, s *flowengine.WorkflowStore)
(*Orchestrator) AppExists(ctx, name) (bool, error)
(*Orchestrator) StartApp(ctx, name) error
(*Orchestrator) StopApp(ctx, name) error
(*Orchestrator) RestartApp(ctx, name) error
(*Orchestrator) EnableApp(ctx, name) error
(*Orchestrator) GetApp(ctx, name) (*App, error)
(*Orchestrator) SetProfileApp(ctx, profileID, appID int64, enabled bool) error
// + more (file is 1700+ lines)
```

**Notably absent (CGC-verified):** No `InstallApp` / `UninstallApp` methods. Install + uninstall flow through FlowEngine workflows submitted via `engine.Submit(...)`.

## Wire diagram

```
NewOrchestrator(cfg):
  1. validate cfg.DB + cfg.Config non-nil → else error
  2. ctx, cancel := WithCancel(Background())
  3. if cfg.SwarmManager: use; else NewSwarmManager(cfg.DockerCB)
  4. NewDockerManager(cfg.Config, cfg.DockerCB)
  5. if cfg.NPMManager: use; else NewNPMManager(cfg.Config, npmConfigDir) + .Init() (log warning on fail)
  6. if cfg.PiholeManager: use; else NewPiholeManager(cfg.Config)
  7. NewPortManager(cfg.DB, o.swarm, cfg.HALClient) — triple-source

handlers receive *Orchestrator via DI:
  apps.go: NewAppsHandler(orchestrator *managers.Orchestrator)
  profiles.go: NewProfilesHandler(orchestrator *managers.Orchestrator)
  casaos.go: NewCasaOSHandler(appStoreManager, orchestrator, gatewayIP, baseDomain)
  registry.go: NewRegistryHandler(..., portMgr, orchestrator, db, syncMgr, ...)

cmd/cubeos-api/main.go:
  1. construct Orchestrator
  2. construct WorkflowEngine + register 12 workflows
  3. engine.Start(ctx)
  4. orchestrator.SetFlowEngine(engine, store) — late binding so handlers can submit work
```

## Concurrency

Orchestrator does NOT hold a per-stack mutex (CGC-verified — that was my previous incorrect assumption). The single-threaded WorkflowEngine + the UNIQUE partial index on `workflow_runs(workflow_type, external_id) WHERE state NOT IN (terminal)` provides per-app idempotency.

## Out of scope

- Per-method detail (read orchestrator.go directly — too much to mirror in a spec)
- WorkflowEngine internals (spec/001)
- Specific workflows (spec/003)
