# Requirements — Orchestrator lifecycle (spec/002 — RETROSPECTIVE)

Source: CGC-verified `internal/managers/orchestrator.go:27` (Orchestrator type) + `:45` (OrchestratorConfig) + `:60` (NewOrchestrator) + the documented method signatures (StartApp, StopApp, RestartApp, GetApp, EnableApp, AppExists, SetProfileApp, SetFlowEngine, Close).

> Retrospective. ID convention: 200-block.

REQ-200: The system shall expose `Orchestrator` type at `internal/managers/orchestrator.go:27` with fields: db, cfg, swarm, docker, npm, pihole, ports, hal, registryURL, registryClient, ctx, cancel, engine *flowengine.WorkflowEngine, feStore *flowengine.WorkflowStore.
REQ-201: The system shall expose `OrchestratorConfig` at `:45` with fields: DB, Config, CoreappsPath, AppsPath, NPMConfigDir, HALClient, RegistryURL, DockerCB, SwarmManager, NPMManager, PiholeManager.
REQ-202: The system shall expose `NewOrchestrator(cfg OrchestratorConfig) (*Orchestrator, error)` constructor that returns an error if DB or Config is nil.
REQ-203: While constructing, the system shall use provided SwarmManager/NPMManager/PiholeManager if non-nil OR construct new instances using the shared DockerCB.
REQ-204: The system shall initialise PortManager with `NewPortManager(cfg.DB, o.swarm, cfg.HALClient)` enabling triple-source validation.
REQ-205: The system shall expose `SetFlowEngine(e *flowengine.WorkflowEngine, s *flowengine.WorkflowStore)` for late wiring of the engine after engine.Start().
REQ-206: The system shall expose `Close() error` that cancels the orchestrator context + closes the DockerManager.
REQ-207: The system shall expose `AppExists(ctx, name string) (bool, error)` checking the `apps` table.
REQ-208: The system shall expose `StartApp(ctx, name) error` that either scale-via-Swarm OR docker.StartContainer based on `app.UsesSwarm()`.
REQ-209: The system shall expose `StopApp(ctx, name) error` that either scales-to-0 (Swarm) OR docker.StopContainer.
REQ-210: The system shall expose `RestartApp(ctx, name) error` that either force-restarts the Swarm service OR docker.RestartContainer.
REQ-211: The system shall expose `EnableApp(ctx, name) error` that updates `apps.enabled` column.
REQ-212: The system shall expose `GetApp(ctx, name) (*App, error)` reading from the apps table.
REQ-213: The system shall expose `SetProfileApp(ctx, profileID, appID int64, enabled bool) error` with `INSERT...ON CONFLICT...DO UPDATE` semantics.
REQ-214: The system shall delegate install + uninstall to FlowEngine workflows (NOT have Orchestrator.InstallApp + UninstallApp methods directly).
REQ-215: While Orchestrator is constructed, the system shall log NPM init warnings via `log.Warn().Err(err).Msg(...)` but continue startup.
