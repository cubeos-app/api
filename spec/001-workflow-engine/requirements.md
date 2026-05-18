# Requirements — WorkflowEngine (spec/001 — RETROSPECTIVE)

Source: CGC-verified `internal/flowengine/engine.go:61` (WorkflowEngine type) + `saga.go:21` (SagaOrchestrator) + `store.go` (WorkflowStore) + `registry.go` (ActivityRegistry) + `definition.go` + `step.go` + `progress.go` + `errors.go`.

> Retrospective. ID convention: 100-block.

REQ-100: The system shall expose `WorkflowEngine` type at `internal/flowengine/engine.go:61` with fields store, saga, registry, config, nodeID, definitions, completionHooks, running atomic.Bool, cancel, wg.
REQ-101: The system shall expose `EngineConfig` struct at `internal/flowengine/engine.go:29` with ActivePollInterval, IdlePollInterval, ReaperInterval, LockDuration, WorkflowTimeout fields.
REQ-102: The system shall provide `NewWorkflowEngine(store, registry, config)` constructor.
REQ-103: The system shall expose `RegisterWorkflow(def WorkflowDefinition) error` to register workflow types before Start.
REQ-104: The system shall expose `Start(ctx) error` that begins poll loop + reaper goroutines.
REQ-105: The system shall expose `Stop()` that gracefully shuts down — cancels context, waits for goroutines, sets running=false.
REQ-106: The system shall expose `Submit(ctx, params SubmitParams) (*WorkflowRun, error)` for submitting work.
REQ-107: The system shall expose `OnCompletion(workflowType string, hook CompletionHook)` for terminal-state hooks.
REQ-108: While the engine runs, the system shall process ONE workflow at a time per node to avoid SQLite contention on the Pi's SD card (Article C-II).
REQ-109: While active workflows exist, the system shall poll at `ActivePollInterval` cadence; otherwise at `IdlePollInterval`.
REQ-110: The system shall release expired worker locks via the reaper goroutine running every `ReaperInterval` calling `store.ReleaseExpiredLocks()`.
REQ-111: When the engine Starts, the system shall recover incomplete workflows in pending/running/compensating states by releasing stale locks so the poll loop resumes them.
REQ-112: When a completion hook fires, the system shall run it in a goroutine wrapped in `defer recover()` so panics are logged but don't kill the engine.
REQ-113: The system shall use a per-node lock model — `store.LockWorkflow(id, nodeID, lockDuration)` — that enables future multi-node coordination.
REQ-114: The system shall reject `RegisterWorkflow` calls for an already-registered workflow type with `fmt.Errorf("workflow type %q already registered", wfType)`.
REQ-115: The system shall enforce UNIQUE constraint on `(workflow_type, external_id)` via partial index on `workflow_runs` table for idempotent submission.
REQ-116: When `WorkflowTimeout` is exceeded for a workflow, the saga executor shall halt + return ErrWorkflowTimeout + leave the workflow in failed state.
REQ-117: The system shall resolve `nodeID` from Swarm node ID OR hostname via `resolveNodeID()` helper at engine creation.
