# Steering — WorkflowEngine deep dive

CGC-grounded against `internal/flowengine/engine.go:61` (the WorkflowEngine type) + `saga.go` + `store.go` + the 12 workflows + 14 activities.

## Core types (real names)

```go
// internal/flowengine/engine.go
type WorkflowEngine struct {
  store    *WorkflowStore
  saga     *SagaOrchestrator
  registry *ActivityRegistry
  config   EngineConfig
  nodeID   string
  definitions map[string]WorkflowDefinition
  // ... + completionHooks, sync.RWMutex fields, running atomic.Bool, cancel, wg
}

type EngineConfig struct {
  ActivePollInterval time.Duration
  IdlePollInterval   time.Duration
  ReaperInterval     time.Duration
  LockDuration       time.Duration
  WorkflowTimeout    time.Duration
}

// internal/flowengine/saga.go
type SagaOrchestrator struct {
  store    *WorkflowStore
  executor *StepExecutor
  registry *ActivityRegistry
  nodeID   string
}
```

## Lifecycle

```go
// 1. Construct
engine := flowengine.NewWorkflowEngine(store, registry, EngineConfig{...})

// 2. Register all 12 workflow definitions
engine.RegisterWorkflow(workflows.AppstoreInstallWorkflow())
engine.RegisterWorkflow(workflows.AppstoreRemoveWorkflow())
// ... 12 total

// 3. Optional completion hooks (cache invalidation etc.)
engine.OnCompletion("appstore_install", func(wfType, externalID string, state WorkflowState) {
  // refresh app catalog cache
})

// 4. Start (returns nil when poll loop + reaper are running)
engine.Start(ctx)

// 5. Submit work
engine.Submit(ctx, SubmitParams{
  WorkflowType: "appstore_install",
  ExternalID: appID,
  Input: ...,
})

// 6. Graceful shutdown
engine.Stop()
```

## Key design facts (from CGC docstrings + code reading)

1. **Single-threaded by design** — `processNextWorkflow` returns after picking + executing ONE workflow. Avoids SQLite contention on Pi SD card.
2. **Adaptive polling** — fast (`ActivePollInterval`) when GetIncompleteWorkflows() returns non-empty; slow (`IdlePollInterval`) when empty.
3. **Reaper goroutine** — runs every `ReaperInterval`, calls `store.ReleaseExpiredLocks()` releasing locks held longer than `LockDuration`. Protects against workers that died mid-workflow.
4. **Recovery on startup** — `recover(ctx)` finds workflows in pending/running/compensating states + unlocks them so the poll loop can resume.
5. **Per-node lock model** — `store.LockWorkflow(id, nodeID, lockDuration)` enables multi-node coordination. v1.0 ships single-node; architecture supports cluster.
6. **Completion hooks** — async, panic-recovered (each hook runs in its own goroutine wrapped in `defer recover()`).
7. **Workflow IDs** — UUID per workflow run; ExternalID is operator-supplied for idempotent submit (UNIQUE partial index on workflow_runs enforces).

## How handlers submit work

```go
// internal/handlers/apps.go (typical pattern)
func (h *AppsHandler) Install(w http.ResponseWriter, r *http.Request) {
  var req InstallRequest
  // ... decode ...
  run, err := h.orchestrator.SubmitWorkflow(ctx, "appstore_install", req.AppID, req.Params)
  if err != nil { /* respond 4xx/5xx */ }
  // respond 202 with job_id = run.ID
}
```

Handler returns 202 Accepted with the workflow_run ID. Client polls `/api/v1/workflows/{id}` for progress.

## Composition: workflows vs activities

| Layer | Lives in | Purpose |
|---|---|---|
| **Workflow** | `internal/flowengine/workflows/<name>.go` | Ordered list of steps that compose activities |
| **Activity** | `internal/flowengine/activities/<domain>.go` | Single-domain primitive (e.g. add_dns, write_compose, stack_deploy) |
| **Step** | inside a WorkflowDefinition | Activity name + input params + compensating action ID |

The 12 workflows reuse the 14 activities (no per-workflow duplication). Adding a new workflow = compose existing activities. Adding a new activity = new file under `activities/` + register in `ActivityRegistry`.

## Out of scope for this steering doc

- Detailed activity semantics (read `activities/` source directly)
- Per-workflow step graphs (read `workflows/<name>.go` source directly)
- Operator UI for workflow inspection (`dashboard/src/components/swarm/` covers stack-level; future spec/007 covers workflow-level inspector)
