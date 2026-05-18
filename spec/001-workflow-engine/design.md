# Design — WorkflowEngine (spec/001)

CGC-grounded retrospective. Real types + line numbers verified 2026-05-18.

## Wire diagram

```
NewWorkflowEngine(store, registry, config)
       │
       ├─ creates SagaOrchestrator with executor + nodeID
       ├─ creates StepExecutor
       └─ initialises definitions map + completionHooks map

handlers call engine.RegisterWorkflow(def) for each of 12 workflow types
engine.OnCompletion(type, hook) for per-type async hooks

engine.Start(ctx):
  ├─ ctx, cancel = WithCancel(ctx)
  ├─ recover incomplete workflows (unlock stale locks)
  ├─ start pollLoop goroutine
  └─ start reaperLoop goroutine

handlers call engine.Submit(ctx, SubmitParams) → store.CreateWorkflow → returns WorkflowRun

pollLoop:
  every tick (Active or Idle interval):
    incomplete := store.GetIncompleteWorkflows()
    if len(incomplete) > 0:
      processNextWorkflow(ctx, incomplete) → locks + executes ONE workflow

reaperLoop:
  every ReaperInterval:
    released := store.ReleaseExpiredLocks()
    if released > 0: log
```

## File layout (real, CGC-verified)

```
internal/flowengine/
  engine.go         — WorkflowEngine type + Start/Stop/Submit/Register/OnCompletion
  saga.go           — SagaOrchestrator type + ExecuteWithTimeout
  store.go          — WorkflowStore type (SQLite-backed persistence + locking)
  step.go           — StepExecutor type
  registry.go       — ActivityRegistry type
  definition.go     — WorkflowDefinition interface
  progress.go       — progress event emission
  errors.go         — ErrWorkflowTimeout
  engine_test.go    — colocated tests
  saga_test.go      — colocated tests
  store_test.go     — colocated tests (uses modernc.org/sqlite for in-memory DB)
  registry_test.go  — colocated tests
```

## Schema (workflow_runs table — added in earlier migration; current is v27)

```sql
CREATE TABLE workflow_runs (
  id TEXT PRIMARY KEY,                  -- UUID
  workflow_type TEXT NOT NULL,
  version INTEGER NOT NULL,
  external_id TEXT,
  input TEXT,                            -- JSON
  metadata TEXT,                         -- JSON
  current_state TEXT NOT NULL,           -- pending|running|compensating|completed|failed
  current_step INTEGER NOT NULL DEFAULT 0,
  max_retries INTEGER NOT NULL DEFAULT 0,
  attempts INTEGER NOT NULL DEFAULT 0,
  locked_by TEXT,
  locked_until TIMESTAMP,
  created_at TIMESTAMP NOT NULL,
  updated_at TIMESTAMP NOT NULL,
  completed_at TIMESTAMP
);

-- partial index for idempotent submission
CREATE UNIQUE INDEX workflow_runs_active_external
  ON workflow_runs(workflow_type, external_id)
  WHERE current_state NOT IN ('completed', 'failed');
```

## Out of scope (covered by other specs)

- The 12 workflow definitions themselves (spec/003).
- Per-step executor mechanics (in step.go; not separately specified).
- Compose transformation (spec/003 + lives in `activities/appstore.go`).
