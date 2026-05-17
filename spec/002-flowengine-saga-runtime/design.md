# Design — FlowEngine saga runtime (spec/002)

The reusable saga executor. Implementation lives at `internal/flowengine/`.

## Interface

```go
type Saga interface {
  Name() string
  Steps() []Step
}

type Step struct {
  Name       string
  Execute    func(ctx context.Context) error
  Compensate func(ctx context.Context) error
  Timeout    time.Duration  // optional; if zero, no per-step timeout
}

type Engine interface {
  Register(saga Saga) error
  Run(ctx context.Context, saga Saga) (*RunResult, error)
  GetRun(ctx, runID string) (*Run, error)
  ListRuns(ctx, filter Filter) ([]*Run, error)
  SubscribeProgress(runID string) <-chan ProgressEvent
}
```

## Execution algorithm

```
runID := uuid.New()
record(runID, status=started)

completedSteps := []
for i, step := range saga.Steps():
  emitProgress(runID, step=i, status=started)
  err := step.Execute(ctx)
  if err != nil:
    emitProgress(runID, step=i, status=failed, error=err)
    rollback(runID, completedSteps)  // reverse-order compensation
    record(runID, status=failed, failedStep=i, error=err)
    return err
  completedSteps = append(completedSteps, step)
  emitProgress(runID, step=i, status=completed)

record(runID, status=succeeded)
return nil
```

## Rollback algorithm

```
for i := len(completedSteps)-1; i >= 0; i--:
  step := completedSteps[i]
  err := step.Compensate(ctx)
  if err != nil:
    log("compensation step %d failed: %v — continuing rollback", i, err)
    // continue; do NOT abort rollback on secondary failure
```

## Idempotency contract

The runner does NOT retry; idempotency is required only for crash-recovery scenarios where the operator manually re-runs a half-completed saga. Saga authors document idempotency in step comments.

## Progress bus

In-memory pub-sub:

```go
type ProgressBus struct {
  mu      sync.RWMutex
  subscribers map[string][]chan ProgressEvent  // keyed by runID
}
```

WebSocket handler at `/ws/flowengine/{run_id}` subscribes; on receive, forwards as JSON to the client.

## Persisted record (flowengine_runs table, schema v22)

```sql
CREATE TABLE flowengine_runs (
  id TEXT PRIMARY KEY,
  saga_name TEXT NOT NULL,
  started_at TIMESTAMP NOT NULL,
  completed_at TIMESTAMP,
  status TEXT NOT NULL,  -- started | succeeded | failed
  failed_step INTEGER,
  error_message TEXT,
  compensation_outcomes TEXT  -- JSON: per-step compensation result
);
```

Pruned by retention job at 30-day default.
