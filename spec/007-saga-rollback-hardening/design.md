# Design — Saga rollback hardening (spec/007)

Future-work spec to make FlowEngine more crash-recoverable + operator-debuggable.

## Persistence at step boundaries

Currently `flowengine_runs` records start + end. This spec adds per-step persist:

```sql
ALTER TABLE flowengine_runs ADD COLUMN current_step INTEGER;
ALTER TABLE flowengine_runs ADD COLUMN completed_steps TEXT;  -- JSON array of step indexes
ALTER TABLE flowengine_runs ADD COLUMN requires_operator BOOLEAN DEFAULT 0;
ALTER TABLE flowengine_runs ADD COLUMN operator_notes TEXT;
ALTER TABLE flowengine_runs ADD COLUMN resolved_at TIMESTAMP;
```

Schema bump to v28 (next version after current v27).

## Crash recovery algorithm

On api boot:
```
SELECT * FROM flowengine_runs WHERE status = 'started' AND completed_at IS NULL
for each row:
  log("found crashed saga %s (run_id=%s)", saga_name, run_id)
  saga := registry.Lookup(saga_name)
  if saga == nil:
    mark as requires_operator + notes "saga no longer registered"; continue
  completedSteps := unmarshal(row.completed_steps)
  // Roll back completed steps in reverse
  for i := len(completedSteps)-1; i >= 0; i--:
    err := saga.Steps()[i].Compensate(ctx)
    if err: log + continue (per Article C-II)
  mark run as 'crashed'
```

## Manual-cleanup-required mode (REQ-704)

If a compensating action fails twice in a row (initial attempt + one retry), set `requires_operator: true`. The run stays in the `flowengine_runs` table indefinitely; dashboard surfaces it; operator can mark resolved via `POST /api/v1/flowengine/runs/{id}/resolve`.

## Concurrency cap (REQ-711)

Pi 5 / 4GB RAM caps the number of concurrent saga runs to keep memory + Docker daemon load bounded. Default 5; configurable via `CUBEOS_MAX_CONCURRENT_SAGAS` env var. Excess requests queue in `Orchestrator.requestQueue` with a 30s timeout.

## Retry policy (REQ-712 / REQ-713)

```go
type Step struct {
  Name       string
  Execute    func(ctx) error
  Compensate func(ctx) error
  Timeout    time.Duration
  MaxRetries int        // default 0 = no retry
}
```

Retry happens INSIDE the saga runner; exponential backoff 250ms → 500ms → 1s → 2s → 5s (capped). If still fails after MaxRetries, the step is treated as failed + compensation kicks in.

## Audit + Matrix integration

Matrix alert format:
```
[CubeOS-Pi-<hostname>] Saga "appstore_install" needs manual cleanup
  Run ID: <uuid>
  Failed step: stack_deploy (step 5/9)
  Compensation outcome: dns_remove FAILED (HAL timeout)
  Resolve via: PUT /api/v1/flowengine/runs/<uuid>/resolve
```

Matrix room configurable via `CUBEOS_ALERT_MATRIX_ROOM` env var.
