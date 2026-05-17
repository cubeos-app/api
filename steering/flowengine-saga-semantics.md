# Steering — FlowEngine saga semantics

Saga runtime at `internal/flowengine/`. Implements multi-step operations with explicit compensating actions per Article C-II.

## Saga shape

```go
type Saga interface {
  Name() string
  Steps() []Step  // ordered
}

type Step struct {
  Name      string
  Execute   func(ctx) error
  Compensate func(ctx) error  // run on rollback of any later step failure
}
```

The runner (`internal/flowengine/engine.go`):

1. Execute Step[0] — if error, return immediately
2. Execute Step[1] — if error, run Compensate[0]
3. Execute Step[N] — if error, run Compensate[N-1], Compensate[N-2], ..., Compensate[0] in REVERSE
4. On success: return nil

Compensating actions are best-effort — they log and continue on internal errors, rather than failing the rollback. Rationale: partial rollback is more recoverable than no rollback.

## The 5 canonical sagas

| Saga | Steps | Compensation strategy |
|---|---:|---|
| `appstore_install` | 9 | reverse-step rollback (port released → compose deleted → stack removed → DNS removed → proxy removed → DB row deleted) |
| `appstore_remove` | 6 | rare to roll back (forward-fail logged; manual cleanup if needed) |
| `network_mode_switch` | 5 | reverse-step (per docs/spec/008 design) |
| `first_boot_setup` | 9 | reverse-step (special case: rollback re-arms first-boot wizard) |
| `access_profile_switch` | 8 | full reverse (per docs/spec/004 design) |

## Saga step idempotency

All step Execute and Compensate functions MUST be idempotent. The runner may re-execute a step if a retry policy is configured (none of the current 5 sagas use retries, but the interface supports it). Idempotency means: running Execute twice produces the same end-state.

## Saga progress tracking

The runner emits per-step progress events to `internal/flowengine/progress_bus.go` which the websocket handler subscribes to. Dashboard renders progress in real time. Persistent record stored in `flowengine_runs` table (schema v22+).

## When to add a new saga

A new saga is justified when:
1. The operation has > 2 steps that can fail mid-way
2. Each step needs explicit cleanup if a later step fails
3. The operator needs progress visibility

Single-step operations (e.g. `StartApp`) do not warrant a saga.

## Cross-references

- Per-step compensating-action examples: see actual saga code under `internal/flowengine/<saga>.go`
- Project-level constraint: `docs/spec/009-swarm-orchestrator` REQ-909/910/911
