# Design — Workflow recovery hardening (spec/007)

Future-work. Extends spec/001 (the shipped WorkflowEngine).

## What's already shipped (spec/001)

- Reaper releases expired locks
- Recovery on Start re-unlocks incomplete workflows
- Per-node lock model with LockDuration timeout

## What this spec adds

1. **Per-step retry policy** — Step{MaxRetries, Backoff} fields. Engine retries with exponential backoff before failing the step.
2. **Manual-cleanup-required mode** — When compensation fails twice, mark workflow_run.requires_operator=true. Surface in dashboard + Matrix alert.
3. **Resolve endpoint** — POST /api/v1/workflows/{id}/resolve {notes} → operator marks cleaned.
4. **Concurrency cap** — soft cap on concurrent workflows (default 5) via CUBEOS_MAX_CONCURRENT_WORKFLOWS env var.
5. **Schema v28** — append columns to workflow_runs: requires_operator, operator_notes, resolved_at.
6. **Dashboard tray** — surface requires_operator workflows + per-step detail + retry button.

## File-level paths (future)

| Function | Path |
|---|---|
| Schema migration | `internal/database/migrations.go` v27→v28 |
| Retry support | extend `internal/flowengine/step.go` + `engine.go` |
| Crash recovery test | new `internal/flowengine/crash_recovery_test.go` |
| Resolve handler | new `internal/handlers/workflows_resolve.go` |
| Matrix alert | extend `internal/clients/` (verify if matrix client exists OR add) |
| Dashboard tray | new `dashboard/src/components/notifications/WorkflowTray.vue` |
| Concurrency cap | extend `internal/flowengine/engine.go` Submit() |
