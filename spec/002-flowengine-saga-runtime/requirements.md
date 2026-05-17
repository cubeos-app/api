# Requirements — FlowEngine saga runtime (spec/002 — retrospective)

Source: `api/CLAUDE.md` §FlowEngine + parent `docs/spec/009-swarm-orchestrator` REQ-909..911.

> Retrospective. ID convention: 200-block.

REQ-200: The system shall provide a saga runtime at `internal/flowengine/engine.go` executing Saga objects with ordered Steps.
REQ-201: The system shall require each Step to define `Execute` and `Compensate` functions.
REQ-202: When the runner executes a saga and any step returns an error, the runner shall invoke compensating actions in reverse order from the failure step.
REQ-203: While the saga runs, the runner shall emit per-step progress events to `internal/flowengine/progress_bus.go`.
REQ-204: The system shall persist saga-run history to the `flowengine_runs` table including: saga name, started_at, completed_at, status, failed_step, compensation_outcomes.
REQ-205: The system shall expose `GET /api/v1/flowengine/runs` returning the last 100 saga runs with filters by saga name + status.
REQ-206: The system shall expose `GET /api/v1/flowengine/runs/{id}` returning the per-step detail of a specific run.
REQ-207: While a saga is running, the system shall surface progress to subscribed websocket clients on `/ws/flowengine/{run_id}`.
REQ-208: The system shall guarantee step idempotency by contract — saga authors shall ensure `Execute` may be invoked twice with the same end-state.
REQ-209: If a compensating action itself fails, then the runner shall log the secondary failure and continue rolling back earlier steps.
REQ-210: When the runner receives a cancelled context, the runner shall halt at the current step boundary and run compensating actions for already-completed steps.
REQ-211: The system shall provide a `flowengine.Saga` interface with `Name()` + `Steps()` methods.
REQ-212: The system shall maintain test coverage for the runtime in `internal/flowengine/engine_test.go` covering: forward success, mid-saga failure, full rollback, compensating-action failure, context cancellation.
REQ-213: The system shall reject the registration of two sagas with the same `Name()` value.
REQ-214: While a saga step is running, the runner shall record the step start time so timeouts can be calculated externally.
REQ-215: The system shall provide a `MockSaga` helper in `internal/flowengine/testing/` for handler-level tests that need a saga without invoking the real workflow.
