# Requirements — Saga rollback hardening (spec/007)

Source: parent docs/spec/009-swarm-orchestrator + component spec/002 retrospective. This spec captures future-work improvements to saga rollback robustness.

> ID convention: 700-block.

REQ-700: The system shall persist saga progress to SQLite (`flowengine_runs`) after every completed step so the runner can resume after crash.
REQ-701: When the api restarts and detects an incomplete saga in `flowengine_runs`, the system shall trigger compensating actions for completed steps + mark the run as crashed.
REQ-702: The system shall provide a `flowengine.ResumeSaga(runID)` method that re-executes from the last completed step.
REQ-703: While a saga is mid-step, the system shall write the step's intent to `flowengine_runs.current_step` so crash recovery knows where it was.
REQ-704: When a compensating action fails twice consecutively, the system shall enter "manual-cleanup-required" mode marking the run with `requires_operator: true`.
REQ-705: The system shall expose `GET /api/v1/flowengine/runs?requires_operator=true` returning the set of runs needing operator cleanup.
REQ-706: The system shall expose `POST /api/v1/flowengine/runs/{id}/resolve` accepting `{notes: string}` to mark an operator-cleaned run as resolved.
REQ-707: When a saga step Execute or Compensate exceeds its declared Timeout, the system shall return ErrStepTimeout and proceed to compensation.
REQ-708: The system shall integrate saga progress with the dashboard "Notifications" tray so operators see in-progress + failed sagas.
REQ-709: When the operator inspects a failed run, the dashboard shall show: failed step, error message, per-compensation outcome, link to retry / mark-resolved.
REQ-710: The system shall test crash-recovery in `internal/flowengine/crash_recovery_test.go` simulating mid-saga process kill.
REQ-711: While a saga is running, the system shall NOT permit more than 5 concurrent saga instances (configurable; default protects Pi 5 RAM).
REQ-712: The system shall add per-saga retry policy support — `Step.MaxRetries int` defaulting to 0 (no retry).
REQ-713: When a Step has MaxRetries > 0 and Execute fails, the system shall retry up to MaxRetries with exponential backoff (250ms, 500ms, 1s, ...).
REQ-714: The system shall log every saga retry to the audit log including: saga_name, step_name, attempt_number, last_error.
REQ-715: When the runner enters manual-cleanup-required mode, the system shall emit a Matrix alert to the operator's configured alert room.
