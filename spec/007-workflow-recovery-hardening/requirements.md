# Requirements — Workflow recovery hardening (spec/007)

Source: extends spec/001 + Article C-II. Future-work improvements to crash-recovery + multi-node coordination.

> Future-work. ID convention: 700-block.

REQ-700: The system shall add per-step retry policy support to `WorkflowDefinition.Steps()` so individual steps can declare MaxRetries + backoff strategy.
REQ-701: When a step has MaxRetries > 0 and fails, the system shall retry up to MaxRetries with exponential backoff (250ms, 500ms, 1s, 2s, 5s capped).
REQ-702: The system shall log every workflow retry to `/cubeos/data/audit.log` including: workflow_type, step_name, attempt_number, last_error.
REQ-703: When a compensating action fails twice consecutively, the system shall mark the workflow_run with `requires_operator: true`.
REQ-704: The system shall expose `GET /api/v1/workflows?requires_operator=true` returning workflow runs needing operator cleanup.
REQ-705: The system shall expose `POST /api/v1/workflows/{id}/resolve` accepting `{notes: string}` to mark an operator-cleaned run as resolved.
REQ-706: The system shall emit a Matrix alert when a workflow transitions to `requires_operator: true`.
REQ-707: While a workflow is mid-step, the system shall persist `current_step` to `workflow_runs.current_step` so crash recovery knows position.
REQ-708: The system shall add schema migration v27→v28 adding columns `requires_operator BOOLEAN DEFAULT 0`, `operator_notes TEXT`, `resolved_at TIMESTAMP`.
REQ-709: The system shall integrate workflow progress with the dashboard "Notifications" tray.
REQ-710: When the operator inspects a failed run, the dashboard shall show: failed step, error message, per-compensation outcome, retry / mark-resolved buttons.
REQ-711: The system shall NOT permit more than 5 concurrent workflow instances (`CUBEOS_MAX_CONCURRENT_WORKFLOWS` env var, default 5).
REQ-712: The system shall test crash-recovery in `internal/flowengine/crash_recovery_test.go` simulating mid-saga process kill.
