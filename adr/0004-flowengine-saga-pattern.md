# 4. FlowEngine saga pattern for multi-step operations

Date: 2026-05-17 (codifying decision originally made 2026-01)

## Status

Accepted

## Context

App install requires: allocate port → write compose → stack deploy → add DNS → add proxy → DB insert. 9 steps. Each can fail. Failure mid-way leaves orphan state (port allocated but no compose, stack deployed but no DNS, etc.). Same shape for uninstall, network mode switch, first-boot setup, access profile switch.

Options considered:
- **Inline error-handling per handler** — gets messy after 3+ steps; cleanup logic duplicated across handlers; easy to miss a cleanup path.
- **Database transaction** — doesn't help because steps span Docker, HAL, Pi-hole, NPM, SQLite (cross-system).
- **External workflow engine** (Temporal, Cadence) — heavy dependency; runtime + DB requirements; massive overkill for single-Pi.
- **Custom saga runner** — explicit Execute + Compensate per step; runner orchestrates rollback.

## Decision

Implement a custom saga runner in `internal/flowengine/`. Each saga is a `Saga` interface with ordered `Steps []Step`. Each step has `Execute` + `Compensate` functions. The runner executes steps forward; on any failure, runs compensating actions in reverse from the failure step.

## Consequences

**Positive:**
- Cleanup logic colocated with the action it cleans up.
- New sagas added incrementally (currently 5; expecting +2-3 in next phase).
- Progress events surface in dashboard via WebSocket subscription to `progress_bus`.
- No external dependency.

**Negative:**
- Saga semantics are bespoke (no learn-once-use-anywhere transferability vs Temporal).
- Idempotency burden is on the saga author. Mitigation: code review checklist + dedicated saga tests.

**Enforced by:** Component Article C-II + project ADR-0008 (parallel-dev workflow override depends on saga semantics being well-defined).
