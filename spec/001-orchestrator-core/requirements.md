# Requirements — Orchestrator core (spec/001 — retrospective)

Source: `api/CLAUDE.md` §"Orchestrator Pattern" + parent `docs/spec/009-swarm-orchestrator/`.

> Retrospective. ID convention: 100-block.

REQ-100: The system shall expose an Orchestrator type at `internal/managers/orchestrator.go` as the single coordinator for app lifecycle.
REQ-101: The Orchestrator shall provide InstallApp, UninstallApp, StartApp, StopApp, RestartApp, GetApp, ListApps methods.
REQ-102: The system shall route every handler-level app-lifecycle action through Orchestrator (no direct SwarmManager calls from handlers).
REQ-103: While two install requests target the same stack name, the Orchestrator shall serialize them via a per-stack mutex.
REQ-104: If a per-stack mutex acquisition exceeds 60 seconds, then the Orchestrator shall return HTTP 503 with an actionable error body.
REQ-105: The Orchestrator shall delegate every Docker Swarm API call to a single SwarmManager instance per Article C-I.
REQ-106: When the Orchestrator handles InstallApp, the Orchestrator shall delegate the implementation to the `appstore_install` FlowEngine saga.
REQ-107: When the Orchestrator handles UninstallApp, the Orchestrator shall delegate to the `appstore_remove` saga.
REQ-108: When the Orchestrator handles StartApp, the Orchestrator shall scale the service to its persisted replica count.
REQ-109: When the Orchestrator handles StopApp, the Orchestrator shall scale the service to zero replicas without removing the stack.
REQ-110: The Orchestrator shall write every lifecycle event to the audit log via the AuditLogger before returning.
REQ-111: If any lifecycle action fails partway through, then the Orchestrator shall surface the saga's compensation result in the error message.
REQ-112: While the Orchestrator is processing requests, the Orchestrator shall expose `GET /api/v1/orchestrator/queue` returning the pending + running request set.
REQ-113: The system shall reject any new code path that imports SwarmManager outside `internal/managers/` (enforced via golangci-lint custom rule).
REQ-114: The system shall test every Orchestrator method with table-driven Go tests in `internal/managers/orchestrator_test.go`.
REQ-115: When the Orchestrator method receives a cancelled context, the Orchestrator shall propagate the cancellation through to the saga step that observes it.
