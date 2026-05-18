# Requirements — 12 Workflows + 14 Activities (spec/003 — RETROSPECTIVE)

Source: CGC-verified `internal/flowengine/workflows/` (12 files) + `internal/flowengine/activities/` (14 files).

> Retrospective. ID convention: 300-block.

REQ-300: The system shall provide exactly 12 canonical workflows at `internal/flowengine/workflows/*.go`: appstore_install, appstore_remove, app_install, app_remove, access_profile_switch, backup, first_boot_setup, network_mode_switch, registry_cache, restore, system_update, wifi_client_switch.
REQ-301: The system shall provide exactly 14 activities at `internal/flowengine/activities/*.go`: access_profile, app_install, app_remove, appstore, backup, database, docker, hal, infra, network, registry, setup, update, wifi_client.
REQ-302: The system shall require every workflow to be a `WorkflowDefinition` registered with the engine via `RegisterWorkflow(def)` per Article C-III.
REQ-303: The system shall require every activity to be registered with the `ActivityRegistry` and addressed by name from workflow steps.
REQ-304: The system shall compose multi-step operations: workflows reuse activities (14 activities serve 12 workflows; no per-workflow duplication).
REQ-305: When a workflow step fails, the saga executor shall run compensating actions in reverse order from the failed step.
REQ-306: The system shall keep compose-to-Swarm transformation inside `activities/appstore.go` + `activities/app_install.go` (NOT a `managers/compose.go` file per Article C-X).
REQ-307: The system shall include `workflows_test.go` covering each workflow's happy path + at least one failure-with-compensation case.
REQ-308: The system shall include `activities_test.go` covering each activity's happy path + idempotency.
REQ-309: The system shall require every activity to be idempotent — running it twice with the same input produces the same end-state.
REQ-310: The system shall persist workflow runs to the `workflow_runs` table via `WorkflowStore.CreateWorkflow` so they survive process restart.
REQ-311: When a workflow reaches terminal state, the system shall fire any registered completion hook for its workflow_type asynchronously.
REQ-312: The system shall NEVER write to the deprecated `installed_apps` table — only the unified `apps` table per project ADR-0002.
REQ-313: The `appstore_install` workflow shall validate the source compose against documented Swarm-supported features + reject early with HTTP 422 on unsupported features per Article C-X.
REQ-314: The `backup` workflow shall write to operator-configured destinations (local, SMB, NFS, S3-compatible) via `internal/managers/backup_destinations.go`.
REQ-315: The `restore` workflow shall verify backup integrity (SHA-256 + signature if signed via `backup_crypto.go`) before applying.
REQ-316: The `first_boot_setup` workflow shall complete atomically — failure leaves `/cubeos/data/.setup_complete` unwritten so next boot retries from scratch.
