# 5. Workflow + activity 2-level composition

Date: 2026-05-18 (codifying shipped design)

## Status
Accepted

## Context
CGC-verified: 12 workflows in `internal/flowengine/workflows/` (appstore_install, appstore_remove, app_install, app_remove, network_mode_switch, wifi_client_switch, access_profile_switch, first_boot_setup, backup, restore, registry_cache, system_update) compose 14 activities in `internal/flowengine/activities/` (access_profile, app_install, app_remove, appstore, backup, database, docker, hal, infra, network, registry, setup, update, wifi_client).

Earlier prototype had flat per-workflow logic — install_app.go duplicated the same "stack deploy → add DNS → add proxy" sequence as appstore_install.go. Refactor moved shared logic to activities, leaving workflows as thin compose layers.

## Decision

Two-level composition:

- **Workflow** (`workflows/<name>.go`) — ordered list of named steps.
- **Step** — names an activity + provides input params + names a compensating action.
- **Activity** (`activities/<domain>.go`) — single primitive (add_dns, write_compose, stack_deploy, etc.). Idempotent.

Adding a new operation: try to compose existing activities into a new workflow first. Only add a new activity if the operation is genuinely new (not just a different ordering / parameterisation of existing).

## Consequences

**Positive:** Activities are reused (14 activities serve 12 workflows). New workflows are quick to author. Activities are unit-testable in isolation.
**Negative:** Slightly more abstraction than a flat workflow per operation. Mitigated by clear naming convention.
**Enforced by:** Article C-III + code review.
