# Design — 12 Workflows + 14 Activities (spec/003 — RETROSPECTIVE)

The 12-and-14 composition catalog. CGC-grounded.

## The 12 workflows

| Workflow | File | Purpose |
|---|---|---|
| appstore_install | workflows/appstore_install.go | Install from app store with compose transform |
| appstore_remove | workflows/appstore_remove.go | Uninstall app-store app |
| app_install | workflows/app_install.go | Generic app install (operator-provided compose) |
| app_remove | workflows/app_remove.go | Generic app remove |
| network_mode_switch | workflows/network_mode_switch.go | 6-mode switching (spec/008 in docs/) |
| wifi_client_switch | workflows/wifi_client_switch.go | WiFi client network change |
| access_profile_switch | workflows/access_profile_switch.go | Profile switching (spec/004 in docs/) |
| first_boot_setup | workflows/first_boot_setup.go | First-boot wizard saga |
| backup | workflows/backup.go | Backup orchestration with destination dispatch |
| restore | workflows/restore.go | Restore from backup with verification |
| registry_cache | workflows/registry_cache.go | Registry GC + sync |
| system_update | workflows/system_update.go | OS package update |

## The 14 activities

Granular primitives in `activities/`:

```
access_profile.go    app_install.go    app_remove.go     appstore.go
backup.go            database.go       docker.go         hal.go
infra.go             network.go        registry.go       setup.go
update.go            wifi_client.go
```

Each activity is idempotent + composable. Workflows pick + sequence activities.

## Anti-pattern (not done)

- No `managers/compose.go` file — compose transformation lives inside `activities/appstore.go` + `activities/app_install.go` per Article C-X. The CGC-verified absence of this file is the constitutional invariant.
- No flat `internal/flowengine/<workflow>.go` files — all workflows live under `workflows/`. My previous spec assumed flat; reality is `workflows/` subdirectory.

## Out of scope

- Per-workflow step graphs (read the source — too much to mirror)
- Per-activity semantics (read the source)
- WorkflowEngine internals (spec/001)
