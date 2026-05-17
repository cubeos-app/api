# Steering — Orchestrator pattern

The single coordinator for app lifecycle. Lives at `internal/managers/orchestrator.go`.

## Why one Orchestrator

Pre-Hydra-fix, three independent components (Services + AppManager + AppStore) each called Docker directly → race conditions + state drift. Orchestrator centralizes lifecycle so two concurrent install requests serialize, status is queried from a single source, and uninstall cleanup is exhaustive.

## Public surface

```go
type Orchestrator interface {
  InstallApp(ctx, app) (*App, error)     // saga: allocate port → write compose → stack deploy → DNS → proxy → DB
  UninstallApp(ctx, id) error             // saga: stack remove → DNS remove → proxy remove → cleanup → DB delete
  StartApp(ctx, id) error                 // service scale to replicas
  StopApp(ctx, id) error                  // service scale to 0
  RestartApp(ctx, id) error               // service force-update
  GetApp(ctx, id) (*App, error)
  ListApps(ctx) ([]*App, error)
}
```

## How handlers call it

```go
func (h *AppsHandler) Install(w http.ResponseWriter, r *http.Request) {
  var req InstallRequest
  // ... decode + validate ...
  app, err := h.orchestrator.InstallApp(r.Context(), &req)
  // ... respond ...
}
```

Handlers MUST NOT bypass Orchestrator to call SwarmManager directly. Article C-I.

## Concurrency model

Orchestrator holds a per-stack mutex (sync.Map keyed by stack-name). Two install requests targeting the same stack serialize; install on stack A + uninstall on stack B run in parallel. Lock acquisition has a 60-second timeout; timeout returns HTTP 503.

## Failure semantics

Each Orchestrator method delegates to a FlowEngine saga (`internal/flowengine/<saga>.go`). On saga failure, the saga runner executes compensating actions in reverse from the failure step. Orchestrator surfaces the final saga error to the caller.

## Profile-aware skipping

Activities `add_dns`, `remove_dns`, `create_proxy`, `remove_proxy` check `ctx.Value(profileKey)` and no-op when profile=`standard`. The check is inside the activity, not in the saga — sagas remain profile-agnostic. (Article C-IV.)

## Cross-references

- Saga semantics: `steering/flowengine-saga-semantics.md`
- DB shape: `steering/database-conventions.md`
- Middleware order: `steering/middleware-stack.md`
- Project-level architectural context: `/home/claude-runner/gitlab/products/cubeos/docs/steering/architecture.md`
