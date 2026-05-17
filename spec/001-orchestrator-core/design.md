# Design — Orchestrator core (spec/001)

Retrospective spec for the shipped Orchestrator. Implementation lives at `internal/managers/orchestrator.go`.

## Public interface (current)

```go
type Orchestrator interface {
  InstallApp(ctx context.Context, req *InstallRequest) (*App, error)
  UninstallApp(ctx context.Context, id string) error
  StartApp(ctx context.Context, id string) error
  StopApp(ctx context.Context, id string) error
  RestartApp(ctx context.Context, id string) error
  GetApp(ctx context.Context, id string) (*App, error)
  ListApps(ctx context.Context) ([]*App, error)
}
```

## Per-stack serialization

```go
type Orchestrator struct {
  stackMutexes sync.Map  // map[string]*sync.Mutex keyed by stack name
  ...
}

func (o *Orchestrator) lockStack(stack string) (release func(), err error) {
  mu, _ := o.stackMutexes.LoadOrStore(stack, &sync.Mutex{})
  acquired := make(chan struct{})
  go func() { mu.(*sync.Mutex).Lock(); close(acquired) }()
  select {
  case <-acquired:
    return func() { mu.(*sync.Mutex).Unlock() }, nil
  case <-time.After(60 * time.Second):
    return nil, ErrLockTimeout
  }
}
```

## Saga delegation

```go
func (o *Orchestrator) InstallApp(ctx, req) (*App, error) {
  release, err := o.lockStack(req.StackName)
  if err != nil { return nil, err }
  defer release()

  saga := flowengine.NewAppstoreInstallSaga(o.deps, req)
  if err := o.flowEngine.Run(ctx, saga); err != nil {
    return nil, fmt.Errorf("install failed: %w (compensation: %s)", err, saga.CompensationResult())
  }
  return saga.Result(), nil
}
```

## Audit logging

Every Orchestrator method wraps its return path:
```go
defer func() {
  o.audit.WriteEvent(ctx, "orchestrator.install", req.ID, returnedError)
}()
```

## Lint enforcement (REQ-113)

`.golangci.yml` includes a custom `forbidigo` rule:
```yaml
forbidigo:
  forbid:
    - p: '^managers\.NewSwarmManager$'
      msg: "SwarmManager must only be instantiated inside internal/managers/. Handlers go through Orchestrator."
```

## Queue introspection (REQ-112)

`/api/v1/orchestrator/queue` returns:
```json
{
  "pending": [{"stack": "...", "action": "install", "enqueued_at": "..."}],
  "running": [{"stack": "...", "action": "uninstall", "saga": "appstore_remove", "step": 3, "step_started_at": "..."}]
}
```

Surfaces via dashboard FlowEngine-inspector view (per access profile = advanced+).
