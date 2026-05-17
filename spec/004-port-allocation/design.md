# Design — Port allocation (spec/004)

The PortManager. Lives at `internal/managers/ports.go`.

## Allocation algorithm

```go
func (p *PortManager) Allocate() (int, error) {
  p.mu.Lock()
  defer p.mu.Unlock()
  for port := 6100; port < 7000; port++ {
    if !p.inUse[port] {
      p.inUse[port] = true
      if err := p.persist(port, true); err != nil {
        delete(p.inUse, port)
        return 0, err
      }
      return port, nil
    }
  }
  return 0, ErrPortPoolExhausted
}
```

## Release

```go
func (p *PortManager) Release(port int) error {
  p.mu.Lock()
  defer p.mu.Unlock()
  delete(p.inUse, port)
  return p.persist(port, false)
}
```

## Boot-time map init

```go
func (p *PortManager) loadFromSQLite() error {
  rows, _ := p.db.Query("SELECT port, app_id FROM apps WHERE port IS NOT NULL ORDER BY id")
  seen := map[int]string{}
  for rows.Next() {
    var port int; var appID string
    rows.Scan(&port, &appID)
    if existing, dup := seen[port]; dup {
      log.Warn("port %d allocated to multiple apps (%s, %s); treating as %s's", port, existing, appID, existing)
      continue  // REQ-414: lower-ID wins
    }
    seen[port] = appID
    p.inUse[port] = true
  }
  return nil
}
```

## Why in-memory + per-allocation persist (not lazy)

Lazy persist (batch every N seconds): if api crashes between in-memory update + persist, the port appears free on next boot but is actually in use by a deployed stack.

Per-allocation persist via `UPDATE apps SET port = ? WHERE id = ?` (called inside the install saga's `allocate_port` step): tightly couples in-memory + on-disk state. Cost: one SQLite write per install (rare; ~10/day typical).

## Concurrency test (REQ-413)

```go
func TestPortManager_concurrent_allocate(t *testing.T) {
  pm := NewPortManager(...)
  var wg sync.WaitGroup
  ports := sync.Map{}
  errors := atomic.Int32{}
  for i := 0; i < 1000; i++ {
    wg.Add(1)
    go func() {
      defer wg.Done()
      p, err := pm.Allocate()
      if err != nil { errors.Add(1); return }
      if _, dup := ports.LoadOrStore(p, true); dup {
        t.Errorf("duplicate port allocated: %d", p)
      }
    }()
  }
  wg.Wait()
  // Expect: ~900 successful allocations, ~100 errors (pool exhausted)
}
```

## REST surface

- `GET /api/v1/system/ports` → map of port → app_id for all allocated ports
- `GET /api/v1/system/ports/free` → `{free_count: int}` (REQ-415)
