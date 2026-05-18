# Design — Port allocation (spec/004 — RETROSPECTIVE)

CGC-grounded. Real PortManager at `internal/managers/ports_new.go:91`.

## Real shape

```go
type PortManager struct {
  db    *sql.DB
  swarm *SwarmManager
  hal   *hal.Client
  mu    sync.RWMutex
}
```

NOT the in-memory map I previously assumed. Real implementation queries DB + Swarm + HAL on every allocation decision (triple-source validation).

## Triple-source validation

A port is FREE only when:
1. DB: `SELECT COUNT(*) FROM port_allocations WHERE port=? AND protocol=?` returns 0
2. Swarm: `getSwarmPorts(ctx)` does not include the port
3. HAL: `getHostPorts(ctx)` (via HAL `/network/ports/listening`) does not include the port

If `swarm == nil` or `hal == nil` at constructor time, fall back gracefully (DB-only). The fallback is documented in `NewPortManager` docstring.

## Allocation algorithm

```go
func (p *PortManager) AllocateUserPortWithContext(ctx) (int, error) {
  p.mu.Lock()
  defer p.mu.Unlock()
  return p.allocateNextUserPort(ctx)
}

func (p *PortManager) allocateNextUserPort(ctx) (int, error) {
  swarmPorts := p.getSwarmPorts(ctx)  // map[int]string
  hostPorts := p.getHostPorts(ctx)    // []int
  for port := UserPortMin; port < UserPortMax; port++ {
    if _, swarm := swarmPorts[port]; swarm { continue }
    if contains(hostPorts, port) { continue }
    if isPortAllocatedInDB(port, "tcp") { continue }
    // FREE per all 3 sources
    return port, nil
  }
  return 0, ErrPortPoolExhausted
}
```

## Persistence

Each allocation = one row in `port_allocations`:

```sql
CREATE TABLE port_allocations (
  id INTEGER PRIMARY KEY,
  app_id INTEGER NOT NULL REFERENCES apps(id),
  port INTEGER NOT NULL,
  protocol TEXT DEFAULT 'tcp',
  description TEXT,
  is_primary BOOLEAN DEFAULT FALSE,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(port, protocol)
);
```

Deallocation removes the row.

## ReservedSystemPorts

`ReservedSystemPorts` map covers: 22, 53, 67, 80, 443, 6005, 6010, 6011 (system + infrastructure-layer ports per Article V). System/platform apps can claim these; user apps cannot.
