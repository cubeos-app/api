# 6. PortManager keeps an in-memory allocation map synced to SQLite

Date: 2026-05-17 (codifying decision originally made 2026-01)

## Status

Accepted

## Context

User-app port allocation in `6100-6999` (per CubeOS project Article V). Naive option: scan `SELECT port FROM apps` on every install — slow at 900 rows + concurrent-install race conditions.

## Decision

PortManager holds an in-memory `map[int]bool` initialised from SQLite at boot. Allocation:

```
mu.Lock()
for port := 6100; port < 7000; port++ {
  if !in_use[port] {
    in_use[port] = true
    persist to apps.port
    mu.Unlock()
    return port
  }
}
return ErrPortPoolExhausted
mu.Unlock()
```

Release on uninstall: `mu.Lock(); delete(in_use, port); persist; mu.Unlock()`.

## Consequences

**Positive:**
- Allocation is O(1) amortized after the in-memory check (no SQLite scan per request).
- Concurrent-install race avoided by the mutex.
- 900 ports × 1 bool = ~900 bytes RAM — trivial.

**Negative:**
- In-memory state must be re-initialised on api restart. Mitigated by init-at-boot reading from `apps` table.
- If api crashes between in-memory update + SQLite persist, recovery on next boot might miss a port (the in-memory state is rebuilt from SQLite, which is the source of truth, so the port becomes available again — slight risk of double-allocation if a compose file references the port without an `apps` row, but this can't happen in normal flow).

**Cross-references:** docs/spec/009-swarm-orchestrator REQ-912/913/914.
