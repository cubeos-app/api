# 3. modernc.org/sqlite (pure Go) as the SQLite driver

Date: 2026-05-17 (codifying decision originally made 2026-01)

## Status

Accepted

## Context

CubeOS project Article XI requires `CGO_ENABLED=0` (unblocks cross-compile, future FIPS, single static binary). The canonical Go SQLite driver `mattn/go-sqlite3` is CGO-bound and therefore forbidden.

## Decision

Use `modernc.org/sqlite` — a pure-Go transpilation of the SQLite C source.

## Consequences

**Positive:**
- Compiles with `CGO_ENABLED=0` per Article XI.
- Cross-compile works for Pi ARM64 + x86_64 from one build host with no toolchain juggling.
- Single static binary; no glibc dependency at runtime.
- API-compatible with `database/sql` — handler code is identical to what it would be on the CGO driver.

**Negative:**
- Slightly slower than the CGO driver (~1.5-2x for write-heavy workloads). Not a concern for api's single-writer / single-reader pattern; benchmarked under our load at <1% CPU impact.
- Some advanced SQLite extensions (loadable extensions, custom collation) may not work; we don't use any.

**Enforced by:** Component Article C-VI + project Article XI.
