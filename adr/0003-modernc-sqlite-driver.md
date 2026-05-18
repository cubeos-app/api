# 3. modernc.org/sqlite (pure Go) as the SQLite driver

Date: 2026-05-18 (codifying decision originally made 2026-01)

## Status
Accepted

## Context
CGC-verified: `_ "modernc.org/sqlite" // Pure Go SQLite driver` in `internal/database/database.go`. Project Article XI mandates `CGO_ENABLED=0`.

## Decision
Pure-Go SQLite driver. WAL mode enabled at open. Backup via file copy.

## Consequences
**Positive:** Cross-compile works for Pi ARM64 + x86_64 from one build host; single static binary; no glibc dependency.
**Negative:** Slightly slower than CGO driver (~1.5-2x for write-heavy workloads). Acceptable for api's single-writer pattern.
**Enforced by:** Article C-VI + parent Article XI.
