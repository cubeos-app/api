# 4. WorkflowEngine processes one workflow at a time

Date: 2026-05-18 (codifying shipped design)

## Status
Accepted

## Context
CGC-verified in `internal/flowengine/engine.go`: the WorkflowEngine's `pollLoop` → `processNextWorkflow` picks one workflow per cycle. The docstring on engine.go explicitly states "Process one at a time (single-threaded to avoid SQLite contention on the Pi's SD card)."

Alternative would be a worker pool with N parallel workflows. On Pi SD card storage, SQLite write contention is the bottleneck — multiple parallel workflows produce thrash, not throughput.

## Decision
Single-threaded workflow processing per node. Future multi-node scaling adds nodes (each still single-threaded internally), not concurrent workflows within a node.

## Consequences
**Positive:** SQLite stays fast on Pi SD card. Per-workflow execution is straightforward to reason about. Reaper handles dead workers without race conditions.
**Negative:** A long-running workflow blocks others until it completes (or hits WorkflowTimeout). Mitigation: WorkflowTimeout exists; workflows are designed to be short (most complete in <30s).
**Enforced by:** Article C-II + the explicit return after processing one workflow in `processNextWorkflow`.
