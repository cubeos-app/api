# 6. Parallel-dev workflow override

Date: 2026-05-18

## Status
Accepted

## Context
Per parent Article XV the default is push-to-main + auto-deploy. Parallel-dev waves need MR-gated merges.

## Decision
Same as CubeOS-family ADR-0008. For parallel-dev waves only: `merge/<feature_id>` short-lived branch + 1 MR per feature + auto-delete on merge. Human work unchanged.

## Consequences
Same as parent. Symmetry across all CubeOS family repos.
