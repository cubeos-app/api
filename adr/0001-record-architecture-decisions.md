# 1. Record architecture decisions

Date: 2026-05-17

## Status

Accepted

## Context

We need to record the architectural decisions made on this api/ component repo. The parent CubeOS project records project-level decisions in `/home/claude-runner/gitlab/products/cubeos/docs/adr/`. This file is the component-local equivalent.

## Decision

Use Markdown ADRs per Nygard. Numbering `adr/NNNN-<kebab>.md` starting at `0001`. Decisions scoped to this component. Project-wide decisions go in the parent docs/ repo.

## Consequences

- api-specific decisions stay greppable.
- Parent-level decisions remain authoritative for cross-cutting concerns.
