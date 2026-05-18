# 7. Docker circuit breaker

Date: 2026-05-18 (codifying shipped design)

## Status
Accepted

## Context
CGC-verified: `internal/circuitbreaker/` package exists, used by SwarmManager + DockerManager constructors (`OrchestratorConfig` includes `DockerCB *circuitbreaker.CircuitBreaker`).

Docker daemon can become unresponsive (long-running pull, ZFS DIO race on the host — see parent project memory). Without a circuit breaker, every API handler that touches Docker blocks for 30+ seconds, exhausting connection pool, cascading to dashboard timeouts.

## Decision

All Docker daemon calls route through a shared `*circuitbreaker.CircuitBreaker` instance. Open-state behavior: fail fast with a documented error message instead of blocking. Half-open: probe with one request before declaring closed.

The breaker is created once at startup + shared across SwarmManager + DockerManager.

## Consequences

**Positive:** Cascading failures contained. Operator gets meaningful error ("Docker daemon unresponsive") instead of long timeouts.
**Negative:** Operator must understand the breaker concept to interpret open-state errors. Documented in steering/security-baseline.md + the runtime error message.

**Enforced by:** Article C-VII + `OrchestratorConfig.DockerCB` field type.
