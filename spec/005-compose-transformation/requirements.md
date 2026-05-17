# Requirements — Compose transformation (spec/005 — retrospective)

Source: `api/CLAUDE.md` + parent docs/spec/009-swarm-orchestrator REQ-915/916.

> Retrospective. ID convention: 500-block.

REQ-500: The system shall transform CasaOS-compatible docker-compose.yml into Swarm-compatible compose at install time via `internal/managers/compose.go`.
REQ-501: When the compose contains `restart: always`, the system shall translate it to `deploy.restart_policy.condition: any`.
REQ-502: When the compose contains `restart: unless-stopped`, the system shall translate it to `deploy.restart_policy.condition: any`.
REQ-503: When the compose contains long-form `depends_on: condition: service_healthy`, the system shall drop the condition + log a warning (Swarm does not honor).
REQ-504: While the compose contains `network_mode: host` on an infrastructure-layer service, the system shall preserve it (pihole, npm need it).
REQ-505: If the compose declares a port outside `6100-6999` for a user-app service, then the system shall reject the install with HTTP 422.
REQ-506: When the compose declares no port but the app needs one, the system shall auto-allocate via PortManager + rewrite the compose with the assigned port.
REQ-507: The system shall preserve `volumes`, `environment`, `labels`, and `extra_hosts` keys unchanged.
REQ-508: When the compose contains a `build:` directive, the system shall reject the install with HTTP 422 — Swarm requires pre-built images.
REQ-509: When the compose references an image not present in the local registry, the system shall pull-and-push to local registry as part of the install saga step.
REQ-510: The system shall apply CubeOS standard labels to every transformed service: `cubeos.app.id`, `cubeos.app.name`, `cubeos.app.version`.
REQ-511: While transforming, the system shall validate the result against Docker Swarm's compose spec via `docker stack config -c <yaml>` dry-run.
REQ-512: When the compose contains a feature deliberately unsupported in CubeOS (e.g. `privileged: true` for non-coreapps), the system shall reject with HTTP 422 + explanatory body.
REQ-513: The system shall test compose-transformation in `internal/managers/compose_test.go` with at least 20 real-world CasaOS app compose fixtures.
REQ-514: When the transformation fails, the system shall return an error including the source compose path + the failing key.
REQ-515: While running, the system shall maintain a list of recognised CasaOS-only directives + their Swarm-equivalent (or rejection rule) in `internal/managers/compose_translation_table.go`.
