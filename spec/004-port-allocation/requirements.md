# Requirements — Port allocation (spec/004 — retrospective)

Source: `api/CLAUDE.md` + parent CubeOS Article V + docs/spec/009-swarm-orchestrator REQ-912/913/914.

> Retrospective. ID convention: 400-block.

REQ-400: The system shall allocate user-app ports inside the `6100-6999` range exclusively.
REQ-401: The system shall reject any user-app install whose compose explicitly requests a port outside `6100-6999` (HTTP 422 with explanatory body).
REQ-402: The system shall maintain an in-memory allocation map in PortManager initialised from SQLite at process start.
REQ-403: When PortManager.Allocate is called, the system shall return the lowest free port in `6100-6999`.
REQ-404: When PortManager.Release is called for a previously-allocated port, the system shall mark it free.
REQ-405: While the port pool is exhausted (all 900 ports in use), the system shall reject new install requests with HTTP 409 + explanatory body.
REQ-406: The system shall persist the in-memory allocation map to SQLite atomically per allocation/release.
REQ-407: If the api process restarts, then the system shall rebuild the in-memory map from SQLite on next boot.
REQ-408: The system shall serialize Allocate and Release via an internal sync.Mutex (single allocator).
REQ-409: The system shall expose `GET /api/v1/system/ports` returning the current allocation map.
REQ-410: When a port is allocated but the install saga fails before db_insert, the system shall release the port via the saga compensating action.
REQ-411: The system shall NOT allocate ports outside `6100-6999` even if the operator explicitly requests via API.
REQ-412: While initialising the in-memory map, the system shall log every port found in SQLite + warn on any duplicates.
REQ-413: The system shall test the port allocator's concurrency safety in `internal/managers/ports_test.go` with a 1000-concurrent-allocator stress test.
REQ-414: When the same port appears twice in SQLite (corruption case), the system shall log the second occurrence and treat the port as allocated to the lower-ID app.
REQ-415: The system shall expose `GET /api/v1/system/ports/free` returning the count of free ports.
