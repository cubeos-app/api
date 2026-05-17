# Requirements — Swagger / routes parity (spec/006 — retrospective)

Source: `api/CLAUDE.md` + parent CubeOS Article XII + component Article C-IX.

> Retrospective. ID convention: 600-block.

REQ-600: The system shall require every Go HTTP handler in `internal/handlers/` to include complete Swagger annotations as godoc comments.
REQ-601: The system shall include `@Summary`, `@Description`, `@Tags`, `@Accept`, `@Produce`, `@Param`, `@Success`, `@Failure`, `@Router` on every public handler.
REQ-602: The system shall generate `docs/swagger.json` + `docs/swagger.yaml` via `swag init` as part of `make build`.
REQ-603: When `make verify-routes` runs, the system shall diff the chi router's registered routes against the Swagger spec route set.
REQ-604: If `make verify-routes` detects a route registered but not Swagger-documented, then the target shall exit non-zero with the route path + method in the error.
REQ-605: If `make verify-routes` detects a Swagger entry for a route not registered, then the target shall exit non-zero (catches stale Swagger).
REQ-606: The system shall run `make verify-routes` as a pre-commit gate in `.gitlab-ci.yml`.
REQ-607: The system shall serve the Swagger UI at `/swagger/*` so operators may explore the API live.
REQ-608: While the api is running, the system shall expose `/swagger.json` as the canonical Swagger spec.
REQ-609: When a new handler is added, the system shall require the corresponding `@Router` annotation BEFORE the route is allowed to register.
REQ-610: The system shall test that every handler has a corresponding Swagger entry via `internal/handlers/swagger_parity_test.go`.
REQ-611: The system shall expose a `/api/v1/system/swagger-coverage` endpoint returning the number of documented vs total routes.
REQ-612: While the operator views the Swagger UI, the system shall surface a list of routes missing documentation (during dev) as a warning banner.
REQ-613: The system shall fail the build if Swagger generation finds any handler missing required annotations.
REQ-614: When a handler is removed, the system shall require the corresponding Swagger entries to be removed in the same commit (asserted by verify-routes).
REQ-615: The system shall include example request + response payloads in `@Success` annotations for handlers returning non-trivial response bodies.
