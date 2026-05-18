# Requirements — Swagger / routes parity (spec/006 — RETROSPECTIVE)

Source: Article XII + Article C-IX + `api/scripts/verify-routes.sh`.

> Retrospective. ID convention: 600-block.

REQ-600: The system shall require every HTTP handler in `internal/handlers/` to include complete Swagger annotations as godoc comments.
REQ-601: The system shall include `@Summary`, `@Description`, `@Tags`, `@Accept`, `@Produce`, `@Param`, `@Success`, `@Failure`, `@Router` on every public handler.
REQ-602: The system shall generate `docs/swagger.json` + `docs/swagger.yaml` via `swag init` as part of `make build`.
REQ-603: When `make verify-routes` runs, the system shall diff the chi router's registered routes against the parsed Swagger spec route set.
REQ-604: If `make verify-routes` detects a route registered but not Swagger-documented, then the target shall exit non-zero with the route path + method in the error.
REQ-605: If `make verify-routes` detects a Swagger entry for a route not registered, then the target shall exit non-zero.
REQ-606: The system shall run `make verify-routes` as a pre-commit gate in `.gitlab-ci.yml`.
REQ-607: The system shall serve the Swagger UI at `/swagger/*` so operators may explore the API live.
REQ-608: While the api is running, the system shall expose `/swagger.json` as the canonical Swagger spec.
REQ-609: The system shall fail the build if Swagger generation finds any handler missing required annotations.
REQ-610: The system shall expose verify-routes as a script at `api/scripts/verify-routes.sh` (CGC-verified).
