Feature: Swagger / routes parity (spec/006 — RETROSPECTIVE)

  # Covers: REQ-600, REQ-602, REQ-603, REQ-604, REQ-605, REQ-606, REQ-607, REQ-608, REQ-610

  Scenario: Every handler has full Swagger annotations
    Given a code review of internal/handlers/
    When a handler is missing one of @Summary @Description @Tags @Accept @Produce @Param @Success @Failure @Router
    Then `swag init` fails the build

  Scenario: make build generates Swagger artifacts
    When `make build` runs
    Then docs/swagger.json + docs/swagger.yaml are generated

  Scenario: Swagger UI accessible
    When the operator visits https://cubeos.cube/swagger/index.html
    Then HTTP 200 is returned

  Scenario: Swagger spec exposed at /swagger.json
    When `curl http://localhost:6010/swagger.json` is called
    Then valid JSON Swagger spec is returned

  Scenario: verify-routes exits non-zero on registered-but-no-Swagger drift
    Given a handler with no @Router annotation is added
    When `make verify-routes` runs
    Then exit code is non-zero
    And error message names the missing route path + method

  Scenario: verify-routes exits non-zero on orphaned Swagger entry
    Given Swagger references /api/v1/legacy/endpoint but the route is no longer registered
    When `make verify-routes` runs
    Then exit code is non-zero

  Scenario: CI gates merges on verify-routes
    Given a PR introduces route/Swagger drift
    When GitLab CI lint stage runs
    Then make verify-routes fails
    And the MR cannot merge until drift is fixed

  Scenario: scripts/verify-routes.sh exists
    When inspecting api/scripts/
    Then verify-routes.sh is present + executable
