Feature: Swagger / routes parity (spec/006 — retrospective)

  # REQ-600 + REQ-601
  Scenario: Every handler has full Swagger annotations
    Given a code review of internal/handlers/
    When a handler is missing one of @Summary @Description @Tags @Accept @Produce @Param @Success @Failure @Router
    Then the review rejects the change
    And `swag init` fails the build

  # REQ-602 + REQ-607
  Scenario: Make build generates swagger artifacts + UI serves
    When `make build` runs
    Then docs/swagger.json + docs/swagger.yaml are generated
    And `curl https://cubeos.cube/swagger/index.html` returns 200

  # REQ-603 + REQ-604
  Scenario: Registered route without Swagger entry fails verify-routes
    Given a handler is added with no @Router annotation
    When `make verify-routes` runs
    Then the target exits non-zero
    And the error message names the missing route path + method

  # REQ-605
  Scenario: Orphaned Swagger entry fails verify-routes
    Given Swagger references /api/v1/legacy/endpoint but the route is no longer registered
    When `make verify-routes` runs
    Then the target exits non-zero
    And the error names the orphaned endpoint

  # REQ-606
  Scenario: CI gates merges on verify-routes
    When a PR introduces route/Swagger drift
    Then GitLab CI's lint stage fails on verify-routes
    And the MR cannot be merged until drift is fixed

  # REQ-611 — coverage endpoint
  Scenario: Swagger-coverage endpoint reports 100%
    Given verify-routes passes
    When the operator GETs /api/v1/system/swagger-coverage
    Then the response includes total_routes, documented, coverage_pct=100.0

  # REQ-612 — dev warning banner
  Scenario: Dev-mode banner lists undocumented routes
    Given api is started with DEV=1 and 2 routes lack Swagger
    When the operator opens /swagger/index.html
    Then a banner is shown listing the 2 undocumented routes

  Scenario: Production build hides dev banner
    Given api is built without DEV=1
    When the operator opens /swagger/index.html
    Then no dev-mode banner is shown

  # REQ-615 — example payloads
  Scenario: Non-trivial responses include example payloads
    Given a handler returns a complex JSON response
    When inspecting its @Success annotation
    Then an example JSON payload is included
    And Swagger UI renders the example in the "Example Value" block
