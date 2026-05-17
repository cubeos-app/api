# Design — Swagger / routes parity (spec/006)

The `make verify-routes` invariant. Constitutional under Article XII (project) + C-IX (component).

## Generation pipeline

```
handler godoc (// @Summary, // @Param, ...)
    │
    ▼
swag init -g cmd/cubeos/main.go -o docs/
    │
    ├─► docs/swagger.json
    └─► docs/swagger.yaml
            │
            ▼
   served at /swagger/index.html (Swagger UI)
   + canonical at /swagger.json
```

## verify-routes algorithm

```go
// Walk chi router to collect registered routes
registered := make(map[string]bool)
chi.Walk(router, func(method, route string, h http.Handler, _ ...func(http.Handler) http.Handler) error {
  registered[fmt.Sprintf("%s %s", method, route)] = true
  return nil
})

// Parse docs/swagger.json
swaggerRoutes := parseSwagger("docs/swagger.json")

// Diff
missingFromSwagger := []string{}
for r := range registered { if !swaggerRoutes[r] { missingFromSwagger = append(missingFromSwagger, r) } }

orphanedSwagger := []string{}
for r := range swaggerRoutes { if !registered[r] { orphanedSwagger = append(orphanedSwagger, r) } }

if len(missingFromSwagger) + len(orphanedSwagger) > 0 {
  return fmt.Errorf("route/Swagger drift:\n  missing from Swagger: %v\n  orphaned Swagger: %v", missingFromSwagger, orphanedSwagger)
}
```

## Why both directions matter

- **Registered without Swagger** (REQ-604) — undocumented endpoint surfaces an attack/integration risk; client integrations can't discover it.
- **Swagger without route** (REQ-605) — operator follows stale Swagger; gets 404; loses trust.

## Coverage endpoint (REQ-611)

```
GET /api/v1/system/swagger-coverage
{
  "total_routes": 87,
  "documented": 87,
  "coverage_pct": 100.0,
  "missing": []
}
```

`coverage_pct < 100` is a constitutional violation but the endpoint stays for operator diagnosis.

## Hot-loop dev warning (REQ-612)

In dev builds (`DEV=1` env), the Swagger UI's index page includes a warning banner listing any routes missing documentation. Disabled in production builds.

## CI integration (REQ-606)

`.gitlab-ci.yml` `lint` stage runs:
```yaml
verify-routes:
  stage: lint
  script:
    - cd api
    - make build
    - make verify-routes
```

Pre-commit hook (`scripts/pre-commit-check.sh`) also runs `make verify-routes`.
