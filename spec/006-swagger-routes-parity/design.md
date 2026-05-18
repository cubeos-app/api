# Design — Swagger / routes parity (spec/006 — RETROSPECTIVE)

CGC-grounded. Real `api/scripts/verify-routes.sh` + `make verify-routes` target.

## verify-routes algorithm

```
1. Walk chi router → collect (method, path) tuples
2. Parse docs/swagger.json → collect Swagger path entries
3. Diff:
   - registered ∖ swagger = missing-from-swagger
   - swagger ∖ registered = orphaned-swagger
4. Exit non-zero if either set is non-empty
```

## Why both directions matter

- Registered without Swagger (REQ-604) → undocumented endpoint = attack surface + integration risk.
- Swagger without route (REQ-605) → operator follows stale Swagger → 404 → loses trust.

## CI integration

`.gitlab-ci.yml` `lint` stage runs `make verify-routes`. PRs introducing drift fail CI.

## Real artifacts

- `api/scripts/verify-routes.sh` (CGC-verified)
- `api/Makefile` `verify-routes:` target (CGC-verified)
- `api/docs/swagger.json` + `api/docs/swagger.yaml` (generated)
