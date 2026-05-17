# Design — Compose transformation (spec/005)

CasaOS → Swarm-compatible compose conversion at install time. Lives at `internal/managers/compose.go` + `internal/managers/compose_translation_table.go`.

## Translation table (excerpt)

| CasaOS / docker-compose         | Swarm equivalent                       | Notes                                          |
|----------------------------------|----------------------------------------|------------------------------------------------|
| `restart: always`               | `deploy.restart_policy.condition: any` |                                                |
| `restart: unless-stopped`       | `deploy.restart_policy.condition: any` |                                                |
| `restart: no`                   | `deploy.restart_policy.condition: none`|                                                |
| `restart: on-failure`           | `deploy.restart_policy.condition: on-failure` |                                         |
| `depends_on: cond: service_healthy` | DROP + log warning                | Swarm ignores; healthcheck still applies      |
| `network_mode: host`            | preserve                                | required for pihole, npm                       |
| `build:`                        | REJECT (HTTP 422)                       | Swarm requires pre-built images                |
| `privileged: true` (non-coreapp)| REJECT (HTTP 422)                       | constitutional violation                       |
| `volumes:` `environment:` `labels:` `extra_hosts:` | preserve                  |                                                |
| `cap_add: SYS_ADMIN` (non-coreapp) | REJECT                              | privilege escalation                            |

## Algorithm

```go
func Transform(in []byte, appID string) ([]byte, error) {
  var spec ComposeSpec
  yaml.Unmarshal(in, &spec)

  for serviceName, svc := range spec.Services {
    // step 1: validate disallowed keys
    if err := rejectDisallowed(svc, isCoreapp(appID)); err != nil {
      return nil, fmt.Errorf("disallowed feature in service %s: %w", serviceName, err)
    }
    // step 2: translate restart → deploy.restart_policy
    if svc.Restart != "" {
      svc.Deploy.RestartPolicy = translateRestart(svc.Restart)
      svc.Restart = ""
    }
    // step 3: translate depends_on long-form
    svc.DependsOn = dropConditionalDeps(svc.DependsOn)
    // step 4: port allocation
    if needsPort(svc) && svc.Ports == nil {
      port, err := portManager.Allocate()
      if err != nil { return nil, err }
      svc.Ports = []string{fmt.Sprintf("%d:%d", port, svc.InternalPort)}
    }
    // step 5: enforce port range
    if err := validatePortRange(svc.Ports, isCoreapp(appID)); err != nil {
      return nil, fmt.Errorf("port out of range: %w", err)
    }
    // step 6: apply CubeOS labels
    svc.Labels["cubeos.app.id"] = appID
    svc.Labels["cubeos.app.name"] = spec.Name
    svc.Labels["cubeos.app.version"] = spec.Version
  }

  out, _ := yaml.Marshal(spec)
  // step 7: validate via docker stack config dry-run
  if err := dockerStackConfigCheck(out); err != nil {
    return nil, fmt.Errorf("Swarm validation failed: %w", err)
  }
  return out, nil
}
```

## Image pre-pull

When a referenced image is absent from local registry, the install saga's `push_image` step pulls from the source (public registry, only on first install) + pushes to `localhost:5000` (per CubeOS Article XIV). On offline_hotspot mode, the pull step fails fast (per CubeOS spec/002-local-registry REQ-210); operator must pre-import the image (REQ-207).

## Test fixtures (REQ-513)

`internal/managers/testdata/compose-fixtures/` contains 20+ real CasaOS app compose files (uptime-kuma, jellyfin, nextcloud, pi-hole, paperless-ngx, ...). Each has a golden `expected.yml` of the transformed output. `compose_test.go` runs through all fixtures.
