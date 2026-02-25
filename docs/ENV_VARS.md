# CubeOS API — Environment Variables

All environment variables consumed by the CubeOS API, organized by source.

## Configuration Files

| File | Required | Description |
|------|----------|-------------|
| `/cubeos/config/defaults.env` | Yes (fatal) | Main configuration — loaded by `godotenv.Load` |
| `/cubeos/config/secrets.env` | No (warn) | Secrets (JWT, Pi-hole password) — loaded by `godotenv.Load` |

---

## Centralized Config (`internal/config/config.go` via `config.Load()`)

### Required (fatal if missing)

| Variable | Type | Read By | Description |
|----------|------|---------|-------------|
| `API_PORT` | int | `config.go` | API listen port (typically `6010`) |
| `DATABASE_PATH` | string | `config.go` | SQLite database file path |
| `GATEWAY_IP` | string | `config.go` | CubeOS gateway IP (e.g. `10.42.24.1`) |
| `DOMAIN` | string | `config.go` | CubeOS domain name (e.g. `cubeos.cube`) |
| `DASHBOARD_PORT` | int | `config.go` | Dashboard listen port (typically `6011`) |
| `NPM_PORT` | int | `config.go` | Nginx Proxy Manager port (typically `6000`) |
| `PIHOLE_PORT` | int | `config.go` | Pi-hole admin port (typically `6001`) |

### Optional (with defaults)

| Variable | Type | Default | Read By | Description |
|----------|------|---------|---------|-------------|
| `API_HOST` | string | `0.0.0.0` | `config.go` | API listen address |
| `CUBEOS_VERSION` | string | `dev` | `config.go` | CubeOS release version |
| `JWT_SECRET` | string | `cubeos-dev-secret-change-in-production` | `config.go` | JWT signing key |
| `JWT_EXPIRATION_HOURS` | int | `24` | `config.go` | JWT token lifetime in hours |
| `DOCKER_SOCKET` | string | `/var/run/docker.sock` | `config.go` | Docker daemon socket path |
| `CONTAINER_STOP_TIMEOUT` | int | `30` | `config.go` | Docker container stop timeout (seconds) |
| `SUBNET` | string | `10.42.24.0/24` | `config.go` | CubeOS network subnet (CIDR) |
| `AP_INTERFACE` | string | `wlan0` | `config.go` | WiFi AP interface name |
| `WAN_INTERFACE` | string | `eth0` | `config.go` | WAN interface name |
| `HOSTAPD_CONF` | string | `/etc/hostapd/hostapd.conf` | `config.go` | hostapd config path |
| `DNSMASQ_CONF` | string | `/etc/dnsmasq.d/090_cubeos.conf` | `config.go` | dnsmasq config path |
| `DNSMASQ_LEASES` | string | `/var/lib/misc/dnsmasq.leases` | `config.go` | DHCP leases file path |
| `CUBEOS_PIHOLE_PASSWORD` | string | _(empty)_ | `config.go` | Pi-hole v6 REST API password |
| `OLLAMA_PORT` | int | `6030` | `config.go` | Ollama API port |
| `CHROMADB_PORT` | int | `6031` | `config.go` | ChromaDB API port |
| `CUBEOS_DATA_DIR` | string | `/cubeos/data` | `config.go` | Data root directory |
| `BACKUP_DIR` | string | `/cubeos/backups` | `config.go` | Backup storage directory |
| `STATS_INTERVAL` | int | `2` | `config.go` | Stats polling interval (seconds) |
| `UPS_I2C_ADDRESS` | hex int | `0x36` | `config.go` | UPS I2C address |
| `BATTERY_CAPACITY_MAH` | int | `3000` | `config.go` | Battery capacity in mAh |
| `CRITICAL_BATTERY_PERCENT` | int | `10` | `config.go` | Critical battery threshold (%) |

---

## Direct `os.Getenv()` Calls (Outside `config.Load()`)

### `cmd/cubeos-api/main.go`

| Variable | Default | Description |
|----------|---------|-------------|
| `HAL_URL` | `http://cubeos-hal:6005` | HAL service endpoint |
| `REGISTRY_URL` | `http://{GATEWAY_IP}:5000` | Local Docker registry URL |
| `REGISTRY_PATH` | `/cubeos/data/registry` | Local registry storage path |
| `CORS_ALLOWED_ORIGINS` | _(none)_ | Additional CORS origins (comma-separated) |
| `CUBEOS_ENABLE_PPROF` | _(disabled)_ | Set to `1` to enable `/debug/pprof/` endpoints |

### `internal/hal/client.go`

| Variable | Default | Description |
|----------|---------|-------------|
| `HAL_URL` | `http://cubeos-hal:6005` | HAL service endpoint (also read at client init) |

### `internal/handlers/`

| Variable | Default | File | Description |
|----------|---------|------|-------------|
| `DOCS_PATH` | `/cubeos/docs` | `docs.go` | Documentation files directory |
| `REGISTRY_URL` | `http://{DefaultGatewayIP}:5000` | `registry.go` | Registry URL (handler fallback) |
| `CUBEOS_DATA_DIR` | `/cubeos/data` | `backups.go` | Data dir for backup paths |
| `CUBEOS_DATA_DIR` | `/cubeos` | `network.go` | Data dir for network config |
| `TZ` | `UTC` | `casaos.go` | Timezone for CasaOS import |

### `internal/managers/`

| Variable | Default | File | Description |
|----------|---------|------|-------------|
| `CUBEOS_VERSION` | _(empty)_ | `backup.go`, `system.go` | CubeOS version for metadata |
| `CUBEOS_HOST_ROOT` | _(empty)_ or `/host-root` | `logs.go`, `system.go`, `appstore_volumes.go`, `network.go`, `setup.go` | Host filesystem mount point inside container |
| `CUBEOS_UPDATE_URL` | _(empty)_ | `update.go` | Update manifest URL |
| `CUBEOS_VERSION` | `0.0.0` | `update.go` | Current version for update comparison |
| `REGISTRY_HOST` | _(empty)_ | `appstore_progress.go` | Registry host for image pulls |
| `REGISTRY_URL` | `http://{cfg.GatewayIP}:5000` | `appstore.go` | Registry URL for app store |
| `TZ` | `UTC` | `appstore.go`, `appstore_volumes.go` | Timezone |
| `PIHOLE_PORT` | `6001` | `pihole_sync.go` | Pi-hole port for password sync |
| `GATEWAY_IP` | `10.42.24.1` | `pihole_sync.go` | Gateway IP for password sync |
| `HAL_URL` | `http://10.42.24.1:6005/hal` | `setup.go` | HAL URL for setup manager |

### `internal/flowengine/activities/`

| Variable | Default | File | Description |
|----------|---------|------|-------------|
| `REGISTRY_HOST` | `10.42.24.1:5000` or `localhost:5000` | `registry.go`, `update.go` | Registry host for image operations |
| `CUBEOS_VERSIONS_PATH` | `/cubeos/versions` | `update.go` | Path to version manifests |
| `CUBEOS_COREAPPS_PATH` | `/cubeos/coreapps` | `update.go` | Path to core app configs |
| `CUBEOS_VERSION` | _(empty)_ | `update.go` | Current version for updates |

### Test-Only Variables

| Variable | File | Description |
|----------|------|-------------|
| `CUBEOS_INTEGRATION_TEST` | `managers/swarm_test.go` | Enable Swarm integration tests |
| `CUBEOS_API_URL` | `tests/integration/api_integration_test.go` | API URL for integration tests |
| `SKIP_VPN_TESTS` | `tests/integration/api_test.go` | Skip VPN integration tests |
