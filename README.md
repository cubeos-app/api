# CubeOS API v2

Go backend API for CubeOS - replacing the Python MuleCube services.

## Features

- **Authentication**: JWT-based auth with login, refresh, password change
- **System Management**: Info, stats, temperature, power control (reboot/shutdown)
- **Network**: Interface status, WiFi AP config, DHCP leases, client management
- **Storage**: Disk usage, storage overview
- **Docker Services**: Container lifecycle (start/stop/restart/enable/disable)
- **WiFi Clients**: Connected clients, signal strength, block/kick functionality

## API Endpoints

### Authentication
- `POST /api/v1/auth/login` - Login with username/password
- `POST /api/v1/auth/refresh` - Refresh JWT token
- `GET /api/v1/auth/me` - Get current user info
- `POST /api/v1/auth/password` - Change password

### System
- `GET /api/v1/system/info` - System information (hostname, kernel, Pi info)
- `GET /api/v1/system/stats` - CPU, memory, disk, temperature stats
- `GET /api/v1/system/temperature` - Temperature and throttling status
- `POST /api/v1/system/reboot` - Reboot system
- `POST /api/v1/system/shutdown` - Shutdown system

### Network
- `GET /api/v1/network/interfaces` - List network interfaces
- `GET /api/v1/network/ap/status` - WiFi AP status
- `GET /api/v1/network/ap/config` - WiFi AP configuration
- `PUT /api/v1/network/ap/config` - Update WiFi AP config
- `GET /api/v1/network/internet` - Internet connectivity check

### Clients (WiFi)
- `GET /api/v1/clients` - List connected WiFi clients
- `GET /api/v1/clients/count` - Client count
- `GET /api/v1/clients/stats` - Client statistics
- `POST /api/v1/clients/block/{mac}` - Block client by MAC
- `POST /api/v1/clients/kick/{mac}` - Disconnect client

### Storage
- `GET /api/v1/storage/disks` - List mounted disks
- `GET /api/v1/storage/overview` - Storage overview

### Services (Docker)
- `GET /api/v1/services` - List all containers
- `GET /api/v1/services/status` - Container status map
- `GET /api/v1/services/{name}` - Get service details
- `POST /api/v1/services/{name}/start` - Start container
- `POST /api/v1/services/{name}/stop` - Stop container
- `POST /api/v1/services/{name}/restart` - Restart container
- `POST /api/v1/services/{name}/enable` - Enable service (set restart policy)
- `POST /api/v1/services/{name}/disable` - Disable service

## Building

```bash
# Local build
go build -o cubeos-api ./cmd/cubeos-api

# Docker build
docker compose build
```

## Running

```bash
# Direct
./cubeos-api

# Docker
docker compose up -d
```

## Configuration

Environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `API_HOST` | `0.0.0.0` | Listen address |
| `API_PORT` | `9009` | Listen port |
| `DATABASE_PATH` | `/cubeos/data/cubeos.db` | SQLite database path |
| `JWT_SECRET` | (default) | JWT signing secret |
| `JWT_EXPIRATION_HOURS` | `24` | Token expiration time |
| `AP_INTERFACE` | `wlan0` | WiFi AP interface |
| `WAN_INTERFACE` | `eth0` | WAN interface |

## Default Credentials

- Username: `admin`
- Password: `cubeos`

## Replaces Python Services

This Go API replaces:
- `mulecube-service-manager` (port 9008)
- `mulecube-hw-monitor`
- `mulecube-wifi-status`
- `mulecube-status`

## License

Apache 2.0

