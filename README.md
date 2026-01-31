# CubeOS API

Go backend API for CubeOS - the unified server operating system for Raspberry Pi and ARM64 SBCs.

## Overview

This API provides:
- Unified app/service management via Docker Swarm
- System monitoring (CPU, RAM, temperature, storage)
- Network configuration (WiFi AP, modes, firewall)
- App store integration (CasaOS compatible)
- VPN management (WireGuard, OpenVPN, Tor)

## Architecture

The API replaces the legacy Python services:
- `cubeos-service-manager` (port 9008)
- `cubeos-hw-monitor`
- `cubeos-wifi-status`
- `cubeos-status`

Now consolidated into a single Go binary running on port 6010.

## Building

```bash
# Build for local testing
make build

# Build for ARM64 (Raspberry Pi)
make build-arm64

# Build Docker image
make docker-build
```

## Running

```bash
# Local development
./cubeos-api

# Docker
docker run -p 6010:6010 ghcr.io/cubeos-app/api:latest
```

## Configuration

Environment variables:
- `CUBEOS_PORT` - API port (default: 6010)
- `CUBEOS_DB_PATH` - SQLite database path (default: /cubeos/data/cubeos.db)
- `CUBEOS_DATA_DIR` - Data directory (default: /cubeos/data)

## API Endpoints

See `/docs/api-reference/` for complete API documentation.

### Core Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Health check |
| `/api/v1/apps` | GET | List all apps |
| `/api/v1/apps/{name}` | GET | Get app details |
| `/api/v1/apps` | POST | Install app |
| `/api/v1/apps/{name}` | DELETE | Uninstall app |
| `/api/v1/system/info` | GET | System information |
| `/api/v1/network/status` | GET | Network status |

## Development

```bash
# Run tests
make test

# Run linter
make lint

# Format code
make fmt
```

## License

Apache 2.0
