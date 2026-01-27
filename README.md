# CubeOS API

Go backend for CubeOS - REST API for system management and Docker orchestration.

## Quick Start
```bash
go mod tidy
make run
```

## Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /health` | Health check |
| `GET /api/v1/system/info` | System information |
| `GET /api/v1/system/stats` | Real-time stats |
| `GET /api/v1/services` | List Docker containers |

## Configuration

Environment variables (prefix `CUBEOS_`):

| Variable | Default | Description |
|----------|---------|-------------|
| `API_PORT` | 9008 | Listen port |
| `LOG_LEVEL` | info | debug/info/warn/error |
| `DOCKER_SOCKET` | /var/run/docker.sock | Docker socket |

## License

Apache 2.0
