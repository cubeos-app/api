#!/usr/bin/env bash
# =============================================================================
# CubeOS API — Pi-side deploy script (executed via SSH from GPU VM)
# =============================================================================
# Usage: GHCR_TOKEN=... GHCR_USER=... GHCR_IMAGE=... CI_COMMIT_SHORT_SHA=...
#        bash /tmp/ci-deploy-api.sh
#
# Handles three failure modes:
#   1. Port held by zombie container -> force-remove before update
#   2. Service stuck at 0/1 from previous failure -> recover and redeploy
#   3. Service deleted entirely -> fresh stack deploy
#
# CRITICAL: Never use --detach=false with host-mode services.
# =============================================================================
set -euo pipefail

SERVICE_NAME="cubeos-api_cubeos-api"
STACK_NAME="cubeos-api"
HOST_PORT="6010"
COMPOSE_PATH="/cubeos/coreapps/cubeos-api/appconfig/docker-compose.yml"
HEALTH_TIMEOUT="120"

echo "Deploying CubeOS API (commit ${CI_COMMIT_SHORT_SHA})..."

# --- GHCR login ---
echo "$GHCR_TOKEN" | docker login ghcr.io -u "$GHCR_USER" --password-stdin

# =========================================================================
# Pre-flight: verify Docker iptables chains are healthy
# =========================================================================
echo "Pre-flight: checking Docker networking health..."
if ! sudo iptables -t nat -L DOCKER -n > /dev/null 2>&1; then
  echo "DOCKER nat chain missing — restarting Docker to recreate..."
  sudo systemctl restart docker
  sleep 15
  if ! sudo iptables -t nat -L DOCKER -n > /dev/null 2>&1; then
    echo "DOCKER nat chain still missing after restart. Manual intervention required."
    exit 1
  fi
  echo "Docker networking restored"
else
  echo "Docker networking healthy"
fi

# Pull the new image first (before touching the running service)
docker pull ${GHCR_IMAGE}:${CI_COMMIT_SHORT_SHA}
docker tag ${GHCR_IMAGE}:${CI_COMMIT_SHORT_SHA} ${GHCR_IMAGE}:latest

# =========================================================================
# Pre-flight: kill zombie containers holding the port
# =========================================================================
echo "Pre-flight: checking for zombie containers on port ${HOST_PORT}..."
SKIP_UPDATE=""
PORT_PID=$(sudo ss -tlnp | grep ":${HOST_PORT} " | sed -n 's/.*pid=\([0-9]*\).*/\1/p' | head -1 || true)
if [ -n "${PORT_PID}" ]; then
  # Find which container owns this docker-proxy
  ZOMBIE=$(docker ps -a --format '{{.ID}} {{.Names}} {{.Status}}' | grep -i "cubeos-api" || true)
  if [ -n "${ZOMBIE}" ]; then
    echo "  Found container(s) on port ${HOST_PORT}:"
    echo "  ${ZOMBIE}"
    # Check if the running container is already on the target image
    RUNNING_IMAGE=$(docker ps --filter "name=cubeos-api" --format '{{.Image}}' | head -1 || true)
    if [ "${RUNNING_IMAGE}" = "${GHCR_IMAGE}:${CI_COMMIT_SHORT_SHA}" ]; then
      echo "  Already running target image — skipping update"
      SKIP_UPDATE=true
    fi
  fi
else
  echo "  Port ${HOST_PORT} is free"
fi

# Show current state
echo "Current state:"
docker service ls | grep ${STACK_NAME} || echo "  No existing services found"

# =========================================================================
# Deploy: detached update + health poll (never --detach=false)
# =========================================================================
if [ "${SKIP_UPDATE}" = "true" ]; then
  echo "Skipping update — correct image already running"
elif docker service inspect ${SERVICE_NAME} > /dev/null 2>&1; then
  echo "Service exists — updating image (detached)..."

  docker service update \
    --image ${GHCR_IMAGE}:${CI_COMMIT_SHORT_SHA} \
    --update-order stop-first \
    --force \
    --detach \
    ${SERVICE_NAME}

  echo "  Update issued (detached) — will poll health endpoint..."
  sleep 10
else
  echo "Service doesn't exist — deploying fresh stack..."
fi

# =========================================================================
# Recovery: if service vanished, redeploy the full stack from compose
# =========================================================================
if [ "${SKIP_UPDATE}" != "true" ] && ! docker service inspect ${SERVICE_NAME} > /dev/null 2>&1; then
  echo "Service not found — deploying stack from compose..."

  # Force-kill any orphan containers still holding the port
  ORPHANS=$(docker ps -a -q --filter "name=cubeos-api")
  if [ -n "${ORPHANS}" ]; then
    echo "  Removing orphan containers..."
    echo "${ORPHANS}" | xargs docker rm -f 2>/dev/null || true
  fi

  # Wait for port to actually be released
  for i in $(seq 1 15); do
    if ! sudo ss -tlnp | grep -q ":${HOST_PORT} "; then
      echo "  Port ${HOST_PORT} is free"
      break
    fi
    if [ "$i" = "15" ]; then
      echo "  Port ${HOST_PORT} still held — killing docker-proxy..."
      PORT_PID=$(sudo ss -tlnp | grep ":${HOST_PORT} " | sed -n 's/.*pid=\([0-9]*\).*/\1/p' | head -1 || true)
      [ -n "${PORT_PID}" ] && sudo kill -9 "${PORT_PID}" 2>/dev/null || true
      sleep 2
    fi
    echo "  Waiting for port ${HOST_PORT} to be released... ($i/15)"
    sleep 2
  done

  docker stack deploy \
    --compose-file ${COMPOSE_PATH} \
    --resolve-image never \
    ${STACK_NAME}

  echo "  Stack deployed — waiting for service registration..."
  sleep 8

  # Pin to exact commit image (detached)
  if docker service inspect ${SERVICE_NAME} > /dev/null 2>&1; then
    echo "  Pinning to commit image..."
    docker service update \
      --image ${GHCR_IMAGE}:${CI_COMMIT_SHORT_SHA} \
      --update-order stop-first \
      --detach \
      ${SERVICE_NAME}
    sleep 5
  fi
fi

# =========================================================================
# Health check: poll until healthy (controlled timeout, not Swarm's)
# =========================================================================
echo ""
echo "Waiting for API to be healthy (timeout: ${HEALTH_TIMEOUT}s)..."
HEALTH_URL="http://127.0.0.1:${HOST_PORT}/health"
SECONDS_WAITED=0
INTERVAL=3

while [ ${SECONDS_WAITED} -lt ${HEALTH_TIMEOUT} ]; do
  RESPONSE=$(curl -sf ${HEALTH_URL} 2>/dev/null) && {
    echo ""
    echo "Health check passed after ${SECONDS_WAITED}s!"
    echo "   Response: ${RESPONSE}"
    echo ""
    echo "=== Deployment Summary ==="
    echo "Image:   ${GHCR_IMAGE}:${CI_COMMIT_SHORT_SHA}"
    echo "Service: ${SERVICE_NAME}"
    echo ""
    docker service ls | grep ${STACK_NAME}
    echo ""
    echo "Swagger UI: http://cubeos.cube:${HOST_PORT}/api/v1/docs/index.html"
    exit 0
  }

  SECONDS_WAITED=$((SECONDS_WAITED + INTERVAL))

  # Every 15s, print service task status for visibility
  if [ $((SECONDS_WAITED % 15)) -eq 0 ]; then
    echo "  ${SECONDS_WAITED}s — checking task status..."
    docker service ps ${SERVICE_NAME} --no-trunc --format '{{.CurrentState}} {{.Error}}' 2>/dev/null | head -3 || true
    # If task shows "port already in use", force-kill and retry
    TASK_ERR=$(docker service ps ${SERVICE_NAME} --no-trunc --format '{{.Error}}' 2>/dev/null | head -1)
    if echo "${TASK_ERR}" | grep -qi "port already in use"; then
      echo "  Port conflict detected — killing holders and forcing update..."
      docker ps -a -q --filter "name=cubeos-api" | xargs docker rm -f 2>/dev/null || true
      sleep 2
      docker service update --force --detach ${SERVICE_NAME} 2>/dev/null || true
      sleep 3
    fi
  else
    echo "  ${SECONDS_WAITED}/${HEALTH_TIMEOUT}s..."
  fi
  sleep ${INTERVAL}
done

# =====================================================================
# Health check failed — diagnostics
# =====================================================================
echo ""
echo "Health check failed after ${HEALTH_TIMEOUT}s"
echo ""
echo "=== Diagnostics ==="
echo "Service status:"
docker service ls | grep ${STACK_NAME} || echo "  Stack not found"
echo ""
echo "Service tasks:"
docker service ps ${SERVICE_NAME} --no-trunc 2>/dev/null | head -5 || echo "  Service not found"
echo ""
echo "Recent logs:"
docker service logs ${SERVICE_NAME} --tail 30 2>/dev/null || echo "  No logs available"
echo ""
echo "Port status:"
sudo ss -tlnp | grep ${HOST_PORT} || echo "  Port ${HOST_PORT} not listening"
echo ""
echo "iptables DOCKER chain:"
sudo iptables -t nat -L DOCKER -n 2>&1 | head -5
echo ""
exit 1
