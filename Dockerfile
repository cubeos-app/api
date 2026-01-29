# =============================================================================
# CubeOS API - Production Image (uses pre-built binary from CI)
# =============================================================================
FROM alpine:3.19

WORKDIR /app

# Install runtime dependencies only
RUN apk add --no-cache \
    ca-certificates \
    tzdata \
    iproute2 \
    wireless-tools \
    iptables \
    docker-cli \
    i2c-tools

# Copy pre-built binary from CI artifacts
COPY cubeos-api /app/cubeos-api

# Ensure executable
RUN chmod +x /app/cubeos-api

EXPOSE 9009

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget -qO- http://localhost:9009/health || exit 1

ENTRYPOINT ["/app/cubeos-api"]
