# =============================================================================
# CubeOS API - Production Multi-Arch Image
# =============================================================================
FROM alpine:3.19
ARG TARGETARCH
WORKDIR /app
RUN apk add --no-cache \
    ca-certificates \
    tzdata \
    iproute2 \
    wireless-tools \
    iptables \
    docker-cli \
    i2c-tools
COPY cubeos-api-${TARGETARCH} /app/cubeos-api
RUN chmod +x /app/cubeos-api
EXPOSE 6010
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget -qO- http://localhost:6010/health || exit 1
ENTRYPOINT ["/app/cubeos-api"]
