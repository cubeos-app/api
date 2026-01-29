# =============================================================================
# Stage 1: Builder
# =============================================================================
FROM golang:1.22-alpine AS builder

WORKDIR /app

RUN apk add --no-cache gcc musl-dev

# Copy deps first for layer caching
COPY go.mod go.sum ./
RUN go mod download

# Copy source and build
COPY . .
RUN CGO_ENABLED=1 GOOS=linux go build -ldflags="-w -s" -o cubeos-api ./cmd/cubeos-api

# =============================================================================
# Stage 2: Runtime
# =============================================================================
FROM alpine:3.19

WORKDIR /app

RUN apk add --no-cache \
    ca-certificates \
    tzdata \
    iproute2 \
    wireless-tools \
    iptables \
    docker-cli \
    i2c-tools

COPY --from=builder /app/cubeos-api /app/cubeos-api
COPY --from=builder /app/openapi.yaml /app/openapi.yaml

RUN mkdir -p /cubeos/data

ENV API_HOST=0.0.0.0
ENV API_PORT=9009
ENV DATABASE_PATH=/cubeos/data/cubeos.db
ENV TZ=Europe/Amsterdam

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:9009/health || exit 1

EXPOSE 9009
CMD ["/app/cubeos-api"]
