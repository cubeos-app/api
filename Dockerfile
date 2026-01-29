# Build stage
FROM golang:1.22-alpine AS builder

WORKDIR /app

# Install build dependencies
RUN apk add --no-cache gcc musl-dev

# Copy go mod file first
COPY go.mod ./

# Copy source code
COPY . .

# Download dependencies and generate go.sum
RUN go mod tidy

# Build binary
RUN CGO_ENABLED=1 GOOS=linux go build -ldflags="-w -s" -o cubeos-api ./cmd/cubeos-api

# Runtime stage
FROM alpine:3.19

WORKDIR /app

# Install runtime dependencies
RUN apk add --no-cache \
    ca-certificates \
    tzdata \
    iproute2 \
    wireless-tools \
    iptables \
    docker-cli \
    i2c-tools

# Copy binary from builder
COPY --from=builder /app/cubeos-api /app/cubeos-api

# Copy OpenAPI spec
COPY --from=builder /app/openapi.yaml /app/openapi.yaml

# Create data directory
RUN mkdir -p /cubeos/data

# Environment variables
ENV API_HOST=0.0.0.0
ENV API_PORT=9009
ENV DATABASE_PATH=/cubeos/data/cubeos.db
ENV TZ=Europe/Amsterdam

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:9009/health || exit 1

EXPOSE 9009

CMD ["/app/cubeos-api"]
