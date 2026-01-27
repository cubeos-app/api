# Build stage
FROM golang:1.23-alpine AS builder

WORKDIR /build
RUN apk add --no-cache git

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags "-s -w" -o cubeos-api ./cmd/cubeos

# Runtime stage
FROM alpine:3.21
RUN apk add --no-cache ca-certificates tzdata
RUN adduser -D -u 1000 cubeos

WORKDIR /app
COPY --from=builder /build/cubeos-api /app/cubeos-api
USER cubeos

EXPOSE 9009
ENTRYPOINT ["/app/cubeos-api"]
