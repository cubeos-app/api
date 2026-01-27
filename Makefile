# CubeOS Makefile
# Build and development commands for the CubeOS API server

# Build variables
BINARY_NAME := cubeos
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_TIME := $(shell date -u '+%Y-%m-%d_%H:%M:%S')
LDFLAGS := -ldflags "-X main.version=$(VERSION) -X main.buildTime=$(BUILD_TIME)"

# Go settings
GOFLAGS := -trimpath
GO := go

# Directories
CMD_DIR := ./cmd/cubeos
BUILD_DIR := ./build
DIST_DIR := ./dist

# Default target
.PHONY: all
all: build

# Build for current platform
.PHONY: build
build:
	@echo "Building $(BINARY_NAME)..."
	$(GO) build $(GOFLAGS) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) $(CMD_DIR)
	@echo "Built: $(BUILD_DIR)/$(BINARY_NAME)"

# Build for Raspberry Pi (ARM64)
.PHONY: build-arm64
build-arm64:
	@echo "Building $(BINARY_NAME) for ARM64..."
	GOOS=linux GOARCH=arm64 $(GO) build $(GOFLAGS) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-arm64 $(CMD_DIR)
	@echo "Built: $(BUILD_DIR)/$(BINARY_NAME)-linux-arm64"

# Build for all target platforms
.PHONY: build-all
build-all: build build-arm64
	@echo "Building for amd64..."
	GOOS=linux GOARCH=amd64 $(GO) build $(GOFLAGS) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 $(CMD_DIR)
	@echo "All builds complete"

# Run locally (development)
.PHONY: run
run:
	$(GO) run $(CMD_DIR)

# Run with hot reload using air (if installed)
.PHONY: dev
dev:
	@if command -v air > /dev/null; then \
		air; \
	else \
		echo "air not installed. Install with: go install github.com/air-verse/air@latest"; \
		echo "Falling back to go run..."; \
		$(GO) run $(CMD_DIR); \
	fi

# Run tests
.PHONY: test
test:
	$(GO) test -v ./...

# Run tests with coverage
.PHONY: test-coverage
test-coverage:
	$(GO) test -v -coverprofile=coverage.out ./...
	$(GO) tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report: coverage.html"

# Run linter
.PHONY: lint
lint:
	@if command -v golangci-lint > /dev/null; then \
		golangci-lint run; \
	else \
		echo "golangci-lint not installed. Install with:"; \
		echo "  go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest"; \
	fi

# Format code
.PHONY: fmt
fmt:
	$(GO) fmt ./...
	@if command -v goimports > /dev/null; then \
		goimports -w .; \
	fi

# Tidy dependencies
.PHONY: tidy
tidy:
	$(GO) mod tidy

# Download dependencies
.PHONY: deps
deps:
	$(GO) mod download

# Clean build artifacts
.PHONY: clean
clean:
	rm -rf $(BUILD_DIR)
	rm -rf $(DIST_DIR)
	rm -f coverage.out coverage.html

# Create build directory
$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

# Install development tools
.PHONY: tools
tools:
	@echo "Installing development tools..."
	go install github.com/air-verse/air@latest
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	go install golang.org/x/tools/cmd/goimports@latest
	@echo "Tools installed"

# Docker build (for local testing)
.PHONY: docker-build
docker-build:
	docker build -t cubeos:$(VERSION) .

# Show help
.PHONY: help
help:
	@echo "CubeOS Makefile commands:"
	@echo ""
	@echo "  make build        - Build for current platform"
	@echo "  make build-arm64  - Build for Raspberry Pi (ARM64)"
	@echo "  make build-all    - Build for all platforms"
	@echo "  make run          - Run locally"
	@echo "  make dev          - Run with hot reload (requires air)"
	@echo "  make test         - Run tests"
	@echo "  make test-coverage- Run tests with coverage report"
	@echo "  make lint         - Run linter"
	@echo "  make fmt          - Format code"
	@echo "  make tidy         - Tidy go.mod"
	@echo "  make deps         - Download dependencies"
	@echo "  make clean        - Remove build artifacts"
	@echo "  make tools        - Install development tools"
	@echo "  make docker-build - Build Docker image"
	@echo ""
