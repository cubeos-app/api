# CubeOS API Makefile

BINARY_NAME := cubeos
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_TIME := $(shell date -u '+%Y-%m-%d_%H:%M:%S')
LDFLAGS := -ldflags "-X main.version=$(VERSION) -X main.buildTime=$(BUILD_TIME)"
GO := go
CMD_DIR := ./cmd/cubeos
BUILD_DIR := ./build

.PHONY: all build build-arm64 run test clean tidy fmt lint help

all: build

build:
	@mkdir -p $(BUILD_DIR)
	$(GO) build -trimpath $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) $(CMD_DIR)
	@echo "Built: $(BUILD_DIR)/$(BINARY_NAME)"

build-arm64:
	@mkdir -p $(BUILD_DIR)
	GOOS=linux GOARCH=arm64 $(GO) build -trimpath $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-arm64 $(CMD_DIR)
	@echo "Built: $(BUILD_DIR)/$(BINARY_NAME)-linux-arm64"

run:
	$(GO) run $(CMD_DIR)

test:
	$(GO) test -v ./...

test-handlers:
	$(GO) test -v -count=1 ./internal/handlers/...

verify-routes:
	bash scripts/verify-routes.sh

clean:
	rm -rf $(BUILD_DIR)

tidy:
	$(GO) mod tidy

fmt:
	$(GO) fmt ./...

lint:
	@command -v golangci-lint > /dev/null && golangci-lint run || echo "golangci-lint not installed"

help:
	@echo "make build       - Build for current platform"
	@echo "make build-arm64 - Build for Raspberry Pi"
	@echo "make run         - Run locally"
	@echo "make test        - Run tests"
	@echo "make clean       - Remove build artifacts"
	@echo "make tidy        - Tidy go.mod"
