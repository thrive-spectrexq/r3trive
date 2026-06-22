# R3TRIVE Makefile
# ─────────────────────────────────────────────────────────────

BINARY     := r3trive
MODULE     := github.com/thrive-spectrexq/r3trive
VERSION    := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT     := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_TIME := $(shell date -u +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || echo "unknown")

LDFLAGS := -s -w \
	-X '$(MODULE)/internal/version.Version=$(VERSION)' \
	-X '$(MODULE)/internal/version.Commit=$(COMMIT)' \
	-X '$(MODULE)/internal/version.BuildTime=$(BUILD_TIME)'

GO       := go
GOFLAGS  := -trimpath
DIST_DIR := dist

# ─────────────────────────────────────────────────────────────
# Build
# ─────────────────────────────────────────────────────────────

.PHONY: build
build: ## Build for current platform
	$(GO) build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(DIST_DIR)/$(BINARY) ./cmd/r3trive

.PHONY: build-all
build-all: ## Cross-compile for all platforms
	GOOS=linux   GOARCH=amd64 $(GO) build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(DIST_DIR)/$(BINARY)-linux-amd64   ./cmd/r3trive
	GOOS=linux   GOARCH=arm64 $(GO) build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(DIST_DIR)/$(BINARY)-linux-arm64   ./cmd/r3trive
	GOOS=windows GOARCH=amd64 $(GO) build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(DIST_DIR)/$(BINARY)-windows-amd64.exe ./cmd/r3trive
	GOOS=darwin  GOARCH=amd64 $(GO) build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(DIST_DIR)/$(BINARY)-darwin-amd64  ./cmd/r3trive
	GOOS=darwin  GOARCH=arm64 $(GO) build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(DIST_DIR)/$(BINARY)-darwin-arm64  ./cmd/r3trive

# ─────────────────────────────────────────────────────────────
# Test
# ─────────────────────────────────────────────────────────────

.PHONY: test
test: ## Run unit tests
	$(GO) test -race -count=1 ./...

.PHONY: test-integration
test-integration: ## Run integration tests
	$(GO) test -race -count=1 -tags integration ./tests/integration/...

.PHONY: test-e2e
test-e2e: ## Run end-to-end tests (requires elevated privileges)
	$(GO) test -race -count=1 -tags e2e ./tests/e2e/...

.PHONY: coverage
coverage: ## Run tests with coverage report
	$(GO) test -race -coverprofile=coverage.out -covermode=atomic ./...
	$(GO) tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report: coverage.html"

# ─────────────────────────────────────────────────────────────
# Lint
# ─────────────────────────────────────────────────────────────

.PHONY: lint
lint: ## Run linters
	golangci-lint run ./...

.PHONY: fmt
fmt: ## Format code
	$(GO) fmt ./...
	goimports -w .

# ─────────────────────────────────────────────────────────────
# Tools
# ─────────────────────────────────────────────────────────────

.PHONY: install-tools
install-tools: ## Install development tools
	$(GO) install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	$(GO) install golang.org/x/tools/cmd/goimports@latest

# ─────────────────────────────────────────────────────────────
# Clean
# ─────────────────────────────────────────────────────────────

.PHONY: clean
clean: ## Remove build artifacts
	rm -rf $(DIST_DIR)
	rm -f coverage.out coverage.html

# ─────────────────────────────────────────────────────────────
# Help
# ─────────────────────────────────────────────────────────────

.PHONY: help
help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

.DEFAULT_GOAL := build
