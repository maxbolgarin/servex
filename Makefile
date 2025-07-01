# Servex Enterprise Makefile
.PHONY: help build test fmt vet security audit deps clean docker run-dev run-prod benchmark coverage docs

# Variables
BINARY_NAME=servex
VERSION ?= $(shell git describe --tags --always --dirty)
BUILD_TIME ?= $(shell date -u '+%Y-%m-%d_%H:%M:%S')
GIT_COMMIT ?= $(shell git rev-parse --short HEAD)
LDFLAGS=-ldflags="-w -s -X main.Version=$(VERSION) -X main.BuildTime=$(BUILD_TIME) -X main.GitCommit=$(GIT_COMMIT)"
DOCKER_IMAGE=servex
DOCKER_TAG=latest

# Go settings
GO_VERSION=1.24
GOFLAGS=-mod=readonly
export CGO_ENABLED=0

# Colors for output
RED=\033[0;31m
GREEN=\033[0;32m
YELLOW=\033[1;33m
NC=\033[0m # No Color

## Help
help: ## Display this help message
	@echo "Servex - Enterprise HTTP Server"
	@echo "================================"
	@echo ""
	@echo "Available commands:"
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  $(GREEN)%-15s$(NC) %s\n", $$1, $$2}' $(MAKEFILE_LIST)

## Development
deps: ## Install development dependencies
	@echo "$(YELLOW)Installing dependencies...$(NC)"
	go mod download
	go mod verify
	@echo "$(GREEN)Dependencies installed!$(NC)"

fmt: ## Format Go code
	@echo "$(YELLOW)Formatting code...$(NC)"
	gofmt -w .
	@echo "$(GREEN)Code formatted!$(NC)"

vet: ## Run go vet
	@echo "$(YELLOW)Running go vet...$(NC)"
	go vet ./...
	@echo "$(GREEN)Go vet complete!$(NC)"

security: ## Run security audit
	@echo "$(YELLOW)Running security audit...$(NC)"
	@if command -v gosec >/dev/null 2>&1; then \
		gosec ./...; \
	else \
		echo "$(RED)gosec not installed. Run: go install github.com/securecodewarrior/gosec/v2/cmd/gosec@latest$(NC)"; \
		exit 1; \
	fi
	@echo "$(GREEN)Security audit complete!$(NC)"

audit: ## Audit dependencies for vulnerabilities
	@echo "$(YELLOW)Auditing dependencies...$(NC)"
	go list -json -deps ./... | nancy sleuth
	@echo "$(GREEN)Dependency audit complete!$(NC)"

## Building
build: deps fmt vet ## Build the binary
	@echo "$(YELLOW)Building $(BINARY_NAME)...$(NC)"
	go build $(LDFLAGS) -o bin/$(BINARY_NAME) ./cmd/servex
	@echo "$(GREEN)Build complete! Binary: bin/$(BINARY_NAME)$(NC)"

build-linux: ## Build for Linux
	@echo "$(YELLOW)Building for Linux...$(NC)"
	GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o bin/$(BINARY_NAME)-linux ./cmd/servex
	@echo "$(GREEN)Linux build complete!$(NC)"

build-windows: ## Build for Windows
	@echo "$(YELLOW)Building for Windows...$(NC)"
	GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -o bin/$(BINARY_NAME)-windows.exe ./cmd/servex
	@echo "$(GREEN)Windows build complete!$(NC)"

build-darwin: ## Build for macOS
	@echo "$(YELLOW)Building for macOS...$(NC)"
	GOOS=darwin GOARCH=amd64 go build $(LDFLAGS) -o bin/$(BINARY_NAME)-darwin ./cmd/servex
	@echo "$(GREEN)macOS build complete!$(NC)"

build-all: build-linux build-windows build-darwin ## Build for all platforms
	@echo "$(GREEN)All platform builds complete!$(NC)"

## Testing
test: ## Run tests
	@echo "$(YELLOW)Running tests...$(NC)"
	go install github.com/mfridman/tparse@latest
	go test -cover -race ./... -json | tparse -all -smallscreen -progress
	@echo "$(GREEN)Tests complete!$(NC)"

test-short: ## Run short tests
	@echo "$(YELLOW)Running short tests...$(NC)"
	go test -short -v ./...
	@echo "$(GREEN)Short tests complete!$(NC)"

benchmark: ## Run benchmarks
	@echo "$(YELLOW)Running benchmarks...$(NC)"
	go test -bench=. -benchmem ./...
	@echo "$(GREEN)Benchmarks complete!$(NC)"

## Docker
docker-build: ## Build Docker image
	@echo "$(YELLOW)Building Docker image...$(NC)"
	docker build \
		--build-arg VERSION=$(VERSION) \
		--build-arg BUILD_TIME=$(BUILD_TIME) \
		--build-arg GIT_COMMIT=$(GIT_COMMIT) \
		-t $(DOCKER_IMAGE):$(DOCKER_TAG) \
		-t $(DOCKER_IMAGE):$(VERSION) \
		.
	@echo "$(GREEN)Docker image built: $(DOCKER_IMAGE):$(DOCKER_TAG)$(NC)"

docker-run: ## Run Docker container
	@echo "$(YELLOW)Running Docker container...$(NC)"
	docker run -it --rm \
		-p 8080:8080 \
		-v $(PWD)/examples/server.yaml:/app/config/server.yaml:ro \
		$(DOCKER_IMAGE):$(DOCKER_TAG)


## Development servers
run-dev: build ## Run development server
	@echo "$(YELLOW)Starting development server...$(NC)"
	./bin/$(BINARY_NAME) -config examples/server.yaml

run-prod: build ## Run production-like server
	@echo "$(YELLOW)Starting production server...$(NC)"
	./bin/$(BINARY_NAME) -config examples/server.yaml

validate-config: build ## Validate configuration
	@echo "$(YELLOW)Validating configuration...$(NC)"
	./bin/$(BINARY_NAME) -validate -config examples/server.yaml


## Maintenance
clean: ## Clean build artifacts
	@echo "$(YELLOW)Cleaning up...$(NC)"
	rm -rf bin/
	go clean
	@echo "$(GREEN)Cleanup complete!$(NC)"

mod-tidy: ## Tidy go modules
	@echo "$(YELLOW)Tidying modules...$(NC)"
	go mod tidy
	@echo "$(GREEN)Modules tidied!$(NC)"

mod-update: ## Update all dependencies
	@echo "$(YELLOW)Updating dependencies...$(NC)"
	go get -u ./...
	go mod tidy
	@echo "$(GREEN)Dependencies updated!$(NC)"


## Show current configuration
info: ## Show build information
	@echo "$(YELLOW)Build Information:$(NC)"
	@echo "  Version:    $(VERSION)"
	@echo "  Build Time: $(BUILD_TIME)"
	@echo "  Git Commit: $(GIT_COMMIT)"
	@echo "  Go Version: $(shell go version)"
	@echo "  Docker Tag: $(DOCKER_IMAGE):$(DOCKER_TAG)" 