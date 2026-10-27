.DEFAULT_GOAL := help
.DELETE_ON_ERROR:

GO ?= go
GOLANGCI_LINT_VERSION := v2.14.0
TOOLS_DIR := $(CURDIR)/bin/tools
GOLANGCI_LINT := $(TOOLS_DIR)/golangci-lint-$(GOLANGCI_LINT_VERSION)

.PHONY: help tools deps build test test-race test-offline vet lint fmt fmt-check mod-check check clean

help: ## Show available development commands (default)
	@printf 'Usage: make <target>\n\n'
	@awk 'BEGIN {FS = ":.*## "} /^[a-zA-Z_-]+:.*## / {printf "  %-16s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

tools: $(GOLANGCI_LINT) ## Install the pinned Go linter locally under bin/tools

$(GOLANGCI_LINT): Makefile
	@mkdir -p "$(TOOLS_DIR)"
	GOBIN="$(TOOLS_DIR)" $(GO) install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)
	mv "$(TOOLS_DIR)/golangci-lint" "$@"

deps: ## Download application dependencies (needed before offline tests)
	$(GO) mod download

build: ## Build the Go port without overwriting the shipping Bash script
	$(GO) build -mod=readonly -o bin/gh-secure ./cmd/gh-secure

test: ## Run all unit tests (no GitHub credentials required)
	$(GO) test -mod=readonly ./...

test-race: ## Run unit tests with the race detector (requires CGO)
	$(GO) test -mod=readonly -race ./...

test-offline: ## Run unit tests with module network access disabled
	GOPROXY=off GOSUMDB=off $(GO) test -mod=readonly ./...

vet: ## Run Go's built-in static analysis
	$(GO) vet -mod=readonly ./...

lint: $(GOLANGCI_LINT) ## Run static analysis, formatting checks, and Bash syntax checks
	"$(GOLANGCI_LINT)" run ./...
	bash -n gh-secure

fmt: $(GOLANGCI_LINT) ## Format Go code and organize imports
	"$(GOLANGCI_LINT)" fmt ./...

fmt-check: $(GOLANGCI_LINT) ## Check Go formatting without modifying files
	"$(GOLANGCI_LINT)" fmt --diff ./...

mod-check: ## Check module files without modifying them
	$(GO) mod tidy -diff

check: mod-check lint build test-offline ## Run the CI-equivalent checks (run make deps first)

clean: ## Remove only the generated development binary (keep cached tools)
	rm -f bin/gh-secure
