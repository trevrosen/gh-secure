.DEFAULT_GOAL := help
.DELETE_ON_ERROR:

GO ?= go
GOLANGCI_LINT_VERSION := v2.14.0
ACTIONLINT_VERSION := v1.7.12
GOVULNCHECK_VERSION := v1.9.0
TOOLS_DIR := $(CURDIR)/bin/tools
GOLANGCI_LINT := $(TOOLS_DIR)/golangci-lint-$(GOLANGCI_LINT_VERSION)
ACTIONLINT := $(TOOLS_DIR)/actionlint-$(ACTIONLINT_VERSION)
GOVULNCHECK := $(TOOLS_DIR)/govulncheck-$(GOVULNCHECK_VERSION)

# Install Go command package $(1) at version $(2) as the versioned target file.
define install-tool
	@mkdir -p "$(TOOLS_DIR)"
	GOBIN="$(TOOLS_DIR)" $(GO) install $(1)@$(2)
	mv "$(TOOLS_DIR)/$(notdir $(1))" "$@"
endef

.PHONY: help tools deps build test test-race test-offline vet lint lint-workflows vulncheck fmt fmt-check mod-check check clean

help: ## Show available development commands (default)
	@printf 'Usage: make <target>\n\n'
	@awk 'BEGIN {FS = ":.*## "} /^[a-zA-Z_-]+:.*## / {printf "  %-16s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

tools: $(GOLANGCI_LINT) $(ACTIONLINT) $(GOVULNCHECK) ## Install the pinned development tools under bin/tools

$(GOLANGCI_LINT):
	$(call install-tool,github.com/golangci/golangci-lint/v2/cmd/golangci-lint,$(GOLANGCI_LINT_VERSION))

$(ACTIONLINT):
	$(call install-tool,github.com/rhysd/actionlint/cmd/actionlint,$(ACTIONLINT_VERSION))

$(GOVULNCHECK):
	$(call install-tool,golang.org/x/vuln/cmd/govulncheck,$(GOVULNCHECK_VERSION))

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

lint: lint-workflows $(GOLANGCI_LINT) ## Run Go static analysis and formatting, workflow, and Bash syntax checks
	"$(GOLANGCI_LINT)" run ./...
	bash -n gh-secure

# ShellCheck/pyflakes integration is disabled so results do not depend on
# whichever optional linters happen to be on PATH (CI runners have ShellCheck).
lint-workflows: $(ACTIONLINT) ## Check GitHub Actions workflows with actionlint
	"$(ACTIONLINT)" -shellcheck= -pyflakes=

vulncheck: $(GOVULNCHECK) ## Report known vulnerabilities in reachable code (needs network)
	"$(GOVULNCHECK)" ./...

fmt: $(GOLANGCI_LINT) ## Format Go code and organize imports
	"$(GOLANGCI_LINT)" fmt ./...

fmt-check: $(GOLANGCI_LINT) ## Check Go formatting without modifying files
	"$(GOLANGCI_LINT)" fmt --diff ./...

mod-check: ## Check module files without modifying them
	$(GO) mod tidy -diff

check: mod-check lint build test-offline ## Run the CI-equivalent checks (run make deps first)

clean: ## Remove only the generated development binary (keep cached tools)
	rm -f bin/gh-secure
