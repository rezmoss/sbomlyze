.PHONY: all test lint vulncheck build build-quick clean snapshot-test update-snapshot snapshot-diff snapshot-review help

all: test lint build ## Run test, lint, and build (full CI check)

test: ## Run all tests with race detector
	go test -v -race -count=1 ./...

lint: ## Run vet, golangci-lint, and staticcheck
	go vet ./...
	golangci-lint run ./...
	staticcheck ./...

vulncheck: ## Run govulncheck for known vulnerabilities
	govulncheck ./...

build: ## Build with goreleaser (snapshot)
	@which goreleaser > /dev/null || (echo "goreleaser not found. Install: go install github.com/goreleaser/goreleaser/v2@latest" && exit 1)
	goreleaser build --snapshot --clean
	@echo "Build artifacts in ./dist/"

build-quick: ## Quick development build (./sbomlyze)
	go build -o sbomlyze ./cmd/sbomlyze
	@echo "Built ./sbomlyze"

snapshot-test: ## Run snapshot tests only
	go test -v -run TestSnapshot ./cmd/sbomlyze/

update-snapshot: ## Update snapshot golden files (use NAME= to filter)
ifdef NAME
	go test -v -run TestSnapshot ./cmd/sbomlyze/ -update -snapshot-filter="$(NAME)"
else
	@echo "Updating ALL snapshots. Use NAME=foo,bar to update selectively."
	@echo "Run 'make snapshot-diff' first to review changes."
	@echo ""
	go test -v -run TestSnapshot ./cmd/sbomlyze/ -update
endif

snapshot-diff: ## Show what snapshot changes would occur (no writes)
	go test -v -run TestSnapshot ./cmd/sbomlyze/ -diff

snapshot-review: ## Interactively review and accept snapshot changes
	@bash scripts/review-snapshots.sh

clean: ## Remove build artifacts
	rm -rf dist/ sbomlyze

help: ## Show this help
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-20s %s\n", $$1, $$2}'
	@echo ""
	@echo "Pre-commit checklist:"
	@echo "  make test && make lint"
