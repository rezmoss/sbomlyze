.PHONY: all test lint build build-quick clean snapshot-test update-snapshot

all: test lint build

test:
	go test -v -race -count=1 ./...

lint:
	golangci-lint run ./...

build:
	@which goreleaser > /dev/null || (echo "goreleaser not found. Install: go install github.com/goreleaser/goreleaser/v2@latest" && exit 1)
	goreleaser build --snapshot --clean
	@echo "Build artifacts in ./dist/"

# Quick build for development
build-quick:
	go build -o sbomlyze ./cmd/sbomlyze
	@echo "Built ./sbomlyze"

snapshot-test:
	go test -v -run TestSnapshot ./cmd/sbomlyze/

update-snapshot:
	go test -v -run TestSnapshot ./cmd/sbomlyze/ -update

clean:
	rm -rf dist/ sbomlyze