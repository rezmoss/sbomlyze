.PHONY: all test lint build

all: test lint build

test:
	go test -v -race ./...

lint:
	golangci-lint run ./...

build:
	@which goreleaser > /dev/null || (echo "goreleaser not found. Install: go install github.com/goreleaser/goreleaser/v2@latest" && exit 1)
	goreleaser build --snapshot --clean
	@echo "Build artifacts in ./dist/"