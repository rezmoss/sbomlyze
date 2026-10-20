# Scanner image for https://github.com/rezmoss/sbomlyze, used by Anthropic's OSS Scanner
# (https://github.com/anthropics/oss-scanner). The scanner builds this with the repository as the build context and
# network access, then runs everything after it offline, so every module and tool the tests need is fetched here.
# threat_model.md, next to this file, says what is in scope and how to exercise it.

# Node runtime for the GitHub Action under action/ (action.yml runs it with node24).
FROM node:24-bookworm-slim AS node

# The Go line go.mod and CI (setup-go with go-version-file) use. The image has git and gcc, which -race needs.
FROM golang:1.25-bookworm
COPY --from=node /usr/local/bin/node /usr/local/bin/node

# scanner contract: the checkout lives inside the image, at /src
COPY . /src
WORKDIR /src

# The project does not vendor dependencies (see Makefile); module mode keeps a stray vendor/ from changing builds.
ENV GOFLAGS=-mod=mod
RUN go mod download && go mod verify

# The CLI as release builds it, plus a debug build. A step that fails fails the build.
RUN CGO_ENABLED=0 go build -trimpath -o /usr/local/bin/sbomlyze ./cmd/sbomlyze \
    && go build -gcflags=all="-N -l" -o /usr/local/bin/sbomlyze-debug ./cmd/sbomlyze \
    && sbomlyze --version \
    && go vet ./... \
    && go test -run '^$' ./... \
    && go test -race -run '^$' ./...

# Run the test suites so the log shows the image works and the build and test caches are warm offline, without letting
# a failure abort the build. Seed the fuzz corpus once so `go test -fuzz` starts immediately.
RUN (timeout 1200 go test -race -count=1 ./... || echo "WARNING: go test reported failures") \
    && (timeout 120 go test -run '^$' -fuzz=FuzzParseDataWithInfo -fuzztime=30s ./internal/sbom/ \
          || echo "WARNING: fuzzing reported failures") \
    && (node --test action/test/*.test.js || echo "WARNING: action tests reported failures")

# Everything is fetched. From here on the go command must not try to reach a proxy or download a toolchain, and the
# CLI must not open a pager.
ENV GOPROXY=off \
    GOTOOLCHAIN=local \
    GOFLAGS=-mod=mod \
    SBOMLYZE_PAGER=cat
