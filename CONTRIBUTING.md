# Contributing to sbomlyze

Thank you for your interest in contributing to sbomlyze! This guide covers everything you need to get started.

## Getting Started

### Prerequisites

| Tool | Version | Install |
|------|---------|---------|
| Go | 1.24+ | https://go.dev/dl/ |
| golangci-lint | v1.64+ | `go install github.com/golangci/golangci-lint/cmd/golangci-lint@v1.64.8` |
| goreleaser (optional) | v2 | `go install github.com/goreleaser/goreleaser/v2@latest` |

### Clone and Build

```bash
git clone https://github.com/rezmoss/sbomlyze.git
cd sbomlyze
make build-quick
./sbomlyze --version
```

### Project Layout

```
cmd/sbomlyze/       CLI entry point
internal/
  analysis/         Diff engine, stats computation, dependency graphs
  cli/              Argument parsing and option handling
  identity/         Component identity matching (PURL, CPE, BOM-ref)
  output/           Output formatters (text, JSON, SARIF, JUnit, Markdown, Patch)
  pager/            Terminal pager support
  policy/           Policy engine for CI/CD enforcement
  progress/         Progress spinner
  sbom/             SBOM format parsers (Syft, CycloneDX, SPDX)
  tui/              Interactive terminal UI (Bubble Tea)
  version/          Build version info
  web/              Web UI server, handlers, and static assets
    static/         HTML, CSS, JavaScript for the web explorer
testdata/           Test fixtures (SBOM samples, snapshots)
examples/policies/  Example policy files
```

## Before You Submit

**Always run tests and lint before committing.** CI will reject PRs that fail either check.

### 1. Run Tests

```bash
make test
```

This runs the full test suite with the race detector:

```bash
go test -v -race -count=1 ./...
```

If you changed output formatting, update snapshots:

```bash
make update-snapshot
```

### 2. Run Linter

```bash
make lint
```

This runs golangci-lint with the project's default configuration:

```bash
golangci-lint run ./...
```

Fix any issues before committing. Common lint fixes:

- Unused variables or imports: remove them
- Error return values: handle or explicitly ignore with `_ =`
- Formatting: run `gofmt -w .`

### 3. Verify Build

```bash
make build-quick
```

### Quick Pre-Commit Checklist

```bash
make test && make lint && make build-quick
```

Or run everything at once:

```bash
make all
```

## Makefile Targets

Run `make help` for a quick reference:

```
make all              Run test, lint, and build (full CI check)
make test             Run all tests with race detector
make lint             Run golangci-lint
make build            Build with goreleaser (snapshot)
make build-quick      Quick development build (./sbomlyze)
make snapshot-test    Run snapshot tests only
make update-snapshot  Update snapshot golden files
make clean            Remove build artifacts
make help             Show this help
```

## Making Changes

### Branching

1. Fork the repository
2. Create a feature branch from `main`:
   ```bash
   git checkout -b feat/my-feature
   ```
3. Make your changes
4. Run `make test && make lint`
5. Commit and push
6. Open a pull request against `main`

### Branch Naming

| Prefix | Use |
|--------|-----|
| `feat/` | New features |
| `fix/` | Bug fixes |
| `refactor/` | Code refactoring (no behavior change) |
| `docs/` | Documentation only |
| `test/` | Test additions or fixes |

### Commit Messages

Write clear, concise commit messages:

```
feat: add SARIF output format for CI integration

fix: handle empty dependency list in CycloneDX parser

refactor: extract identity matching into separate package

docs: add policy engine examples to README

test: add snapshot tests for diff output
```

- Use imperative mood ("add", not "added" or "adds")
- Keep the first line under 72 characters
- Reference issues when applicable: `fix: handle nil pointer in search (#42)`

## Pull Request Guidelines

### What Makes a Good PR

- **Focused**: One logical change per PR
- **Tested**: New code has tests, existing tests pass
- **Linted**: No lint warnings
- **Documented**: Update README if adding user-facing features

### PR Description

Include:
- What the change does and why
- How to test it
- Screenshots for UI changes (web or TUI)

### Review Process

1. CI must pass (tests, lint, build)
2. At least one maintainer review
3. Address review feedback
4. Squash-merge into `main`

## Writing Tests

### Test Files

Tests live next to the code they test:

```
internal/sbom/parse.go
internal/sbom/parse_test.go
```

### Test Data

Place test fixtures in `testdata/`:

```
testdata/cyclonedx-before.json
testdata/spdx-sample.json
testdata/syft-sample.json
```

### Running Specific Tests

```bash
# Run tests for one package
go test -v ./internal/sbom/

# Run a specific test
go test -v -run TestParseCycloneDX ./internal/sbom/

# Run with coverage
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out
```

### Snapshot Tests

Output formatting tests use golden file snapshots in `testdata/snapshots/`. If you intentionally change output formatting:

```bash
# Review changes
make snapshot-test

# Update golden files if the new output is correct
make update-snapshot

# Verify
make snapshot-test
```

## Areas for Contribution

### Good First Issues

Look for issues labeled [`good first issue`](https://github.com/rezmoss/sbomlyze/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22) on GitHub.

### Ideas

- Additional SBOM format support (e.g., CycloneDX XML)
- New policy rules
- Output format improvements
- Performance optimizations for large SBOMs
- Web UI enhancements
- Documentation and examples

## Code Style

- Follow standard Go conventions (`gofmt`, `go vet`)
- Keep functions focused and short
- Use table-driven tests where appropriate
- Handle errors explicitly — don't ignore them silently
- Internal packages (`internal/`) are not part of the public API

## Questions?

- Open a [GitHub Discussion](https://github.com/rezmoss/sbomlyze/discussions) for questions
- Open an [Issue](https://github.com/rezmoss/sbomlyze/issues) for bugs or feature requests

## License

By contributing, you agree that your contributions will be licensed under the [Apache License 2.0](LICENSE).
