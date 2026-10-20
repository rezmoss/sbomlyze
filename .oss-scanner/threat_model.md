# Threat model

## What this project does and where untrusted input enters
sbomlyze is a Go CLI (`cmd/sbomlyze`) that parses, analyzes, diffs, scores and converts SBOMs, plus a GitHub Action
(`action/`, Node, no dependencies) that runs the released CLI in CI and gates pull requests on the result.

Treat every SBOM as attacker-controlled. In CI the head SBOM usually comes from a pull request, and the baseline can come
from git history, a release asset, a workflow artifact or a public URL. Untrusted input enters through:
- SBOM files and standard input (`sbomlyze a.json b.json`, `sbomlyze -`): CycloneDX JSON and XML, SPDX JSON, Syft JSON.
  Format detection and parsing live in `internal/sbom/`, normalization and identity in `internal/sbom/normalize.go` and
  `internal/identity/`.
- Policy files (`--policy`, `internal/policy/`). In the Action the policy path comes from the workflow, but the file
  itself may be changed by the pull request.
- The web UI (`--web`, `internal/web/`): an unauthenticated server on 127.0.0.1 that accepts SBOM uploads and serves
  their contents to a browser UI (`internal/web/static/app.js`).
- The Action's inputs and downloads (`action/lib/`): workflow inputs, the GitHub event payload, baselines fetched from
  GitHub or `baseline-url`, zip workflow artifacts, and the release archive of the CLI itself.

The operator (whoever runs the CLI or writes the workflow) is trusted: command-line flags, environment variables
(`PAGER`, `SBOMLYZE_PAGER`), output paths and workflow-level inputs are theirs.

## Components that matter most / least
Most:
- Integrity drift (`internal/analysis/drift.go`, `internal/analysis/`, `internal/sbom/diff.go`). This is the product's
  security promise: a component whose hash changes without a version change must be reported as integrity drift. Any
  crafted pair of SBOMs that swaps a component's content while sbomlyze reports no integrity drift, or that makes
  `--policy` / the Action's `fail-on` pass when it should fail, is a vulnerability. Examples: identity collisions or
  splits in `internal/identity/` that hide a change, normalization that drops or merges hashes, duplicates that shadow
  each other.
- The Action (`action/lib/`): SSRF protection for `baseline-url` (private-address and redirect checks in `baseline.js`),
  zip extraction of workflow artifacts, release download and SHA-256/provenance verification and tar extraction in
  `download.js`, path confinement to `GITHUB_WORKSPACE` in `action.js`, workflow-command and output-file injection, and
  leaking `github-token`.
- Output that reaches other people: Markdown for pull-request comments and Job Summaries (`internal/output/markdown.go`),
  HTML reports (`internal/output/html.go`), SARIF, JUnit and JSON. Untrusted component names, versions, licenses and
  PURLs flow into all of them.
- The web UI: XSS in `app.js` from SBOM fields, path or memory problems in the upload and filesystem handlers.
- Parsers: panics, unbounded allocation or pathological runtime on malformed input in `internal/sbom/` and
  `internal/convert/`.

Out of scope:
- `site/` (the Hugo documentation site), `docs/`, `examples/`, `scripts/`, `testdata/`, `.github/`, and `install.sh`
  beyond its checksum verification.
- Third-party modules themselves; report them only when sbomlyze's own use of them is the problem.
- The accuracy of SBOM contents. sbomlyze reports what the SBOMs say; a generator that omits a package is not a bug here.

## How you rate severity
- **critical**: code execution from SBOM, policy or baseline content, in the CLI or the Action. Writing files outside
  the intended directory from an artifact, archive or baseline. Installing a CLI release that failed checksum or
  provenance verification.
- **high**: a crafted SBOM pair that hides integrity drift or makes a failing policy or `fail-on` pass. SSRF past the
  `baseline-url` checks. Leaking `github-token`. Script injection in the web UI or the HTML report. Markdown that
  forges the verdict or summary in a pull-request comment.
- **medium**: other output injection (Markdown, SARIF, JUnit, workflow commands) that misleads a reader. Reading files
  outside the workspace in the Action. Resource exhaustion from a small input (much smaller than the 50-500 MiB size
  limits).
- **low**: a panic or hang on malformed input that ends with the process and leaves nothing behind.

Memory or CPU proportional to a very large input is not a vulnerability: sbomlyze is a local and CI tool, not a public
service. The web UI is local-only by design and has no authentication; findings that require it to be exposed on a
network are out of scope, but reaching it from a web page the user visits (DNS rebinding, CSRF) is in scope.

## How to exercise it
- The CLI is at `/usr/local/bin/sbomlyze` (`sbomlyze-debug` is built with `-N -l` for gdb/dlv-style debugging).
  `sbomlyze testdata/cyclonedx-before.json testdata/cyclonedx-after.json --json` diffs two SBOMs;
  `testdata/cyclonedx-integrity-drift.json` is a same-version hash change. Add `--policy testdata/policy-all-rules.json`,
  `--compliance`, or `--format markdown|html|sarif|junit`. `sbomlyze convert <file> --to spdx|cyclonedx|syft` converts.
- `sbomlyze --web --port 8080 &` then `curl -F file=@testdata/syft-sample.json http://127.0.0.1:8080/api/upload` and
  query `/api/tree`, `/api/search?q=`, `/api/component/<id>`, `/api/filesystem`.
- Go tests: `go test -race ./...` (snapshot tests in `cmd/sbomlyze/`). Fuzzing: `go test -run '^$'
  -fuzz=FuzzParseDataWithInfo ./internal/sbom/`.
- Action tests: `node --test action/test/*.test.js`. They stub the network; real GitHub downloads cannot run offline.
- There is no network here. `govulncheck`, `make lint` (golangci-lint) and the GoReleaser build are not installed.

## Reports
Include the input files (or a script that writes them), the exact command or Action inputs, and the commit. Patches
should come with a regression test next to the existing tests for that package.

## Anything to leave alone
- Hash comparisons that flag benign changes (false positives) are not security issues; open an issue instead.
- `PAGER` / `SBOMLYZE_PAGER` executing a command is intended behavior controlled by the operator.
