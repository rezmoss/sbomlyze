# Security Policy

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| Latest  | :white_check_mark: |
| < Latest | :x:               |

Only the latest release receives security updates. We recommend always running the most recent version.

## Reporting a Vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

Instead, report vulnerabilities through a **private GitHub Security Advisory**:

1. Go to https://github.com/rezmoss/sbomlyze/security/advisories/new
2. Fill in the details:
   - A description of the vulnerability
   - Steps to reproduce
   - Affected version(s)
   - Impact assessment (if known)
3. Submit the advisory

You should receive an acknowledgment within **48 hours**. We aim to provide a fix or mitigation within **7 days** for critical issues.

## Scope

### In Scope

- **SBOM parsing vulnerabilities**: Malicious SBOM files causing crashes, memory exhaustion, or code execution
- **Web UI security**: XSS, CSRF, path traversal, or other web vulnerabilities in the `--web` mode
- **Policy engine bypasses**: Crafted inputs that bypass policy rules
- **Dependency vulnerabilities**: Known CVEs in direct dependencies

### Out of Scope

- Denial-of-service via extremely large files (sbomlyze is designed for local/CI use, not as a public-facing service)
- Issues in third-party SBOM generators (Syft, CycloneDX tools, etc.)
- Social engineering attacks

## Security Design

### Web UI (`--web` mode)

The web server is intended for **local use only** (binds to localhost). It is not designed to be exposed to the internet. If you run it in a container or CI environment, ensure it is not publicly accessible.

- File uploads are limited to 500 MB
- No authentication is provided (local-only design - personal use not server component)
- No data is sent to external services

### SBOM Parsing

- All parsing is done in-memory with Go's standard library and well-maintained SBOM libraries
- Malformed input is handled with structured error reporting (`--tolerant` mode)
- No shell commands are executed based on SBOM content

### Supply Chain

- Dependencies are vendored in the `vendor/` directory for reproducible builds
- Releases are built with [GoReleaser](https://goreleaser.com/) and include SHA256 checksums
- CI runs [CodeQL](https://github.com/rezmoss/sbomlyze/actions/workflows/github-code-scanning/codeql) analysis on every push
- All tests run with Go's race detector enabled (`-race`)

## Disclosure Policy

We follow coordinated disclosure:

1. Reporter submits vulnerability privately
2. We acknowledge and assess the report
3. We develop and test a fix
4. We release the fix and publish a security advisory
5. Reporter is credited (unless they prefer anonymity)
